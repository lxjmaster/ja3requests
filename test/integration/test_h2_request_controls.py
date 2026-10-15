"""Real TLS and H2 transport paths for request priority and HPACK exclusions."""

import asyncio
import io
import struct

import pytest

from ja3requests import AsyncSession, HTTPRetry, Session
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.hpack import HPACKDecoder
from test.integration.test_async_h2_network import async_h2_connections
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    h2_readers,
    receive_frame,
    start_h2,
    trusted_h2_peer,
)
from test.mock_servers.local import LocalServer, h2_frame
from test.integration.test_sync_redirect_replay import literal, http1_request


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('huffman', [False, True])
@pytest.mark.parametrize(
    'entry',
    ['sync', 'sync-unpooled', 'sync-upload', 'async', 'async-prepared', 'async-upload'],
)
def test_priority_and_exclusions_reach_all_real_transports(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    async_h2_connections,
    version,
    huffman,
    entry,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    config.h2_huffman = huffman
    config.h2_indexing_exclusions = [':path']
    seen = []
    count = 1 if entry == 'sync-unpooled' else 3

    def peer(conn):
        start_h2(conn)
        decoder, block, priority = HPACKDecoder(), bytearray(), None
        request, body = None, bytearray()
        while len(seen) < count:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 1:
                priority = None
                if flags & 32:
                    dependency, weight = struct.unpack('!IB', payload[:5])
                    priority = (
                        dependency & 0x7FFFFFFF,
                        weight + 1,
                        bool(dependency & 0x80000000),
                    )
                    payload = payload[5:]
                block.clear()
                body.clear()
                end_stream = bool(flags & 1)
            if kind in (1, 9):
                block.extend(payload)
                if flags & 4:
                    headers = dict(decoder.decode_headers(bytes(block)))
                    assert headers['x-reuse'] == 'www.example.com'
                    assert not any(name == ':path' for name, _ in decoder.dynamic_table)
                    request = (stream, priority, headers, len(decoder.dynamic_table))
                    if end_stream:
                        seen.append(request + (bytes(body),))
                        conn.sendall(
                            h2_frame(1, 4, stream, b'\x88')
                            + h2_frame(0, 1, stream, b'done')
                        )
            if kind == 0:
                body.extend(payload)
                if flags & 1:
                    seen.append(request + (bytes(body),))
                    conn.sendall(
                        h2_frame(1, 4, stream, b'\x88')
                        + h2_frame(0, 1, stream, b'done')
                    )
        await_transport_close(conn)

    paths = ['/', '/pixel.png', '/pixel.png'][:count]
    priorities = [(256, True), (183, True), None][:count]
    borrowed = []

    async def run(origin):
        async with AsyncSession(tls_config=config) as session:
            for path, priority in zip(paths, priorities):
                arguments = dict(
                    headers={'x-reuse': 'www.example.com'}, h2_headers_priority=priority
                )
                if entry == 'async-upload':
                    source = io.BytesIO(b'upload')
                    borrowed.append(source)
                    response = await session.post(
                        origin + path, data=source, timeout=3, **arguments
                    )
                elif entry == 'async-prepared':
                    prepared = await session.prepare_request(
                        'GET', origin + path, **arguments
                    )
                    assert prepared.h2_headers_priority == priority
                    response = await session.send(
                        prepared.with_headers(dict(prepared.headers)), timeout=3
                    )
                else:
                    response = await session.get(origin + path, timeout=3, **arguments)
                assert await response.read() == b'done'

    with LocalServer(peer, context) as server:
        origin = 'https://127.0.0.1:%d' % server.port
        if entry.startswith('async'):
            asyncio.run(run(origin))
        else:
            with ConnectionPool() as pool, Session(
                tls_config=config, pool=pool, use_pooling=entry != 'sync-unpooled'
            ) as session:
                for path, priority in zip(paths, priorities):
                    arguments = dict(
                        headers={'x-reuse': 'www.example.com'},
                        h2_headers_priority=priority,
                    )
                    if entry == 'sync-upload':
                        source = io.BytesIO(b'upload')
                        borrowed.append(source)
                        response = session.post(
                            origin + path, data=source, timeout=3, **arguments
                        )
                    else:
                        response = session.get(origin + path, timeout=3, **arguments)
                    assert response.content == b'done'
    assert [row[0] for row in seen] == [1, 3, 5][:count]
    assert [row[1] for row in seen] == [(0, 256, True), (0, 183, True), None][:count]
    assert [row[2][':path'] for row in seen] == paths
    if count == 3:
        assert seen[1][3] == seen[2][3] and seen[0][3] > 0
    assert all(not source.closed for source in borrowed)
    assert [row[4] for row in seen] == (
        [b'upload'] * count if 'upload' in entry else [b''] * count
    )


@pytest.mark.parametrize('entry', ['sync', 'async', 'async-prepared'])
@pytest.mark.parametrize('stage', ['redirect', 'retry'])
def test_priority_survives_new_connection_and_redirect_hooks(
    trusted_certificates, monkeypatch, h2_readers, async_h2_connections, entry, stage
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = []
    target = []

    def peer(conn):
        start_h2(conn)
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 1:
                dependency, weight = struct.unpack('!IB', payload[:5])
                path = dict(HPACKDecoder().decode_headers(payload[5:]))[':path']
                seen.append((stream, dependency, weight + 1, path))
                first = len(seen) == 1
                status = '307' if stage == 'redirect' else '503'
                block = literal(8, status) if first else b'\x88'
                if first and stage == 'redirect':
                    block += literal(46, target[0])
                reply = h2_frame(1, 5, stream, block)
                if first:
                    # Require a new connection through protocol state, rather
                    # than racing the client's reader against a socket close.
                    reply += h2_frame(7, 0, 0, struct.pack('!II', stream, 0))
                conn.sendall(reply)
                await_transport_close(conn)
                return

    def before(request):
        if stage == 'redirect' and request.url.endswith('/target'):
            request.h2_headers_priority = (183, True)

    options = dict(h2_headers_priority=(256, True), hooks={'before_request': [before]})
    retry = (
        HTTPRetry(total=1, backoff_factor=0, status_forcelist={503})
        if stage == 'retry'
        else None
    )

    async def run(url):
        async with AsyncSession(tls_config=config, retry=retry) as session:
            if entry == 'async-prepared':
                prepared = await session.prepare_request(
                    'GET', url, h2_headers_priority=(256, True)
                )
                response = await session.send(
                    prepared, timeout=3, hooks={'before_request': [before]}
                )
            else:
                response = await session.get(url, timeout=3, **options)
            assert response.status_code == 200

    with LocalServer(
        peer, context, connections=1 if stage == 'redirect' else 2
    ) as first:
        with LocalServer(
            peer, context, connections=1 if stage == 'redirect' else 0
        ) as second:
            target.append('https://127.0.0.1:%d/target' % second.port)
            url = 'https://127.0.0.1:%d/start' % first.port
            if entry == 'sync':
                with ConnectionPool() as pool, Session(
                    tls_config=config, pool=pool, retry=retry
                ) as session:
                    assert session.get(url, timeout=3, **options).status_code == 200
            else:
                asyncio.run(run(url))
    assert seen == [
        (1, 0x80000000, 256, '/start'),
        (
            1,
            0x80000000,
            183 if stage == 'redirect' else 256,
            '/target' if stage == 'redirect' else '/start',
        ),
    ]


@pytest.mark.parametrize('entry', ['sync', 'async'])
def test_headers_priority_has_no_http1_wire_effect(
    trusted_certificates, monkeypatch, entry
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    config.alpn_protocols = ['h2', 'http/1.1']
    context.set_alpn_protocols(['http/1.1'])
    config.h2_indexing_exclusions = [':path']
    seen = []

    def peer(conn):
        assert conn.selected_alpn_protocol() == 'http/1.1'
        seen.append(http1_request(conn))
        conn.sendall(
            b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        )

    async def run(url):
        async with AsyncSession(tls_config=config) as session:
            assert (
                await session.get(url, h2_headers_priority=(183, True), timeout=3)
            ).status_code == 200

    with LocalServer(peer, context) as server:
        url = 'https://127.0.0.1:%d/' % server.port
        if entry == 'sync':
            with Session(tls_config=config, use_pooling=False) as session:
                assert (
                    session.get(
                        url, h2_headers_priority=(183, True), timeout=3
                    ).status_code
                    == 200
                )
        else:
            asyncio.run(run(url))
    assert seen[0][0:2] == ('GET', '/') and seen[0][3] == b''
    assert not any('priority' in name for name in seen[0][2])
