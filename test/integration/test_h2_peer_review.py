"""Real project TLS handshakes with independently encoded H2 peer traffic."""

import asyncio
import socket
import struct

import pytest

from ja3requests import AsyncSession, Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.async_connection import H2ProtocolError
from ja3requests.protocol.h2.hpack import HPACKDecoder
from ja3requests.protocol.tls import TLS
from test.integration.test_async_h2_network import async_h2_connections
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    h2_readers,
    receive_frame,
    start_h2,
    trusted_h2_peer,
)
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    tls12_context,
    recv_with_ragged_eof,
)
from test.test_h2_peer_review import literal


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('entry', ['sync', 'async'])
@pytest.mark.parametrize('phase', ['final', 'interim', 'trailers'])
def test_real_tls_malformed_response_cannot_inject_cookie_and_pool_survives(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    async_h2_connections,
    version,
    entry,
    phase,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    observed, resets = [], []
    bad = literal('x-probe', 'value\r\nSet-Cookie: injected=yes; Path=/')
    shared = literal('x-shared', 'saved', indexed=True)

    def peer(conn):
        start_h2(conn)
        while len(observed) < 2:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 3:
                resets.append((stream, payload))
            if kind != 1:
                continue
            observed.append(stream)
            if stream == 1:
                if phase == 'final':
                    wire = h2_frame(1, 5, stream, b'\x88' + bad + shared)
                elif phase == 'interim':
                    wire = h2_frame(
                        1, 4, stream, literal(':status', '103') + bad + shared
                    )
                else:
                    wire = (
                        h2_frame(1, 4, stream, b'\x88')
                        + h2_frame(0, 0, stream, b'discard')
                        + h2_frame(1, 5, stream, bad + shared)
                    )
                # Exercise continuation handling over the authenticated channel.
                if phase == 'final':
                    block = b'\x88' + bad + shared
                    wire = h2_frame(1, 1, stream, block[:7]) + h2_frame(
                        9, 4, stream, block[7:]
                    )
                conn.sendall(wire)
            else:
                conn.sendall(h2_frame(1, 5, stream, b'\x88\xbe'))
        await_transport_close(conn)

    async def run(url):
        async with AsyncSession(tls_config=config) as session:
            with pytest.raises(H2ProtocolError, match='field value'):
                response = await session.get(url, timeout=2)
                await response.aread()
            assert not list(session.cookies)
            response = await session.get(url, timeout=2)
            assert (
                response.status_code == 200 and response.headers['x-shared'] == 'saved'
            )
            assert not list(session.cookies)

    with LocalServer(peer, context) as server:
        url = 'https://127.0.0.1:%d/' % server.port
        if entry == 'sync':
            with ConnectionPool() as pool, Session(
                tls_config=config, pool=pool
            ) as session:
                with pytest.raises(ConnectionError, match='field value'):
                    response = session.get(url, timeout=2)
                    _ = response.content
                assert not list(session.cookies)
                response = session.get(url, timeout=2)
                assert (
                    response.status_code == 200
                    and response.headers['x-shared'] == 'saved'
                )
                assert not list(session.cookies)
        else:
            asyncio.run(run(url))
    assert observed == [1, 3]
    assert resets == [(1, b'\x00\x00\x00\x01')]
    assert len(h2_readers if entry == 'sync' else async_h2_connections) == 1


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('entry', ['sync', 'async'])
def test_real_tls_duplicate_settings_clear_table_before_repeated_request(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    async_h2_connections,
    version,
    entry,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    blocks, decoded, acknowledged = [], [], []

    def peer(conn):
        start_h2(conn)
        decoder = HPACKDecoder()
        while len(blocks) < 3:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 4 and flags & 1:
                acknowledged.append(len(blocks))
            if kind != 1:
                continue
            blocks.append(payload)
            decoded.append(decoder.decode_headers(payload))
            settings = b''
            if len(blocks) == 1:
                settings = h2_frame(4, 0, 0, struct.pack('!HIHI', 1, 0, 1, 4096))
                # Independent peer eviction; the next block must announce both changes.
                decoder.dynamic_table.clear()
                decoder._dynamic_table_size = 0
            conn.sendall(settings + h2_frame(1, 5, stream, b'\x88'))
        await_transport_close(conn)

    async def run(url):
        async with AsyncSession(tls_config=config) as session:
            for _ in range(3):
                assert (
                    await session.get(url, headers={'x-custom': 'value'}, timeout=2)
                ).status_code == 200

    with LocalServer(peer, context) as server:
        url = 'https://127.0.0.1:%d/' % server.port
        if entry == 'sync':
            with ConnectionPool() as pool, Session(
                tls_config=config, pool=pool
            ) as session:
                for _ in range(3):
                    assert (
                        session.get(
                            url, headers={'x-custom': 'value'}, timeout=2
                        ).status_code
                        == 200
                    )
        else:
            asyncio.run(run(url))
    assert decoded[0] == decoded[1] == decoded[2]
    assert blocks[1].startswith(b'\x20\x3f\xe1\x1f')  # 0, then 4096 (RFC7541).
    assert 1 in acknowledged
    assert len(h2_readers if entry == 'sync' else async_h2_connections) == 1


def test_extension_free_legacy_client_hello_completes_real_tls12(local_certificate):
    observed = []
    context = tls12_context(*local_certificate)

    def peer(conn):
        observed.append((conn.version(), conn.selected_alpn_protocol()))
        assert read_exact(conn, 4) == b'ping'
        conn.sendall(b'pong')
        await_transport_close(conn)

    with LocalServer(peer, context) as server:
        with socket.create_connection(('127.0.0.1', server.port), timeout=2) as sock:
            tls = TLS(sock, handshake_timeout=2)
            config = TlsConfig.legacy()
            assert config.validate() == []
            tls.set_payload(config)
            assert tls.body.extensions is None
            assert tls.handshake()
            assert len(tls.sent_client_hellos) == 1
            record = tls.sent_client_hellos[0]
            # Independently locate compression_methods: no extension vector follows.
            offset = 9 + 2 + 32
            offset += 1 + record[offset]
            offset += 2 + int.from_bytes(record[offset : offset + 2], 'big')
            offset += 1 + record[offset]
            assert offset == len(record)
            from ja3requests.sockets.https import HttpsSocket
            from types import SimpleNamespace

            transport = HttpsSocket(SimpleNamespace())
            transport.tls, transport.conn = tls, sock
            sock.sendall(transport._encrypt_application_data(b'ping'))
            assert transport._decrypt_single_record() == b'pong'
    assert observed == [('TLSv1.2', None)]


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('entry', ['sync', 'async'])
@pytest.mark.parametrize(
    'identifier,bad,good', [(2, 1, 0), (4, 2147483648, 65535), (5, 0, 16384)]
)
def test_real_tls_invalid_intermediate_settings_close_without_ack_or_pool_entry(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    async_h2_connections,
    version,
    entry,
    identifier,
    bad,
    good,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    incoming = []

    def peer(conn):
        assert conn.selected_alpn_protocol() == 'h2'
        assert read_exact(conn, 24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        conn.sendall(
            h2_frame(4, 0, 0, struct.pack('!HIHI', identifier, bad, identifier, good))
        )
        wire = b''
        while True:
            chunk = recv_with_ragged_eof(conn, 65536)
            if not chunk:
                break
            wire += chunk
        while wire:
            size = int.from_bytes(wire[:3], 'big')
            assert len(wire) >= 9 + size
            incoming.append((wire[3], wire[4]))
            wire = wire[9 + size :]

    async def run(url):
        async with AsyncSession(tls_config=config) as session:
            with pytest.raises(H2ProtocolError):
                await session.get(url, timeout=2)
            assert not session._pool._entries and not session._pool._creating

    with LocalServer(peer, context) as server:
        url = 'https://127.0.0.1:%d/' % server.port
        if entry == 'sync':
            with ConnectionPool() as pool, Session(
                tls_config=config, pool=pool
            ) as session:
                with pytest.raises(ConnectionError):
                    session.get(url, timeout=2)
                assert pool.get_stats()['total_connections'] == 0
        else:
            asyncio.run(run(url))
    assert (4, 1) not in incoming
