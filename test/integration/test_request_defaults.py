"""Receive default headers/queries on real peers across client policy boundaries."""

import asyncio
from urllib.parse import urlsplit

import pytest

from ja3requests import AsyncSession, HTTPRetry, Session
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.hpack import HPACKDecoder
from ja3requests.requests.request import Request
from test.integration.test_async_h2_network import async_h2_connections
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    h2_readers,
    start_h2,
    trusted_h2_peer,
)
from test.integration.test_request_wire_review import read_h2_request
from test.integration.test_sync_redirect_replay import BorrowedFile, http1_request
from test.mock_servers.local import LocalServer, h2_frame
from test.test_async_session import Peer, ok
from test.test_async_upload import UploadPeer, read_body, reply


@pytest.mark.parametrize('client', ['sync', 'async', 'prepared'])
@pytest.mark.parametrize('protocol', ['http', 'h1', 'h2'])
def test_defaults_reach_peer_and_reused_connection(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    async_h2_connections,
    client,
    protocol,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    if protocol == 'h1':
        config.alpn_protocols = ['http/1.1']
        context.set_alpn_protocols(['http/1.1'])
    seen = []
    source = BorrowedFile(b'body')
    defaults = {
        'headers': {'X-Default': 'configured', 'X-Bytes': b'\xc3\xa9', 'X-Number': 2},
        'params': [('tag', 'a'), ('tag', 'b'), ('page', '1')],
    }
    updated = {'headers': {'X-Default': 'updated'}, 'params': {'page': '2'}}

    def before(_):
        if not seen:
            assert source.reads == 0, 'Preparing defaults consumed the upload source'

    def serve(conn):
        decoder = HPACKDecoder()
        if protocol == 'h2':
            start_h2(conn)
        for _ in range(2):
            if protocol == 'h2':
                stream, headers, body, _ = read_h2_request(conn, decoder)
                seen.append((headers[':method'], headers[':path'], headers, body))
                conn.sendall(h2_frame(1, 5, stream, b'\x88'))
            else:
                seen.append(http1_request(conn))
                conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        await_transport_close(conn)

    async def scenario(url):
        async with AsyncSession(
            tls_config=config, hooks={'before_request': [before]}
        ) as session:
            session.request_defaults = defaults
            options = {
                'headers': {'x-default': 'explicit'},
                'params': [('tag', 'x'), ('tag', 'y')],
            }
            if client == 'prepared':
                ready = await session.prepare_request(
                    'POST', url, data=b'body', **options
                )
                session.request_defaults = updated
                await session.send(ready, timeout=2)
            else:
                await session.post(url, data=source, timeout=2, **options)
                session.request_defaults = updated
            await session.get(url.rsplit('/', 1)[0] + '/next', params={}, timeout=2)
        assert not session.pool._entries and not session._requests

    scheme = 'http' if protocol == 'http' else 'https'
    with LocalServer(serve, None if protocol == 'http' else context) as peer:
        url = '%s://127.0.0.1:%d/start?url=kept' % (scheme, peer.port)
        if client == 'sync':
            with Session(
                tls_config=config,
                pool=ConnectionPool(),
                hooks={'before_request': [before]},
            ) as session:
                session.request_defaults = defaults
                session.post(
                    url,
                    data=source,
                    headers={'x-default': 'explicit'},
                    params=[('tag', 'x'), ('tag', 'y')],
                    timeout=2,
                )
                session.request_defaults = updated
                session.get(
                    '%s://127.0.0.1:%d/next' % (scheme, peer.port), params={}, timeout=2
                )
        else:
            asyncio.run(scenario(url))
    assert len(seen) == 2  # Both requests used the peer's sole accepted connection.
    assert seen[0][0:2] == ('POST', '/start?url=kept&page=1&tag=x&tag=y')
    assert seen[0][2]['x-default'] == 'explicit'
    assert seen[0][2]['x-bytes'] == (
        'é' if protocol == 'h2' else b'\xc3\xa9'.decode('latin1')
    )
    assert seen[0][2]['x-number'] == '2' and seen[0][3] == b'body'
    assert seen[1][1] == '/next'
    assert seen[1][2]['x-default'] == 'updated' and 'x-bytes' not in seen[1][2]
    assert not source.closed
    if client != 'prepared':
        assert source.reads > 0


@pytest.mark.parametrize('client', ['sync', 'async', 'prepared'])
def test_hook_retry_redirect_never_reinject_defaults_or_origin_credentials(client):
    first, final, hooks = [], [], []

    def origin(conn):
        first.append(http1_request(conn))
        status = b'503 Retry' if len(first) == 1 else b'302 Redirect'
        location = (
            b''
            if len(first) == 1
            else ('Location: %s/land?location=kept\r\n' % destination_url).encode()
        )
        conn.sendall(
            b'HTTP/1.1 '
            + status
            + b'\r\n'
            + location
            + b'Content-Length: 0\r\nConnection: close\r\n\r\n'
        )

    def destination(conn):
        final.append(http1_request(conn))
        conn.sendall(
            b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        )

    def before(request):
        path = urlsplit(request.url).path
        hooks.append(path)
        if path == '/start':
            assert request.headers.pop('X-Default') == 'old'
            session.request_defaults = {
                'headers': {'X-Default': 'new'},
                'params': {'d': 'two'},
            }
        elif path == '/land':
            assert 'X-Default' not in request.headers

    initial = {'headers': {'X-Default': 'old'}, 'params': {'d': 'one'}}
    headers = {'Authorization': 'Bearer origin', 'Cookie': 'origin=one'}
    retry = HTTPRetry(total=1, status_forcelist=[503], backoff_factor=0)

    async def scenario(url):
        nonlocal session
        async with AsyncSession(
            retry=retry, hooks={'before_request': [before]}
        ) as session:
            session.request_defaults = initial
            if client == 'prepared':
                ready = await session.prepare_request('GET', url, headers=headers)
                await session.send(ready, timeout=2)
            else:
                await session.get(url, headers=headers, timeout=2)
            await session.get(destination_url + '/next', timeout=2)

    session = None
    with LocalServer(destination, connections=2) as target:
        destination_url = 'http://127.0.0.1:%d' % target.port
        with LocalServer(origin, connections=2) as source:
            url = 'http://127.0.0.1:%d/start?url=kept' % source.port
            if client == 'sync':
                with Session(
                    retry=retry, use_pooling=False, hooks={'before_request': [before]}
                ) as session:
                    session.request_defaults = initial
                    session.get(url, headers=headers, timeout=2)
                    session.get(destination_url + '/next', timeout=2)
            else:
                asyncio.run(scenario(url))
    assert hooks == ['/start', '/land', '/next']
    assert [record[1] for record in first] == ['/start?url=kept&d=one'] * 2
    for record in first:
        assert record[2]['authorization'] == 'Bearer origin'
        assert record[2]['cookie'] == 'origin=one'
        assert 'x-default' not in record[2]
    assert final[0][1] == '/land?location=kept'
    assert not {'authorization', 'cookie', 'x-default'} & final[0][2].keys()
    assert final[1][1] == '/next?d=two' and final[1][2]['x-default'] == 'new'


def test_sync_direct_prepared_send_does_not_apply_session_defaults():
    seen = []

    def serve(conn):
        seen.append(http1_request(conn))
        conn.sendall(
            b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        )

    with LocalServer(serve) as peer, Session(use_pooling=False) as session:
        session.request_defaults = {
            'headers': {'X-Default': 'one'},
            'params': {'d': 'one'},
        }
        ready = Request('GET', 'http://127.0.0.1:%d/standalone' % peer.port).request()
        session.send(ready)
    assert seen[0][1] == '/standalone' and 'x-default' not in seen[0][2]


def test_async_execution_snapshot_inflight_change_and_concurrent_prepared_sends():
    async def scenario():
        entered, resume = asyncio.Event(), asyncio.Event()

        async def before(request):
            if urlsplit(request.url).path == '/inflight':
                entered.set()
                await resume.wait()

        async with Peer(ok) as peer, AsyncSession(
            hooks={'before_request': [before]}
        ) as session:

            def configure(value):
                session.request_defaults = {
                    'headers': {'X-Default': value},
                    'params': {'d': value},
                }

            configure('created')
            call = session.get(peer.url + '/inflight', timeout=2)
            configure('executed')
            task = asyncio.create_task(call)
            try:
                await asyncio.wait_for(entered.wait(), 2)
                configure('later')
                resume.set()
                await asyncio.wait_for(task, 2)
            finally:
                resume.set()
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
            assert peer.requests[0][1] == '/inflight?d=executed'
            assert peer.requests[0][2]['X-Default'] == 'executed'
            preparing = session.prepare_request('GET', peer.url + '/prepared')
            configure('prepared')
            ready = await preparing
            configure('send-time')
            left = ready.with_headers(dict(ready.headers, **{'X-Default': 'left'}))
            right = ready.with_headers(dict(ready.headers, **{'X-Default': 'right'}))
            await asyncio.gather(
                session.send(left, timeout=2), session.send(right, timeout=2)
            )
            assert [record[1] for record in peer.requests[1:]] == [
                '/prepared?d=prepared'
            ] * 2
            assert {record[2]['X-Default'] for record in peer.requests[1:]} == {
                'left',
                'right',
            }
            assert ready.headers['X-Default'] == 'prepared'
            await asyncio.gather(
                session.get(
                    peer.url + '/left', headers={'x-default': 'left'}, timeout=2
                ),
                session.get(
                    peer.url + '/right', headers={'x-default': 'right'}, timeout=2
                ),
            )
            assert {
                (record[1], record[2]['X-Default']) for record in peer.requests[3:]
            } == {('/left?d=send-time', 'left'), ('/right?d=send-time', 'right')}
            assert session.request_defaults == {
                'headers': {'X-Default': 'send-time'},
                'params': (('d', 'send-time'),),
            }
            await session.get(peer.url + '/next', timeout=2)
            assert peer.requests[-1][1] == '/next?d=send-time'
            assert peer.requests[-1][2]['X-Default'] == 'send-time'
            assert not session._requests
        assert not session.pool._entries

    asyncio.run(scenario())


def test_async_defaults_do_not_change_cancelled_source_ownership():
    async def scenario():
        pulling, closed, peer_closed = asyncio.Event(), asyncio.Event(), asyncio.Event()

        async def chunks():
            try:
                yield b'first'
                pulling.set()
                await asyncio.Event().wait()
            finally:
                closed.set()

        async def route(reader, writer, method, path, headers):
            if path.startswith('/upload'):
                await reader.read()
                peer_closed.set()
                return False
            assert await read_body(reader, headers) == b''
            await reply(writer)

        async with UploadPeer(route) as peer, AsyncSession() as session:
            session.request_defaults = {
                'headers': {'X-Default': 'old'},
                'params': {'d': 'old'},
            }
            source = chunks()
            task = asyncio.create_task(
                session.post(peer.url + '/upload', data=source, timeout=2)
            )
            try:
                await asyncio.wait_for(pulling.wait(), 2)
                session.request_defaults = {'headers': {'X-Default': 'new'}}
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 2)
                await asyncio.wait_for(peer_closed.wait(), 2)
                assert closed.is_set() and source.ag_frame is None
                assert not session._requests and not session.pool._entries
                assert peer.requests[0][1] == '/upload?d=old'
                assert peer.requests[0][2]['x-default'] == 'old'
                await session.get(peer.url + '/next', timeout=2)
                assert peer.requests[-1][1] == '/next'
                assert peer.requests[-1][2]['x-default'] == 'new'
            finally:
                if not task.done():
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                await source.aclose()

    asyncio.run(scenario())
