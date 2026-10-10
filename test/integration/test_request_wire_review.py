"""Final request fields across CONNECT, TLS, H2 and streaming uploads."""

import asyncio
import io
import threading
from base64 import b64encode

import pytest

from ja3requests import AsyncSession, HTTPRetry, Session, TlsConfig
from ja3requests.base import BaseSocket
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.hpack import HPACKDecoder
from ja3requests.requests.https import HttpsRequest
from ja3requests.contexts.context import HTTPContext
from ja3requests.protocol.exceptions import ProxyError, ProxyTimeoutError
from ja3requests.sockets.proxy import ProxySocket
from test.integration.test_async_h2_network import async_h2_connections
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    h2_readers,
    receive_frame,
    start_h2,
    trusted_h2_peer,
)
from test.integration.test_sync_upload_network import h2_write_guards
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    read_headers,
    tls13_context,
)
from test.test_sync_upload import read_upload
from test.test_async_session import Peer


def read_h2_request(conn, decoder):
    block, body = b'', bytearray()
    stream_id = None
    while True:
        kind, flags, stream, payload = receive_frame(conn)
        if kind == 1:
            assert flags & 4
            block, stream_id = payload, stream
            if flags & 1:
                break
        elif kind == 0:
            assert stream == stream_id
            body.extend(payload)
            if flags & 1:
                break
    return stream_id, dict(decoder.decode_headers(block)), bytes(body), block


@pytest.mark.parametrize('hook', [False, True])
@pytest.mark.parametrize(
    'name,value',
    [
        ('Proxy-Authorization', 'token\r\nInjected: yes'),
        ('Proxy-Authorization', b'token\x00tail'),
        ('X-Test', 'bad\x01value'),
        ('X-Test', 'bad\x7fvalue'),
        ('X(Bad', 'value'),
    ],
)
def test_connect_rejects_invalid_final_fields_before_connection(
    monkeypatch, hook, name, value
):
    opened = []

    def connect(*_):
        opened.append(True)
        raise AssertionError('Invalid fields reached proxy I/O')

    def before(request):
        request.headers[name] = value

    monkeypatch.setattr(ProxySocket, '_new_conn', connect)
    with Session(use_pooling=False) as session:
        with pytest.raises(ValueError, match='Invalid HTTP header'):
            session.get(
                'http://example.test:8080/',
                proxies={'http': 'http://127.0.0.1:1'},
                headers={'X-Test': 'ok'} if hook else {name: value},
                hooks={'before_request': [before]} if hook else None,
                timeout=1,
            )
    assert not opened


@pytest.mark.parametrize('route', ['http1', 'tls-http1', 'tls-h2'])
@pytest.mark.parametrize('upload', [False, True])
@pytest.mark.parametrize('authentication', ['bare-token', 'field', 'url'])
def test_connect_authentication_stays_out_of_destination_request(
    trusted_certificates, monkeypatch, h2_readers, route, upload, authentication
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    if route == 'tls-http1':
        config = TlsConfig.secure()
        config.alpn_protocols = ['http/1.1']
        context = tls13_context(*trusted_certificates.leaves['valid'])
    token = b64encode(b'proxy-user:proxy-password').decode('ascii')
    auth = token if authentication == 'bare-token' else 'Basic ' + token
    seen = {}

    def application(conn):
        if route == 'tls-h2':
            start_h2(conn)
            stream, headers, body, _ = read_h2_request(conn, HPACKDecoder())
            seen.update(headers=headers, body=body)
            conn.sendall(h2_frame(1, 5, stream, b'\x88'))
            await_transport_close(conn)
        else:
            raw, body = read_upload(conn)
            seen.update(headers=raw, body=body)
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')

    def proxy(conn):
        seen['connect'] = read_headers(conn)
        conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
        if route == 'http1':
            application(conn)
        else:
            with context.wrap_socket(conn, server_side=True) as transport:
                application(transport)

    with LocalServer(proxy) as peer, Session(
        tls_config=config, use_pooling=False
    ) as session:
        scheme = 'http' if route == 'http1' else 'https'
        credentials = 'proxy-user:proxy-password@' if authentication == 'url' else ''
        proxy_url = 'http://%s127.0.0.1:%d' % (credentials, peer.port)
        headers = {'Host': 'virtual.example:8443'}
        if authentication != 'url':
            headers['Proxy-Authorization'] = auth
        response = session.post(
            '%s://127.0.0.1:%d/private' % (scheme, peer.port),
            proxies={scheme: proxy_url},
            headers=headers,
            data=iter([b'body']) if upload else b'body',
            timeout=3,
        )
        assert response.status_code == 200
        response.close()
        if authentication != 'url':
            assert response.request.headers['Proxy-Authorization'] == auth
            assert headers['Proxy-Authorization'] == auth
        assert not session._uploads
    assert seen['connect'].startswith(
        (
            'CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n'
            % (peer.port, peer.port)
        ).encode()
    )
    assert ('Proxy-Authorization: Basic %s\r\n' % token).encode() in seen['connect']
    assert seen['body'] == b'body'
    if route == 'tls-h2':
        assert 'proxy-authorization' not in seen['headers']
        assert seen['headers'][':authority'] == 'virtual.example:8443'
    else:
        assert b'proxy-authorization:' not in seen['headers'].lower()
        assert b'Host: virtual.example:8443\r\n' in seen['headers']


@pytest.mark.parametrize('name', ['Proxy-Authorization', 'pRoXy-aUtHoRiZaTiOn'])
def test_proxy_authentication_survives_retry_without_leaking_to_destination(name):
    observed = []

    def before(request):
        request.headers[name] = 'Basic dXNlcjpwYXNz'

    def proxy(conn):
        connect = read_headers(conn)
        conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
        request = read_headers(conn)
        observed.append((connect, request))
        status = 503 if len(observed) == 1 else 200
        conn.sendall(
            ('HTTP/1.1 %d Test\r\nContent-Length: 0\r\n\r\n' % status).encode()
        )

    with LocalServer(proxy, connections=2) as peer, Session(
        use_pooling=False, retry=HTTPRetry(total=1, backoff_factor=0)
    ) as session:
        response = session.get(
            'http://example.test:8080/',
            proxies={'http': 'http://127.0.0.1:%d' % peer.port},
            hooks={'before_request': [before]},
            timeout=2,
        )
        assert response.status_code == 200
        assert response.request.headers[name] == 'Basic dXNlcjpwYXNz'
    assert len(observed) == 2
    for connect, request in observed:
        assert b'Proxy-Authorization: Basic dXNlcjpwYXNz\r\n' in connect
        assert b'proxy-authorization:' not in request.lower()


@pytest.mark.parametrize('pooled', [False, True])
@pytest.mark.parametrize('upload', [False, True])
@pytest.mark.parametrize('override', [False, True])
def test_sync_h2_uses_final_authority_and_complete_path(
    trusted_certificates, monkeypatch, h2_readers, pooled, upload, override
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = {}

    def peer(conn):
        start_h2(conn)
        stream, headers, body, block = read_h2_request(conn, HPACKDecoder())
        seen.update(headers=headers, body=body, block=block)
        conn.sendall(h2_frame(1, 5, stream, b'\x88'))
        await_transport_close(conn)

    with LocalServer(peer, context) as server, Session(
        tls_config=config,
        pool=ConnectionPool() if pooled else None,
        use_pooling=pooled,
    ) as session:
        response = session.post(
            'https://127.0.0.1:%d/resource;version=2?x=1#fragment' % server.port,
            params={'q': '2'},
            headers={'host': b'virtual.example:8443'} if override else None,
            data=iter([b'body']) if upload else b'body',
            timeout=3,
        )
        assert response.status_code == 200
        response.close()
    authority = 'virtual.example:8443' if override else '127.0.0.1:%d' % server.port
    assert seen['headers'][':authority'] == authority
    # Independently inspect the initial HPACK literal's name index and bytes.
    assert seen['block'].startswith(
        b'\x83\x41' + bytes([len(authority)]) + authority.encode()
    )
    assert seen['headers'][':path'] == '/resource;version=2?x=1&q=2'
    assert seen['body'] == b'body'


def test_async_invalid_hook_fields_preserve_existing_h2_connection(
    trusted_certificates, monkeypatch, async_h2_connections
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = []

    def peer(conn):
        start_h2(conn)
        decoder = HPACKDecoder()
        for _ in range(2):
            stream, headers, _, _ = read_h2_request(conn, decoder)
            seen.append((stream, headers))
            conn.sendall(h2_frame(1, 5, stream, b'\x88'))
        await_transport_close(conn)

    async def run(port):
        async with AsyncSession(tls_config=config) as session:
            prepared = await session.prepare_request(
                'GET', 'https://127.0.0.1:%d/' % port
            )
            assert (await session.send(prepared, timeout=2)).status_code == 200

            def invalid(request):
                request.headers['X-Test'] = 'bad\x00value'

            with pytest.raises(ValueError, match='Invalid HTTP header value'):
                await session.send(
                    prepared, timeout=2, hooks={'before_request': [invalid]}
                )
            assert (await session.send(prepared, timeout=2)).status_code == 200
            assert len(async_h2_connections) == 1
            assert not async_h2_connections[0].failed

    with LocalServer(peer, context) as server:
        asyncio.run(run(server.port))
    assert [stream for stream, _ in seen] == [1, 3]
    assert all('x-test' not in headers for _, headers in seen)


@pytest.mark.parametrize('route', ['direct', 'connect'])
@pytest.mark.parametrize('upload', [False, True])
@pytest.mark.parametrize('value', [b'\xc3\xa9', 'é'], ids=['utf8-bytes', 'text'])
def test_sync_h2_preserves_utf8_field_bytes(
    trusted_certificates, monkeypatch, h2_readers, route, upload, value
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = {}

    def application(conn):
        start_h2(conn)
        stream, headers, body, block = read_h2_request(conn, HPACKDecoder())
        seen.update(headers=headers, body=body, block=block)
        conn.sendall(h2_frame(1, 5, stream, b'\x88'))
        await_transport_close(conn)

    def proxy(conn):
        seen['connect'] = read_headers(conn)
        conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
        with context.wrap_socket(conn, server_side=True) as transport:
            application(transport)

    with LocalServer(
        application if route == 'direct' else proxy,
        context if route == 'direct' else None,
    ) as peer, Session(tls_config=config, use_pooling=False) as session:
        headers = {'X-Probe': value}
        proxies = None
        if route == 'connect':
            headers['Proxy-Authorization'] = 'Basic dXNlcjpwYXNz'
            proxies = {'https': 'http://127.0.0.1:%d' % peer.port}
        response = session.post(
            'https://127.0.0.1:%d/' % peer.port,
            headers=headers,
            proxies=proxies,
            data=iter([b'body']) if upload else b'body',
            timeout=2,
        )
        assert response.status_code == 200
        response.close()
        assert response.request.headers['X-Probe'] == value
    assert seen['headers']['x-probe'] == 'é'
    # Literal field name and two original UTF-8 octets, read from real frames.
    assert b'\x40\x07x-probe\x02\xc3\xa9' in seen['block']
    assert 'proxy-authorization' not in seen['headers']
    assert seen['body'] == b'body'


@pytest.mark.parametrize('route', ['http', 'https', 'connect'])
@pytest.mark.parametrize('upload', [False, True])
@pytest.mark.parametrize('hook', [False, True])
@pytest.mark.parametrize(
    'name,value', [('X-Probe', 'invalid\x00value'), ('X/Bad', 'value')]
)
def test_sync_invalid_fields_never_connect_or_retry(
    monkeypatch, route, upload, hook, name, value
):
    connections = []

    def connect(*_):
        connections.append(True)
        raise ConnectionError('A network operation occurred before header validation')

    def before(request):
        request.headers[name] = value

    monkeypatch.setattr(BaseSocket, '_new_conn', connect)
    with Session(
        use_pooling=False, retry=HTTPRetry(total=2, backoff_factor=0)
    ) as session:
        with pytest.raises(ValueError, match='Invalid HTTP header'):
            session.put(
                (
                    'http://example.invalid/'
                    if route == 'http'
                    else 'https://example.invalid/'
                ),
                headers={'X-Probe': 'ok'} if hook else {name: value},
                hooks={'before_request': [before]} if hook else None,
                proxies={'https': 'http://127.0.0.1:1'} if route == 'connect' else None,
                data=iter([b'body']) if upload else b'body',
                timeout=1,
            )
        assert not session._uploads
    assert not connections


@pytest.mark.parametrize('alpn', ['http/1.1', 'h2'])
def test_direct_https_request_preserves_invalid_field_error(
    trusted_certificates, monkeypatch, h2_readers, alpn
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    config.alpn_protocols = [alpn]
    context = tls13_context(*trusted_certificates.leaves['valid'], alpn=alpn)
    connections = []

    def peer(conn):
        connections.append(conn.selected_alpn_protocol())
        try:
            if alpn == 'h2':
                assert read_exact(conn, 24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
                # Local field validation closes before waiting for peer SETTINGS.
                # Sending them here races that deliberate close on some runtimes.
            await_transport_close(conn)
        except (ConnectionResetError, BrokenPipeError):
            # Rejecting local input closes the newly established transport.
            pass

    with LocalServer(peer, context) as server:
        request = HttpsRequest()
        request.set_payload(
            method='GET',
            url='https://127.0.0.1:%d/' % server.port,
            headers={'X-Probe': 'invalid\x00value'},
            tls_config=config,
            timeout=2,
        )
        with pytest.raises(ValueError, match='Invalid HTTP header value'):
            request.send()
    assert connections == [alpn]


@pytest.mark.parametrize('upload', [False, True])
def test_sync_h2_invalid_utf8_error_preserves_shared_connection(
    trusted_certificates, monkeypatch, h2_readers, upload
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = []

    def peer(conn):
        start_h2(conn)
        decoder = HPACKDecoder()
        for _ in range(2):
            stream, headers, _, _ = read_h2_request(conn, decoder)
            seen.append(headers)
            conn.sendall(h2_frame(1, 5, stream, b'\x88'))
        await_transport_close(conn)

    with LocalServer(peer, context) as server, Session(
        tls_config=config,
        pool=ConnectionPool(),
        retry=HTTPRetry(total=2, backoff_factor=0),
    ) as session:
        url = 'https://127.0.0.1:%d/' % server.port
        assert session.get(url, timeout=2).status_code == 200
        with pytest.raises(ValueError, match='valid UTF-8'):
            session.put(
                url,
                headers={'X-Probe': b'\xff'},
                data=iter([b'body']) if upload else b'body',
                timeout=2,
            )
        assert session.get(url, timeout=2).status_code == 200
        assert not session._uploads
    assert len(h2_readers) == 1
    assert len(seen) == 2 and all('x-probe' not in headers for headers in seen)


@pytest.mark.parametrize('entry', ['request', 'prepared', 'upload'])
@pytest.mark.parametrize(
    'value', ['v\r\nX-Injected: yes', 'bad\x00value', 'bad\x7fvalue']
)
def test_async_cookie_refresh_rejects_before_source_or_connection(
    monkeypatch, entry, value
):
    calls = []

    async def connect(*args, **kwargs):
        calls.append('connection')
        raise AssertionError('Invalid refreshed Cookie reached connection I/O')

    class Source(io.BytesIO):
        def tell(self):
            calls.append('tell')
            return super().tell()

        def read(self, *args):
            calls.append('read')
            return super().read(*args)

    monkeypatch.setattr('ja3requests.async_sessions.open_transport', connect)
    source = Source(b'body')

    async def run():
        async with AsyncSession() as session:
            session.cookies.set('sid', value, domain='example.test', path='/private')

            def move(request):
                request.url = 'http://example.test/private'

            with pytest.raises(ValueError, match='Invalid HTTP header value'):
                if entry == 'prepared':
                    prepared = await session.prepare_request(
                        'GET', 'http://example.test/public'
                    )
                    await session.send(prepared, hooks={'before_request': [move]})
                else:
                    await session.get(
                        'http://example.test/public',
                        data=source if entry == 'upload' else None,
                        hooks={'before_request': [move]},
                    )
        assert not calls and not source.closed

    try:
        asyncio.run(run())
    finally:
        source.close()


@pytest.mark.parametrize('entry', ['request', 'prepared', 'upload'])
@pytest.mark.parametrize('value', ['bad\x00value', 'bad\x7fvalue'])
def test_async_retry_cookie_refresh_rejects_before_second_attempt(entry, value):
    async def run():
        async def route(*_):
            if len(peer.requests) == 1:
                return 503, {'Set-Cookie': 'sid=%s; Path=/' % value}, b''
            return 200, {}, b''

        source = io.BytesIO(b'body')
        try:
            async with Peer(route) as peer, AsyncSession(
                retry=HTTPRetry(total=1, allowed_methods={'POST'}, backoff_factor=0)
            ) as session:
                with pytest.raises(ValueError, match='Invalid HTTP header value'):
                    if entry == 'prepared':
                        prepared = await session.prepare_request(
                            'POST', peer.url, data=b'body'
                        )
                        await session.send(prepared, timeout=2)
                    else:
                        await session.post(
                            peer.url,
                            data=source if entry == 'upload' else b'body',
                            timeout=2,
                        )
                assert len(peer.requests) == 1 and peer.connections == 1
                assert not session._requests and not source.closed
        finally:
            source.close()

    asyncio.run(run())


@pytest.mark.parametrize('entry', ['request', 'prepared', 'upload'])
@pytest.mark.parametrize('route', ['http1', 'tls-http1', 'tls-h2'])
@pytest.mark.parametrize('authentication', ['field', 'bare-token', 'url'])
def test_async_connect_authentication_stays_out_of_destination_request(
    trusted_certificates,
    monkeypatch,
    async_h2_connections,
    entry,
    route,
    authentication,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    if route == 'tls-http1':
        config = TlsConfig.secure()
        config.alpn_protocols = ['http/1.1']
        context = tls13_context(*trusted_certificates.leaves['valid'])
    token = b64encode(b'proxy-user:proxy-password').decode('ascii')
    seen = {}

    def application(conn):
        if route == 'tls-h2':
            start_h2(conn)
            stream, headers, body, _ = read_h2_request(conn, HPACKDecoder())
            seen.update(headers=headers, body=body)
            conn.sendall(h2_frame(1, 5, stream, b'\x88'))
            await_transport_close(conn)
        else:
            raw, body = read_upload(conn)
            seen.update(headers=raw, body=body)
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')

    def proxy(conn):
        seen['connect'] = read_headers(conn)
        conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
        if route == 'http1':
            application(conn)
        else:
            with context.wrap_socket(conn, server_side=True) as transport:
                application(transport)

    async def run(port):
        scheme = 'http' if route == 'http1' else 'https'
        credentials = (
            'proxy-user:proxy-password'
            if authentication == 'url'
            else 'wrong:credentials'
        )
        proxies = {scheme: 'http://%s@127.0.0.1:%d' % (credentials, port)}
        headers = {'Host': 'virtual.example:8443'}
        if authentication != 'url':
            headers['pRoXy-aUtHoRiZaTiOn'] = (
                ('Basic ' + token).encode() if authentication == 'field' else token
            )
        options = dict(headers=headers, proxies=proxies, data=b'body')
        original_headers = dict(headers)
        async with AsyncSession(tls_config=config) as session:
            url = '%s://127.0.0.1:%d/private' % (scheme, port)
            if entry == 'prepared':
                prepared = await session.prepare_request('POST', url, **options)
                response = await session.send(prepared, timeout=3)
            else:
                if entry == 'upload':
                    options['data'] = iter([b'body'])
                response = await session.post(url, timeout=3, **options)
            assert response.status_code == 200
        assert headers == original_headers

    with LocalServer(proxy) as server:
        asyncio.run(run(server.port))
    assert ('Proxy-Authorization: Basic %s\r\n' % token).encode() in seen['connect']
    assert seen['body'] == b'body'
    if route == 'tls-h2':
        assert 'proxy-authorization' not in seen['headers']
    else:
        assert b'proxy-authorization:' not in seen['headers'].lower()


def test_async_connect_authentication_partitions_pool_and_reuses_matching_credentials():
    async def run():
        async def route(method, *_):
            return 200, {}, b'' if method == 'CONNECT' else b'ok'

        async with Peer(route) as peer, AsyncSession() as session:
            proxies = {'http': peer.url}
            for auth in (b'Basic YTpvbmU=', 'Basic Yjp0d28=', b'Basic YTpvbmU='):
                prepared = await session.prepare_request(
                    'GET',
                    'http://destination.test/private',
                    proxies=proxies,
                    headers={'Proxy-Authorization': auth},
                )
                assert (await session.send(prepared, timeout=2)).content == b'ok'
            assert peer.connections == 2
            connect = [r for r in peer.requests if r[0] == 'CONNECT']
            origin = [r for r in peer.requests if r[0] == 'GET']
            assert [r[2].get('Proxy-Authorization') for r in connect] == [
                'Basic YTpvbmU=',
                'Basic Yjp0d28=',
            ]
            assert len(origin) == 3 and all(
                'Proxy-Authorization' not in r[2] for r in origin
            )

    asyncio.run(run())


@pytest.mark.parametrize('entry', ['request', 'prepared', 'upload'])
def test_async_direct_requests_never_send_proxy_credentials(entry):
    async def run():
        async def route(*_):
            return 200, {}, b''

        async with Peer(route) as peer, AsyncSession() as session:
            options = {
                'headers': {'Proxy-Authorization': 'Basic cHJveHk6c2VjcmV0'},
                'data': b'body',
            }
            if entry == 'prepared':
                prepared = await session.prepare_request('POST', peer.url, **options)
                await session.send(prepared, timeout=2)
            else:
                if entry == 'upload':
                    options['data'] = io.BytesIO(b'body')
                await session.post(peer.url, timeout=2, **options)
            assert all('Proxy-Authorization' not in r[2] for r in peer.requests)

    asyncio.run(run())


@pytest.mark.parametrize('route', ['http1', 'tls-http1'])
@pytest.mark.parametrize('proxy', [False, True])
@pytest.mark.parametrize('upload', [False, True])
@pytest.mark.parametrize('value', [b'\xc3\xa9', b'\xff', 'é'])
def test_sync_http1_byte_fields_preserve_original_wire_value(
    trusted_certificates, monkeypatch, route, proxy, upload, value
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    config = TlsConfig.secure()
    config.alpn_protocols = ['http/1.1']
    context = (
        tls13_context(*trusted_certificates.leaves['valid'])
        if route == 'tls-http1'
        else None
    )
    seen = {}

    def application(conn):
        raw, body = read_upload(conn)
        seen.update(headers=raw, body=body)
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')

    def handler(conn):
        if proxy:
            read_headers(conn)
            conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
            if context:
                with context.wrap_socket(conn, server_side=True) as transport:
                    application(transport)
                return
        application(conn)

    with LocalServer(handler, None if proxy else context) as server, Session(
        tls_config=config, use_pooling=False
    ) as session:
        scheme = 'https' if context else 'http'
        response = session.post(
            '%s://127.0.0.1:%d/' % (scheme, server.port),
            headers={'X-Probe': value},
            proxies={scheme: 'http://127.0.0.1:%d' % server.port} if proxy else None,
            data=iter([b'body']) if upload else b'body',
            timeout=3,
        )
        assert response.status_code == 200
    expected = value if isinstance(value, bytes) else value.encode('utf-8')
    assert b'X-Probe: ' + expected + b'\r\n' in seen['headers']
    assert seen['body'] == b'body'


@pytest.mark.parametrize('route', ['http1', 'tls-http1', 'tls-h2'])
@pytest.mark.parametrize('proxy', [False, True])
@pytest.mark.parametrize('entry', ['request', 'prepared', 'upload'])
@pytest.mark.parametrize('value', [b'\xc3\xa9', 'é'])
def test_async_byte_fields_preserve_original_wire_value(
    trusted_certificates, monkeypatch, async_h2_connections, route, proxy, entry, value
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    if route != 'tls-h2':
        config = TlsConfig.secure()
        config.alpn_protocols = ['http/1.1']
        context = (
            tls13_context(*trusted_certificates.leaves['valid'])
            if route == 'tls-http1'
            else None
        )
    seen = {}

    def application(conn):
        if route == 'tls-h2':
            start_h2(conn)
            stream, headers, body, block = read_h2_request(conn, HPACKDecoder())
            seen.update(headers=headers, body=body, block=block)
            conn.sendall(h2_frame(1, 5, stream, b'\x88'))
            await_transport_close(conn)
        else:
            raw, body = read_upload(conn)
            seen.update(headers=raw, body=body)
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')

    def handler(conn):
        if proxy:
            read_headers(conn)
            conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
            if context:
                with context.wrap_socket(conn, server_side=True) as transport:
                    application(transport)
                return
        application(conn)

    async def run(port):
        scheme = 'https' if context else 'http'
        options = dict(headers={'X-Probe': value}, data=b'body')
        if proxy:
            options['proxies'] = {scheme: 'http://127.0.0.1:%d' % port}
        async with AsyncSession(tls_config=config) as session:
            url = '%s://127.0.0.1:%d/' % (scheme, port)
            if entry == 'prepared':
                prepared = await session.prepare_request('POST', url, **options)
                seen['prepared'] = prepared
                response = await session.send(prepared, timeout=3)
            else:
                if entry == 'upload':
                    options['data'] = iter([b'body'])
                response = await session.post(url, timeout=3, **options)
            assert response.status_code == 200

    with LocalServer(handler, None if proxy else context) as server:
        asyncio.run(run(server.port))
    expected = (
        value
        if isinstance(value, bytes)
        else value.encode('utf-8' if route == 'tls-h2' else 'latin1')
    )
    if route == 'tls-h2':
        assert b'\x07x-probe' + bytes([len(expected)]) + expected in seen['block']
    else:
        assert b'X-Probe: ' + expected + b'\r\n' in seen['headers']
    if entry == 'prepared':
        assert seen['prepared'].headers['X-Probe'] == value
        assert (
            seen['prepared']
            .with_headers(dict(seen['prepared'].headers))
            .headers['X-Probe']
            == value
        )
    assert seen['body'] == b'body'


@pytest.mark.parametrize('entry', ['request', 'prepared', 'upload'])
def test_async_h2_byte_fields_reject_invalid_utf8_without_failing_shared_connection(
    trusted_certificates, monkeypatch, async_h2_connections, entry
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = []

    def peer(conn):
        start_h2(conn)
        decoder = HPACKDecoder()
        for _ in range(2):
            stream, headers, _, _ = read_h2_request(conn, decoder)
            seen.append(headers)
            conn.sendall(h2_frame(1, 5, stream, b'\x88'))
        await_transport_close(conn)

    async def run(port):
        async with AsyncSession(tls_config=config) as session:
            url = 'https://127.0.0.1:%d/' % port
            assert (await session.get(url, timeout=2)).status_code == 200
            with pytest.raises(ValueError, match='valid UTF-8'):
                if entry == 'prepared':
                    prepared = await session.prepare_request(
                        'POST', url, headers={'X-Probe': b'\xff'}
                    )
                    await session.send(prepared, timeout=2)
                else:
                    await session.post(
                        url,
                        headers={'X-Probe': b'\xff'},
                        data=iter([b'body']) if entry == 'upload' else b'body',
                        timeout=2,
                    )
            assert (await session.get(url, timeout=2)).status_code == 200
            assert len(async_h2_connections) == 1 and not async_h2_connections[0].failed

    with LocalServer(peer, context) as server:
        asyncio.run(run(server.port))
    assert len(seen) == 2 and all('x-probe' not in headers for headers in seen)


class ConnectSocket:
    def __init__(self, response, failure=None):
        self.response = io.BytesIO(response)
        self.failure = failure
        self.closed = False

    def sendall(self, _message):
        if self.failure == 'send':
            raise ConnectionError('send failed')

    def recv(self, size):
        if self.failure == 'timeout':
            raise TimeoutError('receive timed out')
        return self.response.read(size)

    def settimeout(self, _timeout):
        pass

    def close(self):
        self.closed = True


def connect_context():
    context = HTTPContext()
    context.set_payload(
        method='GET',
        start_line='http://destination.test/',
        headers={'X-Test': 'ok'},
        proxy='http://127.0.0.1:8080',
        timeout=1,
    )
    return context


@pytest.mark.parametrize(
    'fault', ['407', 'malformed', 'eof', 'timeout', 'send', 'oversized']
)
@pytest.mark.parametrize('entry', ['socket', 'session'])
def test_sync_connect_failures_close_owned_connection(monkeypatch, fault, entry):
    response = {
        '407': b'HTTP/1.1 407 Unauthorized\r\n\r\n',
        'malformed': b'not-a-proxy\r\n\r\n',
        'eof': b'HTTP/1.1 200 Tunnel\r\nIncomplete:',
        'oversized': b'HTTP/1.1 200 Tunnel\r\nX-Large: ' + b'a' * 65536 + b'\r\n\r\n',
    }.get(fault, b'')
    conn = ConnectSocket(response, fault)
    monkeypatch.setattr(ProxySocket, '_new_conn', lambda *args: conn)
    error = (
        ConnectionError
        if fault == 'send'
        else ProxyTimeoutError if fault == 'timeout' else ProxyError
    )
    with pytest.raises(error):
        if entry == 'socket':
            ProxySocket(connect_context()).new_conn()
        else:
            with Session(use_pooling=False) as session:
                session.get(
                    'http://destination.test/',
                    proxies={'http': 'http://127.0.0.1:8080'},
                    timeout=1,
                )
    assert conn.closed


def test_sync_connect_response_preserves_unread_tunnel_data(monkeypatch):
    tail = b'\x16\x03\x03tunnel-data'
    conn = ConnectSocket(b'HTTP/1.1 200 Tunnel\r\nProxy-Info: ok\r\n\r\n' + tail)
    monkeypatch.setattr(ProxySocket, '_new_conn', lambda *args: conn)
    sock = ProxySocket(connect_context()).new_conn()
    try:
        assert sock.conn.recv(len(tail)) == tail
    finally:
        sock.close()


@pytest.mark.parametrize('first', [b'HTTP/1.', b'HTTP/1.1 200 Tunnel\r\n'])
def test_sync_connect_response_accepts_fragmented_status_and_headers(
    monkeypatch, first
):
    received = threading.Event()
    original = BaseSocket._new_conn
    full = b'HTTP/1.1 200 Tunnel\r\nProxy-Info: valid\r\n\r\n'

    class ObservedConnection:
        def __init__(self, conn):
            self.conn = conn

        def __getattr__(self, name):
            return getattr(self.conn, name)

        def recv(self, size):
            data = self.conn.recv(size)
            received.set()
            return data

    def connect(sock, *args):
        return ObservedConnection(original(sock, *args))

    monkeypatch.setattr(ProxySocket, '_new_conn', connect)

    def peer(conn):
        read_headers(conn)
        conn.sendall(first)
        assert received.wait(2)
        conn.sendall(full[len(first) :])
        assert read_headers(conn).startswith(b'GET / HTTP/1.1\r\n')
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')

    with LocalServer(peer) as server, Session(use_pooling=False) as session:
        assert (
            session.get(
                'http://destination.test/',
                proxies={'http': 'http://127.0.0.1:%d' % server.port},
                timeout=2,
            ).status_code
            == 200
        )


@pytest.mark.parametrize('entry', ['request', 'prepared', 'upload'])
def test_async_cookie_refresh_rejection_preserves_shared_h2_connection(
    trusted_certificates, monkeypatch, async_h2_connections, entry
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = []

    def peer(conn):
        start_h2(conn)
        decoder = HPACKDecoder()
        for _ in range(2):
            stream, headers, _, _ = read_h2_request(conn, decoder)
            seen.append((stream, headers))
            conn.sendall(h2_frame(1, 5, stream, b'\x88'))
        await_transport_close(conn)

    async def run(port):
        async with AsyncSession(tls_config=config) as session:
            session.cookies.set(
                'sid', 'invalid\x00value', domain='127.0.0.1', path='/private'
            )
            url = 'https://127.0.0.1:%d/public' % port
            assert (await session.get(url, timeout=2)).status_code == 200

            def move(request):
                request.url = url.replace('/public', '/private')

            with pytest.raises(ValueError, match='Invalid HTTP header value'):
                if entry == 'prepared':
                    prepared = await session.prepare_request('POST', url)
                    await session.send(
                        prepared, timeout=2, hooks={'before_request': [move]}
                    )
                else:
                    await session.post(
                        url,
                        data=iter([b'body']) if entry == 'upload' else b'body',
                        timeout=2,
                        hooks={'before_request': [move]},
                    )
            assert (await session.get(url, timeout=2)).status_code == 200
            assert len(async_h2_connections) == 1
            assert not async_h2_connections[0].failed

    with LocalServer(peer, context) as server:
        asyncio.run(run(server.port))
    assert [stream for stream, _ in seen] == [1, 3]
    assert all(headers[':path'] == '/public' for _, headers in seen)
    assert all('cookie' not in headers for _, headers in seen)


@pytest.mark.parametrize('upload', [False, True])
@pytest.mark.parametrize('value', ['bad\x00value', 'bad\x7fvalue'])
def test_sync_retry_cookie_refresh_rejects_before_second_connection(
    monkeypatch, upload, value
):
    connections = []
    original = BaseSocket._new_conn

    def connect(sock, *args):
        conn = original(sock, *args)
        connections.append(conn)
        return conn

    def backoff(*args):
        raise AssertionError('Invalid Cookie reached retry backoff')

    monkeypatch.setattr(BaseSocket, '_new_conn', connect)
    monkeypatch.setattr(HTTPRetry, 'sleep_for_retry', backoff)

    def peer(conn):
        _, body = read_upload(conn)
        assert body == b'body'
        conn.sendall(
            (
                'HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n'
                'Set-Cookie: sid=%s; Path=/\r\nConnection: close\r\n\r\n' % value
            ).encode()
        )
        assert conn.recv(1) == b''

    source = io.BytesIO(b'body')
    try:
        with LocalServer(peer) as server, Session(
            use_pooling=False,
            retry=HTTPRetry(total=1, allowed_methods={'POST'}, backoff_factor=0),
        ) as session:
            with pytest.raises(ValueError, match='Invalid HTTP header value'):
                session.post(
                    'http://127.0.0.1:%d/' % server.port,
                    data=source if upload else b'body',
                    timeout=2,
                )
            assert len(connections) == 1
            assert connections[0].fileno() == -1
            assert not source.closed and not session._uploads
    finally:
        source.close()


def test_sync_real_connect_rejection_closes_socket_before_session_close(monkeypatch):
    connections = []
    original = BaseSocket._new_conn

    def connect(sock, *args):
        conn = original(sock, *args)
        connections.append(conn)
        return conn

    monkeypatch.setattr(ProxySocket, '_new_conn', connect)

    def peer(conn):
        assert read_headers(conn).startswith(b'CONNECT destination.test:80 HTTP/1.1')
        conn.sendall(b'HTTP/1.1 407 Unauthorized\r\nContent-Length: 0\r\n\r\n')
        assert conn.recv(1) == b''

    with LocalServer(peer) as server, Session(use_pooling=False) as session:
        with pytest.raises(ProxyError):
            session.get(
                'http://destination.test/',
                proxies={'http': 'http://127.0.0.1:%d' % server.port},
                timeout=2,
            )
        assert len(connections) == 1 and connections[0].fileno() == -1
