"""Actual project TLS 1.2/1.3 handshakes and exact H2 wire controls."""

import asyncio
import io
import struct

import pytest

from ja3requests import AsyncSession, Session
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.hpack import HPACKDecoder, HeaderLimitError
from ja3requests.protocol.h2.async_connection import H2ProtocolError
from ja3requests.exceptions import TLSHandshakeError
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    h2_readers,
    receive_frame,
    start_h2,
    trusted_h2_peer,
)
from test.integration.test_async_h2_network import async_h2_connections
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_headers,
    recv_with_ragged_eof,
)


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('entry', ['sync', 'sync-unpooled', 'async'])
@pytest.mark.parametrize(
    'settings,repeats,accepted',
    [
        ({}, 20, False),
        ([], 20, False),
        ({2: 0}, 20, False),
        ({}, 3000, False),
        ({6: 32768}, 20, True),
    ],
)
def test_real_tls_h2_local_decoded_budget_without_extra_settings(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    async_h2_connections,
    version,
    entry,
    settings,
    repeats,
    accepted,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    config.h2_settings = settings
    seen, streams = [], []
    count = 1 if entry == 'sync-unpooled' else 2
    block = b'\x88\x40\x01x\x7f\xe9\x06' + b'a' * 1000 + b'\xbe' * repeats
    assert len(block) < 65536  # Compressed size alone cannot detect expansion.

    def peer(conn):
        start_h2(conn)
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 4 and not flags & 1:
                seen.extend(struct.iter_unpack('!HI', payload))
            if kind == 1:
                streams.append(stream)
                conn.sendall(
                    h2_frame(1, 5, stream, block if stream == 1 else b'\x88\xbe')
                )
                if not accepted or len(streams) == count:
                    await_transport_close(conn)
                    return

    async def run(url):
        async with AsyncSession(tls_config=config) as session:
            if accepted:
                for _ in range(2):
                    assert (await session.get(url, timeout=2)).status_code == 200
            else:
                with pytest.raises(H2ProtocolError, match='decoded header list'):
                    await session.get(url, timeout=2)
                assert not session._pool._entries and not session._pool._creating

    with LocalServer(peer, context) as server:
        url = 'https://127.0.0.1:%d/' % server.port
        if entry.startswith('sync'):
            pooled = entry == 'sync'
            with ConnectionPool() as pool, Session(
                tls_config=config, pool=pool, use_pooling=pooled
            ) as session:
                if accepted:
                    for _ in range(count):
                        assert session.get(url, timeout=2).status_code == 200
                else:
                    with pytest.raises(ConnectionError) as caught:
                        session.get(url, timeout=2)
                    error = caught.value
                    while error.__cause__ is not None:
                        error = error.__cause__
                    assert isinstance(error, HeaderLimitError)
                    assert pool.get_stats()['total_connections'] == 0
        else:
            asyncio.run(run(url))
    assert seen == (list(settings.items()) if isinstance(settings, dict) else settings)
    assert streams == ([1, 3][:count] if accepted else [1])


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('route', ['direct', 'connect'])
@pytest.mark.parametrize(
    'entry', ['sync', 'sync-upload', 'async', 'async-prepared', 'async-upload']
)
def test_unknown_alpn_dispatch_after_real_tls_closes_before_http_and_pool(
    trusted_certificates,
    monkeypatch,
    version,
    route,
    entry,
):
    from ja3requests.protocol.tls import TLS
    from ja3requests.async_transport import AsyncTransport

    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    config.alpn_protocols = ['h2', 'http/1.1']
    context.set_alpn_protocols(['http/1.1'])
    original = TLS.handshake
    handshakes, received = [], []

    def change_selection(tls):
        assert tls._negotiated_protocol == 'http/1.1'
        handshakes.append(tls._negotiated_protocol)
        # Fault injection at HTTP dispatch after an authenticated handshake.
        # The independent server actually negotiates the supported HTTP1 name.
        tls._negotiated_protocol = 'review/1'

    def injected(tls):
        result = original(tls)
        assert result
        change_selection(tls)
        return result

    if entry.startswith('sync'):
        monkeypatch.setattr(TLS, 'handshake', injected)
    else:
        original_async = AsyncTransport._start_tls

        async def injected_async(transport, *args):
            await original_async(transport, *args)
            change_selection(transport.tls)

        monkeypatch.setattr(AsyncTransport, '_start_tls', injected_async)

    def observe(conn):
        assert conn.selected_alpn_protocol() == 'http/1.1'
        try:
            received.append(recv_with_ragged_eof(conn, 4096))
        except ConnectionResetError:
            received.append(b'')

    def peer(conn):
        if route == 'connect':
            assert read_headers(conn).startswith(b'CONNECT ')
            conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
            with context.wrap_socket(conn, server_side=True) as tls:
                observe(tls)
        else:
            observe(conn)

    async def run(url, proxies):
        body = io.BytesIO(b'payload')
        async with AsyncSession(tls_config=config) as session:
            with pytest.raises(TLSHandshakeError, match='Unsupported negotiated ALPN'):
                if entry == 'async-prepared':
                    prepared = await session.prepare_request(
                        'POST', url, data=b'payload', proxies=proxies
                    )
                    await session.send(prepared, timeout=2)
                else:
                    await session.post(
                        url,
                        data=body if entry == 'async-upload' else b'payload',
                        proxies=proxies,
                        timeout=2,
                    )
            assert not session._pool._entries and not session._pool._creating
        assert body.tell() == 0 and not body.closed

    with LocalServer(peer, context if route == 'direct' else None) as server:
        url = 'https://127.0.0.1:%d/' % (server.port if route == 'direct' else 443)
        proxies = (
            {} if route == 'direct' else {'https': 'http://127.0.0.1:%d' % server.port}
        )
        if entry.startswith('sync'):
            body = io.BytesIO(b'payload')
            with ConnectionPool() as pool, Session(
                tls_config=config, pool=pool
            ) as session:
                with pytest.raises(
                    TLSHandshakeError, match='Unsupported negotiated ALPN'
                ):
                    session.post(
                        url,
                        data=body if entry == 'sync-upload' else b'payload',
                        proxies=proxies,
                        timeout=2,
                    )
                assert pool.get_stats()['total_connections'] == 0
                assert not pool._h2_connecting
            assert body.tell() == 0 and not body.closed
        else:
            asyncio.run(run(url, proxies))
    assert handshakes == ['http/1.1'] and received == [b'']


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('entry', ['sync', 'async'])
@pytest.mark.parametrize('protocol', [None, 'http/1.1'])
def test_supported_or_absent_alpn_keeps_http1_after_real_tls(
    trusted_certificates,
    monkeypatch,
    version,
    entry,
    protocol,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    config.alpn_protocols = [] if protocol is None else [protocol]
    context.set_alpn_protocols(config.alpn_protocols)
    received = []

    def peer(conn):
        assert conn.selected_alpn_protocol() == protocol
        received.append(read_headers(conn))
        conn.sendall(
            b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
        )

    async def run(url):
        async with AsyncSession(tls_config=config) as session:
            assert (await session.get(url, timeout=2)).status_code == 200

    with LocalServer(peer, context) as server:
        url = 'https://127.0.0.1:%d/' % server.port
        if entry == 'sync':
            with Session(tls_config=config, use_pooling=False) as session:
                assert session.get(url, timeout=2).status_code == 200
        else:
            asyncio.run(run(url))
    assert len(received) == 1 and received[0].startswith(b'GET / HTTP/1.1\r\n')


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('entry', ['sync', 'async'])
@pytest.mark.parametrize('protocol', ['http/1.1', 'h2'])
def test_reused_real_tls_entry_rechecks_alpn_before_another_http_send(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    async_h2_connections,
    version,
    entry,
    protocol,
):
    from ja3requests.sockets.https import HttpsSocket

    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    config.alpn_protocols = [protocol]
    context.set_alpn_protocols([protocol])
    received, connections = [], []
    original = getattr(HttpsSocket, '_send_h2' if protocol == 'h2' else '_send_h1')

    def capture(sock):
        connections.append(sock.tls)
        return original(sock)

    monkeypatch.setattr(
        HttpsSocket, '_send_h2' if protocol == 'h2' else '_send_h1', capture
    )

    def peer(conn):
        if protocol == 'h2':
            start_h2(conn)
            while not received:
                kind, _, stream, _ = receive_frame(conn)
                if kind == 1:
                    received.append(stream)
                    conn.sendall(h2_frame(1, 5, stream, b'\x88'))
        else:
            received.append(read_headers(conn))
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        trailing = bytearray()
        while True:
            try:
                data = recv_with_ragged_eof(conn, 4096)
            except ConnectionResetError:
                break
            if not data:
                break
            trailing.extend(data)
        # H2 may have queued SETTINGS ACKs, but no second request frame.
        if protocol == 'h2':
            while trailing:
                size = int.from_bytes(trailing[:3], 'big')
                assert len(trailing) >= 9 + size
                assert trailing[3] != 1
                del trailing[: 9 + size]
        else:
            assert not trailing

    async def run(url):
        async with AsyncSession(tls_config=config) as session:
            assert (await session.get(url, timeout=2)).status_code == 200
            session._pool._entries[0].transport.tls._negotiated_protocol = 'review/1'
            with pytest.raises(TLSHandshakeError, match='Unsupported negotiated ALPN'):
                await session.get(url, timeout=2)
            assert not session._pool._entries and not session._pool._creating

    with LocalServer(peer, context) as server:
        url = 'https://127.0.0.1:%d/' % server.port
        if entry == 'sync':
            with ConnectionPool() as pool, Session(
                tls_config=config, pool=pool
            ) as session:
                assert session.get(url, timeout=2).status_code == 200
                assert len(connections) == 1
                connections[0]._negotiated_protocol = 'review/1'
                with pytest.raises(
                    TLSHandshakeError, match='Unsupported negotiated ALPN'
                ):
                    session.get(url, timeout=2)
                assert pool.get_stats()['total_connections'] == 0
        else:
            asyncio.run(run(url))
    assert len(received) == 1


SETTINGS = [(4, 123456), (1, 8192), (2, 0), (6, 262144)]
ORDER = [':path', ':method', ':scheme', ':authority']
PRIORITIES = [(3, 0, 1, False), (5, 3, 256, True)]
FIELDS = {
    'Connection': b'X-Hop, X-Other',
    'X-Hop': 'private',
    'X-Other': 'private',
    'Keep-Alive': 'timeout=1',
    'Proxy-Connection': 'keep-alive',
    'TE': b'trailers',
    'X-End': b'\xc3\xa9',
}


def observe_h2(conn, seen, count=2):
    start_h2(conn)
    decoder = HPACKDecoder()
    current, body = None, bytearray()
    while len(seen['requests']) < count:
        kind, flags, stream, payload = receive_frame(conn)
        if kind in (4, 8, 2) and not flags & 1:
            seen['initial'].append((kind, stream, payload))
        if kind == 1:
            assert flags & 4
            current = (stream, decoder.decode_headers(payload))
            body = bytearray()
        elif kind == 0:
            assert current[0] == stream
            body.extend(payload)
        if kind in (0, 1) and flags & 1:
            seen['requests'].append((current[0], current[1], bytes(body)))
            conn.sendall(h2_frame(1, 5, stream, b'\x88'))
    await_transport_close(conn)


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('route', ['direct', 'connect'])
@pytest.mark.parametrize(
    'entry', ['sync', 'sync-upload', 'async', 'async-prepared', 'async-upload']
)
@pytest.mark.parametrize(
    'settings', [None, {}, [], dict(SETTINGS), SETTINGS, [(1, 4096), (1, 8192), (2, 0)]]
)
def test_real_tls_h2_exact_controls_and_reuse(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    async_h2_connections,
    version,
    route,
    entry,
    settings,
):
    from ja3requests.protocol.h2.frame import DEFAULT_SETTINGS

    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    config.h2_settings = settings
    config.h2_window_update = 123
    config.h2_pseudo_header_order = ORDER
    config.h2_priority_frames = PRIORITIES
    seen = {'initial': [], 'requests': []}
    reusable = route == 'direct' or entry.startswith('async')

    def peer(conn):
        if route == 'connect':
            assert read_headers(conn).startswith(b'CONNECT ')
            conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
            with context.wrap_socket(conn, server_side=True) as tls:
                observe_h2(
                    tls, seen, count=2 if reusable else len(seen['requests']) + 1
                )
        else:
            observe_h2(conn, seen)

    async def run_async(url, proxies):
        async with AsyncSession(tls_config=config) as session:
            for _ in range(2):
                if entry == 'async-prepared':
                    prepared = await session.prepare_request(
                        'POST', url, headers=FIELDS, data=b'payload', proxies=proxies
                    )
                    response = await session.send(prepared, timeout=3)
                else:
                    response = await session.post(
                        url,
                        headers=FIELDS,
                        data=(
                            io.BytesIO(b'payload')
                            if entry == 'async-upload'
                            else b'payload'
                        ),
                        proxies=proxies,
                        timeout=3,
                    )
                assert response.status_code == 200
                await response.aclose()

    with LocalServer(
        peer, context if route == 'direct' else None, connections=1 if reusable else 2
    ) as server:
        url = 'https://127.0.0.1:%d/fingerprint' % server.port
        proxies = (
            {'https': 'http://127.0.0.1:%d' % server.port}
            if route == 'connect'
            else None
        )
        if entry.startswith('async'):
            asyncio.run(run_async(url, proxies))
        else:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                for _ in range(2):
                    response = session.post(
                        url,
                        headers=FIELDS,
                        data=(
                            iter([b'pay', b'load'])
                            if entry == 'sync-upload'
                            else b'payload'
                        ),
                        proxies=proxies,
                        timeout=3,
                    )
                    assert response.status_code == 200
                    response.close()
    expected = (
        list(DEFAULT_SETTINGS.items())
        if settings is None
        else list(settings.items()) if isinstance(settings, dict) else settings
    )
    assert seen['initial'] == [
        (4, 0, b''.join(struct.pack('!HI', *pair) for pair in expected)),
        (8, 0, struct.pack('!I', 123)),
        (2, 3, struct.pack('!IB', 0, 0)),
        (2, 5, struct.pack('!IB', 0x80000003, 255)),
    ] * (1 if reusable else 2)
    assert [request[0] for request in seen['requests']] == (
        [1, 3] if reusable else [1, 1]
    )
    for _, headers, body in seen['requests']:
        assert [name for name, _ in headers[:4]] == ORDER
        assert dict(headers)['te'] == 'trailers'
        assert dict(headers)['x-end'] == 'é'
        assert not set(dict(headers)) & {
            'connection',
            'x-hop',
            'x-other',
            'keep-alive',
            'proxy-connection',
            'transfer-encoding',
            'upgrade',
        }
        assert body == b'payload'
    assert FIELDS['X-Hop'] == 'private'
    assert len(h2_readers) + len(async_h2_connections) == (1 if reusable else 2)


@pytest.mark.parametrize(
    'entry', ['sync', 'sync-upload', 'async', 'async-prepared', 'async-upload']
)
@pytest.mark.parametrize('value', ['gzip', b'gzip', 'trailers, gzip'])
def test_invalid_te_preserves_real_shared_tls_h2_connection(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    async_h2_connections,
    entry,
    value,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = {'initial': [], 'requests': []}
    calls = []

    class Source(io.BytesIO):
        def read(self, *args):
            calls.append('read')
            return super().read(*args)

    async def run(url):
        async with AsyncSession(tls_config=config) as session:
            assert (await session.get(url, timeout=3)).status_code == 200
            with pytest.raises(ValueError, match='TE'):
                if entry == 'async-prepared':
                    prepared = await session.prepare_request(
                        'POST', url, headers={'TE': value}, data=b'payload'
                    )
                    await session.send(prepared, timeout=3)
                else:
                    await session.post(
                        url,
                        headers={'TE': value},
                        data=(
                            Source(b'payload')
                            if entry == 'async-upload'
                            else b'payload'
                        ),
                        timeout=3,
                    )
            assert (await session.get(url, timeout=3)).status_code == 200

    with LocalServer(lambda conn: observe_h2(conn, seen), context) as server:
        url = 'https://127.0.0.1:%d/' % server.port
        if entry.startswith('async'):
            asyncio.run(run(url))
        else:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                assert session.get(url, timeout=3).status_code == 200
                with pytest.raises(ValueError, match='TE'):
                    session.post(
                        url,
                        headers={'TE': value},
                        data=(
                            Source(b'payload') if entry == 'sync-upload' else b'payload'
                        ),
                        timeout=3,
                    )
                assert session.get(url, timeout=3).status_code == 200
    assert not calls
    assert [request[0] for request in seen['requests']] == [1, 3]
    assert len(h2_readers) + len(async_h2_connections) == 1


@pytest.mark.parametrize('entry', ['sync', 'async', 'async-prepared'])
@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('payload', [b'\x00\x03\x02h2', b'\x00\x09\x02h2'])
def test_alpn_rejection_stops_actual_handshake_before_http_and_pool(
    trusted_certificates,
    monkeypatch,
    entry,
    version,
    payload,
):
    import ssl

    from ja3requests.protocol.tls import TLS
    from ja3requests.protocol.tls.tls13 import TLS13Handshake
    from ja3requests.exceptions import TLSHandshakeError
    from test.mock_servers.local import tls12_context, tls13_context

    config, _ = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    config.alpn_protocols = ['http/1.1']
    context = (
        tls12_context(
            *trusted_certificates.leaves['valid'], cipher='ECDHE-RSA-AES128-GCM-SHA256'
        )
        if version == 12
        else tls13_context(*trusted_certificates.leaves['valid'])
    )
    checked, received = [], []

    def extension_vector(data, offset):
        result = b''
        cursor = offset + 2
        while cursor < len(data):
            kind, size = struct.unpack('!HH', data[cursor : cursor + 4])
            cursor += 4
            extension = data[cursor : cursor + size]
            cursor += size
            if kind == 16:
                extension = payload
            result += struct.pack('!HH', kind, len(extension)) + extension
        return data[:offset] + struct.pack('!H', len(result)) + result

    if version == 12:
        original = TLS._parse_server_hello

        def corrupt(tls, data):
            checked.append(tls._offered_alpn_protocols)
            return original(tls, extension_vector(data, 38 + data[34]))

        monkeypatch.setattr(TLS, '_parse_server_hello', corrupt)
    else:
        original = TLS13Handshake._parse_encrypted_extensions

        def corrupt(tls, data):
            checked.append(tls._offered_alpn_protocols)
            return original(tls, extension_vector(data, 0))

        monkeypatch.setattr(TLS13Handshake, '_parse_encrypted_extensions', corrupt)

    def peer(conn):
        try:
            with context.wrap_socket(conn, server_side=True) as tls:
                received.append(tls.recv(1024))
        except ssl.SSLError:
            pass  # The client must close before completing this injected handshake.

    async def run(url):
        async with AsyncSession(tls_config=config) as session:
            with pytest.raises(TLSHandshakeError, match='handshake failed'):
                if entry == 'async-prepared':
                    prepared = await session.prepare_request('GET', url)
                    await session.send(prepared, timeout=2)
                else:
                    await session.get(url, timeout=2)
            assert not session._pool._entries
            assert not session._pool._creating

    with LocalServer(peer) as server:
        url = 'https://127.0.0.1:%d/' % server.port
        if entry == 'sync':
            with ConnectionPool() as pool, Session(
                tls_config=config, pool=pool
            ) as session:
                with pytest.raises(ConnectionError, match='handshake failed'):
                    session.get(url, timeout=2)
                assert pool.get_stats()['total_connections'] == 0
        else:
            asyncio.run(run(url))
    assert checked == [(b'http/1.1',)]
    assert not received


@pytest.mark.parametrize('entry', ['sync', 'async'])
@pytest.mark.parametrize('control', ['settings', 'pseudo', 'priority', 'window'])
def test_changed_h2_controls_create_distinct_real_connections(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    async_h2_connections,
    entry,
    control,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = {'initial': [], 'requests': []}

    def change():
        if control == 'settings':
            config.h2_settings = [(4, 123456), (2, 0)]
        elif control == 'pseudo':
            config.h2_pseudo_header_order = ORDER
        elif control == 'priority':
            config.h2_priority_frames = PRIORITIES
        else:
            config.h2_window_update = 123

    import threading

    class ConcurrentPeer(LocalServer):
        def _serve(self):
            workers = []

            def serve(raw):
                try:
                    raw.settimeout(5)
                    with self.tls_context.wrap_socket(raw, server_side=True) as conn:
                        self.handler(conn)
                except Exception as error:
                    self.errors.append(error)

            try:
                for _ in range(2):
                    raw, _ = self.listener.accept()
                    worker = threading.Thread(target=serve, args=(raw,), daemon=True)
                    worker.start()
                    workers.append(worker)
                for worker in workers:
                    worker.join(5)
                    assert not worker.is_alive(), 'Concurrent TLS peer survived cleanup'
            except Exception as error:
                self.errors.append(error)

    def peer(conn):
        start_h2(conn)
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            if kind in (4, 8, 2) and not flags & 1:
                seen['initial'].append((kind, stream, payload))
            if kind == 1:
                seen['requests'].append(
                    (stream, HPACKDecoder().decode_headers(payload), b'')
                )
                conn.sendall(h2_frame(1, 5, stream, b'\x88'))
                await_transport_close(conn)
                return

    async def run(url):
        async with AsyncSession(tls_config=config) as session:
            assert (await session.get(url, timeout=2)).status_code == 200
            change()
            assert (await session.get(url, timeout=2)).status_code == 200

    with ConcurrentPeer(peer, context, connections=2) as server:
        url = 'https://127.0.0.1:%d/' % server.port
        if entry == 'async':
            asyncio.run(run(url))
        else:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                assert session.get(url, timeout=2).status_code == 200
                change()
                assert session.get(url, timeout=2).status_code == 200
    assert [request[0] for request in seen['requests']] == [1, 1]
    assert len(h2_readers) + len(async_h2_connections) == 2
