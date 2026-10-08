"""Synchronous public uploads over authenticated project TLS and real H2."""

import io
import socket
import struct
import threading
import time

import pytest

from ja3requests import Session
from ja3requests.exceptions import InvalidData
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection
from ja3requests.sockets._upload import _H2WriteGuard
from ja3requests.sockets.https import HttpsSocket
from test.test_sync_upload import read_upload, reply, slow_upload_source
from test.integration.test_tls_streaming import streaming_tls_peer
from test.integration.test_h2_streaming_network import (
    trusted_h2_peer,
    receive_frame,
    start_h2,
    await_transport_close,
    h2_readers,
)
from test.mock_servers.local import (
    LocalServer,
    read_exact,
    read_headers,
    serve_socks,
    h2_frame,
)


@pytest.fixture(autouse=True)
def h2_write_guards(monkeypatch):
    guards = []
    original = _H2WriteGuard.__init__

    def create(guard, *args, **kwargs):
        original(guard, *args, **kwargs)
        guards.append(guard)

    monkeypatch.setattr(_H2WriteGuard, '__init__', create)
    yield guards
    for guard in guards:
        guard.thread.join(2)
        assert (
            not guard.thread.is_alive()
        ), 'H2 write watcher survived transport cleanup'


@pytest.mark.parametrize('route', ['direct', 'connect', 'socks5'])
@pytest.mark.parametrize('known', [False, True])
def test_tls_upload_fixed_chunked_and_existing_proxy_routes(
    streaming_tls_peer, route, known
):
    config, context = streaming_tls_peer
    seen = []

    def application(conn):
        seen.append(read_upload(conn))
        reply(conn)

    def secure(conn):
        with context.wrap_socket(conn, server_side=True) as transport:
            application(transport)

    def proxy(conn):
        if route == 'connect':
            assert read_headers(conn).startswith(b'CONNECT ')
            conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
            secure(conn)
        else:
            serve_socks(conn, {}, tunnel_handler=secure)

    payload = b'\xff\x00binary' * 5000
    source = (
        io.BytesIO(payload) if known else iter([payload[:10000], b'', payload[10000:]])
    )
    with LocalServer(
        application if route == 'direct' else proxy,
        context if route == 'direct' else None,
    ) as peer:
        proxies = (
            None
            if route == 'direct'
            else {
                'https': '%s://127.0.0.1:%d'
                % ('http' if route == 'connect' else route, peer.port)
            }
        )
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.put(
                'https://127.0.0.1:%d/' % peer.port,
                data=source,
                proxies=proxies,
                timeout=3,
            )
            assert response.content == b'ok'
            assert not session._uploads
            assert response.request.data._closed
    assert seen[0][1] == payload
    if known:
        assert not source.closed


def test_tls_upload_progress_outlives_response_read_timeout(streaming_tls_peer):
    config, context = streaming_tls_peer
    seen = []

    def serve(conn):
        seen.append(read_upload(conn)[1])
        reply(conn)

    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        response = session.put(
            'https://127.0.0.1:%d/' % peer.port,
            data=slow_upload_source(),
            timeout=(2, 0.25),
        )
        assert response.content == b'ok'
        assert not session._uploads
    assert seen == [b'piece' * 8]


@pytest.mark.parametrize('early_headers', [False, True])
def test_tls_upload_response_waits_still_timeout(streaming_tls_peer, early_headers):
    config, context = streaming_tls_peer
    release = threading.Event()
    seen = []

    def source():
        yield b'prefix'
        if early_headers:
            assert release.wait(3)
            yield b'must-not-send'

    def serve(conn):
        if early_headers:
            read_headers(conn)
            assert read_exact(conn, 11) == b'6\r\nprefix\r\n'
            seen.append(b'prefix')
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n')
        else:
            seen.append(read_upload(conn)[1])
        await_transport_close(conn)

    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        try:
            if early_headers:
                response = session.put(
                    'https://127.0.0.1:%d/' % peer.port,
                    data=source(),
                    timeout=(2, 0.2),
                    stream=True,
                )
                release.set()
                assert not response.response._upload_owner.complete
                with pytest.raises(TimeoutError):
                    response.content
            else:
                with pytest.raises(TimeoutError):
                    session.put(
                        'https://127.0.0.1:%d/' % peer.port,
                        data=source(),
                        timeout=(2, 0.2),
                    )
            assert not session._uploads
        finally:
            release.set()
    assert seen == [b'prefix']


@pytest.mark.parametrize('version', [12, 13])
def test_h2_upload_progress_outlives_response_header_timeout(
    trusted_certificates, monkeypatch, h2_readers, version
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    received = bytearray()

    def serve(conn):
        start_h2(conn)
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 0:
                received.extend(payload)
                if flags & 1:
                    conn.sendall(
                        h2_frame(1, 4, stream, b'\x88') + h2_frame(0, 1, stream, b'ok')
                    )
                    break
        await_transport_close(conn)

    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        response = session.put(
            'https://127.0.0.1:%d/' % peer.port,
            data=slow_upload_source(),
            timeout=(2, 0.25),
        )
        assert response.content == b'ok'
        assert not session._uploads
    assert received == b'piece' * 8


@pytest.mark.parametrize('phase', ['source', 'credit', 'response'])
def test_h2_upload_without_response_headers_still_bounds_each_phase(
    trusted_certificates, monkeypatch, h2_readers, phase
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    safety_stop = threading.Event()
    resets, completed = [], []

    def source():
        if phase == 'source':
            while not safety_stop.is_set():
                yield b''
        else:
            yield b'body'

    def serve(conn):
        assert read_exact(conn, 24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        settings = struct.pack('!HI', 4, 0) if phase == 'credit' else b''
        conn.sendall(h2_frame(4, 0, 0, settings))
        while True:
            kind, flags, stream, _ = receive_frame(conn)
            if kind == 0 and flags & 1:
                completed.append(stream)
            elif kind == 3:
                resets.append(stream)
            elif kind == 1 and stream == 3:
                conn.sendall(h2_frame(1, 4, 3, b'\x88') + h2_frame(0, 1, 3, b'next'))
                break
        await_transport_close(conn)

    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        url = 'https://127.0.0.1:%d/' % peer.port
        try:
            with pytest.raises(ConnectionError, match='timed out'):
                session.put(url, data=source(), timeout=(2, 0.2))
            assert not session._uploads
            assert session.get(url, timeout=2).content == b'next'
        finally:
            safety_stop.set()
    assert resets == [1]
    assert completed == ([1] if phase == 'response' else [])


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('known', [False, True])
def test_public_h2_upload_obeys_credit_and_frame_limits(
    trusted_certificates, monkeypatch, h2_readers, version, known
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    size = 150000
    received = bytearray()
    lengths = []

    def serve(conn):
        start_h2(conn)
        stream_id = None
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 1:
                stream_id = stream
                assert not flags & 1
            elif kind == 0:
                assert stream == stream_id
                received.extend(payload)
                lengths.append(len(payload))
                if payload:
                    credit = len(payload).to_bytes(4, 'big')
                    conn.sendall(
                        h2_frame(8, 0, 0, credit) + h2_frame(8, 0, stream, credit)
                    )
                if flags & 1:
                    conn.sendall(
                        h2_frame(1, 4, stream, b'\x88') + h2_frame(0, 1, stream, b'ok')
                    )
                    break
        await_transport_close(conn)

    source = io.BytesIO(b'x' * size) if known else iter([b'x' * 50000] * 3)
    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        response = session.put(
            'https://127.0.0.1:%d/' % peer.port, data=source, timeout=3
        )
        assert response.content == b'ok'
        assert not session._uploads
        assert response.request.data._closed
    assert received == b'x' * size
    assert max(lengths) <= 16384 and lengths[-1] == 0
    assert len(h2_readers) == 1


def test_h2_empty_unknown_source_ends_at_zero_stream_credit(
    trusted_certificates, monkeypatch, h2_readers
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)

    def serve(conn):
        assert conn.recv(24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        conn.sendall(h2_frame(4, 0, 0, struct.pack('!HI', 4, 0)))
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 0:
                assert flags & 1 and payload == b''
                conn.sendall(h2_frame(1, 5, stream, b'\x88'))
                break
        await_transport_close(conn)

    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        response = session.put(
            'https://127.0.0.1:%d/' % peer.port, data=iter(()), timeout=2
        )
        assert response.content == b''
        assert not session._uploads


@pytest.mark.parametrize('failure', [False, True])
def test_h2_slow_source_control_other_stream_and_target_only_finish(
    trusted_certificates, monkeypatch, h2_readers, failure
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    entered, release, ping = threading.Event(), threading.Event(), threading.Event()
    resets = []
    sent_body = []

    def source():
        yield b'prefix'
        entered.set()
        assert release.wait(4)
        if failure:
            raise OSError('only this source failed')
        yield b'must-not-send-after-complete-response'

    def serve(conn):
        start_h2(conn)
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 1:
                conn.sendall(h2_frame(1, 4, stream, b'\x88'))
                if stream != 1:
                    conn.sendall(h2_frame(0, 1, stream, b'fast'))
                    if stream == 3:
                        conn.sendall(h2_frame(6, 0, 0, b'progress'))
                        if not failure:
                            conn.sendall(h2_frame(0, 1, 1, b'early'))
                    if stream == 5:
                        break
            elif kind == 0 and stream == 1:
                sent_body.append(payload)
            elif kind == 3:
                resets.append(stream)
            elif kind == 6 and flags & 1:
                assert payload == b'progress'
                ping.set()
        await_transport_close(conn)

    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        url = 'https://127.0.0.1:%d/' % peer.port
        slow = session.put(url, data=source(), stream=True, timeout=3)
        try:
            assert entered.wait(2)
            assert session.get(url, timeout=2).content == b'fast'
            assert ping.wait(2), 'source pull blocked the shared H2 reader/writer'
            release.set()
            if failure:
                with pytest.raises(InvalidData, match='source'):
                    slow.content
            else:
                assert slow.content == b'early'
            assert session.get(url, timeout=2).content == b'fast'
        finally:
            release.set()
            slow.close()
        assert not session._uploads
    assert resets == [1]
    assert sent_body == [b'prefix']
    assert len(h2_readers) == 1


def test_h2_zero_credit_bounds_each_source_and_close_discards_pending_chunks(
    trusted_certificates,
    monkeypatch,
    h2_readers,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    pulled = [threading.Event(), threading.Event()]
    counts = [0, 0]
    ping = threading.Event()
    resets = []

    def source(index):
        for _ in range(4):
            counts[index] += 1
            pulled[index].set()
            yield b'x' * (1024 * 1024)

    def serve(conn):
        assert conn.recv(24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        conn.sendall(h2_frame(4, 0, 0, struct.pack('!HI', 4, 0)))
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            assert kind != 0, 'upload sent DATA without stream credit'
            if kind == 1:
                conn.sendall(h2_frame(1, 4, stream, b'\x88'))
                if stream == 3:
                    assert all(event.wait(2) for event in pulled)
                    conn.sendall(h2_frame(6, 0, 0, b'zero-win'))
                elif stream == 5:
                    conn.sendall(h2_frame(0, 1, stream, b'next'))
                    break
            elif kind == 3:
                resets.append(stream)
            elif kind == 6 and flags & 1:
                assert payload == b'zero-win'
                ping.set()
        await_transport_close(conn)

    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        url = 'https://127.0.0.1:%d/' % peer.port
        responses = [
            session.put(url, data=source(i), stream=True, timeout=2) for i in range(2)
        ]
        try:
            assert ping.wait(2)
            assert counts == [1, 1]
            for response in responses:
                adapter = response.request.data
                owner = response.response._upload_owner
                assert adapter._pending is not None
                response.close()
                assert adapter._closed and adapter._pending is None
                assert not owner.thread.is_alive()
                assert owner.unregister is None
            assert not session._uploads
            assert session.get(url, timeout=2).content == b'next'
        finally:
            for response in responses:
                response.close()
    assert counts == [1, 1] and resets == [1, 3]
    assert len(h2_readers) == 1


def test_h2_upload_credit_timeout_releases_only_target_stream(
    trusted_certificates,
    monkeypatch,
    h2_readers,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    resets = []

    def serve(conn):
        assert conn.recv(24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        conn.sendall(h2_frame(4, 0, 0, struct.pack('!HI', 4, 0)))
        while True:
            kind, _, stream, _ = receive_frame(conn)
            if kind == 1:
                conn.sendall(h2_frame(1, 4, stream, b'\x88'))
                if stream == 3:
                    conn.sendall(h2_frame(0, 1, stream, b'next'))
                    break
            elif kind == 3:
                resets.append(stream)
        await_transport_close(conn)

    source = io.BytesIO(b'body')
    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        url = 'https://127.0.0.1:%d/' % peer.port
        response = session.put(url, data=source, stream=True, timeout=0.2)
        owner = response.response._upload_owner
        with pytest.raises(TimeoutError):
            response.content
        assert not owner.thread.is_alive()
        assert response.request.data._closed
        assert not session._uploads
        assert session.get(url, timeout=2).content == b'next'
    assert resets == [1] and not source.closed


def test_h2_response_before_worker_registration_does_not_pull_source(
    trusted_certificates,
    monkeypatch,
    h2_readers,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    original = H2MultiplexConnection._begin_request
    pulled = []

    def begin(connection, *args, **kwargs):
        result = original(connection, *args, **kwargs)
        connection._wait_for(lambda: result[1].done, 2)
        return result

    monkeypatch.setattr(H2MultiplexConnection, '_begin_request', begin)

    def source():
        pulled.append(True)
        yield b'must-not-be-read'

    def serve(conn):
        start_h2(conn)
        while True:
            kind, _, stream, _ = receive_frame(conn)
            if kind == 1:
                conn.sendall(h2_frame(1, 5, stream, b'\x88'))
                break
        await_transport_close(conn)

    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        response = session.put(
            'https://127.0.0.1:%d/' % peer.port, data=source(), timeout=2
        )
        assert response.content == b''
        assert response.request.data._closed
        assert not session._uploads
    assert not pulled


def test_h2_real_blocked_socket_write_honors_timeout_and_releases_locks(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    h2_write_guards,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    stopped_reading, release_peer, begin_body = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    original = HttpsSocket._new_conn
    owners, requests, pulls = [], [], []

    def connect(transport, *args):
        connection = original(transport, *args)
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        return connection

    monkeypatch.setattr(HttpsSocket, '_new_conn', connect)

    def source():
        assert begin_body.wait(4)
        for _ in range(1024):
            pulls.append(True)
            yield b'x' * 65536

    def serve(conn):
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        assert conn.recv(24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        # Keep HTTP/2 credit available: only the TCP peer's stopped reads can
        # stall this upload, not a missing WINDOW_UPDATE or a blocked source.
        conn.sendall(
            h2_frame(4, 0, 0, struct.pack('!HI', 4, 1 << 30))
            + h2_frame(8, 0, 0, (1 << 30).to_bytes(4, 'big'))
        )
        while True:
            kind, _, stream, _ = receive_frame(conn)
            if kind == 1:
                conn.sendall(h2_frame(1, 4, stream, b'\x88'))
                stopped_reading.set()
                assert release_peer.wait(4)
                break

    with LocalServer(serve, context) as peer, Session(
        tls_config=config,
        pool=ConnectionPool(),
        hooks={'before_request': [lambda request: requests.append(request)]},
    ) as session:
        original_register = session._register_upload

        def register(owner):
            owners.append(owner)
            return original_register(owner)

        session._register_upload = register
        response = session.put(
            'https://127.0.0.1:%d/' % peer.port,
            data=source(),
            timeout=0.25,
            stream=True,
        )
        try:
            assert stopped_reading.wait(2)
            started = time.monotonic()
            begin_body.set()
            owners[0].thread.join(2)
            assert not owners[
                0
            ].thread.is_alive(), 'upload remained stuck behind the writer lock'
            assert time.monotonic() - started < 2
            assert h2_write_guards[0]._expired
            with pytest.raises(OSError):
                response.content
            assert not session._uploads
            assert requests[0].data._closed
            assert requests[0].data._pending is None
            condition = owners[0].connection._condition
            assert condition.acquire(timeout=0.2)
            condition.release()
        finally:
            begin_body.set()
            release_peer.set()
            response.close()
    assert 0 < len(pulls) < 1024


@pytest.mark.parametrize('early_response', [False, True])
def test_h2_empty_chunks_are_bounded_and_do_not_block_other_streams(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    early_response,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    entered, safety_stop = threading.Event(), threading.Event()
    resets = []

    def source():
        while not safety_stop.is_set():
            entered.set()
            yield b''

    def serve(conn):
        start_h2(conn)
        while True:
            kind, _, stream, _ = receive_frame(conn)
            if kind == 1:
                if stream == 1:
                    assert entered.wait(2)
                    conn.sendall(h2_frame(1, 5 if early_response else 4, 1, b'\x88'))
                else:
                    conn.sendall(
                        h2_frame(1, 4, stream, b'\x88')
                        + h2_frame(0, 1, stream, b'next')
                    )
                    break
            elif kind == 3:
                resets.append(stream)
        await_transport_close(conn)

    with LocalServer(serve, context) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        url = 'https://127.0.0.1:%d/' % peer.port
        response = session.put(
            url, data=source(), stream=True, timeout=1 if early_response else 0.2
        )
        owner = response.response._upload_owner
        try:
            # Do not read/close the response until the producer stops itself;
            # no response-reader timeout can mask the source-progress deadline.
            owner.thread.join(2)
            assert not owner.thread.is_alive(), 'empty chunks ignored stop/deadline'
            if early_response:
                assert response.content == b''
            else:
                with pytest.raises(TimeoutError, match='Upload source timed out'):
                    response.content
            assert response.request.data._closed
            assert not session._uploads
            assert session.get(url, timeout=2).content == b'next'
        finally:
            safety_stop.set()
            response.close()
    assert resets == [1]
