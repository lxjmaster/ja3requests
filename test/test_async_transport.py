"""Independent TCP/proxy peers and cancellation boundaries for native I/O."""

import asyncio
import gc
import socket
import threading
from types import SimpleNamespace

import pytest

from ja3requests import Timeout, TlsConfig
from ja3requests.async_transport import AsyncTransport, open_transport
from ja3requests.exceptions import TLSDecryptionError
from ja3requests.protocol.exceptions import ProxyError
from ja3requests.protocol.tls.tls13 import TLS13RecordProtection
from ja3requests.sockets.https import TLSRecordCodec
from test.mock_servers.local import LocalServer, read_exact, read_headers, serve_socks


async def wait_event(event):
    while not event.is_set():
        await asyncio.sleep(0.001)


def test_small_reads_reuse_bounded_native_read_ahead(monkeypatch):
    async def scenario():
        left, right = socket.socketpair()
        transport = AsyncTransport(left)
        loop = asyncio.get_running_loop()
        native_recv = loop.sock_recv
        requests = []

        async def observed_recv(conn, size):
            requests.append(size)
            return await native_recv(conn, size)

        monkeypatch.setattr(loop, 'sock_recv', observed_recv)
        try:
            right.sendall(b'headerbodytail')
            right.shutdown(socket.SHUT_WR)
            assert await transport.read(0) == b''
            assert requests == []
            assert await transport.read(6) == b'header'
            assert await transport.read(4) == b'body'
            assert await transport.read(4) == b'tail'
            assert requests == [65536]
            assert transport._pending == b''
        finally:
            right.close()
            await transport.aclose()

    asyncio.run(asyncio.wait_for(scenario(), 2))


def test_close_after_native_completion_does_not_restore_read_ahead(monkeypatch):
    async def scenario():
        left, right = socket.socketpair()
        transport = AsyncTransport(left)
        completed = transport._native_done

        def close_after_result(task):
            completed(task)
            transport.close()

        monkeypatch.setattr(transport, '_native_done', close_after_result)
        try:
            right.sendall(b'headerbodytail')
            # A completed native result may already be committed to the caller;
            # close must still discard any excess buffered bytes permanently.
            assert await transport.read(6) == b'header'
            assert transport.closed
            assert transport._pending == b''
            assert await transport.read(4) == b''
        finally:
            right.close()
            await transport.aclose()
        assert not transport._native_tasks
        assert not transport._native_waiters

    asyncio.run(asyncio.wait_for(scenario(), 2))


def test_native_tcp_wait_keeps_loop_responsive_and_closes_read(monkeypatch):
    release = threading.Event()

    def peer(conn):
        assert read_exact(conn, 4) == b'ping'
        conn.sendall(b'pre')
        assert release.wait(2)
        conn.sendall(b'tail')
        assert conn.recv(1) == b''

    async def scenario(port):
        transport = await open_transport('127.0.0.1', port)
        await transport.write(b'ping')
        assert await transport.read(3) == b'pre'
        waiting = asyncio.create_task(transport.read(4))
        ticks = 0
        for _ in range(8):
            await asyncio.sleep(0.002)
            ticks += 1
            assert not waiting.done()
        assert ticks == 8
        release.set()
        assert await asyncio.wait_for(waiting, 1) == b'tail'
        loop = asyncio.get_running_loop()
        native_started = asyncio.Event()
        native_recv = loop.sock_recv

        async def observed_recv(conn, size):
            native_started.set()
            return await native_recv(conn, size)

        monkeypatch.setattr(loop, 'sock_recv', observed_recv)
        waiting = asyncio.create_task(transport.read(1))
        await asyncio.wait_for(native_started.wait(), 1)
        transport.close()
        try:
            assert await asyncio.wait_for(waiting, 1) == b''
        except asyncio.TimeoutError:
            pytest.fail('close() did not wake the pending native read')
        except OSError:
            pass
        await transport.aclose()
        assert transport.closed

    with LocalServer(peer) as server:
        asyncio.run(scenario(server.port))


@pytest.mark.parametrize('operation', ['read', 'write'])
def test_close_wakes_native_io_without_cancelling_application(monkeypatch, operation):
    async def scenario():
        left, right = socket.socketpair()
        transport = AsyncTransport(left)
        started = asyncio.Event()
        stopped = asyncio.Event()
        handled = asyncio.Event()
        release_application = asyncio.Event()

        async def blocked_io(*_args):
            started.set()
            try:
                await asyncio.Future()
            finally:
                stopped.set()

        loop = asyncio.get_running_loop()
        monkeypatch.setattr(
            loop, 'sock_recv' if operation == 'read' else 'sock_sendall', blocked_io
        )

        async def application():
            try:
                if operation == 'read':
                    await transport.read(1)
                else:
                    await transport.write(b'pending')
            except ConnectionError:
                handled.set()
            await release_application.wait()
            return 'still running'

        task = asyncio.create_task(application())
        await asyncio.wait_for(started.wait(), 1)
        transport.close()
        await asyncio.wait_for(handled.wait(), 1)
        assert not task.done()
        await asyncio.wait_for(transport.aclose(), 1)
        assert stopped.is_set()
        release_application.set()
        assert await asyncio.wait_for(task, 1) == 'still running'
        right.close()

    asyncio.run(scenario())


def test_close_and_caller_cancel_observe_both_io_and_waiter_errors(monkeypatch):
    async def scenario():
        left, right = socket.socketpair()
        transport = AsyncTransport(left)
        started = asyncio.Event()
        loop = asyncio.get_running_loop()
        unhandled = []
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: unhandled.append(context))

        async def failed_io(*_args):
            started.set()
            try:
                await asyncio.Future()
            finally:
                raise ConnectionResetError('native close race')

        monkeypatch.setattr(loop, 'sock_recv', failed_io)
        try:
            task = asyncio.create_task(transport.read(1))
            await asyncio.wait_for(started.wait(), 1)
            transport.close()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(transport.aclose(), 1)
            del task, transport
            gc.collect()
            await asyncio.sleep(0)
            assert not unhandled
        finally:
            loop.set_exception_handler(previous_handler)
            right.close()

    asyncio.run(scenario())


@pytest.mark.parametrize('operation', ['read', 'write'])
def test_close_unregisters_cancelled_legacy_socket_io(monkeypatch, operation):
    async def scenario():
        loop = asyncio.get_running_loop()
        left, right = socket.socketpair()
        transport = AsyncTransport(left)
        descriptor = left.fileno()
        started = asyncio.Event()
        add = loop.add_reader if operation == 'read' else loop.add_writer
        remove = loop.remove_reader if operation == 'read' else loop.remove_writer

        async def legacy_io(*_args):
            # Python 3.7 removes these registrations on readiness, not when
            # cancellation completes. Closing the fd first leaves stale state.
            pending = loop.create_future()
            add(descriptor, lambda: None)
            started.set()
            return await pending

        monkeypatch.setattr(
            loop, 'sock_recv' if operation == 'read' else 'sock_sendall', legacy_io
        )
        task = asyncio.create_task(
            transport.read(1) if operation == 'read' else transport.write(b'pending')
        )
        try:
            await asyncio.wait_for(started.wait(), 1)
            transport.close()
            # Check synchronously: the descriptor must be unregistered before
            # another connection can reuse its number in this same loop turn.
            assert not remove(descriptor)
            with pytest.raises(ConnectionError):
                await task
        finally:
            remove(descriptor)
            await transport.aclose()
            await asyncio.gather(task, return_exceptions=True)
            right.close()

    asyncio.run(scenario())


def test_close_supports_loops_without_reader_registration(monkeypatch):
    async def scenario():
        left, right = socket.socketpair()
        transport = AsyncTransport(left)

        def unsupported(_descriptor):
            raise NotImplementedError

        try:
            with monkeypatch.context() as patch:
                patch.setattr(asyncio.get_running_loop(), 'remove_reader', unsupported)
                transport.close()
            assert left.fileno() == -1
            await transport.aclose()
        finally:
            left.close()
            right.close()

    asyncio.run(scenario())


def test_repeated_cancelled_aclose_still_joins_native_io(monkeypatch):
    async def scenario():
        left, right = socket.socketpair()
        transport = AsyncTransport(left)
        started = asyncio.Event()
        cleaning = asyncio.Event()
        release = asyncio.Event()
        stopped = asyncio.Event()

        async def delayed_cleanup(*_args):
            started.set()
            try:
                await asyncio.Future()
            finally:
                cleaning.set()
                await release.wait()
                stopped.set()

        monkeypatch.setattr(asyncio.get_running_loop(), 'sock_recv', delayed_cleanup)
        reading = asyncio.create_task(transport.read(1))
        await asyncio.wait_for(started.wait(), 1)
        closing = asyncio.create_task(transport.aclose())
        await asyncio.wait_for(cleaning.wait(), 1)
        with pytest.raises(ConnectionError):
            await reading
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        again = asyncio.create_task(transport.aclose())
        await asyncio.sleep(0)
        assert not again.done() and not stopped.is_set()
        again.cancel()
        with pytest.raises(asyncio.CancelledError):
            await again
        release.set()
        await asyncio.wait_for(transport.aclose(), 1)
        assert stopped.is_set()
        assert not transport._native_tasks
        assert not transport._native_waiters
        right.close()

    asyncio.run(scenario())


def test_connect_headers_preserve_tail_and_proxy_authentication():
    observed = []

    def peer(conn):
        observed.append(read_headers(conn))
        conn.sendall(b'HTTP/1.1 200 Connection Established\r\nX: 1\r\n\r\nhello')
        assert read_exact(conn, 4) == b'ping'

    async def scenario(port):
        transport = await open_transport(
            'origin.test', 80, proxy='http://user:p%40ss@127.0.0.1:{}'.format(port)
        )
        assert transport.tls is None
        assert await transport.read(5) == b'hello'
        await transport.write(b'ping')
        await transport.aclose()

    with LocalServer(peer) as server:
        asyncio.run(scenario(server.port))
    assert observed[0].startswith(b'CONNECT origin.test:80 HTTP/1.1\r\n')
    assert b'Proxy-Authorization: Basic dXNlcjpwQHNz\r\n' in observed[0]


@pytest.mark.parametrize('scheme', ['socks4a', 'socks5', 'socks5h'])
def test_native_socks_fragmented_replies_and_auth(scheme):
    observed = {}
    version = 4 if scheme == 'socks4a' else 5

    def peer(conn):
        serve_socks(conn, observed, version=version, auth=version == 5)

    async def scenario(port):
        transport = await open_transport(
            'origin.test',
            443,
            proxy='{}://user:p%40ss@127.0.0.1:{}'.format(scheme, port),
            timeout=1,
        )
        await transport.write(b'ping')
        assert await transport.read(4) == b'ping'
        await transport.aclose()

    with LocalServer(peer) as server:
        asyncio.run(scenario(server.port))
    assert observed['host'] == b'origin.test'
    assert observed['port'] == 443
    if version == 5:
        assert observed['credentials'] == (b'user', b'p@ss')


@pytest.mark.parametrize('phase', ['proxy', 'tls'])
@pytest.mark.parametrize('expiry', [False, True], ids=['cancel', 'timeout'])
def test_cancel_and_timeout_discard_establishment(phase, expiry):
    started = threading.Event()
    closed = threading.Event()

    def peer(conn):
        if phase == 'proxy':
            read_headers(conn)
        else:
            header = read_exact(conn, 5)
            read_exact(conn, int.from_bytes(header[3:5], 'big'))
        started.set()
        assert conn.recv(1) == b''
        closed.set()

    async def scenario(port):
        task = asyncio.create_task(
            open_transport(
                '127.0.0.1',
                port,
                proxy='http://127.0.0.1:{}'.format(port) if phase == 'proxy' else None,
                tls_config=TlsConfig.legacy() if phase == 'tls' else None,
                timeout=0.2 if expiry else None,
            )
        )
        await asyncio.wait_for(wait_event(started), 1)
        if expiry:
            with pytest.raises(Timeout):
                await task
        else:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        await asyncio.wait_for(wait_event(closed), 1)

    with LocalServer(peer) as server:
        asyncio.run(scenario(server.port))


@pytest.mark.parametrize('phase', ['dns', 'tcp'])
def test_cancel_dns_or_tcp_closes_candidate(monkeypatch, phase):
    async def scenario():
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        candidates = []

        async def resolver(*_args, **_kwargs):
            if phase == 'dns':
                started.set()
                await asyncio.Future()
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 1))]

        async def connect(conn, _address):
            candidates.append(conn)
            started.set()
            await asyncio.Future()

        monkeypatch.setattr(loop, 'getaddrinfo', resolver)
        monkeypatch.setattr(loop, 'sock_connect', connect)
        task = asyncio.create_task(open_transport('origin.test', 80))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert all(candidate.fileno() == -1 for candidate in candidates)
        assert bool(candidates) is (phase == 'tcp')

    asyncio.run(scenario())


@pytest.mark.parametrize(
    'wire',
    [
        b'\x17\x03',
        b'\x17\x03\x03\x00\x20short',
        b'\x17\x03\x03\x00\x05short',
    ],
)
def test_truncated_tls_record_is_failure_not_eof(wire):
    async def scenario(port):
        transport = await open_transport('127.0.0.1', port)
        transport.tls = SimpleNamespace(
            _is_tls13=True,
            _tls13_server_rp=TLS13RecordProtection(b'1' * 16, b'2' * 12),
        )
        transport._codec = TLSRecordCodec(transport.tls)
        with pytest.raises(TLSDecryptionError):
            await transport.read(1)
        assert transport.closed

    with LocalServer(lambda conn: conn.sendall(wire)) as server:
        asyncio.run(scenario(server.port))


def test_body_cancel_closes_native_transport():
    def peer(conn):
        conn.sendall(b'p')
        assert conn.recv(1) == b''

    async def scenario(port):
        transport = await open_transport('127.0.0.1', port)
        assert await transport.read(1) == b'p'
        task = asyncio.create_task(transport.read(1))
        await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert transport.closed
        assert transport._socket.fileno() == -1

    with LocalServer(peer) as server:
        asyncio.run(scenario(server.port))


def test_rejected_proxy_closes_without_origin_request():
    def peer(conn):
        read_headers(conn)
        conn.sendall(b'HTTP/1.1 407 Authentication Required\r\n\r\n')
        assert conn.recv(1) == b''

    async def scenario(port):
        with pytest.raises(ProxyError):
            await open_transport(
                'origin.test', 80, proxy='http://127.0.0.1:{}'.format(port)
            )

    with LocalServer(peer) as server:
        asyncio.run(scenario(server.port))


def test_cancel_committed_write_discards_transport(monkeypatch):
    async def scenario():
        left, right = socket.socketpair()
        transport = AsyncTransport(left)
        started = asyncio.Event()

        async def blocked_send(conn, data):
            assert conn is left and data == b'committed'
            started.set()
            await asyncio.Future()

        monkeypatch.setattr(asyncio.get_running_loop(), 'sock_sendall', blocked_send)
        task = asyncio.create_task(transport.write(b'committed'))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert transport.closed and left.fileno() == -1
        right.close()

    asyncio.run(scenario())


def test_key_update_waits_for_committed_record_and_precedes_next_plaintext(monkeypatch):
    from cryptography.hazmat.primitives import hashes
    from test.test_tls13_key_update import make_transport, next_secret, read_record

    async def scenario():
        sync, handshake, peer_server, peer_client = make_transport(0x1301)
        original_client_secret = (
            handshake._key_schedule.client_application_traffic_secret
        )
        original_server_secret = (
            handshake._key_schedule.server_application_traffic_secret
        )
        left, right = socket.socketpair()
        right.setblocking(False)
        transport = AsyncTransport(left)
        transport.tls = sync.tls
        transport._codec = TLSRecordCodec(sync.tls)
        committed = asyncio.Event()
        release = asyncio.Event()
        received_update = asyncio.Event()
        updated = asyncio.Event()
        sent = []
        original_send = transport._send
        original_post = transport._codec.post_handshake
        original_decrypt = transport._codec.decrypt_tls13

        async def gated_send(record):
            sent.append(record)
            if len(sent) == 1:
                committed.set()
                await release.wait()
            await original_send(record)

        def observe_post(plaintext):
            result = original_post(plaintext)
            updated.set()
            return result

        def observe_decrypt(header, payload):
            result = original_decrypt(header, payload)
            if result[0] == 22:
                received_update.set()
            return result

        monkeypatch.setattr(transport, '_send', gated_send)
        monkeypatch.setattr(transport._codec, 'post_handshake', observe_post)
        monkeypatch.setattr(transport._codec, 'decrypt_tls13', observe_decrypt)
        loop = asyncio.get_running_loop()
        first = asyncio.create_task(transport.write(b'first'))
        await committed.wait()
        reading = asyncio.create_task(transport.read(4))
        await loop.sock_sendall(right, peer_server.encrypt(22, b'\x18\x00\x00\x01\x01'))
        # The reader has received KeyUpdate but cannot rotate either key while
        # the old-key application record is committed and awaiting native I/O.
        await asyncio.wait_for(received_update.wait(), 1)
        assert not updated.is_set()
        assert (
            handshake._key_schedule.client_application_traffic_secret
            == original_client_secret
        )
        assert (
            handshake._key_schedule.server_application_traffic_secret
            == original_server_secret
        )
        next_write = asyncio.create_task(transport.write(b'next'))
        release.set()
        await asyncio.wait_for(asyncio.gather(first, next_write), 1)
        await asyncio.wait_for(updated.wait(), 1)
        assert len(sent) == 3
        assert read_record(peer_client, sent[0]) == (23, b'first')
        assert read_record(peer_client, sent[1]) == (22, b'\x18\x00\x00\x01\x00')
        key, iv = handshake._key_schedule.derive_traffic_keys(
            next_secret(original_client_secret, hashes.SHA256()), 16
        )
        peer_client.update_keys(key, iv)
        assert read_record(peer_client, sent[2]) == (23, b'next')
        key, iv = handshake._key_schedule.derive_traffic_keys(
            next_secret(original_server_secret, hashes.SHA256()), 16
        )
        peer_server.update_keys(key, iv)
        await loop.sock_sendall(right, peer_server.encrypt(23, b'done'))
        assert await asyncio.wait_for(reading, 1) == b'done'
        await transport.aclose()
        right.close()

    asyncio.run(scenario())


def test_cancel_uncommitted_lock_wait_leaves_transport_usable(monkeypatch):
    async def scenario():
        left, right = socket.socketpair()
        transport = AsyncTransport(left)
        committed = asyncio.Event()
        release = asyncio.Event()
        sent = []

        async def gated_send(data):
            sent.append(data)
            committed.set()
            await release.wait()

        monkeypatch.setattr(transport, '_send', gated_send)
        first = asyncio.create_task(transport.write(b'first'))
        await committed.wait()
        cancelled = asyncio.create_task(transport.write(b'unsent'))
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        assert not transport.closed
        release.set()
        await first
        await transport.write(b'next')
        assert sent == [b'first', b'next']
        await transport.aclose()
        right.close()

    asyncio.run(scenario())
