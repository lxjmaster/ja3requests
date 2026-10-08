"""Public streaming uploads over authenticated project TLS and raw H2 peers."""

import asyncio
import contextvars
import io
import struct
import threading

import pytest

from ja3requests import AsyncSession
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    receive_frame,
    start_h2,
    trusted_h2_peer,
)
from test.mock_servers.local import LocalServer, h2_frame


def receive_upload_headers(conn):
    while True:
        kind, flags, stream, _ = receive_frame(conn)
        if kind == 1:
            assert flags == 4
            return stream


def test_public_source_context_survives_upload_longer_than_phase_budget(
    trusted_certificates, monkeypatch
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    caller = contextvars.ContextVar('public_h2_upload_caller')
    scope = contextvars.ContextVar('public_h2_upload_scope', default='outside')

    def peer(conn):
        start_h2(conn)
        stream = receive_upload_headers(conn)
        body = bytearray()
        while True:
            kind, flags, target, payload = receive_frame(conn)
            if kind != 0:
                continue
            assert target == stream
            body.extend(payload)
            if flags & 1:
                break
        assert body == b'caller:inside' * 4
        conn.sendall(h2_frame(1, 4, stream, b'\x88') + h2_frame(0, 1, stream, b'ok'))
        await_transport_close(conn)

    async def scenario(port):
        cleaned = asyncio.Event()

        async def source():
            token = scope.set('inside')
            try:
                for _ in range(4):
                    await asyncio.sleep(0.2)
                    yield (caller.get() + ':' + scope.get()).encode('ascii')
            finally:
                scope.reset(token)
                cleaned.set()

        token = caller.set('caller')
        try:
            async with AsyncSession(tls_config=config) as session:
                started = asyncio.get_running_loop().time()
                response = await session.post(
                    'https://127.0.0.1:%d/' % port,
                    data=source(),
                    timeout=(3, 0.5),
                )
                assert await response.read() == b'ok'
                assert asyncio.get_running_loop().time() - started > 0.5
                assert cleaned.is_set() and scope.get() == 'outside'
                assert all(entry.leases == 0 for entry in session.pool._entries)
        finally:
            caller.reset(token)

    with LocalServer(peer, context) as server:
        asyncio.run(scenario(server.port))


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('kind', ['file', 'iterator', 'async'])
def test_public_upload_exact_payload_and_window_progress(
    trusted_certificates, monkeypatch, version, kind
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    received_prefix = threading.Event()
    expected = b'prefix' + bytes(range(256)) * 1024
    streams = []

    def peer(conn):
        start_h2(conn)
        stream = receive_upload_headers(conn)
        streams.append(stream)
        body = bytearray()
        while True:
            frame_kind, flags, target, payload = receive_frame(conn)
            if frame_kind != 0:
                continue
            assert target == stream and len(payload) <= 16384
            body.extend(payload)
            if payload:
                received_prefix.set()
                credit = struct.pack('!I', len(payload))
                conn.sendall(h2_frame(8, 0, 0, credit) + h2_frame(8, 0, stream, credit))
            if flags & 1:
                break
        assert body == expected
        conn.sendall(h2_frame(1, 4, stream, b'\x88') + h2_frame(0, 1, stream, b'ok'))
        await_transport_close(conn)

    async def scenario(port):
        handle = io.BytesIO(b'skipped' + expected)
        handle.seek(7)

        def chunks():
            yield expected[:6]
            assert received_prefix.wait(3), 'Peer must see prefix before source EOF'
            for offset in range(6, len(expected), 8192):
                yield expected[offset : offset + 8192]

        async def async_chunks():
            yield expected[:6]
            assert await asyncio.get_running_loop().run_in_executor(
                None, received_prefix.wait, 3
            )
            for offset in range(6, len(expected), 8192):
                yield expected[offset : offset + 8192]

        source = {'file': handle, 'iterator': chunks, 'async': async_chunks}[kind]
        if kind != 'file':
            source = source()
        async with AsyncSession(tls_config=config) as session:
            response = await session.put(
                'https://127.0.0.1:%d/upload' % port, data=source, timeout=3
            )
            assert response.protocol_version == 'HTTP/2'
            assert await response.read() == b'ok'
            assert all(entry.leases == 0 for entry in session.pool._entries)
        assert not handle.closed

    with LocalServer(peer, context) as server:
        asyncio.run(scenario(server.port))
    assert streams == [1]


def test_public_slow_source_and_ping_share_connection_with_fast_response(
    trusted_certificates, monkeypatch
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    ping_ack = threading.Event()
    streams = []

    def peer(conn):
        start_h2(conn)
        first = receive_upload_headers(conn)
        streams.append(first)
        conn.sendall(h2_frame(6, 0, 0, b'upload!!'))
        fast = None
        while fast is None or not ping_ack.is_set():
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 1:
                fast = stream
                streams.append(fast)
                assert flags == 5
                conn.sendall(
                    h2_frame(1, 4, fast, b'\x88') + h2_frame(0, 1, fast, b'fast')
                )
            elif kind == 6 and flags & 1:
                assert payload == b'upload!!'
                ping_ack.set()
            assert kind != 0, 'Slow source advanced before the second response'
        body = bytearray()
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 0:
                assert stream == first
                body.extend(payload)
                if flags & 1:
                    break
        assert body == b'slow'
        conn.sendall(h2_frame(1, 5, first, b'\x88'))
        await_transport_close(conn)

    async def scenario(port):
        started, release = asyncio.Event(), asyncio.Event()

        async def source():
            started.set()
            await release.wait()
            yield b'slow'

        async with AsyncSession(tls_config=config) as session:
            url = 'https://127.0.0.1:%d/' % port
            slow = asyncio.create_task(session.post(url, data=source(), timeout=3))
            try:
                await started.wait()
                fast = await session.get(url, timeout=3)
                assert await fast.read() == b'fast'
                assert await asyncio.get_running_loop().run_in_executor(
                    None, ping_ack.wait, 3
                )
                release.set()
                assert await (await slow).read() == b''
                assert len(session.pool._entries) == 1
            finally:
                release.set()
                if not slow.done():
                    slow.cancel()
                await asyncio.gather(slow, return_exceptions=True)

    with LocalServer(peer, context) as server:
        asyncio.run(scenario(server.port))
    assert streams == [1, 3]


def test_public_early_response_cancels_source_and_reuses_h2_connection(
    trusted_certificates, monkeypatch
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    streams = []

    def peer(conn):
        start_h2(conn)
        first = receive_upload_headers(conn)
        streams.append(first)
        conn.sendall(
            h2_frame(1, 4, first, b'\x08\x03417')
            + h2_frame(0, 1, first, b'early')
            + h2_frame(3, 0, first, struct.pack('!I', 0))
        )
        while True:
            kind, flags, stream, _ = receive_frame(conn)
            assert kind != 0
            if kind == 1:
                streams.append(stream)
                assert flags == 5
                conn.sendall(h2_frame(1, 5, stream, b'\x88'))
                break
        await_transport_close(conn)

    async def scenario(port):
        stopped = asyncio.Event()

        async def source():
            try:
                await asyncio.Event().wait()
                yield b'unreachable'
            finally:
                stopped.set()

        async with AsyncSession(tls_config=config) as session:
            url = 'https://127.0.0.1:%d/' % port
            response = await session.post(url, data=source(), timeout=3)
            assert response.status_code == 417
            assert await response.read() == b'early'
            assert stopped.is_set()
            assert (await session.get(url, timeout=3)).status_code == 200
            assert len(session.pool._entries) == 1

    with LocalServer(peer, context) as server:
        asyncio.run(scenario(server.port))
    assert streams == [1, 3]
