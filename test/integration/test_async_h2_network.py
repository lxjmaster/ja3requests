"""Native async TLS/H2 streaming against independent OpenSSL wire peers."""

import asyncio
import struct
import threading

import pytest

from ja3requests.async_sessions import AsyncSession
from ja3requests.exceptions import Timeout
from ja3requests.protocol.h2.async_connection import AsyncH2Connection
from test.integration.test_h2_streaming_network import (
    H2GatedBody,
    await_transport_close,
    receive_frame,
    receive_request,
    start_h2,
    trusted_h2_peer,
)
from test.mock_servers.local import LocalServer, h2_frame, read_exact
from test.test_async_session import Peer, ok


@pytest.fixture
def async_h2_connections(monkeypatch):
    connections = []
    original = AsyncH2Connection.initiate

    async def initiate(connection, *args, **kwargs):
        await original(connection, *args, **kwargs)
        connections.append(connection)

    monkeypatch.setattr(AsyncH2Connection, "initiate", initiate)
    yield connections
    for connection in connections:
        assert connection._reader_task.done(), "H2 reader survived owner shutdown"
        assert connection._writer_task.done(), "H2 writer survived owner shutdown"
        assert connection._close_task.done(), "H2 cleanup survived owner shutdown"
        assert not connection._streams
        assert connection._buffered_bytes == 0


@pytest.mark.parametrize("version", [12, 13], ids=["tls12", "tls13"])
@pytest.mark.parametrize("pooled", [False, True], ids=["unpooled", "pooled"])
def test_async_headers_and_prefix_precede_end_stream(
    trusted_certificates, monkeypatch, async_h2_connections, version, pooled
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    gate = H2GatedBody()

    async def scenario(port):
        async with AsyncSession(tls_config=config, use_pooling=pooled) as session:
            response = await session.get(
                "https://127.0.0.1:%d/stream" % port, stream=True, timeout=(3, 2)
            )
            try:
                assert response.status_code == 200
                assert response.protocol_version == "HTTP/2"
                assert not gate.allow_first.is_set()
                gate.allow_first.set()
                iterator = response.aiter_content(3)
                prefix = await iterator.__anext__() + await iterator.__anext__()
                assert prefix == b"alpha"
                assert not gate.tail_sent.is_set()
                gate.allow_tail.set()
                tail = b"".join([part async for part in iterator])
                assert tail == b"omega"
                assert response.closed
            finally:
                gate.allow_first.set()
                gate.allow_tail.set()
                await response.aclose()

    with LocalServer(gate.serve, context) as server:
        asyncio.run(scenario(server.port))
    assert gate.streams == [1]
    assert len(async_h2_connections) == 1


@pytest.mark.parametrize("version", [12, 13], ids=["tls12", "tls13"])
def test_async_cancelled_consumer_preserves_other_and_later_streams(
    trusted_certificates, monkeypatch, async_h2_connections, version
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    config.h2_settings = {4: 8}
    streams = []
    resets = []

    def peer(conn):
        start_h2(conn)
        slow = receive_request(conn)
        streams.append(slow)
        conn.sendall(h2_frame(1, 4, slow, b"\x88") + h2_frame(0, 0, slow, b"paused!!"))
        fast = receive_request(conn)
        streams.append(fast)
        conn.sendall(h2_frame(1, 4, fast, b"\x88") + h2_frame(0, 0, fast, b"fast"))
        while not resets:
            kind, _, stream, payload = receive_frame(conn)
            if kind == 3:
                resets.append((stream, int.from_bytes(payload, "big")))
        conn.sendall(h2_frame(0, 1, fast, b"done"))
        later = receive_request(conn)
        streams.append(later)
        conn.sendall(h2_frame(1, 5, later, b"\x88"))
        await_transport_close(conn)

    async def scenario(port):
        async with AsyncSession(tls_config=config) as session:
            url = "https://127.0.0.1:%d/" % port
            slow = await session.get(url + "slow", stream=True, timeout=2)
            fast = await session.get(url + "fast", stream=True, timeout=2)
            pending = asyncio.create_task(slow.read())
            await asyncio.sleep(0)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            assert slow.closed
            assert await fast.read() == b"fastdone"
            later = await session.get(url + "later", timeout=2)
            assert await later.read() == b""
            assert len(async_h2_connections) == 1
            assert not async_h2_connections[0].failed

    with LocalServer(peer, context) as server:
        asyncio.run(scenario(server.port))
    assert streams == [1, 3, 5]
    assert resets == [(1, 8)]


def test_private_session_close_preserves_all_transferred_h2_responses(
    trusted_certificates, monkeypatch, async_h2_connections
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    allow_first, allow_second = threading.Event(), threading.Event()
    streams, resets = [], []

    def peer(conn):
        start_h2(conn)
        for _ in range(3):
            stream = receive_request(conn)
            streams.append(stream)
            conn.sendall(h2_frame(1, 4, stream, b'\x88'))
        while not resets:
            kind, _, stream, payload = receive_frame(conn)
            if kind == 3:
                resets.append((stream, int.from_bytes(payload, 'big')))
        assert resets == [(streams[0], 8)]
        assert allow_first.wait(3)
        conn.sendall(h2_frame(0, 1, streams[1], b'first'))
        assert allow_second.wait(3)
        conn.sendall(h2_frame(0, 1, streams[2], b'second'))
        await_transport_close(conn)

    async def scenario(port):
        async with Peer(ok) as ready:
            donor = AsyncSession(tls_config=config)
            first, second = AsyncSession(), AsyncSession()
            try:
                url = 'https://127.0.0.1:%d/' % port
                own = await donor.get(url, stream=True, timeout=2)
                one = await donor.get(url, stream=True, timeout=2)
                two = await donor.get(url, stream=True, timeout=2)
                transport = donor.pool._entries[0].transport
                for session, response in ((first, one), (second, two)):
                    await session.get(
                        ready.url,
                        stream=True,
                        timeout=1,
                        hooks={'after_request': [lambda _, result=response: result]},
                    )
                await asyncio.wait_for(donor.aclose(), 1)
                assert own.closed and not one.closed and not two.closed
                assert not transport.closed
                allow_first.set()
                assert await one.read() == b'first'
                await first.aclose()
                assert not transport.closed
                assert not async_h2_connections[0]._reader_task.done()
                allow_second.set()
                assert await two.read() == b'second'
                assert transport.closed and not donor.pool._entries
                assert async_h2_connections[0]._reader_task.done()
                assert async_h2_connections[0]._writer_task.done()
            finally:
                allow_first.set()
                allow_second.set()
                await first.aclose()
                await second.aclose()
                await donor.aclose()

    with LocalServer(peer, context) as server:
        asyncio.run(scenario(server.port))
    assert streams == [1, 3, 5]
    assert len(async_h2_connections) == 1


def test_async_unpooled_close_finishes_before_peer_eof(
    trusted_certificates, monkeypatch, async_h2_connections
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    allow_peer_close = threading.Event()
    close_observed = threading.Event()

    def peer(conn):
        start_h2(conn)
        stream = receive_request(conn)
        conn.sendall(h2_frame(1, 4, stream, b"\x88"))
        await_transport_close(conn)
        close_observed.set()
        assert allow_peer_close.wait(5)

    async def scenario(port):
        async with AsyncSession(tls_config=config, use_pooling=False) as session:
            response = await session.get(
                "https://127.0.0.1:%d/unfinished" % port, stream=True, timeout=2
            )
            await asyncio.wait_for(response.aclose(), 2)
            assert response.closed
            connection = async_h2_connections[0]
            assert connection._reader_task.done()
            assert connection._writer_task.done()
            assert not allow_peer_close.is_set()

    with LocalServer(peer, context) as server:
        try:
            asyncio.run(scenario(server.port))
        finally:
            allow_peer_close.set()
    assert close_observed.is_set()


def test_async_upload_window_wait_keeps_control_and_parallel_request_live(
    trusted_certificates, monkeypatch, async_h2_connections
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    upload_started = threading.Event()
    uploaded = []
    streams = []

    def peer(conn):
        # Advertise no initial stream DATA credit before the request arrives.
        assert conn.selected_alpn_protocol() == "h2"
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0, struct.pack("!HI", 4, 0)))
        while True:
            kind, flags, upload, _ = receive_frame(conn)
            if kind == 1:
                assert flags == 4
                break
        streams.append(upload)
        upload_started.set()
        conn.sendall(h2_frame(6, 0, 0, b"upload!!"))
        ping_seen = False
        fast = None
        while not ping_seen or fast is None:
            kind, _, stream, payload = receive_frame(conn)
            assert kind != 0, "Upload exceeded its zero stream window"
            if kind == 6:
                assert payload == b"upload!!"
                ping_seen = True
            elif kind == 1:
                fast = stream
        streams.append(fast)
        conn.sendall(h2_frame(1, 5, fast, b"\x88"))
        conn.sendall(h2_frame(8, 0, upload, struct.pack("!I", 6)))
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 0:
                assert stream == upload and flags & 1
                uploaded.append(payload)
                break
        conn.sendall(h2_frame(1, 5, upload, b"\x88"))
        await_transport_close(conn)

    async def scenario(port):
        async with AsyncSession(tls_config=config) as session:
            url = "https://127.0.0.1:%d/" % port
            upload = asyncio.create_task(session.post(url, data=b"upload", timeout=3))
            while not upload_started.is_set():
                await asyncio.sleep(0)
            fast = await session.get(url + "fast", timeout=3)
            assert fast.status_code == 200
            assert (await upload).status_code == 200
            assert len(async_h2_connections) == 1

    with LocalServer(peer, context) as server:
        asyncio.run(asyncio.wait_for(scenario(server.port), 5))
    assert streams == [1, 3]
    assert uploaded == [b"upload"]


def test_async_peer_settings_wait_uses_connect_budget_and_releases_candidate(
    trusted_certificates, monkeypatch, async_h2_connections
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    observed = []

    def peer(conn):
        assert conn.selected_alpn_protocol() == "h2"
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        while True:
            try:
                header = read_exact(conn, 9)
                length = int.from_bytes(header[:3], "big")
                kind, flags, stream = struct.unpack("!BBI", header[3:])
                payload = read_exact(conn, length)
            except EOFError:
                return
            observed.append((kind, flags, stream, payload))

    async def scenario(port):
        async with AsyncSession(tls_config=config) as session:
            with pytest.raises(Timeout) as error:
                await session.get(
                    "https://127.0.0.1:%d/no-settings" % port,
                    timeout=(0.05, None),
                )
            assert error.value.phase == "connect"
            assert not session._pool._entries
            assert not session._pool._creating
            assert async_h2_connections[0]._reader_task.done()
            assert async_h2_connections[0]._writer_task.done()

    with LocalServer(peer, context) as server:
        asyncio.run(scenario(server.port))
    assert any(frame[0] == 4 for frame in observed)
    assert not any(frame[0] == 1 for frame in observed)
