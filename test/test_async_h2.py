"""Async H2 scheduling and cancellation against independent frame bytes."""

import asyncio
from collections import namedtuple
from contextlib import asynccontextmanager
import contextvars
from functools import wraps
import struct

import pytest

from ja3requests.exceptions import RequestException, Timeout
from ja3requests.protocol.h2.async_connection import AsyncH2Connection, H2ProtocolError
from ja3requests.protocol.h2.hpack import HPACKDecoder
from test.mock_servers.local import h2_frame


Frame = namedtuple("Frame", "kind flags stream payload")
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def async_test(function):
    """Keep the suite independent of an async pytest plugin, including on 3.7."""

    @wraps(function)
    def run(*args, **kwargs):
        async def bounded():
            await asyncio.wait_for(function(*args, **kwargs), 5)

        asyncio.run(bounded())

    return run


class Wire:
    def __init__(self):
        self.incoming = asyncio.Queue()
        self.sent = []
        self.attempted = []
        self.changed = asyncio.Event()
        self.block = None
        self.blocked = asyncio.Event()
        self.resume = asyncio.Event()
        self.failure = None
        self.ping = 0
        self.context = None
        self.seen_contexts = []

    def notify(self):
        self.changed.set()
        self.changed = asyncio.Event()

    async def send(self, data):
        if self.context is not None:
            self.seen_contexts.append(self.context.get())
        if data == PREFACE:
            self.sent.append(data)
            self.notify()
            return
        assert len(data) >= 9
        length = int.from_bytes(data[:3], "big")
        kind, flags, stream = struct.unpack("!BBI", data[3:9])
        assert len(data) == 9 + length
        frame = Frame(kind, flags, stream, data[9:])
        self.attempted.append(frame)
        if self.block is not None and self.block(frame):
            self.blocked.set()
            await self.resume.wait()
        if self.failure is not None:
            raise self.failure
        self.sent.append(frame)
        self.notify()

    async def recv(self, _size):
        if self.context is not None:
            self.seen_contexts.append(self.context.get())
        value = await self.incoming.get()
        if isinstance(value, BaseException):
            raise value
        return value

    def feed(self, *values):
        for value in values:
            self.incoming.put_nowait(value)

    async def until(self, predicate):
        while not predicate():
            await asyncio.wait_for(self.changed.wait(), 2)

    async def flush(self):
        self.ping += 1
        payload = self.ping.to_bytes(8, "big")
        self.feed(h2_frame(6, 0, 0, payload))
        await self.until(
            lambda: any(
                frame.kind == 6 and frame.flags == 1 and frame.payload == payload
                for frame in self.frames()
            )
        )

    def frames(self, kind=None, stream=None):
        return [
            frame
            for frame in self.sent
            if isinstance(frame, Frame)
            and (kind is None or frame.kind == kind)
            and (stream is None or frame.stream == stream)
        ]

    def updates(self, stream):
        return [
            int.from_bytes(frame.payload, "big") for frame in self.frames(8, stream)
        ]


@asynccontextmanager
async def connected(window=8, peer_settings=None, wire=None, initial_increment=None):
    wire = wire or Wire()
    conn = AsyncH2Connection(wire.send, wire.recv, settings={4: window})
    try:
        await conn.initiate(initial_increment)
        payload = b"".join(
            struct.pack("!HI", key, value)
            for key, value in (peer_settings or {}).items()
        )
        wire.feed(h2_frame(4, 0, 0, payload))
        await wire.flush()
        yield conn, wire
    finally:
        await conn.aclose()
        assert conn._reader_task.done()
        assert conn._writer_task.done()
        assert conn._close_task.done()
        assert not conn._streams
        assert conn._buffered_bytes == 0
        assert conn._control_bytes == 0


async def request(conn, **kwargs):
    return await conn.send_request("GET", "example.test", "/", **kwargs)


def headers(stream, end=False, block=b"\x88"):
    return h2_frame(1, 4 | int(end), stream, block)


@async_test
async def test_invalid_utf8_request_preserves_existing_and_future_streams():
    async with connected() as (conn, wire):
        first = await request(conn)
        sent = list(wire.sent)
        next_stream = conn._next_stream_id
        for invalid in (
            {"headers": [("x-test", b"\xff")]},
            {"headers": [(b"\xff", "value")]},
            {"headers": [("x-test", "\ud800")]},
            {"path": "/\ud800"},
        ):
            arguments = dict(method="GET", authority="example.test", path="/")
            arguments.update(invalid)
            with pytest.raises(ValueError, match="valid UTF-8"):
                await conn.send_request(**arguments)
            assert not conn.failed
            assert conn._next_stream_id == next_stream
            assert set(conn._streams) == {first}
            assert not conn._outbound
            assert wire.sent == sent
        second = await request(conn)
        wire.feed(
            headers(first),
            h2_frame(0, 1, first, b"first"),
            headers(second),
            h2_frame(0, 1, second, b"second"),
        )
        for stream, body in ((first, b"first"), (second, b"second")):
            assert await conn.receive_headers(stream) == [(":status", "200")]
            assert await conn.read_stream(stream, 8) == body
            assert await conn.read_stream(stream, 8) == b""
        assert not conn.failed
        assert not conn._streams


@async_test
async def test_headers_and_prefix_are_available_before_end_stream():
    async with connected() as (conn, wire):
        stream = await request(conn)
        wire.feed(headers(stream))
        assert await conn.receive_headers(stream) == [(":status", "200")]
        assert not conn._streams[stream].done
        wire.feed(h2_frame(0, 0, stream, b"abcde"))
        await wire.flush()
        assert wire.updates(stream) == []
        assert await conn.read_stream(stream, 3, timeout=0) == b"abc"
        await wire.flush()
        assert wire.updates(stream) == [3]
        assert await conn.read_stream(stream, 100, timeout=0) == b"de"
        wire.feed(h2_frame(0, 1, stream, b"end"))
        assert await conn.read_stream(stream, 100) == b"end"
        assert await conn.read_stream(stream, 0) == b""
        assert stream in conn._streams
        assert await conn.read_stream(stream, 100) == b""
        assert stream not in conn._streams
        await conn.cancel_stream(stream)
        assert not wire.frames(3)


@async_test
async def test_paused_stream_does_not_block_a_consumed_stream():
    async with connected() as (conn, wire):
        paused, active = await request(conn), await request(conn)
        wire.feed(headers(paused), headers(active), h2_frame(0, 0, paused, b"p" * 8))
        await wire.flush()
        for index in range(4):
            data = bytes([index]) * 8
            wire.feed(h2_frame(0, int(index == 3), active, data))
            assert await conn.read_stream(active, 8) == data
            await wire.flush()
            assert len(conn._streams[paused].body) == 8
            assert conn._buffered_bytes <= 16
        assert await conn.read_stream(active, 8) == b""
        assert wire.updates(paused) == []
        assert wire.updates(active) == [8, 8, 8]
        await conn.cancel_stream(paused)
        assert conn._buffered_bytes == 0
        assert not conn.failed


@async_test
async def test_aggregate_receive_budget_and_discarded_padding():
    async with connected(window=65535) as (conn, wire):
        streams = [await request(conn) for _ in range(3)]
        wire.feed(*(headers(stream) for stream in streams))
        for stream in streams[:2]:
            for offset in range(0, 65535, 16384):
                wire.feed(h2_frame(0, 0, stream, b"x" * min(16384, 65535 - offset)))
        await wire.flush()
        assert conn._buffered_bytes == conn.receive_buffer_limit == 131070
        assert conn._connection_receive_window == 0
        assert sum(wire.updates(0)) == 65535
        await conn.cancel_stream(streams[0])
        await wire.flush()
        assert conn._buffered_bytes == 65535
        assert conn._connection_receive_window == 65535
        wire.feed(h2_frame(0, 1, streams[2], b"ok"))
        assert await conn.read_stream(streams[2], 2) == b"ok"
        await conn.cancel_stream(streams[1])
        assert conn._buffered_bytes == 0
    async with connected() as (conn, wire):
        stream = await request(conn)
        wire.feed(headers(stream), h2_frame(0, 8, stream, b"\x04a" + b"\0" * 4))
        await wire.flush()
        assert wire.updates(stream) == [5]
        assert conn._buffered_bytes == 1
        assert await conn.read_stream(stream, 8) == b"a"


@pytest.mark.parametrize("cancel", [False, True], ids=["timeout", "cancel"])
@async_test
async def test_read_interruption_only_resets_its_stream(cancel):
    async with connected() as (conn, wire):
        slow, fast = await request(conn), await request(conn)
        wire.feed(headers(slow), headers(fast, end=True))
        await conn.receive_headers(slow)
        if cancel:
            pending = asyncio.create_task(conn.read_stream(slow, 8))
            await asyncio.sleep(0)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
        else:
            with pytest.raises(Timeout):
                await conn.read_stream(slow, 8, timeout=0)
        assert await conn.receive_headers(fast) == [(":status", "200")]
        assert await conn.read_stream(fast, 8) == b""
        later = await request(conn)
        wire.feed(headers(later, end=True))
        assert await conn.receive_headers(later) == [(":status", "200")]
        await wire.flush()
        assert [(frame.stream, frame.payload) for frame in wire.frames(3)] == [
            (slow, b"\0\0\0\x08")
        ]
        assert not conn.failed


@async_test
async def test_slot_waiter_cancellation_sends_no_request_or_reset():
    async with connected(peer_settings={3: 1}) as (conn, wire):
        first = await request(conn)
        cancelled = asyncio.create_task(request(conn))
        waiting = asyncio.create_task(request(conn))
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        assert not waiting.done()
        assert len(wire.frames(1)) == 1
        wire.feed(headers(first, end=True))
        await conn.receive_headers(first)
        assert await conn.read_stream(first, 8) == b""
        assert await waiting == 3
        assert not wire.frames(3)
        assert [frame.stream for frame in wire.frames(1)] == [1, 3]


@async_test
async def test_peer_settings_waiter_cancel_and_none_deadline():
    wire = Wire()
    conn = AsyncH2Connection(wire.send, wire.recv)
    await conn.initiate()
    try:
        waiting = asyncio.create_task(request(conn, timeout=None))
        await asyncio.sleep(0)
        assert not waiting.done()
        assert not conn._streams
        assert not wire.frames(1)
        waiting.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiting
        wire.feed(h2_frame(4, 0, 0))
        await wire.flush()
        assert await request(conn) == 1
    finally:
        await conn.aclose()


@async_test
async def test_uncommitted_header_cancel_does_not_mutate_hpack():
    async with connected() as (conn, wire):
        wire.block = lambda frame: frame.kind == 6
        wire.feed(h2_frame(6, 0, 0, b"gateping"))
        await wire.blocked.wait()
        pending = asyncio.create_task(
            request(conn, headers=[("x-cancelled", "hidden")])
        )
        await asyncio.sleep(0)
        assert conn._streams[1].request_committed is False
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        wire.resume.set()
        stream = await request(conn, headers=[("x-cancelled", "hidden")])
        assert stream == 3
        assert not wire.frames(3)
        assert [frame.stream for frame in wire.frames(1)] == [3]
        decoded = HPACKDecoder().decode_headers(wire.frames(1)[0].payload)
        assert ("x-cancelled", "hidden") in decoded


@async_test
async def test_committed_header_block_finishes_before_reset_and_next_header():
    async with connected() as (conn, wire):
        wire.block = lambda frame: frame.kind == 1 and frame.stream == 1
        value = "long-field-" * 5000
        pending = asyncio.create_task(request(conn, headers=[("x-large", value)]))
        await wire.blocked.wait()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        later = asyncio.create_task(request(conn, headers=[("x-large", value)]))
        await asyncio.sleep(0)
        assert not later.done()
        wire.feed(h2_frame(6, 0, 0, b"busyread"))
        wire.resume.set()
        assert await later == 3
        await wire.flush()
        frames = [frame for frame in wire.frames() if frame.kind in (1, 3, 9)]
        first_reset = next(
            index for index, frame in enumerate(frames) if frame.kind == 3
        )
        committed = frames[:first_reset]
        assert len(committed) >= 2
        assert committed[0].kind == 1
        assert all(frame.kind == 9 for frame in committed[1:])
        assert all(frame.stream == 1 for frame in committed)
        assert not any(frame.flags & 4 for frame in committed[:-1])
        assert committed[-1].flags & 4
        assert frames[first_reset].stream == 1
        decoder = HPACKDecoder()
        assert ("x-large", value) in decoder.decode_headers(
            b"".join(frame.payload for frame in committed)
        )
        following = [frame for frame in frames[first_reset + 1 :] if frame.stream == 3]
        assert ("x-large", value) in decoder.decode_headers(
            b"".join(frame.payload for frame in following)
        )


@async_test
async def test_zero_data_window_does_not_stop_reader_or_other_streams():
    async with connected(peer_settings={4: 0}) as (conn, wire):
        upload = asyncio.create_task(request(conn, body=b"upload"))
        await wire.until(lambda: bool(wire.frames(1, 1)))
        assert not upload.done()
        fast = await request(conn)
        wire.feed(headers(fast, end=True))
        assert await conn.receive_headers(fast) == [(":status", "200")]
        assert await conn.read_stream(fast, 8) == b""
        await wire.flush()
        assert not wire.frames(0)
        wire.feed(h2_frame(8, 0, 1, struct.pack("!I", 6)))
        assert await upload == 1
        assert wire.frames(0, 1) == [Frame(0, 1, 1, b"upload")]


@async_test
async def test_remote_end_stream_still_accepts_upload_window_credit():
    async with connected(peer_settings={4: 0}) as (conn, wire):
        upload = asyncio.create_task(request(conn, body=b"upload", timeout=None))
        await wire.until(lambda: bool(wire.frames(1, 1)))
        wire.feed(headers(1, end=True, block=b"\x08\x03413"))
        await wire.flush()
        assert not upload.done()
        assert conn._streams[1].done and not conn._streams[1].send_done

        wire.feed(h2_frame(8, 0, 1, struct.pack("!I", 6)))
        assert await asyncio.wait_for(upload, 1) == 1
        assert wire.frames(0, 1) == [Frame(0, 1, 1, b"upload")]
        assert await conn.receive_headers(1) == [(":status", "413")]
        assert await conn.read_stream(1, 8) == b""
        assert not wire.frames(3)
        assert await request(conn) == 3


@async_test
async def test_complete_response_reset_stops_upload_and_preserves_its_body():
    async with connected(peer_settings={4: 0}) as (conn, wire):
        upload = asyncio.create_task(request(conn, body=b"upload", timeout=None))
        await wire.until(lambda: bool(wire.frames(1, 1)))
        wire.feed(
            headers(1, block=b"\x08\x03413"),
            h2_frame(0, 1, 1, b"denied"),
            h2_frame(3, 0, 1, struct.pack("!I", 0)),
        )
        assert await asyncio.wait_for(upload, 1) == 1
        assert await conn.receive_headers(1) == [(":status", "413")]
        assert await conn.read_stream(1, 8) == b"denied"
        assert await conn.read_stream(1, 8) == b""
        assert not wire.frames(0)
        assert not wire.frames(3)
        assert await request(conn) == 3
        assert not conn.failed


@async_test
async def test_early_response_reset_keeps_committed_data_write_intact():
    async with connected() as (conn, wire):
        wire.block = lambda frame: frame.kind == 0 and frame.stream == 1
        upload = asyncio.create_task(request(conn, body=b"x" * 40000))
        await wire.blocked.wait()
        wire.feed(
            headers(1, end=True, block=b"\x08\x03413"),
            h2_frame(3, 0, 1, struct.pack("!I", 0)),
        )
        assert await asyncio.wait_for(upload, 1) == 1
        assert await conn.receive_headers(1) == [(":status", "413")]
        assert not conn._writer_task.done()
        assert not wire.frames(0)
        wire.resume.set()
        assert await request(conn) == 3
        assert await conn.read_stream(1, 8) == b""
        data = wire.frames(0, 1)
        assert len(data) == 1 and len(data[0].payload) == 16384
        assert data[0].flags == 0
        assert not wire.frames(3)
        assert not conn.failed


@pytest.mark.parametrize("interrupt", ["request", "stream", "timeout"])
@async_test
async def test_half_closed_upload_cancellation_still_resets_and_wakes(interrupt):
    async with connected(peer_settings={4: 0}) as (conn, wire):
        timeout = 0.05 if interrupt == "timeout" else None
        upload = asyncio.create_task(request(conn, body=b"upload", timeout=timeout))
        await wire.until(lambda: bool(wire.frames(1, 1)))
        wire.feed(headers(1, end=True, block=b"\x08\x03413"))
        await wire.flush()
        assert conn._streams[1].done and not conn._streams[1].send_done

        if interrupt == "request":
            upload.cancel()
            expected = asyncio.CancelledError
        elif interrupt == "stream":
            await conn.cancel_stream(1)
            expected = ConnectionError
        else:
            expected = Timeout
        with pytest.raises(expected):
            await asyncio.wait_for(upload, 1)
        await wire.flush()
        assert wire.frames(3, 1) == [Frame(3, 0, 1, struct.pack("!I", 8))]
        assert not wire.frames(0)
        assert await request(conn) == 3
        assert not conn.failed


@async_test
async def test_write_timeout_does_not_cancel_shared_writer_or_reset_other_streams():
    async with connected(peer_settings={4: 0}) as (conn, wire):
        pending = asyncio.create_task(request(conn, body=b"upload", timeout=0.01))
        await wire.until(lambda: bool(wire.frames(1, 1)))
        fast = await request(conn)
        wire.feed(headers(fast, end=True))
        # Unrelated PING progress must not refresh the upload's window deadline.
        while not pending.done():
            await wire.flush()
        with pytest.raises(Timeout) as error:
            await pending
        assert error.value.phase == "HTTP/2 write"
        assert await conn.receive_headers(fast) == [(":status", "200")]
        assert await conn.read_stream(fast, 8) == b""
        await wire.flush()
        assert [frame.stream for frame in wire.frames(3)] == [1]
        assert not conn._writer_task.done()
        assert not conn.failed


@async_test
async def test_cancelled_data_commit_finishes_without_sending_next_piece():
    async with connected() as (conn, wire):
        wire.block = lambda frame: frame.kind == 0 and frame.stream == 1
        pending = asyncio.create_task(request(conn, body=b"x" * 40000))
        await wire.blocked.wait()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert not conn.failed
        wire.resume.set()
        assert await request(conn) == 3
        await wire.flush()
        frames = [frame for frame in wire.frames() if frame.stream == 1]
        assert [frame.kind for frame in frames] == [1, 0, 3]
        assert len(frames[1].payload) == 16384
        assert frames[1].flags == 0


@async_test
async def test_cancelled_partial_response_headers_preserve_decoder_state():
    async with connected() as (conn, wire):
        first, second = await request(conn), await request(conn)
        # Literal with incremental indexing: x-shared = saved.
        block = b"\x88\x40\x08x-shared\x05saved"
        wire.feed(h2_frame(1, 0, first, block[:7]))
        while not conn._streams[first].header_open:
            await asyncio.sleep(0)
        await conn.cancel_stream(first)
        # Dynamic table index 62 must still exist for the surviving stream.
        wire.feed(h2_frame(9, 4, first, block[7:]), headers(second, True, b"\x88\xbe"))
        assert await conn.receive_headers(second) == [
            (":status", "200"),
            ("x-shared", "saved"),
        ]
        assert not conn.failed


@pytest.mark.parametrize(
    "bad_frame",
    [
        h2_frame(0, 0, 1, b"no headers"),
        h2_frame(1, 4, 1, b"\xff\xff\xff\xff\x7f"),
        h2_frame(8, 0, 0, b"\0" * 4),
        h2_frame(6, 0, 1, b"badping!"),
        h2_frame(1, 4, 2, b"\x88"),
        h2_frame(0, 8, 1, b"\xff"),
    ],
    ids=[
        "data-before-headers",
        "hpack",
        "zero-credit",
        "ping-stream",
        "idle-stream",
        "padding",
    ],
)
@async_test
async def test_protocol_failure_wakes_waiters_without_transient_classification(
    bad_frame,
):
    async with connected() as (conn, wire):
        first, second = await request(conn), await request(conn)
        waiters = [
            asyncio.create_task(conn.receive_headers(stream))
            for stream in (first, second)
        ]
        wire.feed(bad_frame)
        for waiter in waiters:
            with pytest.raises(H2ProtocolError):
                await waiter
        assert conn.failed
        assert isinstance(conn._failed, RequestException)


@pytest.mark.parametrize(
    "code, expected", [(7, ConnectionError), (1, H2ProtocolError), (0, H2ProtocolError)]
)
@async_test
async def test_peer_reset_preserves_only_refused_stream_retry_eligibility(
    code, expected
):
    async with connected() as (conn, wire):
        first, second = await request(conn), await request(conn)
        wire.feed(h2_frame(3, 0, first, struct.pack("!I", code)), headers(second, True))
        with pytest.raises(expected) as error:
            await conn.receive_headers(first)
        assert isinstance(error.value, RequestException) is (code != 7)
        assert await conn.receive_headers(second) == [(":status", "200")]
        assert not conn.failed


@async_test
async def test_goaway_stops_admission_but_retains_accepted_stream():
    async with connected() as (conn, wire):
        first, second = await request(conn), await request(conn)
        wire.feed(h2_frame(7, 0, 0, struct.pack("!II", first, 0)), headers(first, True))
        assert await conn.receive_headers(first) == [(":status", "200")]
        with pytest.raises(ConnectionError, match="rejected by GOAWAY"):
            await conn.receive_headers(second)
        with pytest.raises(ConnectionError, match="GOAWAY"):
            await request(conn)
        assert not conn.failed
        assert await conn.read_stream(first, 8) == b""


@async_test
async def test_complete_body_survives_eof_while_incomplete_stream_fails():
    async with connected() as (conn, wire):
        complete, incomplete = await request(conn), await request(conn)
        wire.feed(
            headers(complete), h2_frame(0, 1, complete, b"ok"), headers(incomplete), b""
        )
        assert await conn.receive_headers(complete) == [(":status", "200")]
        assert await conn.read_stream(complete, 8) == b"ok"
        assert await conn.read_stream(complete, 8) == b""
        with pytest.raises(ConnectionError) as error:
            await conn.read_stream(incomplete, 8)
        assert not isinstance(error.value, RequestException)


@pytest.mark.parametrize("direction", ["read", "write"])
@async_test
async def test_transport_failure_preserves_transient_error(direction):
    async with connected() as (conn, wire):
        if direction == "read":
            stream = await request(conn)
            wire.feed(OSError("read failed"))
            operation = conn.receive_headers(stream)
        else:
            wire.failure = OSError("write failed")
            operation = request(conn)
        with pytest.raises(ConnectionError) as error:
            await operation
        assert not isinstance(error.value, RequestException)
        assert str(error.value.__cause__) == direction + " failed"
        assert conn.failed


@async_test
async def test_control_budget_includes_blocked_output_and_cancel_discards_body():
    async with connected() as (conn, wire):
        stream = await request(conn)
        wire.feed(headers(stream), h2_frame(0, 0, stream, b"body"))
        await wire.flush()
        wire.block = lambda frame: frame.kind == 6
        wire.feed(h2_frame(6, 0, 0, b"blocking"))
        await wire.blocked.wait()
        conn.CONTROL_BUFFER_LIMIT = conn._control_bytes
        assert conn._control_bytes == 17
        await conn.cancel_stream(stream)
        assert conn.failed
        assert conn._buffered_bytes == 0
        assert not conn._streams
        assert conn._control_bytes <= conn.CONTROL_BUFFER_LIMIT


@async_test
async def test_peer_control_flood_fails_with_bounded_queue():
    async with connected() as (conn, wire):
        stream = await request(conn)
        wire.block = lambda frame: frame.kind == 6
        wire.feed(h2_frame(6, 0, 0, b"blocking"))
        await wire.blocked.wait()
        conn.CONTROL_BUFFER_LIMIT = 34
        wire.feed(*(h2_frame(6, 0, 0, b"flooding") for _ in range(3)))
        with pytest.raises(H2ProtocolError, match="control output buffer exceeded"):
            await conn.receive_headers(stream)
        assert conn._control_bytes <= 34


@async_test
async def test_initial_fingerprint_context_isolation_and_close_idempotence():
    wire = Wire()
    wire.context = contextvars.ContextVar("request_id", default=None)
    token = wire.context.set("first-request")
    async with connected(wire=wire, initial_increment=123) as (conn, _):
        wire.context.reset(token)
        assert wire.sent[0] == PREFACE
        settings = dict(struct.iter_unpack("!HI", wire.frames(4)[0].payload))
        assert settings == conn._local_settings
        assert wire.updates(0) == [123]
        assert conn.receive_buffer_limit == 65535 + 123 + 8
        assert wire.seen_contexts and set(wire.seen_contexts) == {None}
        await conn.aclose()
        await conn.aclose()


@async_test
async def test_cancelled_close_keeps_owned_cleanup_running():
    async with connected() as (conn, wire):
        wire.block = lambda frame: frame.kind == 1
        pending = asyncio.create_task(request(conn))
        await wire.blocked.wait()
        closing = asyncio.create_task(conn.aclose())
        await asyncio.sleep(0)
        closing.cancel()
        with pytest.raises(asyncio.CancelledError):
            await closing
        await conn.aclose()
        with pytest.raises(ConnectionError):
            await pending
        assert conn._reader_task.done() and conn._writer_task.done()
