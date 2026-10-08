"""Streaming producers against independent HTTP/2 frame bytes."""

import asyncio
import contextvars
import io
import struct
import threading
import tracemalloc

import pytest

from ja3requests._upload import UploadSource
from ja3requests.exceptions import InvalidData, Timeout
from ja3requests.protocol.h2.hpack import HPACKDecoder
from test.mock_servers.local import h2_frame
from test.test_async_h2 import PREFACE, Wire, async_test, connected, headers, request


async def upload(conn, body, **kwargs):
    return await conn.begin_upload('POST', 'example.test', '/', body=body, **kwargs)


@async_test
async def test_async_source_keeps_caller_context_and_scope_across_yields():
    caller = contextvars.ContextVar('upload_caller', default='outside')
    scope = contextvars.ContextVar('upload_scope', default='outside')
    seen, finished = [], []

    async def chunks(label):
        token = scope.set(label)
        try:
            for _ in range(3):
                seen.append((label, caller.get(), scope.get()))
                yield label.encode('ascii')
        finally:
            scope.reset(token)
            finished.append((label, caller.get(), scope.get()))

    async with connected() as (conn, wire):

        async def begin(label):
            token = caller.set(label)
            try:
                return await upload(conn, UploadSource(chunks(label)), timeout=1)
            finally:
                caller.reset(token)

        streams = await asyncio.gather(begin('first'), begin('second'))
        await wire.until(
            lambda: all(any(f.flags & 1 for f in wire.frames(0, s)) for s in streams)
        )
        for stream, label in zip(streams, ('first', 'second')):
            assert b''.join(f.payload for f in wire.frames(0, stream)) == (
                label.encode('ascii') * 3
            )
            wire.feed(headers(stream, end=True))
            assert await conn.read_stream(stream, 1) == b''
        assert sorted(seen) == [
            (label, label, label) for label in ('first', 'second') for _ in range(3)
        ]
        assert sorted(finished) == [
            (label, label, 'outside') for label in ('first', 'second')
        ]
        assert caller.get() == scope.get() == 'outside'


@async_test
async def test_source_context_scope_is_reset_in_original_context_on_cancel():
    scope = contextvars.ContextVar('cancelled_upload_scope', default='outside')
    waiting, finished = asyncio.Event(), asyncio.Event()

    async def chunks():
        token = scope.set('inside')
        try:
            yield b'prefix'
            waiting.set()
            await asyncio.Event().wait()
        finally:
            scope.reset(token)
            finished.set()

    async with connected() as (conn, _wire):
        stream = await upload(conn, UploadSource(chunks()))
        await waiting.wait()
        await conn.cancel_stream(stream)
        assert finished.is_set() and not conn._producers
        assert scope.get() == 'outside' and not conn.failed


@pytest.mark.parametrize('timeout', [None, 0.02])
@pytest.mark.parametrize('cancel_source', ['future', 'raise'])
@async_test
async def test_source_cancellation_wakes_headers_and_only_cleans_own_stream(
    timeout, cancel_source
):
    entered, stopped = asyncio.Event(), asyncio.Event()
    source_wait = asyncio.get_running_loop().create_future()

    async def chunks():
        try:
            yield b'prefix'
            entered.set()
            await source_wait
            raise asyncio.CancelledError('source cancelled')
        finally:
            stopped.set()

    async with connected() as (conn, wire):
        other = await request(conn)
        stream = await upload(conn, UploadSource(chunks()), timeout=timeout)
        await entered.wait()
        receiving = asyncio.create_task(conn.receive_headers(stream, timeout=timeout))
        if cancel_source == 'future':
            source_wait.cancel()
        else:
            source_wait.set_result(None)
        # A producer which cancels itself must publish a terminal stream state;
        # an outer bound catches the former indefinite upload-header wait.
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(receiving, 0.2)
        assert stopped.is_set()
        assert stream not in conn._streams
        assert stream not in conn._outbound
        assert stream not in conn._producers
        await wire.until(lambda: bool(wire.frames(3, stream)))
        assert len(wire.frames(3, stream)) == 1
        assert not any(frame.flags & 1 for frame in wire.frames(0, stream))
        wire.feed(headers(other), h2_frame(0, 1, other, b'ok'))
        assert await conn.receive_headers(other) == [(':status', '200')]
        assert await conn.read_stream(other, 8) == b'ok'
        assert await conn.read_stream(other, 8) == b''
        assert not conn._streams and not conn._outbound and not conn._producers
        assert not conn.failed


@pytest.mark.parametrize('delayed_phase', ['source', 'write', 'both'])
@async_test
async def test_header_wait_does_not_limit_active_upload_total_time(delayed_phase):
    budget, delay = 0.15, 0.06

    class ReplyWire(Wire):
        async def send(self, data):
            is_data = data != PREFACE and data[3] == 0
            if is_data and len(data) > 9 and delayed_phase in ('write', 'both'):
                await asyncio.sleep(delay)
            await super().send(data)
            if is_data and data[4] & 1:
                self.feed(headers(int.from_bytes(data[5:9], 'big'), end=True))

    async def chunks():
        for _ in range(4):
            if delayed_phase in ('source', 'both'):
                await asyncio.sleep(delay)
            yield b'piece'

    async with connected(wire=ReplyWire()) as (conn, wire):
        started = asyncio.get_running_loop().time()
        stream = await upload(conn, UploadSource(chunks()), timeout=budget)
        assert await conn.receive_headers(stream, timeout=budget) == [
            (':status', '200')
        ]
        assert asyncio.get_running_loop().time() - started > budget
        assert await conn.read_stream(stream, 1) == b''
        assert b''.join(f.payload for f in wire.frames(0, stream)) == b'piece' * 4


@async_test
async def test_header_deadline_remains_effective_after_upload_finishes():
    async with connected() as (conn, wire):
        stream = await upload(conn, UploadSource(iter((b'body',))), timeout=0.03)
        with pytest.raises(Timeout) as caught:
            await conn.receive_headers(stream, timeout=0.03)
        assert caught.value.phase == 'HTTP/2 headers'
        assert any(f.flags & 1 for f in wire.frames(0, stream))
        assert not conn.failed and not conn._producers


@async_test
async def test_empty_upload_final_write_keeps_its_own_deadline():
    async with connected() as (conn, wire):
        wire.block = lambda frame: frame.kind == 0 and frame.flags & 1
        stream = await upload(conn, UploadSource(iter(())), timeout=0.03)
        await wire.blocked.wait()
        with pytest.raises(Timeout) as caught:
            await conn.receive_headers(stream, timeout=0.3)
        assert caught.value.phase == 'HTTP/2 upload write'
        wire.resume.set()
        second = await request(conn)
        wire.feed(headers(second, end=True))
        assert await conn.read_stream(second, 1) == b''
        assert not conn.failed and not conn._producers


@async_test
async def test_slow_source_does_not_block_ready_stream_or_ping():
    entered, release = asyncio.Event(), asyncio.Event()

    async def slow():
        entered.set()
        await release.wait()
        yield b'slow'

    async with connected() as (conn, wire):
        first = await upload(conn, UploadSource(slow()))
        await entered.wait()
        second = await upload(conn, UploadSource(iter((b'fast',))))
        await wire.until(lambda: any(f.flags & 1 for f in wire.frames(0, second)))
        await wire.flush()
        assert not wire.frames(0, first)
        wire.feed(headers(second), h2_frame(0, 1, second, b'ok'))
        assert await conn.read_stream(second, 8) == b'ok'
        assert await conn.read_stream(second, 8) == b''
        release.set()
        await wire.until(lambda: any(f.flags & 1 for f in wire.frames(0, first)))
        assert b''.join(f.payload for f in wire.frames(0, first)) == b'slow'
        assert not conn.failed


@pytest.mark.parametrize('size', [0, 65535])
@async_test
async def test_eof_end_stream_needs_no_flow_credit(size):
    async with connected(peer_settings={4: size}) as (conn, wire):
        stream = await upload(conn, UploadSource(iter((b'x' * size,))))
        await wire.until(lambda: any(f.flags & 1 for f in wire.frames(0, stream)))
        frames = wire.frames(0, stream)
        assert b''.join(f.payload for f in frames) == b'x' * size
        assert frames[-1].payload == b'' and frames[-1].flags == 1
        assert conn._streams[stream].send_window == 0
        if size:
            assert conn._connection_send_window == 0
        assert all(len(f.payload) <= 16384 for f in frames)


@async_test
async def test_backpressure_retains_one_piece_per_stream():
    pulls = [0, 0]

    async def chunks(index):
        for _ in range(5):
            pulls[index] += 1
            yield b'x' * 131072

    async with connected(peer_settings={4: 1}) as (conn, wire):
        streams = [
            await upload(conn, UploadSource(chunks(index))) for index in range(2)
        ]
        await wire.until(lambda: all(wire.frames(0, s) for s in streams))
        await wire.flush()
        assert pulls == [1, 1]
        for stream in streams:
            pending = conn._outbound[stream]
            assert len(pending.piece) == 65536
            assert pending.offset == 1
            assert len(pending.source._pending) == 131072
        await conn.cancel_stream(streams[0])
        wire.feed(h2_frame(8, 0, streams[1], struct.pack('!I', 4)))
        await wire.until(lambda: len(wire.frames(0, streams[1])) == 2)
        assert sum(len(f.payload) for f in wire.frames(0, streams[1])) == 5
        assert pulls == [1, 1]
        assert not conn.failed


@pytest.mark.parametrize('bad', ['not bytes', OSError('source failure')])
@async_test
async def test_source_failure_is_stream_local_and_preserves_hpack(bad):
    allow = asyncio.Event()

    async def chunks():
        yield b'prefix'
        await allow.wait()
        if isinstance(bad, Exception):
            raise bad
        yield bad

    async with connected() as (conn, wire):
        first = await upload(
            conn, UploadSource(chunks()), headers=[('x-shared', 'compressed')]
        )
        await wire.until(lambda: bool(wire.frames(0, first)))
        allow.set()
        with pytest.raises(InvalidData):
            await conn.receive_headers(first)
        await wire.until(lambda: bool(wire.frames(3, first)))
        assert not conn.failed and first not in conn._streams
        second = await request(conn, headers=[('x-shared', 'compressed')])
        wire.feed(headers(second, end=True))
        assert await conn.receive_headers(second) == [(':status', '200')]
        assert await conn.read_stream(second, 8) == b''
        # Decode both request blocks in order using the independent peer view.
        decoder = HPACKDecoder()
        decoded = [decoder.decode_headers(f.payload) for f in wire.frames(1)]
        assert all(('x-shared', 'compressed') in fields for fields in decoded)


@pytest.mark.parametrize('content,length', [(b'a', 2), (b'abc', 2)])
@async_test
async def test_declared_length_failure_has_no_successful_end_stream(content, length):
    async with connected() as (conn, wire):
        stream = await upload(conn, UploadSource(iter((content,)), length=length))
        with pytest.raises(InvalidData):
            await conn.receive_headers(stream)
        assert not any(f.flags & 1 for f in wire.frames(0, stream))
        assert sum(len(f.payload) for f in wire.frames(0, stream)) <= length
        assert not conn.failed


@async_test
async def test_complete_early_response_stops_source_and_preserves_body():
    entered, stopped = asyncio.Event(), asyncio.Event()

    async def chunks():
        entered.set()
        try:
            await asyncio.Event().wait()
            yield b'unreachable'
        finally:
            stopped.set()

    async with connected() as (conn, wire):
        first = await upload(conn, UploadSource(chunks()))
        await entered.wait()
        await wire.until(lambda: bool(wire.frames(1, first)))
        wire.feed(headers(first), h2_frame(0, 1, first, b'early'))
        await stopped.wait()
        assert await conn.receive_headers(first) == [(':status', '200')]
        wire.feed(h2_frame(3, 0, first, struct.pack('!I', 0)))
        await wire.flush()
        assert await conn.read_stream(first, 8) == b'early'
        assert await conn.read_stream(first, 8) == b''
        assert len(wire.frames(3, first)) == 1
        assert not wire.frames(0, first)
        assert not conn._producers and not conn.failed


@pytest.mark.parametrize('phase', ['credit', 'write'])
@async_test
async def test_early_response_joins_generator_finalization_in_producer_context(phase):
    scope = contextvars.ContextVar('early_upload_scope', default='outside')
    yielded, closing, release, closed = (asyncio.Event() for _ in range(4))

    async def chunks():
        token = scope.set('inside')
        try:
            yielded.set()
            yield b'pending'
        finally:
            closing.set()
            await release.wait()
            assert scope.get() == 'inside'
            scope.reset(token)
            closed.set()

    generator = chunks()
    async with connected(peer_settings={4: 0 if phase == 'credit' else 65535}) as (
        conn,
        wire,
    ):
        if phase == 'write':
            wire.block = lambda frame: frame.kind == 0
        stream = await upload(conn, UploadSource(generator))
        await yielded.wait()
        if phase == 'write':
            await wire.blocked.wait()
        wire.feed(headers(stream), h2_frame(0, 1, stream, b'early'))
        await closing.wait()
        try:
            assert await conn.receive_headers(stream) == [(':status', '200')]
            assert await conn.read_stream(stream, 8) == b'early'
            complete = asyncio.create_task(conn.read_stream(stream, 8))
            await asyncio.sleep(0)
            assert not complete.done() and not closed.is_set()
            assert stream in conn._producers
        finally:
            release.set()
            wire.resume.set()
        assert await complete == b''
        assert closed.is_set() and scope.get() == 'outside'
        await generator.aclose()
        assert not conn._streams and not conn._outbound and not conn._producers
        assert not conn._stopping_producers and not conn.failed


@pytest.mark.parametrize('phase', ['source', 'credit', 'write'])
@async_test
async def test_repeated_stream_cancellation_joins_awaiting_generator_finalizer(phase):
    scope = contextvars.ContextVar('repeated_cancel_scope', default='outside')
    entered, closing, release, closed = (asyncio.Event() for _ in range(4))

    async def chunks():
        token = scope.set('inside')
        try:
            entered.set()
            if phase == 'source':
                await asyncio.Event().wait()
            yield b'pending'
        finally:
            closing.set()
            await release.wait()
            assert scope.get() == 'inside'
            scope.reset(token)
            closed.set()

    generator = chunks()
    async with connected(peer_settings={4: 0 if phase == 'credit' else 65535}) as (
        conn,
        wire,
    ):
        if phase == 'write':
            wire.block = lambda frame: frame.kind == 0
        stream = await upload(conn, UploadSource(generator))
        await entered.wait()
        if phase == 'write':
            await wire.blocked.wait()
        cleanup = asyncio.create_task(conn.cancel_stream(stream))
        await closing.wait()
        try:
            # An independent close and repeated caller cancellation must neither
            # re-cancel the producer nor interrupt the generator's pending await.
            repeated = asyncio.create_task(conn.cancel_stream(stream))
            await asyncio.sleep(0)
            cleanup.cancel()
            await asyncio.sleep(0)
            cleanup.cancel()
            repeated.cancel()
            await asyncio.sleep(0)
            assert not cleanup.done() and not repeated.done()
            assert not closed.is_set() and stream in conn._producers
        finally:
            release.set()
            wire.resume.set()
        for waiter in (cleanup, repeated):
            with pytest.raises(asyncio.CancelledError):
                await waiter
        assert closed.is_set() and scope.get() == 'outside'
        await generator.aclose()
        assert not conn._streams and not conn._outbound and not conn._producers
        assert not conn._stopping_producers and not conn.failed
        other = await request(conn)
        wire.feed(headers(other, end=True))
        assert await conn.read_stream(other, 1) == b''


@pytest.mark.parametrize('phase', ['source', 'credit'])
@async_test
async def test_finalizer_failure_preserves_original_upload_timeout(phase):
    closed = asyncio.Event()

    async def chunks():
        try:
            if phase == 'source':
                await asyncio.Event().wait()
            yield b'pending'
        finally:
            closed.set()
            raise RuntimeError('finalizer failure')

    async with connected(peer_settings={4: 0}) as (conn, _wire):
        stream = await upload(conn, UploadSource(chunks()), timeout=0.02)
        with pytest.raises(Timeout) as caught:
            await conn.receive_headers(stream)
        assert caught.value.phase == (
            'upload source' if phase == 'source' else 'HTTP/2 upload write'
        )
        assert closed.is_set()
        assert not conn._streams and not conn._outbound and not conn._producers
        assert not conn._stopping_producers and not conn.failed


@async_test
async def test_final_headers_alone_allow_request_body_progress():
    release = asyncio.Event()

    async def chunks():
        await release.wait()
        yield b'body'

    async with connected() as (conn, wire):
        stream = await upload(conn, UploadSource(chunks()))
        wire.feed(headers(stream))
        assert await conn.receive_headers(stream) == [(':status', '200')]
        release.set()
        await wire.until(lambda: any(f.flags & 1 for f in wire.frames(0, stream)))
        assert b''.join(f.payload for f in wire.frames(0, stream)) == b'body'


@async_test
async def test_cancel_waits_for_borrowed_worker_and_tolerates_repeated_cancel():
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()

    class BlockedFile(io.BytesIO):
        def read(self, size):
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(3)
            return super().read(size)

    handle = BlockedFile(b'body')
    async with connected() as (conn, wire):
        stream = await upload(conn, UploadSource(handle))
        await entered.wait()
        cleanup = asyncio.create_task(conn.cancel_stream(stream))
        try:
            await wire.flush()
            assert not cleanup.done()
            cleanup.cancel()
            await wire.flush()
            cleanup.cancel()
            await wire.flush()
            assert not cleanup.done() and not handle.closed
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await cleanup
        assert not conn._producers and stream not in conn._streams
        assert handle.tell() == 4 and not handle.closed


@async_test
async def test_early_response_then_peer_reset_cannot_detach_pending_source_worker():
    entered, release = asyncio.Event(), threading.Event()
    loop = asyncio.get_running_loop()

    class BlockedFile(io.BytesIO):
        def read(self, size):
            loop.call_soon_threadsafe(entered.set)
            assert release.wait(3)
            return super().read(size)

    source = UploadSource(BlockedFile(b'body'))
    async with connected() as (conn, wire):
        stream = await upload(conn, source, timeout=1)
        await entered.wait()
        try:
            wire.feed(headers(stream, end=True))
            await wire.flush()
            wire.feed(h2_frame(3, 0, stream, struct.pack('!I', 0)))
            await wire.flush()
            reading = asyncio.create_task(conn.read_stream(stream, 8))
            await wire.flush()
            assert not reading.done()
            assert stream in conn._producers
            assert source._operation_done is not None
        finally:
            release.set()
        assert await reading == b''
        assert source._operation_done is None and not conn._producers


@pytest.mark.parametrize('credit', [0, 65535])
@async_test
async def test_source_and_credit_timeout_only_fail_own_stream(credit):
    async def chunks():
        if credit:
            await asyncio.Event().wait()
        yield b'pending'

    async with connected(peer_settings={4: credit}) as (conn, wire):
        stream = await upload(conn, UploadSource(chunks()), timeout=0.03)
        with pytest.raises(Timeout):
            await conn.receive_headers(stream)
        second = await request(conn)
        wire.feed(headers(second, end=True))
        assert await conn.read_stream(second, 8) == b''
        assert not conn.failed and not conn._producers


@async_test
async def test_attempt_completion_keeps_source_replayable():
    handle = io.BytesIO(b'prefixpayload')
    handle.seek(6)
    source = UploadSource(handle)
    async with connected() as (conn, wire):
        for attempt in range(2):
            if attempt:
                await source.arewind()
            stream = await upload(conn, source)
            await wire.until(lambda: any(f.flags & 1 for f in wire.frames(0, stream)))
            wire.feed(headers(stream, end=True))
            assert await conn.read_stream(stream, 8) == b''
            assert b''.join(f.payload for f in wire.frames(0, stream)) == b'payload'
            assert not source._closed and not handle.closed
    await source.aclose_owned()
    assert not handle.closed


@async_test
async def test_goaway_rejection_joins_blocked_producer():
    entered, stopped = asyncio.Event(), asyncio.Event()

    async def chunks():
        entered.set()
        try:
            await asyncio.Event().wait()
            yield b'unreachable'
        finally:
            stopped.set()

    async with connected() as (conn, wire):
        stream = await upload(conn, UploadSource(chunks()))
        await entered.wait()
        wire.feed(h2_frame(7, 0, 0, struct.pack('!II', 0, 0)))
        await stopped.wait()
        with pytest.raises(ConnectionError, match='GOAWAY'):
            await conn.receive_headers(stream)
        assert not conn._producers and not conn.failed


@async_test
async def test_concurrent_generated_upload_memory_does_not_grow_with_total_size():
    class CountingWire(Wire):
        def __init__(self):
            super().__init__()
            self.totals = {}

        async def send(self, data):
            if data != PREFACE and data[3] == 0:
                length = int.from_bytes(data[:3], 'big')
                stream = int.from_bytes(data[5:9], 'big')
                assert length <= 16384
                self.totals[stream] = self.totals.get(stream, 0) + length
                if length:
                    credit = struct.pack('!I', length)
                    self.feed(h2_frame(8, 0, 0, credit), h2_frame(8, 0, stream, credit))
                if data[4] & 1:
                    self.feed(headers(stream, end=True))
                return
            await super().send(data)

    peaks = []
    for count in (16, 128):
        wire = CountingWire()

        async def chunks():
            for _ in range(count):
                yield b'x' * 65536

        async with connected(wire=wire) as (conn, _):
            tracemalloc.start()
            try:
                streams = [await upload(conn, UploadSource(chunks())) for _ in range(2)]
                assert await asyncio.gather(
                    *(conn.read_stream(s, 1) for s in streams)
                ) == [b'', b'']
                peaks.append(tracemalloc.get_traced_memory()[1])
            finally:
                tracemalloc.stop()
            assert list(wire.totals.values()) == [count * 65536] * 2
            assert not conn._outbound and not conn._producers
    assert peaks[1] < peaks[0] + 512 * 1024
