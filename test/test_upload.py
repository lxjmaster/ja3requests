"""Request-body source contracts, bounded allocation and cancellation ownership."""

import asyncio
import gzip
import hashlib
import io
import os
import threading
import tracemalloc

import pytest

from ja3requests._upload import UploadSource, is_upload
from ja3requests.exceptions import InvalidData, StreamConsumedError


async def wait_thread_event(event):
    while not event.is_set():
        await asyncio.sleep(0)


class ObservedFile(io.BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.calls = []

    def read(self, size=-1):
        self.calls.append(('read', threading.get_ident(), size))
        return super().read(size)

    def seek(self, offset, whence=0):
        self.calls.append(('seek', threading.get_ident(), offset))
        return super().seek(offset, whence)

    def tell(self):
        self.calls.append(('tell', threading.get_ident(), None))
        return super().tell()

    def seekable(self):
        self.calls.append(('seekable', threading.get_ident(), None))
        return super().seekable()

    def fileno(self):
        self.calls.append(('fileno', threading.get_ident(), None))
        return super().fileno()


class BlockingFile(io.BytesIO):
    def __init__(self, fail=False):
        super().__init__(b'payload')
        self.started = threading.Event()
        self.release = threading.Event()
        self.reads = 0
        self.fail = fail

    def read(self, size=-1):
        self.reads += 1
        self.started.set()
        if not self.release.wait(2):
            raise AssertionError('Test did not release the file worker')
        if self.fail:
            raise OSError('worker failed after cancellation')
        return super().read(size)


def test_source_recognition_preserves_buffered_forms_and_does_no_io():
    source = ObservedFile(b'ab')
    for value in ('text', b'bytes', bytearray(b'x'), {}, [], (), io.StringIO('text')):
        assert not is_upload(value)
    assert not is_upload([b'a', b'b'])
    assert is_upload(iter([b'a', b'b']))
    assert is_upload(source)
    body = UploadSource(source)
    assert source.calls == []
    assert body.length is None and not body.consumed
    body.close_owned()
    assert not source.closed


@pytest.mark.parametrize('length', [-1, True, 1.5, '2'])
def test_invalid_declared_length_is_rejected_without_source_io(length):
    source = ObservedFile(b'ab')
    with pytest.raises(InvalidData):
        UploadSource(source, length=length)
    assert source.calls == []


@pytest.mark.parametrize('source', [io.StringIO('text'), object(), [b'a'], b''])
def test_constructor_rejects_unsupported_inputs_but_accepts_internal_bytes(source):
    if isinstance(source, bytes):
        body = UploadSource(source)
        assert body.read_piece() == b''
        assert body.length == 0
    else:
        with pytest.raises(InvalidData):
            UploadSource(source)


def test_file_prepare_is_idempotent_and_replay_restores_initial_offset():
    source = ObservedFile(b'prefix-body')
    source.seek(7)
    source.calls.clear()
    body = UploadSource(source, length=4)
    body.prepare()
    assert body.length == 4 and source.tell() == 7
    calls = len(source.calls)
    body.prepare()
    assert len(source.calls) == calls
    assert not any(call[0] == 'read' for call in source.calls)
    assert body.read_piece(2) == b'bo'
    assert body.consumed
    body.rewind()
    assert not body.consumed and source.tell() == 7
    assert body.read_piece(3) == b'bod'
    assert body.read_piece(3) == b'y'
    assert body.read_piece(3) == b''
    reads = len(source.calls)
    assert body.read_piece() == b''
    assert len(source.calls) == reads
    body.close_owned()
    assert not source.closed


@pytest.mark.parametrize('kind', ['raw', 'buffered', 'random', 'memory'])
@pytest.mark.parametrize('declared', [False, True])
def test_plain_file_length_uses_current_offset_and_preserves_borrowed_handle(
    tmp_path, kind, declared
):
    path = tmp_path / 'upload.bin'
    path.write_bytes(b'012345')
    source = (
        io.BytesIO(b'012345')
        if kind == 'memory'
        else path.open(
            'r+b' if kind == 'random' else 'rb', buffering=0 if kind == 'raw' else -1
        )
    )
    with source:
        source.seek(2)
        body = UploadSource(source, length=4 if declared else None)
        body.prepare()
        assert body.length == 4 and source.tell() == 2
        assert body.read_piece() == b'2345'
        body.rewind()
        assert body.read_piece() == b'2345'
        body.close_owned()
        assert not source.closed


@pytest.mark.parametrize('asynchronous', [False, True])
@pytest.mark.parametrize('declared', [False, True])
@pytest.mark.parametrize('buffered', [False, True])
def test_gzip_stream_keeps_decoded_offset_and_replays_without_prescanning(
    tmp_path, monkeypatch, asynchronous, declared, buffered
):
    payload = b'prefix-' + b'decoded payload\x00' * 8192
    path = tmp_path / 'upload.gz'
    path.write_bytes(gzip.compress(payload))
    offset = 7
    expected = payload[offset:]
    assert path.stat().st_size < len(expected)

    async def scenario():
        compressed = gzip.open(path, 'rb')
        source = io.BufferedReader(compressed) if buffered else compressed
        with source:
            source.seek(offset)
            reads, seeks = [], []
            original_read, original_seek = source.read, source.seek

            def read(size=-1):
                reads.append(size)
                return original_read(size)

            def seek(position, whence=0):
                assert whence != os.SEEK_END, 'Preparation must not scan gzip to EOF'
                # GzipFile.tell() delegates to seek(0, SEEK_CUR).
                if (position, whence) != (0, os.SEEK_CUR):
                    seeks.append((position, whence))
                return original_seek(position, whence)

            monkeypatch.setattr(source, 'read', read)
            monkeypatch.setattr(source, 'seek', seek)
            body = UploadSource(source, length=len(expected) if declared else None)

            async def invoke(operation, *args):
                if asynchronous:
                    return await getattr(body, 'a' + operation)(*args)
                return getattr(body, operation)(*args)

            try:
                await invoke('prepare')
                assert body.length == (len(expected) if declared else None)
                assert source.tell() == offset and not reads and not seeks
                assert await invoke('read_piece', 97) == expected[:97]
                assert source.tell() == offset + 97
                await invoke('rewind')
                assert source.tell() == offset and seeks == [(offset, 0)]
                pieces = []
                while True:
                    piece = await invoke('read_piece', 4096)
                    if not piece:
                        break
                    pieces.append(piece)
                assert b''.join(pieces) == expected
                assert all(0 < size <= 4096 for size in reads)
            finally:
                await invoke('close_owned')
            assert not source.closed

    asyncio.run(scenario())


@pytest.mark.parametrize('delta', [-1, 1])
def test_gzip_explicit_length_is_validated_against_decoded_bytes(tmp_path, delta):
    payload = b'decoded' * 100
    path = tmp_path / 'upload.gz'
    path.write_bytes(gzip.compress(payload))
    with gzip.open(path, 'rb') as source:
        body = UploadSource(source, length=len(payload) + delta)
        body.prepare()
        assert source.tell() == 0 and not body.consumed
        with pytest.raises(InvalidData, match='length'):
            while body.read_piece():
                pass
        body.close_owned()
        assert not source.closed


def test_file_past_eof_is_a_zero_length_source():
    source = io.BytesIO(b'abc')
    source.seek(8)
    body = UploadSource(source)
    body.prepare()
    assert body.length == 0 and source.tell() == 8
    assert body.read_piece() == b''


@pytest.mark.parametrize('declared', [0, 2, 4])
def test_known_length_mismatch_fails_before_reading_and_preserves_offset(
    monkeypatch, declared
):
    source = io.BytesIO(b'abc')

    def reject_read(*_args):
        pytest.fail('A length mismatch must fail before reading the source')

    monkeypatch.setattr(source, 'read', reject_read)
    body = UploadSource(source, length=declared)
    with pytest.raises(InvalidData, match='length'):
        body.prepare()
    assert source.tell() == 0
    assert not body.consumed


def test_metadata_failure_keeps_position_and_the_original_cause():
    failure = OSError('position lookup failed')

    class FailedTell(io.BytesIO):
        def tell(self):
            raise failure

    source = FailedTell(b'abc')
    source.seek(1)
    body = UploadSource(source)
    with pytest.raises(InvalidData) as caught:
        body.prepare()
    assert caught.value.__cause__ is failure
    assert io.BytesIO.tell(source) == 1 and not body.consumed


def test_empty_iterator_chunks_are_skipped_and_eof_is_stable():
    body = UploadSource(iter((b'', b'abcd', b'', b'ef', b'')), length=6)
    body.rewind()
    assert not body.consumed
    assert [body.read_piece(2) for _ in range(5)] == [b'ab', b'cd', b'ef', b'', b'']
    with pytest.raises(StreamConsumedError):
        body.rewind()


@pytest.mark.parametrize(
    'bad_chunk', ['text', bytearray(b'bad'), memoryview(b'bad'), None]
)
def test_non_bytes_chunks_fail_without_an_implicit_conversion(bad_chunk):
    body = UploadSource(iter((bad_chunk, b'next')))
    with pytest.raises(InvalidData, match='chunks must be bytes') as caught:
        body.read_piece()
    assert body.consumed
    with pytest.raises(InvalidData) as repeated:
        body.read_piece()
    assert repeated.value is caught.value


@pytest.mark.parametrize('limit', [0, -1, True, 1.5])
def test_invalid_piece_limits_do_not_consume_the_source(limit):
    body = UploadSource(iter((b'ab',)))
    with pytest.raises(ValueError):
        body.read_piece(limit)
    assert not body.consumed
    assert body.read_piece() == b'ab'


def test_unknown_length_excess_is_never_returned_and_short_input_fails_at_eof():
    excess = UploadSource(iter((b'ab', b'cdef')), length=4)
    assert excess.read_piece(2) == b'ab'
    with pytest.raises(InvalidData, match='exceeds'):
        excess.read_piece(2)
    short = UploadSource(iter((b'ab',)), length=3)
    assert short.read_piece() == b'ab'
    with pytest.raises(InvalidData, match='ended before'):
        short.read_piece()


def test_file_cannot_violate_requested_read_bound():
    class BadReader:
        def read(self, _size):
            return b'too much'

    body = UploadSource(BadReader())
    with pytest.raises(InvalidData, match='requested size'):
        body.read_piece(1)


def test_non_seekable_file_and_source_io_errors_keep_replay_boundaries():
    failure = OSError('device read failed')

    class Device:
        def seekable(self):
            return False

        def read(self, _size):
            raise failure

    body = UploadSource(Device())
    body.prepare()
    assert body.length is None
    body.rewind()
    with pytest.raises(InvalidData) as caught:
        body.read_piece()
    assert caught.value.__cause__ is failure
    with pytest.raises(StreamConsumedError):
        body.rewind()


def test_resized_file_is_rejected_before_replay():
    source = io.BytesIO(b'ab')
    body = UploadSource(source)
    assert body.read_piece() == b'ab'
    source.write(b'c')
    with pytest.raises(StreamConsumedError) as caught:
        body.rewind()
    assert isinstance(caught.value.__cause__, InvalidData)
    assert body.consumed


def test_large_iterator_chunk_is_retained_once_and_only_pieces_are_copied():
    chunk = b'abcd' * (2 * 1024 * 1024)
    expected = hashlib.sha256(chunk).digest()
    body = UploadSource(iter((chunk,)))
    digest = hashlib.sha256()
    count = 0
    tracemalloc.start()
    try:
        piece = body.read_piece()
        assert body._pending.obj is chunk
        while piece:
            count += len(piece)
            digest.update(piece)
            assert len(piece) <= 65536
            piece = body.read_piece()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert count == len(chunk) and digest.digest() == expected
    assert peak < 6 * 65536


def test_borrowed_generator_is_not_closed_by_the_adapter():
    closed = []

    def chunks():
        try:
            yield b'ab'
            yield b'cd'
        finally:
            closed.append(True)

    iterator = chunks()
    body = UploadSource(iterator)
    assert body.read_piece(1) == b'a'
    body.close_owned()
    body.close_owned()
    assert closed == []
    assert next(iterator) == b'cd'
    iterator.close()
    assert closed == [True]


def test_async_file_prepare_read_and_rewind_are_all_off_loop():
    async def scenario():
        loop_thread = threading.get_ident()
        source = ObservedFile(b'prefix-body')
        source.seek(7)
        source.calls.clear()
        body = UploadSource(source, length=4)
        await body.aprepare()
        assert body.length == 4 and not body.consumed
        assert await body.aread_piece(2) == b'bo'
        await body.arewind()
        assert not body.consumed
        assert await body.aread_piece() == b'body'
        assert await body.aread_piece() == b''
        assert source.calls
        assert all(call[1] != loop_thread for call in source.calls)
        await body.aclose_owned()
        assert not source.closed

    asyncio.run(asyncio.wait_for(scenario(), 3))


def test_async_iterator_is_accepted_only_by_async_path_and_stays_borrowed():
    async def scenario():
        closed = []

        async def chunks():
            try:
                yield b''
                yield b'abcd'
                yield b'next'
            finally:
                closed.append(True)

        iterator = chunks()
        assert not is_upload(iterator)
        assert is_upload(iterator, allow_async=True)
        body = UploadSource(iterator)
        await body.aprepare()
        await body.arewind()
        assert await body.aread_piece(2) == b'ab'
        assert await body.aread_piece(2) == b'cd'
        with pytest.raises(StreamConsumedError):
            await body.arewind()
        await body.aclose_owned()
        assert closed == []
        assert await iterator.__anext__() == b'next'
        await iterator.aclose()
        assert closed == [True]

        other = chunks()
        with pytest.raises(InvalidData, match='aread_piece'):
            UploadSource(other).read_piece()
        await other.aclose()

    asyncio.run(asyncio.wait_for(scenario(), 3))


@pytest.mark.parametrize('native_async', [False, True])
def test_infinite_empty_chunks_yield_to_loop_and_share_one_outer_timeout(native_async):
    async def scenario():
        started = threading.Event()
        calls = []

        class SyncEmpty:
            def __iter__(self):
                return self

            def __next__(self):
                calls.append(threading.get_ident())
                started.set()
                return b''

        class AsyncEmpty:
            def __aiter__(self):
                return self

            async def __anext__(self):
                calls.append(threading.get_ident())
                started.set()
                return b''

        body = UploadSource(AsyncEmpty() if native_async else SyncEmpty())
        reading = asyncio.create_task(body.aread_piece())
        await wait_thread_event(started)
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(reading, 0.02)
        assert calls
        loop_thread = threading.get_ident()
        assert all((ident == loop_thread) is native_async for ident in calls)
        count = len(calls)
        await body.aclose_owned()
        await asyncio.sleep(0)
        assert len(calls) == count

    asyncio.run(asyncio.wait_for(scenario(), 3))


@pytest.mark.parametrize('worker_fails', [False, True])
def test_repeated_cancel_drains_the_current_worker_and_does_not_close_file(
    worker_fails,
):
    async def scenario():
        source = BlockingFile(fail=worker_fails)
        body = UploadSource(source)
        reading = asyncio.create_task(body.aread_piece(3))
        try:
            await wait_thread_event(source.started)
            reading.cancel()
            await asyncio.sleep(0)
            reading.cancel()
            await asyncio.sleep(0)
            assert not reading.done()
            source.release.set()
            with pytest.raises(asyncio.CancelledError):
                await reading
            assert source.reads == 1 and body.consumed
            assert not source.closed
            with pytest.raises(StreamConsumedError):
                await body.aread_piece()
            if not worker_fails:
                await body.arewind()
                assert await body.aread_piece(3) == b'pay'
            await body.aclose_owned()
            assert not source.closed
        finally:
            source.release.set()
            if not reading.done():
                reading.cancel()
                await asyncio.gather(reading, return_exceptions=True)

    asyncio.run(asyncio.wait_for(scenario(), 3))


def test_one_pull_at_a_time_and_close_waits_without_cancelling_the_caller():
    async def scenario():
        source = BlockingFile()
        body = UploadSource(source)
        reading = asyncio.create_task(body.aread_piece())
        closing = None
        try:
            await wait_thread_event(source.started)
            with pytest.raises(RuntimeError, match='in progress'):
                await body.aread_piece()
            with pytest.raises(RuntimeError, match='aclose_owned'):
                body.close_owned()
            closing = asyncio.create_task(body.aclose_owned())
            await asyncio.sleep(0)
            closing.cancel()
            await asyncio.sleep(0)
            assert not reading.done() and not closing.done()
            source.release.set()
            with pytest.raises(RuntimeError, match='closed'):
                await reading
            with pytest.raises(asyncio.CancelledError):
                await closing
            assert not reading.cancelled()
            assert source.reads == 1 and not source.closed
            await body.aclose_owned()
            with pytest.raises(RuntimeError, match='closed'):
                await body.aread_piece()
        finally:
            source.release.set()
            await asyncio.gather(
                *(task for task in (reading, closing) if task is not None),
                return_exceptions=True,
            )

    asyncio.run(asyncio.wait_for(scenario(), 3))


def test_sync_close_waits_for_a_worker_and_leaves_borrowed_file_open(monkeypatch):
    source = BlockingFile()
    body = UploadSource(source)
    errors = []
    closing_started = threading.Event()
    closed = threading.Event()
    original_closing_state = body._closing_state

    def observed_closing_state(asynchronous):
        result = original_closing_state(asynchronous)
        closing_started.set()
        return result

    monkeypatch.setattr(body, '_closing_state', observed_closing_state)

    def read():
        try:
            body.read_piece()
        except RuntimeError as error:
            errors.append(error)

    def close():
        body.close_owned()
        closed.set()

    reader = threading.Thread(target=read)
    closer = threading.Thread(target=close)
    reader.start()
    try:
        assert source.started.wait(1)
        closer.start()
        assert closing_started.wait(1)
        assert not closed.is_set()
        source.release.set()
    finally:
        source.release.set()
        reader.join(2)
        if closer.ident is not None:
            closer.join(2)
    assert not reader.is_alive() and not closer.is_alive()
    assert closed.is_set() and not source.closed
    assert len(errors) == 1


def test_async_source_error_is_chained_and_async_eof_does_not_leak_stopiteration():
    async def scenario():
        failure = OSError('producer failed')

        async def chunks():
            yield b'ab'
            raise failure

        body = UploadSource(chunks())
        assert await body.aread_piece() == b'ab'
        with pytest.raises(InvalidData) as caught:
            await body.aread_piece()
        assert caught.value.__cause__ is failure
        await body.aclose_owned()
        synchronous = UploadSource(iter(()))
        assert await synchronous.aread_piece() == b''
        assert await synchronous.aread_piece() == b''
        await synchronous.aclose_owned()

    asyncio.run(asyncio.wait_for(scenario(), 3))


@pytest.mark.parametrize(
    'error', [TimeoutError('deadline'), StreamConsumedError('stop')]
)
def test_sync_empty_chunks_observe_transport_stop_without_false_eof(error):
    pulls = []

    def chunks():
        while True:
            pulls.append(True)
            yield b''

    def check_continue():
        if len(pulls) == 3:
            raise error

    body = UploadSource(chunks())
    try:
        with pytest.raises(type(error)) as caught:
            body.read_piece(check_continue=check_continue)
        assert caught.value is error
        assert len(pulls) == 3 and body.consumed and not body._eof
        assert body._operation_done is None
    finally:
        body.close_owned()
