"""Independent multipart framing, bounded I/O, replay and ownership contracts."""

import asyncio
import builtins
import gzip
import io
import os
import threading
import tracemalloc
from email import policy
from email.parser import BytesParser

import pytest

from ja3requests import _multipart
from ja3requests._multipart import MultipartSource
from ja3requests.exceptions import InvalidData, StreamConsumedError


async def collect(body, limit=65536):
    pieces = []
    while True:
        piece = await body.aread_piece(limit)
        if not piece:
            return b''.join(pieces)
        assert len(piece) <= limit
        pieces.append(piece)


def parse(body, payload):
    message = BytesParser(policy=policy.default).parsebytes(
        b'Content-Type: ' + body.content_type.encode('ascii') + b'\r\n\r\n' + payload
    )
    assert message.is_multipart() and not message.defects
    parts = list(message.iter_parts())
    assert all(not part.defects for part in parts)
    return parts


async def wait_event(event):
    while not event.is_set():
        await asyncio.sleep(0)


class NonSeekable:
    def __init__(self, payload):
        self.file = io.BytesIO(payload)
        self.reads = 0
        self.closed = False

    def seekable(self):
        return False

    def read(self, size):
        self.reads += 1
        return self.file.read(size)

    def close(self):
        self.closed = True
        self.file.close()


class FileTracker:
    def __init__(self, block=None):
        self.calls = []
        self.handles = []
        self.maximum = 0
        self.block = block
        self.started = threading.Event()
        self.release = threading.Event()

    def record(self, operation):
        self.calls.append((operation, threading.get_ident()))
        if operation == self.block and not self.started.is_set():
            self.started.set()
            if not self.release.wait(2):
                raise AssertionError('Test did not release the file worker')

    def open(self, path, mode):
        self.record('open')
        handle = TrackedFile(builtins.open(path, mode), self)
        self.handles.append(handle)
        self.maximum = max(self.maximum, sum(not item.closed for item in self.handles))
        return handle


class TrackedFile:
    def __init__(self, file, tracker):
        self.file = file
        self.tracker = tracker

    @property
    def closed(self):
        return self.file.closed

    @property
    def name(self):
        return getattr(self.file, 'name', None)

    def read(self, size):
        self.tracker.record('read')
        assert 0 < size <= 65536
        return self.file.read(size)

    def seekable(self):
        self.tracker.record('seekable')
        return self.file.seekable()

    def tell(self):
        self.tracker.record('tell')
        return self.file.tell()

    def seek(self, offset, whence=0):
        self.tracker.record('seek')
        return self.file.seek(offset, whence)

    def fileno(self):
        self.tracker.record('fileno')
        return self.file.fileno()

    def close(self):
        self.tracker.record('close')
        return self.file.close()


def test_exact_crlf_length_repeated_fields_and_independent_mime_parse(tmp_path):
    path = tmp_path / 'first.txt'
    path.write_bytes(b'path\r\ncontent\x00')
    borrowed = io.BytesIO(b'prefix-binary\xff\x00')
    borrowed.seek(7)
    fields = [('tag', ['one', 'two']), ('empty', b''), ('number', 3)]
    files = {'upload': [path, borrowed]}
    body = MultipartSource(fields, files)
    fields.append(('later', 'ignored'))
    fields[0][1].append('ignored')
    files['upload'].clear()

    async def scenario():
        await body.aprepare()
        payload = await collect(body, 7)
        boundary = body.boundary.encode('ascii')
        expected = b''
        for name, value in [
            ('tag', b'one'),
            ('tag', b'two'),
            ('empty', b''),
            ('number', b'3'),
        ]:
            expected += (
                b'--'
                + boundary
                + b'\r\nContent-Disposition: form-data; name="'
                + name.encode('ascii')
                + b'"\r\n\r\n'
                + value
                + b'\r\n'
            )
        expected += (
            b'--'
            + boundary
            + b'\r\nContent-Disposition: form-data; name="upload"; filename="first.txt"'
            + b'\r\nContent-Type: text/plain\r\n\r\npath\r\ncontent\x00\r\n'
            + b'--'
            + boundary
            + b'\r\nContent-Disposition: form-data; name="upload"; filename="upload"'
            + b'\r\nContent-Type: application/octet-stream\r\n\r\nbinary\xff\x00\r\n'
            + b'--'
            + boundary
            + b'--\r\n'
        )
        assert payload == expected and body.length == len(payload)
        parts = parse(body, payload)
        assert [p.get_param('name', header='content-disposition') for p in parts] == [
            'tag',
            'tag',
            'empty',
            'number',
            'upload',
            'upload',
        ]
        assert [p.get_payload(decode=True) for p in parts] == [
            b'one',
            b'two',
            b'',
            b'3',
            b'path\r\ncontent\x00',
            b'binary\xff\x00',
        ]
        assert [p.get_filename() for p in parts[-2:]] == ['first.txt', 'upload']
        await body.arewind()
        assert borrowed.tell() == 7
        assert await collect(body, 31) == payload
        await body.aclose_owned()
        assert not borrowed.closed

    asyncio.run(asyncio.wait_for(scenario(), 3))


def test_unicode_and_quoted_names_are_escaped_without_filename_star():
    borrowed = io.BytesIO(b'data')
    borrowed.name = 'folder/文"\\件.bin'
    body = MultipartSource({'字"\\段': '值'}, {'文件': borrowed})

    async def scenario():
        payload = await collect(body)
        assert b'filename*' not in payload
        assert 'name="字\\"\\\\段"'.encode('utf-8') in payload
        assert 'filename="文\\"\\\\件.bin"'.encode('utf-8') in payload
        parts = parse(body, payload)
        assert parts[0].get_param('name', header='content-disposition') == '字"\\段'
        assert parts[0].get_payload(decode=True) == '值'.encode('utf-8')
        assert parts[1].get_filename() == '文"\\件.bin'
        await body.aclose_owned()
        assert not borrowed.closed

    asyncio.run(asyncio.wait_for(scenario(), 3))


@pytest.mark.parametrize('path_kind', ['str', 'bytes', 'pathlike'])
def test_path_types_basename_and_no_constructor_file_io(
    tmp_path, monkeypatch, path_kind
):
    path = tmp_path / 'payload.bin'
    path.write_bytes(b'abc')
    value = {'str': str(path), 'bytes': os.fsencode(path), 'pathlike': path}[path_kind]
    tracker = FileTracker()
    original_stat = os.stat

    def observed_stat(target, *args, **kwargs):
        tracker.record('stat')
        return original_stat(target, *args, **kwargs)

    monkeypatch.setattr(_multipart, 'open', tracker.open, raising=False)
    monkeypatch.setattr(_multipart.os, 'stat', observed_stat)
    body = MultipartSource(None, {'file': value})
    assert not tracker.calls

    async def scenario():
        loop_thread = threading.get_ident()
        await body.aprepare()
        assert [operation for operation, _ in tracker.calls] == ['stat']
        first = await body.aread_piece()
        assert first.endswith(b'\r\n\r\n') and not tracker.handles
        payload = first + await collect(body)
        assert parse(body, payload)[0].get_filename() == 'payload.bin'
        assert body.length == len(payload) and tracker.maximum == 1
        assert all(handle.closed for handle in tracker.handles)
        await body.arewind()
        assert await collect(body) == payload
        await body.aclose_owned()
        assert all(ident != loop_thread for _, ident in tracker.calls)
        assert len(tracker.handles) == 2 and all(h.closed for h in tracker.handles)

    asyncio.run(asyncio.wait_for(scenario(), 3))


@pytest.mark.parametrize(
    'bad_name', ['bad\rname', 'bad\nname', 'bad\x00name', b'\xff', '\ud800']
)
def test_invalid_field_names_and_filenames_fail_before_io(bad_name):
    borrowed = io.BytesIO(b'payload')
    with pytest.raises(InvalidData):
        MultipartSource({bad_name: 'value'}, {'file': borrowed})
    with pytest.raises(InvalidData):
        MultipartSource(None, {bad_name: borrowed})
    borrowed.name = bad_name
    with pytest.raises(InvalidData):
        MultipartSource(None, {'file': borrowed})
    assert borrowed.tell() == 0 and not borrowed.closed


@pytest.mark.parametrize(
    'raw', [b'raw', 'raw', iter((b'raw',)), [b'bad pair'], [('too', 'many', 'items')]]
)
def test_raw_or_invalid_data_cannot_be_combined_with_files(raw):
    with pytest.raises(InvalidData):
        MultipartSource(raw, {'file': io.BytesIO(b'x')})


@pytest.mark.parametrize(
    'files',
    [
        [('file', b'path')],
        {'file': ('name', io.BytesIO(b'x'))},
        {'file': io.StringIO('text')},
        {'file': object()},
    ],
)
def test_invalid_file_conventions_are_rejected(files):
    with pytest.raises(InvalidData):
        MultipartSource(None, files)


@pytest.mark.parametrize(
    'content_type',
    [
        'application/json',
        'multipart/form-data; boundary=foreign',
        'multipart/form-data\r\nBad: header',
    ],
)
def test_conflicting_content_type_is_rejected(content_type):
    with pytest.raises(InvalidData):
        MultipartSource(None, {}, content_type=content_type)


def test_bare_content_type_gets_generated_boundary_and_empty_body_has_exact_length():
    body = MultipartSource({}, {}, content_type=' MULTIPART/FORM-DATA ')
    body.prepare()
    expected = ('--' + body.boundary + '--\r\n').encode('ascii')
    assert body.content_type == 'multipart/form-data; boundary=' + body.boundary
    assert body.read_piece() == expected and body.read_piece() == b''
    assert body.length == len(expected)
    body.close_owned()


def test_unknown_length_borrowed_file_stays_open_and_consumed_body_cannot_replay():
    borrowed = NonSeekable(b'unknown')
    body = MultipartSource({'field': 'value'}, {'file': borrowed})

    async def scenario():
        await body.aprepare()
        assert body.length is None and borrowed.reads == 0
        assert (await body.aread_piece()).startswith(b'--')
        await body.arewind()  # The borrowed part has not been touched yet.
        payload = await collect(body)
        assert parse(body, payload)[1].get_payload(decode=True) == b'unknown'
        with pytest.raises(StreamConsumedError):
            await body.arewind()
        await body.aclose_owned()
        assert not borrowed.closed

    asyncio.run(asyncio.wait_for(scenario(), 3))


@pytest.mark.parametrize('declared', [False, True])
def test_gzip_borrowed_parts_keep_decoded_offsets_length_and_replay(
    tmp_path, monkeypatch, declared
):
    path = tmp_path / 'payload.gz'
    payload = b'prefix-' + b'decoded multipart\x00' * 1024
    path.write_bytes(gzip.compress(payload))
    offset = 7
    expected = payload[offset:]
    with io.BytesIO(expected) as probe_file:
        probe_file.name = path.name
        probe = MultipartSource({'tag': 'value'}, {'file': [probe_file, probe_file]})
        probe.prepare()
        total_length = probe.length
        probe.close_owned()

    async def scenario():
        with gzip.open(path, 'rb') as borrowed:
            borrowed.seek(offset)
            reads, seeks = [], []
            original_read, original_seek = borrowed.read, borrowed.seek

            def read(size=-1):
                reads.append(size)
                return original_read(size)

            def seek(position, whence=0):
                assert whence != os.SEEK_END, 'Preparation must not scan gzip to EOF'
                # GzipFile.tell() delegates to seek(0, SEEK_CUR).
                if (position, whence) != (0, os.SEEK_CUR):
                    seeks.append((position, whence))
                return original_seek(position, whence)

            monkeypatch.setattr(borrowed, 'read', read)
            monkeypatch.setattr(borrowed, 'seek', seek)
            body = MultipartSource(
                {'tag': 'value'},
                {'file': [borrowed, borrowed]},
                length=total_length if declared else None,
            )
            try:
                await body.aprepare()
                assert body.length == (total_length if declared else None)
                assert borrowed.tell() == offset and not reads and not seeks
                first = await collect(body, 97)
                assert len(first) == total_length
                assert [p.get_payload(decode=True) for p in parse(body, first)] == [
                    b'value',
                    expected,
                    expected,
                ]
                await body.arewind()
                assert borrowed.tell() == offset
                assert await collect(body) == first
                assert all(0 < size <= 65536 for size in reads)
                assert all(call == (offset, 0) for call in seeks)
            finally:
                await body.aclose_owned()
            assert not borrowed.closed

    asyncio.run(scenario())


def test_repeated_seekable_handle_replays_its_original_offset_each_part():
    borrowed = io.BytesIO(b'prefix-payload')
    borrowed.seek(7)
    body = MultipartSource(None, {'file': [borrowed, borrowed]})

    async def scenario():
        payload = await collect(body)
        assert [p.get_payload(decode=True) for p in parse(body, payload)] == [
            b'payload',
            b'payload',
        ]
        assert len(payload) == body.length
        await body.arewind()
        assert await collect(body) == payload
        await body.aclose_owned()
        assert not borrowed.closed

    asyncio.run(asyncio.wait_for(scenario(), 3))


def test_repeated_nonseekable_handle_fails_before_reading():
    borrowed = NonSeekable(b'payload')
    body = MultipartSource(None, {'file': [borrowed, borrowed]})
    with pytest.raises(InvalidData, match='seekable'):
        body.prepare()
    assert borrowed.reads == 0 and not borrowed.closed
    body.close_owned()


def test_explicit_known_length_mismatch_fails_before_open(tmp_path, monkeypatch):
    path = tmp_path / 'file.bin'
    path.write_bytes(b'abc')
    tracker = FileTracker()
    monkeypatch.setattr(_multipart, 'open', tracker.open, raising=False)
    body = MultipartSource(None, {'file': path}, length=1)

    async def scenario():
        with pytest.raises(InvalidData, match='length'):
            await body.aprepare()
        assert not tracker.handles
        await body.aclose_owned()

    asyncio.run(asyncio.wait_for(scenario(), 3))


@pytest.mark.parametrize('delta', [-1, 1])
def test_explicit_unknown_total_length_detects_excess_and_short_source(delta):
    borrowed = NonSeekable(b'payload')
    probe = MultipartSource(None, {'file': io.BytesIO(b'payload')})
    probe.prepare()
    body = MultipartSource(None, {'file': borrowed}, length=probe.length + delta)
    probe.close_owned()

    async def scenario():
        with pytest.raises(InvalidData, match='length'):
            await collect(body, 17)
        await body.aclose_owned()
        assert not borrowed.closed

    asyncio.run(asyncio.wait_for(scenario(), 3))


@pytest.mark.parametrize('replacement', [b'ab', b'abcdef'])
def test_resized_path_is_rejected_before_replay(tmp_path, replacement):
    path = tmp_path / 'file.bin'
    path.write_bytes(b'abcd')
    body = MultipartSource(None, {'file': path})

    async def scenario():
        await collect(body)
        path.write_bytes(replacement)
        with pytest.raises(StreamConsumedError, match='reopen') as caught:
            await body.arewind()
        assert isinstance(caught.value.__cause__, InvalidData)
        await body.aclose_owned()

    asyncio.run(asyncio.wait_for(scenario(), 3))


def test_later_file_open_failure_closes_owned_paths_and_preserves_borrowed(
    tmp_path, monkeypatch
):
    first, later = tmp_path / 'first.bin', tmp_path / 'later.bin'
    first.write_bytes(b'first')
    later.write_bytes(b'later')
    borrowed = io.BytesIO(b'borrowed')
    tracker = FileTracker()
    monkeypatch.setattr(_multipart, 'open', tracker.open, raising=False)
    body = MultipartSource(None, {'file': [first, borrowed, later]})

    async def scenario():
        await body.aprepare()
        later.unlink()
        with pytest.raises(InvalidData) as caught:
            await collect(body)
        assert isinstance(caught.value.__cause__, FileNotFoundError)
        assert tracker.maximum == 1 and len(tracker.handles) == 1
        assert all(handle.closed for handle in tracker.handles) and not borrowed.closed
        await body.aclose_owned()

    asyncio.run(asyncio.wait_for(scenario(), 3))


def test_file_growth_after_prepare_closes_handle_on_length_error(tmp_path, monkeypatch):
    path = tmp_path / 'file.bin'
    path.write_bytes(b'abc')
    tracker = FileTracker()
    monkeypatch.setattr(_multipart, 'open', tracker.open, raising=False)
    body = MultipartSource(None, {'file': path})

    async def scenario():
        await body.aprepare()
        path.write_bytes(b'abcdef')
        with pytest.raises(InvalidData, match='length'):
            await collect(body)
        assert len(tracker.handles) == 1 and tracker.handles[0].closed
        await body.aclose_owned()

    asyncio.run(asyncio.wait_for(scenario(), 3))


def test_large_files_stream_with_bounded_allocation_and_one_active_path(
    tmp_path, monkeypatch
):
    paths = [tmp_path / 'small.bin', tmp_path / 'large.bin']
    sizes = [2 * 1024 * 1024, 16 * 1024 * 1024]
    block = b'x' * 65536
    for path, size in zip(paths, sizes):
        with path.open('wb') as handle:
            for _ in range(size // len(block)):
                handle.write(block)
    tracker = FileTracker()
    monkeypatch.setattr(_multipart, 'open', tracker.open, raising=False)

    async def peak_for(files):
        body = MultipartSource(None, files)
        await body.aprepare()
        count = 0
        tracemalloc.start()
        try:
            while True:
                piece = await body.aread_piece()
                if not piece:
                    break
                count += len(piece)
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
            await body.aclose_owned()
        assert count == body.length
        return peak

    async def scenario():
        small_peak = await peak_for({'file': paths[0]})
        large_peak = await peak_for({'file': paths})
        assert large_peak < small_peak + 512 * 1024
        assert large_peak < 1024 * 1024
        assert tracker.maximum == 1 and all(handle.closed for handle in tracker.handles)

    asyncio.run(asyncio.wait_for(scenario(), 8))


@pytest.mark.parametrize('operation', ['open', 'read', 'close'])
def test_cancel_drains_owned_file_operation_closes_off_loop_and_can_replay(
    tmp_path, monkeypatch, operation
):
    path = tmp_path / 'file.bin'
    path.write_bytes(b'payload')
    tracker = FileTracker(block=operation)
    monkeypatch.setattr(_multipart, 'open', tracker.open, raising=False)
    body = MultipartSource(None, {'file': path})

    async def scenario():
        loop_thread = threading.get_ident()
        reading = asyncio.create_task(collect(body))
        try:
            await wait_event(tracker.started)
            reading.cancel()
            await asyncio.sleep(0)
            reading.cancel()
            await asyncio.sleep(0)
            assert not reading.done()
            tracker.release.set()
            with pytest.raises(asyncio.CancelledError):
                await reading
            assert tracker.handles and all(handle.closed for handle in tracker.handles)
            with pytest.raises(StreamConsumedError):
                await body.aread_piece()
            await body.arewind()
            assert (
                parse(body, await collect(body))[0].get_payload(decode=True)
                == b'payload'
            )
            await body.aclose_owned()
            assert all(ident != loop_thread for _, ident in tracker.calls)
            assert all(handle.closed for handle in tracker.handles)
        finally:
            tracker.release.set()
            if not reading.done():
                reading.cancel()
            await asyncio.gather(reading, return_exceptions=True)
            await body.aclose_owned()

    asyncio.run(asyncio.wait_for(scenario(), 4))


def test_cancel_borrowed_read_drains_worker_preserves_handle_and_rewinds():
    tracker = FileTracker(block='read')
    borrowed = TrackedFile(io.BytesIO(b'prefix-payload'), tracker)
    borrowed.file.seek(7)
    body = MultipartSource(None, {'file': borrowed})

    async def scenario():
        loop_thread = threading.get_ident()
        reading = asyncio.create_task(collect(body))
        try:
            await wait_event(tracker.started)
            reading.cancel()
            await asyncio.sleep(0)
            assert not reading.done()
            tracker.release.set()
            with pytest.raises(asyncio.CancelledError):
                await reading
            assert not borrowed.closed
            await body.arewind()
            assert borrowed.file.tell() == 7
            assert (
                parse(body, await collect(body))[0].get_payload(decode=True)
                == b'payload'
            )
            await body.aclose_owned()
            assert all(ident != loop_thread for _, ident in tracker.calls)
            assert not borrowed.closed and not any(
                op == 'close' for op, _ in tracker.calls
            )
        finally:
            tracker.release.set()
            if not reading.done():
                reading.cancel()
            await asyncio.gather(reading, return_exceptions=True)
            await body.aclose_owned()

    asyncio.run(asyncio.wait_for(scenario(), 4))


def test_cancelled_close_waits_for_read_and_releases_owned_file(tmp_path, monkeypatch):
    path = tmp_path / 'file.bin'
    path.write_bytes(b'payload')
    tracker = FileTracker(block='read')
    monkeypatch.setattr(_multipart, 'open', tracker.open, raising=False)
    body = MultipartSource(None, {'file': path})

    async def scenario():
        reading = asyncio.create_task(collect(body))
        closing = None
        try:
            await wait_event(tracker.started)
            closing = asyncio.create_task(body.aclose_owned())
            await asyncio.sleep(0)
            closing.cancel()
            await asyncio.sleep(0)
            closing.cancel()
            await asyncio.sleep(0)
            assert not closing.done() and not reading.done()
            tracker.release.set()
            with pytest.raises(RuntimeError, match='closed'):
                await reading
            with pytest.raises(asyncio.CancelledError):
                await closing
            assert not reading.cancelled()
            assert tracker.handles and all(handle.closed for handle in tracker.handles)
            await body.aclose_owned()
            with pytest.raises(RuntimeError, match='closed'):
                await body.aread_piece()
        finally:
            tracker.release.set()
            await asyncio.gather(
                *(task for task in (reading, closing) if task is not None),
                return_exceptions=True
            )
            await body.aclose_owned()

    asyncio.run(asyncio.wait_for(scenario(), 4))
