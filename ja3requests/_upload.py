"""Private, bounded request-body sources with explicit replay and ownership."""

from __future__ import annotations

import asyncio
import inspect
import io
import os
import stat
import threading
from collections.abc import AsyncIterator, Iterator
from typing import Optional

from ja3requests.exceptions import InvalidData, StreamConsumedError


_EOF = object()
_PIECE_SIZE = 65536


def is_upload(value: object, allow_async: bool = False) -> bool:
    """Recognize new stream inputs without consuming them or calling file I/O."""
    if isinstance(value, (str, bytes, bytearray, dict, list, tuple, io.TextIOBase)):
        return False
    return (
        callable(getattr(value, 'read', None))
        or isinstance(value, Iterator)
        or (allow_async and isinstance(value, AsyncIterator))
    )


async def _drain(future):
    """Observe an owned operation even if cleanup receives repeated cancellation."""
    while not future.done():
        try:
            await asyncio.shield(future)
        except asyncio.CancelledError:
            continue
        except BaseException:
            break
    if not future.cancelled():
        future.exception()


class UploadSource:
    """Borrow source state; producers finalize started native async generators.

    File reads and synchronous iterator pulls use the executor in async methods.
    Cancellation waits for a started worker before returning the borrowed source
    to its caller. A cancelled pull cannot be resumed without a successful rewind.
    Bytes are accepted for internal composition but are not classified as a new
    streaming input by :func:`is_upload`.
    """

    def __init__(self, source: object, length: Optional[int] = None) -> None:
        if length is not None and (
            isinstance(length, bool) or not isinstance(length, int) or length < 0
        ):
            raise InvalidData('Upload length must be a non-negative integer or None')
        if isinstance(source, io.TextIOBase):
            raise InvalidData('Upload files must be opened in binary mode')
        if isinstance(source, bytes):
            kind = 'bytes'
        elif callable(getattr(source, 'read', None)):
            kind = 'file'
        elif isinstance(source, Iterator):
            kind = 'iterator'
        elif isinstance(source, AsyncIterator):
            kind = 'async'
        else:
            raise InvalidData('Upload source must be a binary file or byte iterator')
        self._source = source
        self._kind = kind
        self.length = length
        self.consumed = False
        self._declared_length = length
        self._prepared = False
        self._initial_offset = None
        self._pending = None
        self._pending_offset = 0
        self._produced = 0
        self._bytes_pulled = False
        self._source_started = False
        self._eof = False
        self._failure = None
        self._closed = False
        self._state_lock = threading.Lock()
        self._operation_done = None
        self._async_done = None
        self._operation_thread = None
        self._loop = None
        self._worker = None

    def _bind(self):
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise RuntimeError('UploadSource belongs to another event loop')
        return loop

    def _begin(self, asynchronous=False):
        loop = self._bind() if asynchronous else None
        with self._state_lock:
            if self._closed:
                raise RuntimeError('UploadSource is closed')
            if self._operation_done is not None:
                raise RuntimeError('An upload source operation is already in progress')
            self._operation_done = threading.Event()
            self._async_done = loop.create_future() if loop is not None else None
            self._operation_thread = threading.get_ident()

    def _finish(self):
        with self._state_lock:
            done, async_done = self._operation_done, self._async_done
            self._operation_done = None
            self._async_done = None
            self._operation_thread = None
            done.set()
            if async_done is not None and not async_done.done():
                async_done.set_result(None)

    def _check_open(self):
        if self._closed:
            raise RuntimeError('UploadSource is closed')

    @staticmethod
    def _validate_limit(limit):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError('Upload piece limit must be a positive integer')

    def _discover_file(self):
        """Return the initial offset/remaining length, preserving file position."""
        source = self._source
        try:
            seekable = getattr(source, 'seekable', None)
            if callable(seekable):
                if not seekable():
                    return None, None
            elif not (
                callable(getattr(source, 'tell', None))
                and callable(getattr(source, 'seek', None))
            ):
                return None, None
            offset = source.tell()
            if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
                raise InvalidData('Upload file position must be a non-negative integer')
            source_type = type(source)
            if source_type is io.FileIO or (
                source_type in (io.BufferedReader, io.BufferedRandom)
                and type(source.raw) is io.FileIO
            ):
                info = os.fstat(source.fileno())
                if stat.S_ISREG(info.st_mode):
                    return offset, max(0, info.st_size - offset)
            if source_type is not io.BytesIO:
                # Wrappers may expose the encoded file's descriptor while read()
                # returns decoded bytes (for example gzip). Seeking such a stream
                # to EOF may consume the whole input. Its position still permits
                # replay; only its decoded length remains unknown.
                return offset, None
            try:
                source.seek(0, os.SEEK_END)
                end = source.tell()
                if isinstance(end, bool) or not isinstance(end, int) or end < 0:
                    raise InvalidData(
                        'Upload file length must be a non-negative integer'
                    )
            finally:
                source.seek(offset)
                if source.tell() != offset:
                    raise InvalidData('Could not restore the upload file position')
            return offset, max(0, end - offset)
        except asyncio.CancelledError:
            raise
        except InvalidData:
            raise
        except Exception as error:
            raise InvalidData('Could not prepare the upload file') from error

    def _commit_preparation(self, offset, discovered_length):
        if (
            self._declared_length is not None
            and discovered_length is not None
            and self._declared_length != discovered_length
        ):
            raise InvalidData(
                'Declared upload length does not match the remaining source'
            )
        self._initial_offset = offset
        self.length = (
            discovered_length
            if self._declared_length is None
            else self._declared_length
        )
        self._prepared = True

    def _prepare(self):
        if self._prepared:
            return
        if self._kind == 'file':
            offset, length = self._discover_file()
        else:
            offset = None
            length = len(self._source) if self._kind == 'bytes' else None
        self._check_open()
        self._commit_preparation(offset, length)

    async def _run_worker(self, operation, *args):
        worker = self._loop.run_in_executor(None, operation, *args)
        self._worker = worker
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            await _drain(worker)
            raise
        finally:
            self._worker = None

    async def _aprepare(self):
        if self._prepared:
            return
        if self._kind == 'file':
            offset, length = await self._run_worker(self._discover_file)
        else:
            offset = None
            length = len(self._source) if self._kind == 'bytes' else None
        self._check_open()
        self._commit_preparation(offset, length)

    def prepare(self) -> None:
        """Discover file length/offset once, without reading body content."""
        self._begin()
        try:
            self._prepare()
        finally:
            self._finish()

    async def aprepare(self) -> None:
        """Prepare while keeping all synchronous file operations off-loop."""
        self._begin(asynchronous=True)
        try:
            await self._aprepare()
        finally:
            self._finish()

    def _pull(self, limit):
        """One source operation only; never skip iterator chunks in a worker."""
        try:
            if self._kind == 'bytes':
                if self._bytes_pulled:
                    return _EOF
                self._bytes_pulled = True
                return self._source if self._source else _EOF
            if self._kind == 'file':
                value = self._source.read(limit)
                if isinstance(value, bytes) and not value:
                    return _EOF
                if isinstance(value, bytes) and len(value) > limit:
                    raise InvalidData(
                        'Upload file returned more than the requested size'
                    )
                return value
            try:
                return next(self._source)
            except StopIteration:
                return _EOF
        except asyncio.CancelledError:
            raise
        except InvalidData:
            raise
        except Exception as error:
            raise InvalidData('Could not read the upload source') from error

    async def _apull(self, limit):
        if self._kind != 'async':
            if self._kind == 'bytes':
                return self._pull(limit)
            return await self._run_worker(self._pull, limit)
        try:
            operation = self._source.__anext__()
            # Mark the native generator before awaiting its operation. If the
            # producer is cancelled at this boundary, aclose() is still safe;
            # a request that never reached this method leaves a fresh generator
            # untouched.
            self._source_started = True
            return await operation
        except StopAsyncIteration:
            return _EOF
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise InvalidData('Could not read the async upload source') from error

    def _take_pending(self, limit):
        end = min(self._pending_offset + limit, len(self._pending))
        result = bytes(self._pending[self._pending_offset : end])
        self._pending_offset = end
        if end == len(self._pending):
            self._pending = None
            self._pending_offset = 0
        return result

    def _accept(self, value, limit):
        self._check_open()
        if value is _EOF:
            if self.length is not None and self._produced != self.length:
                raise InvalidData('Upload source ended before its declared length')
            self._eof = True
            return b''
        if not isinstance(value, bytes):
            raise InvalidData('Upload source chunks must be bytes')
        if not value:
            return None
        if self.length is not None and self._produced + len(value) > self.length:
            raise InvalidData('Upload source exceeds its declared length')
        self._produced += len(value)
        self._pending = memoryview(value)
        return self._take_pending(limit)

    def _cached_piece(self, limit):
        if self._failure is not None:
            raise self._failure
        if self._pending is not None:
            return self._take_pending(limit)
        return b'' if self._eof else None

    def read_piece(self, limit: int = _PIECE_SIZE, *, check_continue=None) -> bytes:
        """Read a bounded piece; only confirmed EOF returns empty bytes."""
        self._validate_limit(limit)
        self._begin()
        try:
            if self._kind == 'async':
                raise InvalidData('An async upload source requires aread_piece()')
            self._prepare()
            if check_continue is not None:
                check_continue()
            cached = self._cached_piece(limit)
            if cached is not None:
                return cached
            while True:
                self._check_open()
                if check_continue is not None:
                    check_continue()
                self.consumed = True
                result = self._accept(self._pull(limit), limit)
                if result is not None:
                    return result
        except InvalidData as error:
            self._failure = error
            raise
        finally:
            self._finish()

    async def aread_piece(self, limit: int = _PIECE_SIZE) -> bytes:
        """Read without blocking the loop; drain a cancelled synchronous pull."""
        self._validate_limit(limit)
        self._begin(asynchronous=True)
        try:
            await self._aprepare()
            cached = self._cached_piece(limit)
            if cached is not None:
                return cached
            while True:
                self._check_open()
                self.consumed = True
                result = self._accept(await self._apull(limit), limit)
                if result is not None:
                    return result
                # Even an async iterator may complete immediately forever. Empty
                # chunks must remain cancellable under one caller-owned budget.
                await asyncio.sleep(0)
        except asyncio.CancelledError:
            self._failure = StreamConsumedError(
                'Upload source pull was cancelled; rewind before reuse'
            )
            raise
        except InvalidData as error:
            self._failure = error
            raise
        finally:
            self._finish()

    async def afinish_producer(self) -> None:
        """Finish a started native async generator in its producer's task/context.

        A generator stopped at yield can retain ContextVar tokens. Its producer
        must await this method directly, before that task exits; a cleanup task
        would copy the Context and could not reset those tokens. Files, custom
        iterators and generators never advanced by this adapter remain borrowed.
        """
        if self._source_started and inspect.isasyncgen(self._source):
            try:
                await self._source.aclose()
            except asyncio.CancelledError:
                raise
            except Exception as error:
                raise InvalidData(
                    'Could not finalize the async upload source'
                ) from error

    def _rewind_file(self):
        try:
            self._source.seek(self._initial_offset)
            if self._source.tell() != self._initial_offset:
                raise InvalidData('Could not restore the initial upload file position')
            offset, length = self._discover_file()
            if offset != self._initial_offset or (
                self.length is not None and length is not None and self.length != length
            ):
                raise InvalidData(
                    'Upload file position or length changed before replay'
                )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            raise StreamConsumedError('Could not rewind the upload file') from error

    def _needs_rewind(self):
        if not self.consumed:
            return False
        if self._kind == 'bytes':
            return False
        if self._kind != 'file' or self._initial_offset is None:
            raise StreamConsumedError('A consumed upload iterator cannot be replayed')
        return True

    def _reset(self):
        self._check_open()
        self.consumed = False
        self._produced = 0
        self._pending = None
        self._pending_offset = 0
        self._bytes_pulled = False
        self._eof = False
        self._failure = None

    def rewind(self) -> None:
        """Restore an original file position, or reject consumed one-shot input."""
        self._begin()
        try:
            self._prepare()
            if self._needs_rewind():
                self._rewind_file()
            self._reset()
        finally:
            self._finish()

    async def arewind(self) -> None:
        """Rewind without performing blocking seek/metadata operations on-loop."""
        self._begin(asynchronous=True)
        try:
            await self._aprepare()
            if self._needs_rewind():
                await self._run_worker(self._rewind_file)
            self._reset()
        except asyncio.CancelledError:
            self._failure = StreamConsumedError(
                'Upload rewind was cancelled; rewind again before reuse'
            )
            raise
        finally:
            self._finish()

    def _closing_state(self, asynchronous):
        with self._state_lock:
            done, async_done = self._operation_done, self._async_done
            if done is not None and not asynchronous:
                if self._operation_thread == threading.get_ident():
                    raise RuntimeError('Use aclose_owned() during an async operation')
            self._closed = True
            return done, async_done

    def _discard(self):
        self._pending = None
        self._pending_offset = 0

    def close_owned(self) -> None:
        """Wait for active use and drop buffers; the underlying source is borrowed."""
        done, _ = self._closing_state(asynchronous=False)
        if done is not None:
            done.wait()
        self._discard()

    async def aclose_owned(self) -> None:
        """Wait for active use without cancelling the application task or source."""
        loop = self._bind()
        done, async_done = self._closing_state(asynchronous=True)
        waiter = async_done
        if done is not None and waiter is None:
            waiter = loop.run_in_executor(None, done.wait)
        try:
            if waiter is not None:
                try:
                    await asyncio.shield(waiter)
                except asyncio.CancelledError:
                    await _drain(waiter)
                    raise
        finally:
            self._discard()
