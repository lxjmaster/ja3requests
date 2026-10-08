"""Private streaming multipart source for the asynchronous files convenience API."""

from __future__ import annotations

import asyncio
import mimetypes
import os
import secrets
import stat
from collections.abc import Mapping
from typing import Optional

from ja3requests._async_utils import owner_task
from ja3requests._upload import UploadSource, _drain
from ja3requests.exceptions import InvalidData, StreamConsumedError


def _text(value, label):
    if isinstance(value, bytes):
        try:
            value = value.decode('utf-8')
        except UnicodeError as error:
            raise InvalidData('Multipart %s must be UTF-8 text' % label) from error
    if not isinstance(value, str):
        raise InvalidData('Multipart %s must be text' % label)
    if any(character in value for character in ('\r', '\n', '\x00')):
        raise InvalidData('Invalid multipart %s' % label)
    try:
        value.encode('utf-8')
    except UnicodeError as error:
        raise InvalidData('Multipart %s must be UTF-8 text' % label) from error
    return value


def _quoted(value):
    return value.replace('\\', '\\\\').replace('"', '\\"').encode('utf-8')


def _fields(data):
    if data is None:
        return []
    if isinstance(data, Mapping):
        items = list(data.items())
    elif isinstance(data, (list, tuple)):
        items = list(data)
    else:
        raise InvalidData('Multipart data must be form fields, not a raw body')
    result = []
    for item in items:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise InvalidData('Multipart form fields must be name/value pairs')
        name, value = item
        name = _text(name, 'field name')
        values = value if isinstance(value, (list, tuple)) else (value,)
        for field in values:
            if not isinstance(field, bytes):
                try:
                    field = str(field).encode('utf-8')
                except (UnicodeError, ValueError, TypeError) as error:
                    raise InvalidData('Could not encode multipart field') from error
            result.append((name, field))
    return result


class MultipartSource(UploadSource):
    """Freeze part metadata and stream files without taking borrowed ownership.

    Paths are library-owned and opened lazily, one at a time. Regular-file sizes
    and borrowed initial offsets are captured by prepare/aprepare. The inherited
    async piece reader runs one generator step in an owned executor job, so every
    stat/open/read/seek/close stays off the event loop.
    """

    def __init__(
        self, data, files, content_type=None, length: Optional[int] = None
    ) -> None:
        if not isinstance(files, Mapping):
            raise InvalidData('Multipart files must be a field-to-file mapping')
        self.boundary = secrets.token_hex(16)
        self.content_type = 'multipart/form-data; boundary=' + self.boundary
        if content_type is not None:
            supplied = _text(content_type, 'Content-Type').strip()
            media, separator, parameters = supplied.partition(';')
            if media.strip().lower() != 'multipart/form-data' or (
                separator and parameters.strip() != 'boundary=' + self.boundary
            ):
                raise InvalidData('Multipart Content-Type conflicts with its boundary')
        self._parts = []
        self._borrowed = {}
        self._borrowed_counts = {}
        self._active_file = None
        self._active_body = None
        self._close_task = None
        self._closing_boundary = ('--' + self.boundary + '--\r\n').encode('ascii')
        for name, value in _fields(data):
            self._parts.append(
                {
                    'header': self._header(name),
                    'data': value,
                    'path': None,
                    'body': None,
                    'length': len(value),
                }
            )
        for name, values in list(files.items()):
            name = _text(name, 'field name')
            values = list(values) if isinstance(values, list) else (values,)
            for value in values:
                path = None
                body = None
                if isinstance(value, (str, bytes, os.PathLike)):
                    try:
                        path = os.fspath(value)
                    except (TypeError, ValueError) as error:
                        raise InvalidData('Invalid multipart file path') from error
                    filename = os.path.basename(os.fsdecode(path))
                elif callable(getattr(value, 'read', None)):
                    key = id(value)
                    body = self._borrowed.get(key)
                    if body is None:
                        body = UploadSource(value)
                        self._borrowed[key] = body
                    self._borrowed_counts[key] = self._borrowed_counts.get(key, 0) + 1
                    candidate = getattr(value, 'name', None)
                    filename = (
                        os.path.basename(os.fsdecode(candidate))
                        if isinstance(candidate, (str, bytes, os.PathLike))
                        else name
                    )
                else:
                    raise InvalidData('Multipart files must be paths or binary files')
                filename = _text(filename or name, 'filename')
                self._parts.append(
                    {
                        'header': self._header(name, filename),
                        'data': None,
                        'path': path,
                        'body': body,
                        'length': None,
                    }
                )
        super().__init__(self._pieces(), length=length)

    def _header(self, name, filename=None):
        header = (
            ('--' + self.boundary + '\r\n').encode('ascii')
            + b'Content-Disposition: form-data; name="'
            + _quoted(name)
            + b'"'
        )
        if filename is not None:
            # guess_type() can initialize from system files on its first call.
            # The already-loaded extension table keeps construction free of I/O.
            extension = os.path.splitext(filename)[1].lower()
            media_type = mimetypes.types_map.get(extension, 'application/octet-stream')
            header += (
                b'; filename="'
                + _quoted(filename)
                + b'"\r\nContent-Type: '
                + media_type.encode('ascii')
            )
        return header + b'\r\n\r\n'

    def _prepare_parts(self):
        total = len(self._closing_boundary)
        unknown = False
        try:
            for body in self._borrowed.values():
                body.prepare()
            for key, count in self._borrowed_counts.items():
                if count > 1 and self._borrowed[key]._initial_offset is None:
                    raise InvalidData(
                        'Repeated multipart file handles must be seekable'
                    )
            for part in self._parts:
                if part['path'] is not None:
                    info = os.stat(part['path'])
                    if stat.S_ISDIR(info.st_mode):
                        raise InvalidData('Multipart file path is a directory')
                    part['length'] = (
                        info.st_size if stat.S_ISREG(info.st_mode) else None
                    )
                elif part['body'] is not None:
                    part['length'] = part['body'].length
                total += len(part['header']) + 2
                if part['length'] is None:
                    unknown = True
                else:
                    total += part['length']
            return None if unknown else total
        except asyncio.CancelledError:
            raise
        except InvalidData:
            raise
        except Exception as error:
            raise InvalidData('Could not prepare multipart files') from error

    def _prepare(self):
        if not self._prepared:
            length = self._prepare_parts()
            self._check_open()
            self._commit_preparation(None, length)

    async def _aprepare(self):
        if not self._prepared:
            length = await self._run_worker(self._prepare_parts)
            self._check_open()
            self._commit_preparation(None, length)

    def _close_active_path(self):
        if self._active_file is None:
            return
        handle, body = self._active_file, self._active_body
        if body is not None:
            body.close_owned()
        try:
            handle.close()
        finally:
            if handle.closed:
                self._active_file = None
                self._active_body = None

    def _pieces(self):
        for part in self._parts:
            yield part['header']
            if part['data'] is not None:
                if part['data']:
                    yield part['data']
            else:
                body = part['body']
                try:
                    if part['path'] is not None:
                        self._active_file = open(part['path'], 'rb')
                        body = UploadSource(self._active_file, length=part['length'])
                        self._active_body = body
                        body.prepare()
                    elif body.consumed:
                        # The same seekable borrowed file can appear in several
                        # parts, each beginning at its captured original offset.
                        body.rewind()
                    while True:
                        chunk = body.read_piece()
                        if not chunk:
                            break
                        yield chunk
                finally:
                    self._close_active_path()
            yield b'\r\n'
        yield self._closing_boundary

    def _cleanup_attempt(self):
        try:
            self._source.close()
        finally:
            self._close_active_path()

    def _pull(self, limit):
        try:
            value = super()._pull(limit)
            if (
                isinstance(value, bytes)
                and self.length is not None
                and self._produced + len(value) > self.length
            ):
                raise InvalidData('Multipart source exceeds its declared length')
            return value
        except BaseException:
            self._cleanup_attempt()
            raise

    async def _apull(self, limit):
        try:
            return await super()._apull(limit)
        except asyncio.CancelledError as cancellation:
            # The parent has drained the generator's worker. Closing that owned
            # generator now can safely close a path opened by the cancelled pull.
            cleanup = self._loop.run_in_executor(None, self._cleanup_attempt)
            await _drain(cleanup)
            if cleanup.exception() is not None:
                raise cancellation from cleanup.exception()
            raise

    def _rewind_parts(self):
        self._cleanup_attempt()
        # Check all borrowed one-shot sources before rewinding any seekable one.
        # A replayable earlier part does not make a consumed later part replayable.
        for body in self._borrowed.values():
            body._needs_rewind()
        for body in self._borrowed.values():
            body.rewind()
        try:
            for part in self._parts:
                if part['path'] is not None:
                    info = os.stat(part['path'])
                    current = info.st_size if stat.S_ISREG(info.st_mode) else None
                    if current != part['length']:
                        raise InvalidData('Multipart file length changed before replay')
        except Exception as error:
            raise StreamConsumedError('Could not reopen multipart files') from error
        self._source = self._pieces()

    def rewind(self) -> None:
        self._begin()
        try:
            self._prepare()
            self._rewind_parts()
            self._reset()
        finally:
            self._finish()

    async def arewind(self) -> None:
        self._begin(asynchronous=True)
        try:
            await self._aprepare()
            await self._run_worker(self._rewind_parts)
            self._reset()
        except asyncio.CancelledError:
            self._failure = StreamConsumedError(
                'Multipart rewind was cancelled; rewind again before reuse'
            )
            raise
        finally:
            self._finish()

    def _close_parts(self):
        try:
            self._cleanup_attempt()
        finally:
            for body in self._borrowed.values():
                body.close_owned()

    def close_owned(self) -> None:
        if self._close_task is not None and not self._close_task.done():
            raise RuntimeError('Multipart async cleanup is already in progress')
        super().close_owned()
        self._close_parts()

    async def _finish_close(self):
        await super().aclose_owned()
        await self._run_worker(self._close_parts)

    async def aclose_owned(self) -> None:
        self._bind()
        if self._close_task is None:
            self._closing_state(asynchronous=True)
            self._close_task = owner_task(self._finish_close())
        try:
            await asyncio.shield(self._close_task)
        except asyncio.CancelledError:
            await _drain(self._close_task)
            raise
