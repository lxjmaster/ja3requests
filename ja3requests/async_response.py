"""Native asynchronous response framing, decoding and ownership."""

from __future__ import annotations

import asyncio
import json
import math
from types import SimpleNamespace, TracebackType
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Type,
)

from ja3requests._async_utils import owner_task
from ja3requests.async_pool import _Lease
from ja3requests.const import MAX_HEADERS, MAX_LINE
from ja3requests.cookies import Ja3RequestsCookieJar, extract_cookies_to_jar
from ja3requests.exceptions import (
    ConnectionException,
    HTTPError,
    InvalidResponseHeaders,
    InvalidStatusLine,
    StreamConsumedError,
    Timeout,
)
from ja3requests.response import _ContentDecoder


class AsyncResponse:
    """An awaitable body with one consumer and explicit resource ownership."""

    def __init__(
        self,
        *,
        method: str,
        url: str,
        request: Any = None,
        release: Optional[Callable[[bool], Awaitable[None]]] = None,
        timeout: Optional[float] = None,
    ) -> None:
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout < 0
        ):
            raise ValueError("read timeout must be finite and non-negative, or None")
        self._loop = asyncio.get_running_loop()
        self._method = method.upper()
        self.url = url
        self.request = request
        self.response = (
            self  # Existing CookieJar adapters inspect response.raw_headers.
        )
        self.status_code = -1
        self.status_text = ""
        self.protocol_version = ""
        self.headers: Dict[str, str] = {}
        self.raw_headers: List[Dict[str, str]] = []
        self._headers_lower: Dict[str, str] = {}
        self._encoding: Optional[str] = None
        self._content_encoding = b""
        self._body: Optional[bytes] = None
        self._stream_started = False
        self._closed = False
        self._released = False
        self._release = release
        self._pool_lease: Optional[_Lease] = None
        self._timeout = timeout
        self._transport: Any = None
        self._h2: Any = None
        self._stream_id: Optional[int] = None
        self._buffer = bytearray()
        self._remaining: Optional[int] = None
        self._chunked = False
        self._chunk_remaining = 0
        self._chunk_crlf = False
        self._no_body = False
        self._reusable = False
        self._pending_read: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._session_owner: Optional[Callable[[], Any]] = None

    @classmethod
    async def from_http1(
        cls,
        transport: Any,
        *,
        method: str,
        url: str,
        request: Any = None,
        release: Optional[Callable[[bool], Awaitable[None]]] = None,
        timeout: Optional[float] = None,
    ) -> AsyncResponse:
        """Return after final response headers, preserving already received bytes."""
        response = cls(
            method=method, url=url, request=request, release=release, timeout=timeout
        )
        response._transport = transport
        try:
            while True:
                line = await response._readline(
                    InvalidStatusLine, response_start=response.status_code < 0
                )
                parts = line.rstrip(b"\r\n").split(None, 2)
                if (
                    len(parts) < 2
                    or parts[0] not in (b"HTTP/1.0", b"HTTP/1.1")
                    or len(parts[1]) != 3
                    or not parts[1].isdigit()
                    or int(parts[1]) < 100
                ):
                    raise InvalidStatusLine("Invalid HTTP response status line")
                response.protocol_version = parts[0].decode('ascii')
                response.status_code = int(parts[1])
                response.status_text = (
                    parts[2].decode('latin-1') if len(parts) > 2 else ""
                )
                response._set_headers(await response._read_headers())
                if response.status_code >= 200 or response.status_code == 101:
                    break
            response._configure_framing()
            if response._no_body or (
                response._remaining == 0 and not response._chunked
            ):
                response._body = b""
                await response._finish(response._reusable)
            return response
        except BaseException:
            await response._abort()
            raise

    @classmethod
    async def from_http2(
        cls,
        h2: Any,
        stream_id: int,
        headers: Any,
        *,
        method: str,
        url: str,
        request: Any = None,
        release: Optional[Callable[[bool], Awaitable[None]]] = None,
        timeout: Optional[float] = None,
    ) -> AsyncResponse:
        """Adapt a single H2 stream without taking ownership of its connection."""
        response = cls(
            method=method, url=url, request=request, release=release, timeout=timeout
        )
        response._h2 = h2
        response._stream_id = stream_id
        response.protocol_version = "HTTP/2"
        try:
            pairs = (
                list(headers.items()) if isinstance(headers, dict) else list(headers)
            )
            normalized = []
            for item in pairs:
                entries = item.items() if isinstance(item, dict) else [item]
                for name, value in entries:
                    name = name.decode('latin-1') if isinstance(name, bytes) else name
                    value = (
                        value.decode('latin-1') if isinstance(value, bytes) else value
                    )
                    if name == ':status':
                        if len(value) != 3 or not value.isdigit() or int(value) < 200:
                            raise InvalidStatusLine("Invalid final H2 response status")
                        response.status_code = int(value)
                    else:
                        normalized.append((name, value))
            if response.status_code < 200:
                raise InvalidStatusLine("H2 response is missing :status")
            response._set_headers(normalized)
            response._configure_framing()
            return response
        except BaseException:
            await response._abort()
            raise

    def __repr__(self) -> str:
        return "<AsyncResponse [%d]>" % self.status_code

    def _check_loop(self) -> None:
        if asyncio.get_running_loop() is not self._loop:
            raise RuntimeError("AsyncResponse belongs to a different event loop")

    async def _wait_read(self, operation: Awaitable[bytes]) -> bytes:
        task = asyncio.ensure_future(operation)
        self._pending_read = task
        try:
            if self._timeout is None:
                return await task
            done, _ = await asyncio.wait((task,), timeout=self._timeout)
            if not done:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                error = Timeout("Response read timed out", response=self)
                error.phase = 'read'
                raise error
            return task.result()
        except asyncio.CancelledError:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
        finally:
            if self._pending_read is task:
                self._pending_read = None

    async def _read_transport(self, size: int) -> bytes:
        if self._closed:
            raise StreamConsumedError("The response is closed", response=self)
        return await self._wait_read(self._transport.read(size))

    async def _readline(
        self, error_type: Type[Exception], *, response_start: bool = False
    ) -> bytes:
        while True:
            end = self._buffer.find(b"\n")
            if end >= 0:
                if end + 1 > MAX_LINE:
                    raise error_type("HTTP response line exceeds the size limit")
                line = bytes(self._buffer[: end + 1])
                del self._buffer[: end + 1]
                return line
            if len(self._buffer) >= MAX_LINE:
                raise error_type("HTTP response line exceeds the size limit")
            data = await self._read_transport(
                min(4096, MAX_LINE + 1 - len(self._buffer))
            )
            if not data:
                if response_start and not self._buffer:
                    raise ConnectionError('Connection closed before HTTP response')
                raise error_type("Truncated HTTP response line")
            self._buffer.extend(data)

    async def _read_headers(self) -> List[Any]:
        headers = []
        while True:
            line = await self._readline(InvalidResponseHeaders)
            if line in (b"\r\n", b"\n"):
                return headers
            if len(headers) >= MAX_HEADERS:
                raise InvalidResponseHeaders("Too many response headers")
            try:
                name, value = line.rstrip(b"\r\n").split(b":", 1)
            except ValueError as error:
                raise InvalidResponseHeaders("Invalid response header") from error
            if not name or name.strip() != name:
                raise InvalidResponseHeaders("Invalid response header name")
            headers.append((name.decode('latin-1'), value.strip().decode('latin-1')))

    def _set_headers(self, pairs: List[Any]) -> None:
        self.raw_headers = []
        self.headers = {}
        self._headers_lower = {}
        for name, value in pairs:
            lower = name.lower()
            self.raw_headers.append({name: value})
            if lower in ('content-length', 'transfer-encoding', 'connection'):
                previous = self._headers_lower.get(lower)
                self._headers_lower[lower] = (
                    previous + ', ' + value if previous is not None else value
                )
            else:
                self._headers_lower.setdefault(lower, value)
            if lower != 'set-cookie':
                self.headers[name] = value

    def _configure_framing(self) -> None:
        headers = self._headers_lower
        self._content_encoding = (
            headers.get('content-encoding', '').lower().encode('latin-1')
        )
        transfer = headers.get('transfer-encoding', '').lower()
        if transfer:
            if self._h2 is not None or transfer.strip() != 'chunked':
                raise InvalidResponseHeaders("Unsupported Transfer-Encoding")
            self._chunked = True
        length = headers.get('content-length')
        if length is not None:
            values = [part.strip() for part in length.split(',')]
            if any(
                not value or any(char not in '0123456789' for char in value)
                for value in values
            ):
                raise InvalidResponseHeaders("Invalid Content-Length")
            lengths = {int(value) for value in values}
            if len(lengths) != 1:
                raise InvalidResponseHeaders("Conflicting Content-Length headers")
            self._remaining = lengths.pop()
        if transfer:
            self._remaining = None
        self._no_body = (
            self._method == 'HEAD'
            or self.status_code in (204, 304)
            or self.status_code < 200
        )
        if self._no_body:
            self._remaining = 0
            self._chunked = False
        tokens = {
            token.strip() for token in headers.get('connection', '').lower().split(',')
        }
        self._reusable = self._h2 is not None or (
            'close' not in tokens
            and (self.protocol_version == 'HTTP/1.1' or 'keep-alive' in tokens)
            and (self._no_body or self._chunked or self._remaining is not None)
            and self.status_code != 101
        )

    async def _read_some(self, size: int) -> bytes:
        if self._buffer:
            data = bytes(self._buffer[:size])
            del self._buffer[:size]
            return data
        return await self._read_transport(size)

    async def _read_exact(self, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            data = await self._read_some(size - len(result))
            if not data:
                raise ConnectionException("Truncated HTTP response body", response=self)
            result.extend(data)
        return bytes(result)

    async def _next_raw(self, size: int) -> bytes:
        if self._closed:
            raise StreamConsumedError("The response is closed", response=self)
        if self._h2 is not None:
            data = await self._wait_read(
                self._h2.read_stream(self._stream_id, size, timeout=None)
            )
            if self._remaining is not None:
                self._remaining -= len(data)
                if self._remaining < 0:
                    raise ConnectionException(
                        "HTTP response exceeds Content-Length", response=self
                    )
                if not data and self._remaining:
                    raise ConnectionException(
                        "Truncated HTTP response body", response=self
                    )
            return data
        if self._chunked:
            if not self._chunk_remaining:
                if self._chunk_crlf:
                    if await self._read_exact(2) != b"\r\n":
                        raise ConnectionException(
                            "Invalid HTTP chunk terminator", response=self
                        )
                    self._chunk_crlf = False
                line = await self._readline(ConnectionException)
                value = line.split(b';', 1)[0].strip()
                if (
                    not line.endswith(b"\r\n")
                    or not value
                    or any(char not in b'0123456789abcdefABCDEF' for char in value)
                ):
                    raise ConnectionException("Invalid HTTP chunk size", response=self)
                self._chunk_remaining = int(value, 16)
                if not self._chunk_remaining:
                    await self._read_headers()  # Trailers precede connection reuse.
                    return b""
            size = min(size, self._chunk_remaining)
        elif self._remaining is not None:
            if not self._remaining:
                return b""
            size = min(size, self._remaining)
        data = await self._read_some(size)
        if not data:
            if self._chunked or self._remaining not in (None, 0):
                raise ConnectionException("Truncated HTTP response body", response=self)
            return b""
        if self._chunked:
            self._chunk_remaining -= len(data)
            self._chunk_crlf = not self._chunk_remaining
        elif self._remaining is not None:
            self._remaining -= len(data)
        return data

    async def _finish(self, reusable: bool, cancel: bool = False) -> None:
        if self._cleanup_task is None:
            # No pipelined request owns bytes beyond this response's framing.
            if self._h2 is None and self._buffer:
                reusable = False
            self._closed = self._released = True
            release, self._release = self._release, None
            self._pool_lease = None
            transport, self._transport = self._transport, None
            h2, self._h2 = self._h2, None
            pending, self._pending_read = self._pending_read, None
            self._buffer.clear()

            async def cleanup() -> None:
                if pending is not None and not pending.done():
                    pending.cancel()
                    await asyncio.gather(pending, return_exceptions=True)
                try:
                    if cancel and h2 is not None:
                        await h2.cancel_stream(self._stream_id)
                finally:
                    try:
                        if release is not None:
                            await release(reusable)
                        elif transport is not None:
                            await transport.aclose()
                    finally:
                        owner = self._session_owner
                        self._session_owner = None
                        # Session assigns a weakref; inference sees only None here.
                        session = None
                        if owner is not None:
                            session = owner()  # pylint: disable=not-callable
                        if session is not None:
                            session._responses.discard(self)

            self._cleanup_task = owner_task(cleanup())
        cancelled = None
        while not self._cleanup_task.done():
            try:
                await asyncio.shield(self._cleanup_task)
            except asyncio.CancelledError as error:
                cancelled = error
            except Exception:
                break
        if cancelled is not None:
            # Observe a cleanup failure without losing the caller's cancellation.
            if not self._cleanup_task.cancelled():
                self._cleanup_task.exception()
            raise cancelled
        self._cleanup_task.result()

    async def _abort(self) -> None:
        """Preserve a protocol/decode/cancellation error if release also fails."""
        try:
            await self.aclose()
        except asyncio.CancelledError:
            raise
        except Exception:
            # The original failure is still active in the caller. The cleanup
            # task's exception has been observed, and ownership is detached.
            pass

    async def _iter_decoded(self, chunk_size: int) -> AsyncIterator[bytes]:
        decoder = _ContentDecoder(self._content_encoding, chunk_size)
        try:
            while True:
                data = await self._next_raw(min(chunk_size, 65536))
                if not data:
                    break
                for output in decoder.feed(data):
                    if self._closed:
                        raise StreamConsumedError(
                            "The response is closed", response=self
                        )
                    yield output
            decoder.finish()
            await self._finish(self._reusable)
        except BaseException:
            await self._abort()
            raise

    def _claim_body(self) -> None:
        self._check_loop()
        if self._stream_started or self._closed:
            raise StreamConsumedError(
                "The response body cannot be replayed", response=self
            )
        self._stream_started = True

    async def read(self) -> bytes:
        """Collect and cache a strictly decoded body, or return the existing cache."""
        self._check_loop()
        if self._body is not None:
            return self._body
        self._claim_body()
        body = bytearray()
        iterator = self._iter_decoded(65536)
        try:
            async for chunk in iterator:
                body.extend(chunk)
        finally:
            await iterator.aclose()
        self._body = bytes(body)
        return self._body

    async def text(self) -> str:
        """Decode the cached or newly collected body using the selected charset."""
        return (await self.read()).decode(self.encoding)

    async def json(self) -> Any:
        """Collect and parse a JSON body."""
        return json.loads(await self.read())

    async def aiter_content(self, chunk_size: int = 1024) -> AsyncIterator[bytes]:
        """Yield bounded decoded chunks without retaining an uncached replay copy."""
        self._check_loop()
        if (
            not isinstance(chunk_size, int)
            or isinstance(chunk_size, bool)
            or chunk_size <= 0
        ):
            raise ValueError("chunk_size must be a positive integer")
        if self._body is not None:
            for start in range(0, len(self._body), chunk_size):
                yield self._body[start : start + chunk_size]
            return
        self._claim_body()
        iterator = self._iter_decoded(chunk_size)
        try:
            async for chunk in iterator:
                yield chunk
        finally:
            await iterator.aclose()

    async def aiter_lines(
        self, chunk_size: int = 512, delimiter: Optional[bytes] = None
    ) -> AsyncIterator[bytes]:
        """Yield byte lines; one unfinished line may grow independently of chunks."""
        if delimiter is not None and not isinstance(delimiter, bytes):
            raise TypeError("delimiter must be bytes or None")
        pending = b""
        separator = delimiter or b"\n"
        iterator = self.aiter_content(chunk_size)
        try:
            async for chunk in iterator:
                pending += chunk
                while separator in pending:
                    line, pending = pending.split(separator, 1)
                    yield (
                        line[:-1]
                        if delimiter is None and line.endswith(b"\r")
                        else line
                    )
            if pending:
                yield pending
        finally:
            await iterator.aclose()

    async def aclose(self) -> None:
        """Release once, cancelling only this response's unfinished H2 stream."""
        self._check_loop()
        if self._body is None:
            self._stream_started = True
        await self._finish(False, cancel=True)

    async def __aenter__(self) -> AsyncResponse:
        self._check_loop()
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> None:
        await self.aclose()

    @property
    def closed(self) -> bool:
        """Whether the response has detached its transport/stream lease."""
        return self._closed

    @property
    def content(self) -> bytes:
        """Return cached bytes only; this property never starts network I/O."""
        if self._body is not None:
            return self._body
        if self._stream_started:
            raise StreamConsumedError(
                "The response body cannot be replayed", response=self
            )
        raise RuntimeError("Response content is unread; await response.read() first")

    @property
    def cookies(self) -> Ja3RequestsCookieJar:
        """Extract all Set-Cookie fields against the request's actual URL."""
        jar = Ja3RequestsCookieJar()
        request = self.request or SimpleNamespace(url=self.url, headers={})
        extract_cookies_to_jar(jar, request, self)
        return jar

    @property
    def encoding(self) -> str:
        """Use an explicit override, Content-Type charset, or UTF-8."""
        if self._encoding is not None:
            return self._encoding
        for part in self._headers_lower.get('content-type', '').split(';')[1:]:
            name, separator, value = part.partition('=')
            if separator and name.strip().lower() == 'charset':
                charset = value.strip().strip('"').strip("'")
                if charset:
                    return charset
        return 'utf-8'

    @encoding.setter
    def encoding(self, value: Optional[str]) -> None:
        self._encoding = value

    @property
    def location(self) -> Optional[str]:
        return self._headers_lower.get('location')

    @property
    def is_redirected(self) -> bool:
        return 300 <= self.status_code < 400

    def raise_for_status(self) -> None:
        """Raise without reading the body for an HTTP client/server error."""
        if 400 <= self.status_code < 600:
            raise HTTPError(
                "%d Error for url: %s" % (self.status_code, self.url), response=self
            )
