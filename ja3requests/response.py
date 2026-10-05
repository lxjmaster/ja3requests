"""
Ja3Requests.response
~~~~~~~~~~~~~~~~~~~~

This module contains response.
"""

from __future__ import annotations

import json
import gzip
import zlib
from types import TracebackType
from typing import TYPE_CHECKING, Any, Callable, Dict, Iterator, List, Optional, Type
import brotli
from ja3requests.base import BaseResponse
from ja3requests.cookies import Ja3RequestsCookieJar, extract_cookies_to_jar
from ja3requests.const import MAX_LINE, MAX_HEADERS
from ja3requests.exceptions import (
    InvalidStatusLine,
    InvalidResponseHeaders,
    HTTPError,
    StreamConsumedError,
    ContentDecodingError,
)
from ja3requests.protocol.tls.debug import debug

if TYPE_CHECKING:
    from typing_extensions import Literal
    from ja3requests.base import BaseRequest


class _ContentDecoder:
    """Byte-fed incremental decoding shared by synchronous and async readers."""

    def __init__(self, encoding: Optional[bytes], chunk_size: int) -> None:
        self.encoding = encoding
        self.chunk_size = chunk_size
        self.decoder = None
        self.prefix = b""
        self.deflate_probe = b""
        self.can_fallback = False

    def feed(self, data: bytes) -> Iterator[bytes]:
        """Drain bounded decoded blocks before the caller supplies more input."""
        if self.encoding not in (b"gzip", b"deflate", b"br"):
            yield data
            return
        try:
            if self.encoding == b"br":
                if self.decoder is None:
                    self.decoder = brotli.Decompressor()
                # Stay below the native allocation quantum (32 KiB in 1.2).
                while True:
                    output = self.decoder.process(data, output_buffer_limit=1)
                    data = b""
                    for start in range(0, len(output), self.chunk_size):
                        yield output[start : start + self.chunk_size]
                    if self.decoder.is_finished() or (
                        not output and self.decoder.can_accept_more_data()
                    ):
                        return
            if self.can_fallback:
                if len(self.deflate_probe) + len(data) <= 65536:
                    self.deflate_probe += data
                else:
                    self.can_fallback = False
                    self.deflate_probe = b""
            if self.decoder is None:
                self.prefix += data
                if self.encoding == b"deflate" and len(self.prefix) < 2:
                    return
                wrapped = (
                    len(self.prefix) >= 2
                    and self.prefix[0] & 15 == 8
                    and int.from_bytes(self.prefix[:2], 'big') % 31 == 0
                )
                window = (
                    16 + zlib.MAX_WBITS
                    if self.encoding == b"gzip"
                    else (zlib.MAX_WBITS if wrapped else -zlib.MAX_WBITS)
                )
                self.decoder = zlib.decompressobj(window)
                data, self.prefix = self.prefix, b""
                self.can_fallback = self.encoding == b"deflate" and wrapped
                self.deflate_probe = data if self.can_fallback else b""
            while data:
                if self.decoder.eof:
                    if self.encoding != b"gzip":
                        raise ContentDecodingError("Trailing compressed response data")
                    self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                try:
                    output = self.decoder.decompress(data, self.chunk_size)
                except zlib.error:
                    if not self.can_fallback:
                        raise
                    # A raw stored block can share a zlib prefix. Fall back only
                    # before any decoded bytes have escaped to the consumer.
                    self.decoder = zlib.decompressobj(-zlib.MAX_WBITS)
                    data, self.deflate_probe = self.deflate_probe, b""
                    self.can_fallback = False
                    continue
                data = (
                    self.decoder.unused_data
                    if self.decoder.eof
                    else self.decoder.unconsumed_tail
                )
                if output:
                    self.can_fallback = False
                    self.deflate_probe = b""
                    yield output
        except (zlib.error, brotli.error) as error:
            raise ContentDecodingError("Invalid compressed response body") from error

    def finish(self) -> None:
        """Reject an incomplete compressed stream after framing reaches EOF."""
        if self.decoder is not None:
            complete = (
                self.decoder.is_finished()
                if self.encoding == b"br"
                else self.decoder.eof
            )
            if not complete:
                raise ContentDecodingError("Truncated compressed response body")
        elif self.prefix:
            raise ContentDecodingError("Truncated compressed response body")


class HTTPResponse(BaseResponse):
    """
    An HTTP response from socket connection.
    """

    def __init__(
        self,
        sock: Any,
        method: Optional[str] = None,
        release: Optional[Callable[[bool], None]] = None,
    ) -> None:
        super().__init__()
        self.fp = sock.makefile("rb")
        self._method = method
        self._chunked = False
        self._content_encoding = None
        self._content_length = None
        self._remaining = None
        self._chunk_remaining = 0
        self._chunk_crlf = False
        self._finished = False
        self._reusable = False
        self._framed_stream = getattr(sock, 'body_framed', False) is True
        self._release = getattr(sock, 'release_response', None) or release

    def __repr__(self) -> str:
        return (
            f"<HTTPResponse [{self.status_code.decode()}] {self.status_text.decode()}>"
        )

    def _close_conn(self) -> None:
        self._finish(False)

    def _finish(self, reusable: bool) -> None:
        if self._finished:
            return
        self._finished = True
        fp = self.fp
        self.fp = None
        try:
            if fp is not None:
                fp.close()
        finally:
            release, self._release = self._release, None
            if release is not None:
                release(reusable)

    def _read_status_line(self):
        line = self.fp.readline(MAX_LINE + 1)
        if len(line) > MAX_LINE:
            raise InvalidStatusLine(
                f"The status line is too long, exceeding the {MAX_LINE} Max limit"
            )

        if not line:
            raise InvalidStatusLine(
                f"The remote server closed the connection without sending a response. "
                f"This may indicate TLS handshake failure or server rejection of the connection. "
                f"Status line received: {line!r}"
            )

        try:
            protocol_version, status_code, status_text = line.split(None, 2)
            self.protocol_version = protocol_version
            self.status_code = status_code
            self.status_text = status_text.strip()
        except ValueError as err:
            raise InvalidStatusLine(f"Can't parse status line: {line!r}") from err

        if not self.protocol_version.startswith(b"HTTP/"):
            self._close_conn()
            raise InvalidStatusLine(f"The status line version not support: {line!r}")

        return protocol_version, status_code, status_text

    def _read_headers(self):
        headers = []
        while True:
            line = self.fp.readline(MAX_LINE + 1)
            if len(line) > MAX_LINE:
                raise InvalidResponseHeaders(
                    f"The response headers is too long, exceeding the {MAX_LINE} Max limit"
                )

            headers.append(line)
            if len(headers) > MAX_HEADERS:
                raise InvalidResponseHeaders(
                    f"The response headers is too long, exceeding the {MAX_LINE} Max limit"
                )

            if not line:
                raise InvalidResponseHeaders("Response ended before headers completed")
            if line in (b"\r\n", b"\n"):
                headers.pop()
                break

        return headers

    def _parse_headers(self, headers_list=None):
        headers = {}
        headers_list = headers_list if headers_list is not None else self.headers
        if headers_list is None:
            raise ValueError("Required headers to parse.")

        self.headers = b""
        for header in headers_list:
            self.headers += header
            try:
                name, value = header.rstrip(b"\r\n").split(b":", 1)
            except ValueError as error:
                raise InvalidResponseHeaders("Invalid response header") from error
            name, value = name.strip().lower(), value.strip()
            if name == b"content-length" and name in headers and headers[name] != value:
                raise InvalidResponseHeaders("Conflicting Content-Length headers")
            headers.setdefault(name, value)

        return headers

    def read_body(self) -> bytes:
        """Read the complete body, preserving eager decoding compatibility."""
        body = b"".join(self._iter_raw_body(65536))

        if self._content_encoding and self._content_encoding != b"":
            try:
                if self._content_encoding == b"gzip":
                    body = gzip.decompress(body)
                elif self._content_encoding == b"deflate":
                    try:
                        body = zlib.decompress(body, -zlib.MAX_WBITS)
                    except zlib.error:
                        body = zlib.decompress(body)
                elif self._content_encoding == b"br":
                    body = brotli.decompress(body)
            except (OSError, zlib.error, brotli.error) as e:
                debug(
                    f"Warning: Failed to decompress content with {self._content_encoding}: {e}"
                )
                # Return original body if decompression fails

        return body

    def _read_exact(self, size: int) -> bytes:
        data = self.fp.read(size)
        if len(data) != size:
            raise ConnectionError("Truncated HTTP response body")
        return data

    def _read_chunk_size(self) -> None:
        if self._chunk_crlf:
            if self._read_exact(2) != b"\r\n":
                raise ConnectionError("Invalid HTTP chunk terminator")
            self._chunk_crlf = False
        line = self.fp.readline(MAX_LINE + 1)
        if len(line) > MAX_LINE or not line.endswith(b"\r\n"):
            raise ConnectionError("Invalid or truncated HTTP chunk size")
        value = line.split(b";", 1)[0].strip()
        if not value or any(char not in b"0123456789abcdefABCDEF" for char in value):
            raise ConnectionError("Invalid HTTP chunk size")
        self._chunk_remaining = int(value, 16)
        if not self._chunk_remaining:
            self._read_headers()  # Consume bounded trailers before reusing HTTP/1.
            self._finish(self._reusable)

    def _iter_raw_body(self, chunk_size: int) -> Iterator[bytes]:
        """Read at most one available transport block on each iteration."""
        try:
            while not self._finished:
                if self._chunked:
                    if not self._chunk_remaining:
                        self._read_chunk_size()
                    if self._finished:
                        break
                    size = min(chunk_size, self._chunk_remaining)
                elif self._remaining is not None and not self._framed_stream:
                    if self._remaining == 0:
                        self._finish(self._reusable)
                        break
                    size = min(chunk_size, self._remaining)
                else:
                    size = chunk_size
                reader = getattr(self.fp, 'read1', self.fp.read)
                data = reader(size)
                if not data:
                    if self._chunked or self._remaining not in (None, 0):
                        raise ConnectionError("Truncated HTTP response body")
                    self._finish(self._reusable)
                    break
                if self._chunked:
                    self._chunk_remaining -= len(data)
                    self._chunk_crlf = self._chunk_remaining == 0
                elif self._remaining is not None:
                    self._remaining -= len(data)
                    if self._remaining < 0:
                        raise ConnectionError("HTTP response exceeds Content-Length")
                    if self._remaining == 0 and not self._framed_stream:
                        self._finish(self._reusable)
                yield data
        finally:
            if not self._finished:
                self._finish(False)

    def iter_body(self, chunk_size: int) -> Iterator[bytes]:
        """Incrementally decode without retaining a replay copy of the body."""
        raw = self._iter_raw_body(min(chunk_size, 65536))
        decoder = _ContentDecoder(self._content_encoding, chunk_size)
        try:
            for data in raw:
                yield from decoder.feed(data)
            decoder.finish()
        finally:
            raw.close()

    def handle(self) -> None:
        """
        Receive data from remote connection and handle message.
        :return:
        """
        if self.headers is not None:
            return

        try:
            while True:
                self._read_status_line()
                self.headers = self._read_headers()
                headers = self._parse_headers()
                if not 100 <= int(self.status_code) < 200 or self.status_code == b"101":
                    break
            self._content_encoding = headers.get(b"content-encoding", b"").lower()
            transfer = headers.get(b"transfer-encoding", b"").lower()
            self._chunked = transfer.split(b",")[-1].strip() == b"chunked"
            length = headers.get(b"content-length")
            self._content_length = int(length) if length is not None else None
            if self._content_length is not None and self._content_length < 0:
                raise InvalidResponseHeaders("Negative Content-Length")
            self._remaining = None if transfer else self._content_length
            connection = headers.get(b"connection", b"").lower().split(b",")
            tokens = {token.strip() for token in connection}
            no_body = (
                self._method == "HEAD"
                or int(self.status_code) in (204, 304)
                or int(self.status_code) < 200
            )
            self._reusable = self._framed_stream or (
                b"close" not in tokens
                and (self.protocol_version == b"HTTP/1.1" or b"keep-alive" in tokens)
                and (no_body or self._chunked or self._remaining is not None)
            )
            if no_body:
                self._remaining = 0
                self._chunked = False
                self._finish(self._reusable and self.status_code != b"101")
            elif self._remaining == 0 and not self._chunked and not self._framed_stream:
                self._finish(self._reusable)
        except Exception:
            self._finish(False)
            raise

    @property
    def raw_headers(self) -> List[Dict[str, str]]:
        """
        Raw response headers
        :return:
        """
        headers = []
        if self.headers:
            headers_raw = self.headers.decode()
            header_list = headers_raw.split("\r\n")
            for header_item in header_list:
                if header_item == "":
                    continue
                name, value = header_item.split(":", 1)
                headers.append({name.strip(): value.strip()})

        return headers


class HTTPSResponse(HTTPResponse):
    """An HTTPS response from socket connection."""


class Response(BaseResponse):
    """Response
    <Response [200]>
    """

    def __init__(
        self,
        request: Optional[BaseRequest] = None,
        response: Optional[HTTPResponse] = None,
        stream: bool = False,
    ) -> None:
        super().__init__()
        self.request = request
        self.response = response
        self._stream = stream
        self._encoding: Optional[str] = None  # user override
        self._body: Optional[bytes] = None
        self._body_consumed = False
        self._stream_started = False

        if not stream:
            self._body = self.response.read_body() if self.response else b""
            self._body_consumed = True

    def __repr__(self) -> str:
        """
        Response repr
        :return:
        """
        return f"<Response [{self.status_code}]>"

    @property
    def cookies(self) -> Ja3RequestsCookieJar:
        """
        Response cookie property
        :return:
        """

        cookies = Ja3RequestsCookieJar()
        if self.request is not None and self.response is not None:
            extract_cookies_to_jar(cookies, self.request, self)

        return cookies

    @property
    def headers(self) -> Dict[str, str]:
        """
        Response Headers.
        :return:
        """
        headers = {}
        if not self.response.raw_headers:
            return headers

        for header in self.response.raw_headers:
            set_cookie = header.get("Set-Cookie", None)
            if set_cookie is None:
                set_cookie = header.get("set-cookie", None)

            if set_cookie:
                continue

            headers.update(header)

        return headers

    @property
    def status_code(self) -> int:
        """
        Response Status Code
        :return:
        """
        status_code = -1
        if self.response is None:
            return status_code

        return int(self.response.status_code)

    @property
    def body(self) -> bytes:
        """Response body bytes. Triggers full read if streaming."""
        if self._stream_started and self._body is None:
            raise StreamConsumedError("The streaming response body cannot be replayed")
        if self._body is None and not self._body_consumed:
            # Claim the body before I/O. A failed read closes the underlying
            # stream and cannot later be retried into an empty success cache.
            self._stream_started = True
            try:
                self._body = self.response.read_body() if self.response else b""
            finally:
                self._body_consumed = True
        return self._body or b""

    @body.setter
    def body(self, value: Optional[bytes]) -> None:
        self._body = value

    @property
    def content(self) -> bytes:
        """
        Response Content
        :return:
        """
        return self.body

    def iter_content(self, chunk_size: int = 1024) -> Iterator[bytes]:
        """
        Yield response body in chunks.

        :param chunk_size: Size of each chunk in bytes.
        :yield: bytes chunks
        """
        if (
            not isinstance(chunk_size, int)
            or isinstance(chunk_size, bool)
            or chunk_size <= 0
        ):
            raise ValueError("chunk_size must be a positive integer")
        if self._body is not None:
            # Body already fully read, yield from buffer
            data = self._body or b""
            for i in range(0, len(data), chunk_size):
                yield data[i : i + chunk_size]
            return

        if self._stream_started:
            raise StreamConsumedError("The streaming response body cannot be replayed")
        self._stream_started = True
        try:
            if self.response:
                yield from self.response.iter_body(chunk_size)
        finally:
            self._body_consumed = True

    def iter_lines(
        self, chunk_size: int = 512, delimiter: Optional[bytes] = None
    ) -> Iterator[bytes]:
        """
        Yield response body line by line.

        :param chunk_size: Size of chunks to read at a time.
        :param delimiter: Line delimiter (default: newline).
        :yield: bytes lines
        """
        pending = b""
        for chunk in self.iter_content(chunk_size=chunk_size):
            pending += chunk
            sep = delimiter or b"\n"
            while sep in pending:
                line, pending = pending.split(sep, 1)
                yield line[:-1] if delimiter is None and line.endswith(b"\r") else line
        if pending:
            yield pending

    def close(self) -> None:
        """Close the underlying connection and release resources."""
        if self.response and hasattr(self.response, 'fp') and self.response.fp:
            try:
                self.response._close_conn()
            except (OSError, AttributeError):
                pass
        if self._body is None:
            self._stream_started = True
            self._body_consumed = True

    def __enter__(self) -> Response:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Literal[False]:
        self.close()
        return False

    @property
    def encoding(self) -> str:
        """
        Response encoding, detected from Content-Type header charset.
        Can be set manually to override auto-detection.
        Falls back to 'utf-8' if no charset is found.
        :return:
        """
        if self._encoding is not None:
            return self._encoding

        content_type = self.headers.get("Content-Type") or self.headers.get(
            "content-type", ""
        )
        if "charset" in content_type.lower():
            # Extract charset value from Content-Type header
            for part in content_type.split(";"):
                # Normalize: strip whitespace, handle "charset = value" with spaces around =
                part = part.strip()
                lower_part = part.lower().replace(" ", "")
                if lower_part.startswith("charset="):
                    charset = part.split("=", 1)[1].strip().strip('"').strip("'")
                    if charset:  # Guard against empty "charset="
                        return charset

        return "utf-8"

    @encoding.setter
    def encoding(self, value: Optional[str]) -> None:
        """
        Override the auto-detected encoding.
        :param value: encoding name (e.g., 'gbk', 'iso-8859-1')
        """
        self._encoding = value

    @property
    def text(self) -> str:
        """
        Response Text, decoded using the detected or overridden encoding.
        :return:
        """
        return self.content.decode(self.encoding)

    def json(self) -> Any:
        """
        Response JSON
        :return:
        """
        return json.loads(self.body)

    @property
    def is_redirected(self) -> bool:
        """
        Response property of has redirected
        :return:
        """

        return 300 <= self.status_code < 400

    def raise_for_status(self) -> None:
        """
        Raise an HTTPError if the response status code indicates an error (4xx or 5xx).
        """
        if 400 <= self.status_code < 600:
            raise HTTPError(
                f"{self.status_code} Error for url: {getattr(self.request, 'url', 'unknown')}",
                response=self,
            )

    @property
    def location(self) -> Optional[str]:
        """
        Response redirected location
        :return:
        """
        location = self.headers.get("Location", None)
        if not location:
            location = self.headers.get("location", None)

        return location
