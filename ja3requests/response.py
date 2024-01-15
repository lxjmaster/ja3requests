"""
Ja3Requests.response
~~~~~~~~~~~~~~~~~~~~

This module contains response.
"""


import json
import gzip
import zlib
import brotli
from ja3requests.base import BaseResponse
from ja3requests.cookies import Ja3RequestsCookieJar
from ja3requests.utils import add_dict_to_cookiejar
from ja3requests.const import MAX_LINE, MAX_HEADERS
from ja3requests.exceptions import InvalidStatusLine, InvalidResponseHeaders, IssueError


class HTTPResponse(BaseResponse):
    """
    An HTTP response from socket connection.
    """

    def __init__(self, sock, method=None):
        super().__init__()
        self.fp = sock.makefile("rb")
        self._method = method
        self._chunked = False
        self._content_encoding = None
        self._content_length = 0

    def __repr__(self):
        return (
            f"<HTTPResponse [{self.status_code.decode()}] {self.status_text.decode()}>"
        )

    def _close_conn(self):
        fp = self.fp
        self.fp = None
        fp.close()

    def _read_status_line(self):
        line = self.fp.readline(MAX_LINE + 1)
        if len(line) > MAX_LINE:
            raise InvalidStatusLine(
                f"The status line is too long, exceeding the {MAX_LINE} Max limit"
            )

        if not line:
            raise InvalidStatusLine(
                f"The remote servers return an invalid response status line: {line!r}"
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

            if line in (b"\r\n", b"\n", b""):
                headers.pop()
                break

        return headers

    def _parse_headers(self, headers_list=None):
        headers = {}
        headers_list = headers_list if headers_list is not None else self.headers
        if headers_list is None:
            raise ValueError("Required headers to parse.")

        self.headers = b""
        for header in headers_list[1:]:
            self.headers += header
            name, value = header.strip().split(b": ")
            headers.setdefault(name.lower(), value)

        return headers

    def read_body(self):
        """
        Read body from remote connection.
        :return:
        """
        body = b""

        if self.fp is None:
            return body

        if self._method == "HEAD":
            self._close_conn()
            return body

        if self._chunked:
            body = self._read_chunked()

        if self._content_length > 0:
            body = self.fp.read(self._content_length)

        if self._content_encoding is not None or self._content_encoding != b"":
            if self._content_encoding == b"gzip":
                body = gzip.decompress(body)
            elif self._content_encoding == b"deflate":
                try:
                    body = zlib.decompress(body, -zlib.MAX_WBITS)
                except zlib.error:
                    body = zlib.decompress(body)
            elif self._content_encoding == b"br":
                body = brotli.decompress(body)

        return body

    def _read_chunked(self):
        chunked_data = b""
        while True:
            chunked_size = self.fp.readline(MAX_LINE + 1).strip()
            if chunked_size == b"":
                continue
            if chunked_size == b"0":
                break
            size = int(chunked_size, 16)
            chunked_data += self.fp.read(size)

        return chunked_data

    def begin(self):
        """
        Receive data from remote connection and begin parse message.
        :return:
        """
        if self.headers is not None:
            return

        self._read_status_line()
        self.headers = self._read_headers()
        headers = self._parse_headers()

        self._content_encoding = headers.get(b"content-encoding", b"")

        transfer_encoding = headers.get(b"transfer-encoding", b"")
        if transfer_encoding == b"chunked":
            self._chunked = True
        elif transfer_encoding != b"":
            raise IssueError(
                "This situation may not be considered yet, please issue it"
            )

        self._content_length = int(headers.get(b"content-length", 0))

    @property
    def raw_headers(self):
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
                name, value = header_item.split(": ", 1)
                headers.append({name.strip(): value.strip()})

        return headers


class Response(BaseResponse):
    """Response
    <Response [200]>
    """

    def __init__(self, request=None, response=None):
        super().__init__()
        self.request = request
        self.response = response
        self.body = self.response.read_body() if self.response else b""

    def __repr__(self):
        """
        Response repr
        :return:
        """
        return f"<Response [{self.status_code}]>"

    @property
    def cookies(self):
        """
        Response cookie property
        :return:
        """

        cookies = Ja3RequestsCookieJar()
        if self.response.raw_headers:
            for header in self.response.raw_headers:
                set_cookie = header.get("Set-Cookie", None)
                if set_cookie is None:
                    set_cookie = header.get("set-cookie", None)

                if set_cookie:
                    cookie_item = set_cookie.split(";")
                    if len(cookie_item) > 0:
                        cookie = cookie_item[0].split("=")
                        if len(cookie) == 2:
                            cookies = add_dict_to_cookiejar(
                                cookies, {cookie[0].strip(): cookie[1].strip()}
                            )

        return cookies

    @property
    def headers(self):
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
    def status_code(self):
        """
        Response Status Code
        :return:
        """
        status_code = -1
        if self.response is None:
            return status_code

        return int(self.response.status_code)

    @property
    def content(self):
        """
        Response Content
        :return:
        """
        return self.body

    @property
    def text(self):
        """
        Response Text
        :return:
        """
        return self.content.decode("utf8")

    def json(self):
        """
        Response JSON
        :return:
        """
        return json.loads(self.body)

    @property
    def is_redirected(self):
        """
        Response property of has redirected
        :return:
        """

        return 300 <= self.status_code < 400

    @property
    def location(self):
        """
        Response redirected location
        :return:
        """
        location = self.headers.get("Location", None)
        if not location:
            location = self.headers.get("location", None)

        return location
