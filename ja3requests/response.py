"""
ja3requests.response
~~~~~~~~~~~~~~~~~~~~~~~

This module contains response.
"""


import json
import gzip
import zlib
from io import BytesIO

import brotli

from .base import BaseResponse
from .const import DEFAULT_CHUNKED_SIZE
from .exceptions import InvalidStatusLine, InvalidResponseHeaders


class HTTPResponse(BaseResponse):

    def __init__(self, response=None):
        super().__init__()
        self.response = response

    def __repr__(self):

        return f"<HTTPResponse [{self.status_code.decode()}] {self.status_text.decode()}>"

    def _seek(self):

        if self.raw is not None:
            if len(self.raw) <= DEFAULT_CHUNKED_SIZE and self.raw.endswith(b"\r\n"):
                return self.raw

            if self.raw.endswith(b"\r\n\r\n"):
                return self.raw

        data = b""
        try:
            data = next(self.response)
            self.raw = data
        except StopIteration:
            pass

        return data

    def _get_lines(self):

        lines = self._seek().split(b"\r\n", 1)
        if len(lines) > 0:
            self.protocol_version, self.status_code, self.status_text = status_lines = lines[0].split(b" ", 2)
        else:
            raise InvalidStatusLine(f"Invalid response status line: {lines!r}")

        return status_lines

    def _get_headers(self):

        lines = self._seek().split(b"\r\n\r\n", 1)
        if len(lines) > 0:
            self.headers = headers = lines[0].split(b"\r\n", 1)[1]
        else:
            raise InvalidResponseHeaders(f"Invalid response headers: {lines!r}")

        return headers

    def _get_body(self, content_length=None, transfer_encode=None, content_encoding=None):

        body = b""
        data = self._seek()
        if transfer_encode is not None:
            while not data.endswith(b"0\r\n\r\n"):
                data = self._seek()

            lines = data.split(b"\r\n\r\n")
            chunked_body = lines[1]
            chunked_list = chunked_body.split(b"\r\n", 1)
            while len(chunked_list) == 2:
                chunked_size, chunked = chunked_list
                size = int(chunked_size, 16)
                body += chunked[:size]
                chunked_body = chunked[size:].lstrip()
                chunked_list = chunked_body.split(b"\r\n", 1)
        else:
            if content_length == 0:
                return body

            # body = data[len(data)-content_length:]
            body = data.split(b"\r\n\r\n", 1)[1]
            while len(body) < content_length:
                data = self._seek()
                # body = data[len(data) - content_length:]
                body = data.split(b"\r\n\r\n", 1)[1]

        if content_encoding == "gzip":
            body = gzip.decompress(body)
        elif content_encoding == "deflate":
            try:
                body = zlib.decompress(body, -zlib.MAX_WBITS)
            except zlib.error:
                body = zlib.decompress(body)
        elif content_encoding == "br":
            body = brotli.decompress(body)

        return body

    def begin(self):

        self._get_lines()
        headers = self._get_headers()
        content_encoding = None
        content_length = None
        transfer_encode = None
        for header in headers.decode().split("\r\n"):
            if "Content-Encoding" in header:
                content_encoding = header.split(': ')[1]
            elif "Content-Length" in header:
                content_length = int(header.split(': ')[1])
            elif 'Transfer-Encoding' in header:
                transfer_encode = header.split(': ')[1]

        self.body = self._get_body(content_length=content_length, transfer_encode=transfer_encode, content_encoding=content_encoding)


class Response(BaseResponse):

    def __init__(self, response=None):
        super().__init__()
        self.response = response

    def __repr__(self):

        return f"<Response [{self.status_code}]>"

    @property
    def headers(self):

        headers = []
        if self.response is None:
            return headers

        headers_raw = self.response.headers.decode()
        header_list = headers_raw.split("\r\n")
        for header_item in header_list:
            name, value = header_item.split(":", 1)
            headers.append(
                {
                    name.strip(): value.strip()
                }
            )

        return headers

    @property
    def body(self):

        body = b""
        if self.response is None:
            return body

        return self.response.body

    @property
    def status_code(self):

        status_code = 400
        if self.response is None:
            return status_code

        return int(self.response.status_code)

    @property
    def content(self):

        return self.body

    @property
    def text(self):

        return self.content.decode("utf8")

    def json(self):

        return json.loads(self.text)
