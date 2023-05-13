"""
ja3requests.response
~~~~~~~~~~~~~~~~~~~~~~~

This module contains response.
"""


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
            if len(self.raw) <= DEFAULT_CHUNKED_SIZE:
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

    def _get_body(self, content_length=None, transfer_encode=None):

        body = b""
        data = self._seek()
        if transfer_encode is not None:
            while not data.endswith(b"\r\n\r\n"):
                data = self._seek()
                size = data[data.find(b'\r\n\r\n')+4: data.find(b'\r\n\r\n')+7]
                # chunk_size = int(size, 32)
                body = data[data.find(size)+5:data.find(b"\r\n0")]
                # print(len(body), chunk_size)
                # if len(body) < chunk_size:
                #     data = self._seek()
            # else:
            #     break
        else:
            if content_length == 0:
                return body

            # body = data[len(data)-content_length:]
            body = data.split(b"\r\n\r\n", 1)[1]
            while len(body) < content_length:
                data = self._seek()
                # body = data[len(data) - content_length:]
                body = data.split(b"\r\n\r\n", 1)[1]

        # data = self._seek()
        # chunk = data.endswith(b"\r\n\r\n")
        # while not chunk:
        #     data = self._seek()
        #     chunk = data.endswith(b"\r\n\r\n")

        # lines = data.split(b"\r\n\r\n", 1)
        # if len(lines) > 1:
        #     if lines[1] == b"":
        #         self.body = body = b""
        #         return body
        #
        #     self.body = body = lines[1].split(b"\r\n", 1)[1]
        # else:
        #     raise InvalidResponseHeaders(f"Invalid response headers: {lines!r}")

        # print(data)
        # print(body)
        # print(len(body))
        return body

    def begin(self):

        self._get_lines()
        headers = self._get_headers()
        content_length = None
        transfer_encode = None
        for header in headers.decode().split("\r\n"):
            if "Content-Length" in header:
                content_length = int(header.split(': ')[1])
            elif 'Transfer-Encoding' in header:
                transfer_encode = header.split(': ')[1]

        self.body = self._get_body(content_length=content_length, transfer_encode=transfer_encode)


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
