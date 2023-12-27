"""
ja3requests.context
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HTTP Context and HTTPS Context
"""


from ja3requests.base import BaseContext
import typing


DEFAULT_HTTP_CONTEXT_PROTOCOL = 11
DEFAULT_HTTP_VERSION = "HTTP/1.1"


class HTTPContext(BaseContext):
    """
    HTTPContext
    """

    def __init__(self):
        super().__init__()
        self.protocol = DEFAULT_HTTP_CONTEXT_PROTOCOL
        self.version = DEFAULT_HTTP_VERSION

    @property
    def message(self):
        """
        HTTP Context message to send
        :return:
        """
        self.start_line = " ".join([self.method, self.connection.path, self.version])
        self._message = "\r\n".join([self.start_line, self.put_headers()])
        self._message += "\r\n\r\n"

        if self.body:
            self._message += self.body

        print(self._message)

        return self._message.encode()

    def set_payload(self, request):
        """
        Set context payload
        :param request:
        :return:
        """
        self.method = request.method
        self.headers = request.headers
        self.body = request.body

    def set_headers(self, headers: typing.Dict[typing.AnyStr, typing.AnyStr]):
        """
        Set context headers
        :return:
        """
        headers_ctx = ""

    def put_headers(self):
        """
        Set context headers
        :return:
        """
        headers = ""
        if self.headers is not None:
            if not self.headers.get("host", None):
                self.headers["host"] = self.connection.host

            headers = "\r\n".join([f"{k}: {v}" for k, v in self.headers.items()])

        return headers


class HTTPSContext(BaseContext):

    def set_payload(self, request):
        pass
