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

        return self._message.encode()

    def set_payload(
        self,
        method,
        url,
        data,
        headers,
    ):
        """
        Set context payload
        :return:
        """
        self.method = method
        self.start_line = url
        self.headers = headers
        # self.body = request.body


class HTTPSContext(BaseContext):

    def set_payload(self, request):
        pass
