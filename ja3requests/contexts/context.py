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

    def set_payload(
        self,
        method,
        url,
        port,
        data,
        headers,
        timeout,
    ):
        """
        Set context payload
        :return:
        """
        self.method = method
        self.start_line = url
        self.port = port
        self.headers = headers
        self.timeout = timeout
        # self.body = request.body


class HTTPSContext(BaseContext):

    def set_payload(self, request):
        pass
