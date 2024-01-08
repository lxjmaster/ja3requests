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
        files,
        headers,
        timeout,
        json,
        proxy,
    ):
        """
        Set context payload
        :return:
        """
        self.method = method
        self.start_line = url
        self.port = port
        self.data = data
        self.json = json
        self.files = files
        self.headers = headers
        self.proxy = proxy
        self.timeout = timeout


class HTTPSContext(BaseContext):

    def set_payload(self, request):
        pass
