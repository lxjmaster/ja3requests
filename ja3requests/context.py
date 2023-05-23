"""
ja3requests.context
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HTTP Context and HTTPS Context
"""


from .base import BaseContext


DEFAULT_HTTP_CONTEXT_PROTOCOL = 11
DEFAULT_HTTP_VERSION = "HTTP/1.1"


class HTTPContext(BaseContext):
    """
    HTTPContext
    """

    def __init__(self, connection):
        super().__init__()
        self.protocol = DEFAULT_HTTP_CONTEXT_PROTOCOL
        self.version = DEFAULT_HTTP_VERSION
        self.connection = connection

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

    def set_payload(self, **kwargs):
        """
        Set context payload
        :param kwargs:
        :return:
        """
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)

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
