"""
Ja3Requests.contexts.context
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HTTP Context and HTTPS Context
"""


from ja3requests.base import BaseContext


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

    def set_payload(self, **kwargs):
        """
        Set context payload
        :return:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)


class HTTPSContext(BaseContext):
    """
    HTTPS Context
    """

    def set_payload(self, request):
        pass
