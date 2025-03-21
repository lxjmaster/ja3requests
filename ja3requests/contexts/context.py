"""
Ja3Requests.contexts.context
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HTTP Context and HTTPS Context
"""


from ja3requests.base import BaseContext


class HTTPContext(BaseContext):
    """
    HTTPContext
    """

    def __init__(self, protocol: str = "HTTP/1.1"):
        super().__init__()
        self.protocol_version = protocol

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

    def __init__(self, protocol: str = "HTTP/2.0"):
        super().__init__()
        self.protocol_version = protocol

    def set_payload(self, **kwargs):
        """
        Set context payload
        :return:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)
