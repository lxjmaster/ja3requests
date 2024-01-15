"""
Ja3Requests.requests.https
~~~~~~~~~~~~~~~~~~~~~~~~~~

This module of HTTPS Request.
"""


from ja3requests.const import DEFAULT_HTTPS_SCHEME, DEFAULT_HTTPS_PORT
from ja3requests.base import BaseRequest


class HttpsRequest(BaseRequest):
    """
    HTTPS Request
    """

    def __init__(self):
        super().__init__()
        self.scheme = DEFAULT_HTTPS_SCHEME
        self.port = DEFAULT_HTTPS_PORT

    def send(self):
        pass
