from ja3requests.base import BaseRequest
from ja3requests.const import DEFAULT_HTTPS_SCHEME, DEFAULT_HTTPS_PORT


class HttpsRequest(BaseRequest):

    def __init__(self):
        super(HttpsRequest, self).__init__()
        self.scheme = DEFAULT_HTTPS_SCHEME
        self.port = DEFAULT_HTTPS_PORT

    def send(self):
        pass
