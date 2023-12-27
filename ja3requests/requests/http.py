from ja3requests.base import BaseRequest
from ja3requests.contexts.context import HTTPContext
from ja3requests.const import DEFAULT_HTTP_SCHEME, DEFAULT_HTTP_PORT


class HttpRequest(BaseRequest):

    def __init__(self, context: HTTPContext):
        super(HttpRequest, self).__init__(context)
        self.scheme = DEFAULT_HTTP_SCHEME
        self.port = DEFAULT_HTTP_PORT

    def send(self):
        pass
