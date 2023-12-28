from ja3requests.base import BaseRequest
from ja3requests.contexts.context import HTTPContext
from ja3requests.sockets.http import HttpSocket
from ja3requests.const import DEFAULT_HTTP_SCHEME, DEFAULT_HTTP_PORT
import typing


class HttpRequest(BaseRequest):

    def __init__(self):
        super(HttpRequest, self).__init__()
        self.scheme = DEFAULT_HTTP_SCHEME
        self.port = DEFAULT_HTTP_PORT

    @staticmethod
    def create_connection(context: HTTPContext):
        sock = HttpSocket(context)

        return sock.new_conn()

    def send(self):
        context = HTTPContext()
        context.set_payload(
            self.method,
            self.url,
            self.data,
            self.headers
        )
        conn = self.create_connection(context)

        return conn.send()
