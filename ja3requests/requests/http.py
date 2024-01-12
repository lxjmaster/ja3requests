from ja3requests.base import BaseRequest
from ja3requests.contexts.context import HTTPContext
from ja3requests.sockets.http import HttpSocket
from ja3requests.sockets.proxy import ProxySocket
from ja3requests.const import DEFAULT_HTTP_SCHEME, DEFAULT_HTTP_PORT
from ja3requests.response import HTTPResponse
import typing


class HttpRequest(BaseRequest):

    def __init__(self):
        super(HttpRequest, self).__init__()
        self.scheme = DEFAULT_HTTP_SCHEME
        self.port = DEFAULT_HTTP_PORT

    @staticmethod
    def create_connection(context: HTTPContext):
        if context.proxy:
            sock = ProxySocket(context)
        else:
            sock = HttpSocket(context)

        return sock.new_conn()

    def send(self):
        context = HTTPContext()
        context.set_payload(
            method=self.method,
            start_line=self.url,
            port=self.port,
            data=self.data,
            files=self.files,
            headers=self.headers,
            timeout=self.timeout,
            json=self.json,
            proxy=self.proxy,
            cookies=self.cookies,
        )
        sock = self.create_connection(context)
        sock.send()
        response = HTTPResponse(sock.conn)
        response.begin()

        return response
