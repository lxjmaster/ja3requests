"""
Ja3Requests.requests.http
~~~~~~~~~~~~~~~~~~~~~~~~~

This module of HTTP Request.
"""

from ja3requests.base import BaseRequest
from ja3requests.contexts.context import HTTPContext
from ja3requests.sockets.http import HttpSocket
from ja3requests.sockets.proxy import ProxySocket
from ja3requests.const import DEFAULT_HTTP_SCHEME, DEFAULT_HTTP_PORT
from ja3requests.response import HTTPResponse


class HttpRequest(BaseRequest):
    """
    HTTP Request
    """

    def __init__(self):
        super().__init__()
        self.scheme = DEFAULT_HTTP_SCHEME
        self.port = DEFAULT_HTTP_PORT

    @staticmethod
    def create_connection(context: HTTPContext, pool=None):
        """
        create a new connection by context
        :param context:
        :param pool: Connection pool for reuse
        :return:
        """
        if context.proxy:
            sock = ProxySocket(context)
        else:
            sock = HttpSocket(context, pool=pool)

        return sock.new_conn()

    def send(self, **kwargs):
        pool = kwargs.pop('pool', None)

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
        sock = self.create_connection(context, pool=pool)
        sock.send()
        response = HTTPResponse(sock.conn)
        response.handle()

        # Return connection to pool if available
        if pool and hasattr(sock, 'return_to_pool'):
            sock.return_to_pool()

        return response
