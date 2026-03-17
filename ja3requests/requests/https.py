"""
Ja3Requests.requests.https
~~~~~~~~~~~~~~~~~~~~~~~~~~

This module of HTTPS Request.
"""

from ja3requests.const import DEFAULT_HTTPS_SCHEME, DEFAULT_HTTPS_PORT
from ja3requests.base import BaseRequest
from ja3requests.contexts.context import HTTPSContext
from ja3requests.sockets.https import HttpsSocket
from ja3requests.sockets.proxy import ProxySocket
from ja3requests.response import HTTPSResponse


class HttpsRequest(BaseRequest):
    """
    HTTPS Request
    """

    def __init__(self):
        super().__init__()
        self.scheme = DEFAULT_HTTPS_SCHEME
        self.port = DEFAULT_HTTPS_PORT

    @staticmethod
    def create_connection(context: HTTPSContext, pool=None):
        """
        create a new connection by context
        :param context:
        :param pool: Connection pool for reuse
        :return:
        """
        if context.proxy:
            sock = ProxySocket(context)
        else:
            sock = HttpsSocket(context, pool=pool)

        return sock.new_conn()

    def send(self, **kwargs):
        pool = kwargs.pop('pool', None)

        if kwargs.get("h1", False) is True:
            context = HTTPSContext(protocol="HTTP/1.1")
        else:
            context = HTTPSContext()

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
            tls_config=self.tls_config,
        )
        sock = self.create_connection(context, pool=pool)
        conn = sock.send()
        response = HTTPSResponse(conn)
        response.handle()

        # Return connection to pool if available
        if pool and hasattr(sock, 'return_to_pool'):
            sock.return_to_pool()

        return response
