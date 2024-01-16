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
    def create_connection(context: HTTPSContext):
        """
        create a new connection by context
        :param context:
        :return:
        """
        if context.proxy:
            sock = ProxySocket(context)
        else:
            sock = HttpsSocket(context)

        return sock.new_conn()

    def send(self):
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
        )
        sock = self.create_connection(context)
        sock.send()
        response = HTTPSResponse(sock.conn)
        response.begin()

        return response
