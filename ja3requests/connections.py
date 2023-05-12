"""
ja3requests.connections
~~~~~~~~~~~~~~~~~~~~~~~

This module contains HTTP connection and HTTPS connection.
"""


from .response import HTTPResponse
from .exceptions import InvalidHost
from .base import BaseHttpConnection
from .protocol.sockets import create_connection
from .protocol.exceptions import SocketTimeout, ConnectTimeoutError, ReadTimeout


DEFAULT_HTTP_SCHEME = "http"
DEFAULT_HTTPS_SCHEME = "https"

DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443


class HTTPConnection(BaseHttpConnection):

    def __init__(self):

        super().__init__()
        self.scheme = DEFAULT_HTTP_SCHEME
        self.port = DEFAULT_HTTP_PORT
        self.is_close = False

    def __del__(self):
        self.close()

    def _new_conn(self):
        """
        Establish a socket connection
        :return: socket connection
        """

        try:
            conn = create_connection(
                (self.destination_address, self.port),
                self.timeout,
                self.source_address,
            )
        except SocketTimeout:
            raise ConnectTimeoutError(
                f"Connection to {self.destination_address} timeout out. timeout={self.timeout}"
            )

        return conn

    def _ready_connect(self, **kwargs):
        """
        Ready http connection.
        :param kwargs:
        :return:
        """
        if kwargs.get("scheme", None):
            self.scheme = kwargs["scheme"]

        if kwargs.get("port", None):
            self.port = kwargs["port"]

        if kwargs.get("source_address", None):
            self.source_address = kwargs["source_address"]

        if kwargs.get("host", None):
            host = kwargs["host"].replace("http://", "").split("/")
            if len(host) > 0:
                self.host = host[0]
                self.path = "/" + "/".join(host[1:])
                if ":" in self.host:
                    self.destination_address = self.host.split(":")[0]
                    if self.port is None:
                        self.port = self.host.split(":")[1]
                else:
                    self.destination_address = self.host
            else:
                raise InvalidHost(f"Invalid Host: {kwargs['host']!r}, can not parse destination address or path.")

        if kwargs.get("timeout", None):
            self.timeout = kwargs["timeout"]

        if kwargs.get("proxy", None):
            self.proxy = kwargs["proxy"]

        if kwargs.get("proxy_username", None):
            self.proxy_username = kwargs["proxy_username"]

        if kwargs.get("proxy_password", None):
            self.proxy_password = kwargs["proxy_password"]

    def connect(
            self,
            scheme=None,
            port=None,
            source_address=None,
            host=None,
            timeout=None,
            proxy=None,
            proxy_username=None,
            proxy_password=None,
    ):

        self._ready_connect(
            scheme=scheme,
            port=port,
            source_address=source_address,
            host=host,
            timeout=timeout,
            proxy=proxy,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
        )
        conn = self._new_conn()
        self.connection = conn

    def send(self, context):
        """
        Send socket.
        :return:
        """
        self.connection.sendall(
            context.message
        )

        data = self.receive()
        response = HTTPResponse(data)
        response.begin()

        return response

        # response_data = b""
        # #
        # self.connection.settimeout(3)
        # try:
        #     while True:
        #         data = self.connection.recv(2048)
        #         if not data:
        #             break
        #         response_data += data
        # except TimeoutError:
        #     pass
        #
        # print(response_data)
        # return response_data

    def receive(self):

        response_data = bytes()
        while True:
            data = self.connection.recv(2048)
            if not data:
                self.is_close = True
                break

            response_data += data
            yield response_data

    def close(self):

        if self.connection:
            self.connection.close()
