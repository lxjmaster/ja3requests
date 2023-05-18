"""
ja3requests.connections
~~~~~~~~~~~~~~~~~~~~~~~

This module contains HTTP connection and HTTPS connection.
"""


from .response import HTTPResponse
from .exceptions import InvalidHost
from .base import BaseHttpConnection
from .protocol.sockets import create_connection
from .const import DEFAULT_HTTP_SCHEME
from .const import DEFAULT_HTTP_PORT
from .protocol.exceptions import SocketTimeout, ConnectTimeoutError


class HTTPConnection(BaseHttpConnection):
    """
    HTTP connection.
    """

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
        except SocketTimeout as err:
            raise ConnectTimeoutError(
                f"Connection to {self.destination_address} timeout out. timeout={self.timeout}"
            ) from err

        return conn

    def _ready_connect(self, **kwargs):
        """
        Ready http connection.
        :param kwargs:
        :return:
        """
        self.scheme = kwargs["scheme"] if kwargs.get("scheme", None) else self.scheme
        self.port = kwargs["port"] if kwargs.get("port", None) else self.port
        self.source_address = (
            kwargs["source_address"]
            if kwargs.get("source_address", None)
            else self.source_address
        )
        self.timeout = (
            kwargs["timeout"] if kwargs.get("timeout", None) else self.timeout
        )
        self.proxy = kwargs["proxy"] if kwargs.get("proxy", None) else self.proxy
        self.proxy_username = (
            kwargs["proxy_username"]
            if kwargs.get("proxy_username", None)
            else self.proxy_username
        )
        self.proxy_password = (
            kwargs["proxy_password"]
            if kwargs.get("proxy_password", None)
            else self.proxy_password
        )

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
                raise InvalidHost(
                    f"Invalid Host: {kwargs['host']!r}, can not parse destination address or path."
                )

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
        """
        Create an http connection.
        :param scheme:
        :param port:
        :param source_address:
        :param host:
        :param timeout:
        :param proxy:
        :param proxy_username:
        :param proxy_password:
        :return:
        """
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
        self.connection.sendall(context.message)

        response = HTTPResponse(sock=self.connection, method=context.method)
        response.begin()

        return response

    def close(self):
        """
        Close connection.
        :return:
        """
        if self.connection:
            self.connection.close()
