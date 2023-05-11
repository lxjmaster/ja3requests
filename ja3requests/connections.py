"""
ja3requests.connections
~~~~~~~~~~~~~~~~~~~~~~~

This module contains HTTP connection and HTTPS connection.
"""

from .base import BaseHttpConnection
from .protocol.sockets import create_connection
from .protocol.exceptions import SocketTimeout, ConnectTimeoutError


class HTTPConnection(BaseHttpConnection):

    def __init__(self):

        super().__init__()

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

        if kwargs.get("destination_address", None):
            self.destination_address = kwargs["destination_address"]

            # Remove scheme
            if self.destination_address.startswith("http://"):
                self.destination_address = self.destination_address.replace("http://", "")

            # Remove port
            if ":" in self.destination_address:
                self.destination_address = self.destination_address.split(":")[0]

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
            destination_address=None,
            timeout=None,
            proxy=None,
            proxy_username=None,
            proxy_password=None,
    ):

        self._ready_connect(
            scheme=scheme,
            port=port,
            source_address=source_address,
            destination_address=destination_address,
            timeout=timeout,
            proxy=proxy,
            proxy_username=proxy_username,
            proxy_password=proxy_password,
        )
        conn = self._new_conn()
        self.connection = conn

    def send(self):
        """
        Send socket.
        :return:
        """
        self.connection.sendall(
            "GET / HTTP/1.1\r\n\r\n".encode()
        )
        response_data = b""
        while True:
            data = self.connection.recv(1024)
            if not data:
                break
            response_data += data

        return response_data

    def close(self):

        if self.connection:
            self.connection.close()
