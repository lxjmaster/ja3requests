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

        pass

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

