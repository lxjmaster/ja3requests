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

    def connect(self):

        conn = self._new_conn()


