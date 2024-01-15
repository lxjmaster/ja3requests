"""
Ja3Requests.base.__sockets
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic of Socket.
"""

import socket
from abc import ABC, abstractmethod
from ja3requests.base.__contexts import BaseContext
from ja3requests.protocol.sockets import create_connection
from ja3requests.protocol.exceptions import (
    SocketTimeout,
    ConnectTimeoutError,
)
from ja3requests.utils import Retry


class BaseSocket(ABC):
    """
    Basic socket class
    """

    def __init__(self, context: BaseContext):
        self.context = context
        self._conn = None

    @property
    def conn(self):
        """
        Socket property conn
        :return:
        """
        return self._conn

    @conn.setter
    def conn(self, attr):
        """
        Socket property conn set
        :param attr:
        :return:
        """
        self._conn = attr

    @abstractmethod
    def new_conn(self):
        """
        New socket connection
        :return:
        """
        raise NotImplementedError("new_conn method must be implemented by subclass.")

    def _new_conn(self, dest_address, port):
        try:
            retry = Retry()
            conn = retry.do(
                create_connection,
                socket.error,
                (dest_address, port),
                self.context.timeout,
                self.context.source_address,
            )
        except SocketTimeout as err:
            raise ConnectTimeoutError(
                f"Connection to {dest_address}:{port} timeout out."
            ) from err

        return conn
