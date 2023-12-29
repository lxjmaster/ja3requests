from ja3requests.base import BaseSocket
from ja3requests.protocol.sockets import create_connection
from ja3requests.protocol.exceptions import SocketError, SocketTimeout, ConnectTimeoutError
from ja3requests.utils import Retry
import socket


class HttpSocket(BaseSocket):

    def new_conn(self):

        self.conn = self._new_conn()
        return self

    def _new_conn(self):

        try:
            retry = Retry()
            conn = retry.do(
                create_connection,
                socket.error,
                (self.context.destination_address, self.context.port),
                self.context.timeout,
                self.context.source_address
            )
        except SocketTimeout as err:
            raise ConnectTimeoutError(
                f"Connection to {self.context.destination_address} timeout out. timeout={self.context.timeout}"
            ) from err

        return conn

    def send(self):

        print(self.context.message)
        self.conn.sendall(self.context.message.encode())

        return self.conn

