from ja3requests.base import BaseSocket
from ja3requests.protocol.sockets import create_connection
from ja3requests.protocol.exceptions import SocketTimeout, ConnectTimeoutError


class HttpSocket(BaseSocket):

    def new_conn(self):

        return self

    def _new_conn(self):
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

    def send(self):
        pass
