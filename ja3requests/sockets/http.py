"""
Ja3Requests.sockets.http
~~~~~~~~~~~~~~~~~~~~~~~~

This module of HTTP Socket.
"""


from ja3requests.base import BaseSocket


class HttpSocket(BaseSocket):
    """
    HTTP Socket
    """

    def new_conn(self):
        self.conn = self._new_conn(self.context.destination_address, self.context.port)
        return self

    def send(self):
        """
        Connection send message
        :return:
        """
        self.conn.sendall(self.context.message)

        return self.conn
