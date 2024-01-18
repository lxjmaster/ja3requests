"""
Ja3Requests.sockets.https
~~~~~~~~~~~~~~~~~~~~~~~~~

This module of HTTPS Socket.
"""


from ja3requests.base import BaseSocket
from ja3requests.protocol.tls import TLS


class HttpsSocket(BaseSocket):
    """
    HTTPS Socket
    """

    def new_conn(self):
        # 建立链接
        self.conn = self._new_conn(self.context.destination_address, self.context.port)

        # TLS握手
        tls = TLS(self.conn)
        # 设置相关ja3参数等
        tls.set_payload(
            # TODO set tls payload
        )
        tls.handshake()

        return self

    def send(self):
        """
        Connection send message
        :return:
        """
        self.conn.sendall(self.context.message)

        return self.conn
