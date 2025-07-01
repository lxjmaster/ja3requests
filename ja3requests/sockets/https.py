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

        # # TLS握手
        tls = TLS(self.conn)
        
        # 获取TLS配置并设置默认server_name
        tls_config = getattr(self.context, 'tls_config', None)
        if tls_config and not getattr(tls_config, 'server_name', None):
            # 如果没有设置server_name，使用destination_address作为SNI
            tls_config.server_name = self.context.destination_address
        
        # # 设置相关ja3参数等
        tls.set_payload(tls_config=tls_config)
        tls.handshake()

        return self

    def send(self):
        """
        Connection send message
        :return:
        """
        # print(self.context.message)
        self.conn.sendall(self.context.message)

        return self.conn
