"""
Ja3Requests.sockets.http
~~~~~~~~~~~~~~~~~~~~~~~~

This module of HTTP Socket.
"""

from ja3requests.base import BaseSocket
from ja3requests.protocol.tls.debug import debug


class HttpSocket(BaseSocket):
    """
    HTTP Socket with connection pooling support
    """

    def __init__(self, context, pool=None):
        super().__init__(context)
        self._pool = pool
        self._pooled_conn = None
        self._reused = False

    def new_conn(self):
        host = self.context.destination_address
        port = self.context.port

        # Try to get connection from pool
        if self._pool:
            pooled_conn = self._pool.get_connection(host, port, "http")
            if pooled_conn and pooled_conn.conn:
                debug(f"Reusing pooled HTTP connection to {host}:{port}")
                self.conn = pooled_conn.conn
                self._pooled_conn = pooled_conn
                self._reused = True
                return self

        # Create new connection
        self.conn = self._new_conn(host, port)
        self._reused = False
        return self

    def send(self):
        """
        Connection send message
        :return:
        """
        self.conn.sendall(self.context.message)
        return self.conn

    def return_to_pool(self):
        """Return connection to pool for reuse"""
        if self._pool and self.conn:
            host = self.context.destination_address
            port = self.context.port

            if self._reused and self._pooled_conn:
                success = self._pool.put_connection(
                    host, port, "http", self.conn,
                    pooled_conn=self._pooled_conn
                )
            else:
                success = self._pool.put_connection(host, port, "http", self.conn)

            if success:
                debug(f"Returned HTTP connection to pool: {host}:{port}")
                self.conn = None
                self._pooled_conn = None
            else:
                self.close()

    def close(self):
        """Close the connection"""
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        self.conn = None
