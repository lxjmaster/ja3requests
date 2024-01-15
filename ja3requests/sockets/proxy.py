"""
Ja3Requests.sockets.proxy
~~~~~~~~~~~~~~~~~~~~~~~~~

This module of Proxy Socket.
"""


from base64 import b64encode
from ja3requests.base import BaseSocket
from ja3requests.protocol.exceptions import (
    SocketException,
    ProxyError,
    ProxyTimeoutError,
)


class ProxySocket(BaseSocket):
    """
    Proxy Socket
    """

    def __init__(self, context):
        super().__init__(context)
        if self.context.proxy:
            self.proxy_host, self.proxy_port = self.context.proxy.split(":")
        else:
            self.proxy_host, self.proxy_port = None, None

        if self.context.proxy_auth:
            if ":" in self.context.proxy_auth:
                (
                    self.proxy_username,
                    self.proxy_password,
                ) = self.context.proxy_auth.split(":")
            else:
                self.proxy_username, self.proxy_password = self.context.proxy_auth, None
        else:
            self.proxy_username, self.proxy_password = None, None

    def new_conn(self):
        if not self.proxy_host and not self.proxy_port:
            raise SocketException("The proxy socket must require host and port.")

        self.conn = self._new_conn(self.proxy_host, self.proxy_port)

        message = [
            f"CONNECT {self.context.destination_address}:{self.context.port} HTTP/1.1",
            f"Host: {self.context.destination_address}",
        ]
        if auth := self.context.headers.get("Proxy-Authorization", None):
            message.append(f"Proxy-Authorization: Basic {auth}")
        else:
            auth = ""
            if self.proxy_username:
                auth += self.proxy_username
            if self.proxy_password:
                auth += f":{self.proxy_password}"

            if len(auth) > 0:
                message.append(
                    f"Proxy-Authorization: Basic {b64encode(auth.encode()).decode()}"
                )

        message = "\r\n".join(message)
        message += "\r\n\r\n"

        try:
            self.conn.send(message.encode())
            status_line = self.conn.recv(4096).decode()
            proto, status_code, _ = status_line.split(" ", 2)
        except (TimeoutError, ConnectionRefusedError, UnicodeError) as err:
            raise ProxyTimeoutError("Proxy server connection time out") from err

        if not proto.startswith("HTTP/"):
            raise ProxyError("Proxy server does not appear to be an HTTP proxy")

        status_code = int(status_code)
        if status_code != 200:
            error = ""
            # Tunnel connection failed: 502 Proxy Bad Server
            if status_code in (400, 403, 405):
                error = "The HTTP proxy server may not be supported"

            elif status_code in (407,):
                error = f"Tunnel connection failed: status_code = {status_code}, Unauthorized"

            else:
                error = f"Tunnel connection failed: status_code = {status_code}"

            raise ProxyError(error)

        return self

    def send(self):
        """
        Connection send message
        :return:
        """
        self.conn.sendall(self.context.message)

        return self.conn
