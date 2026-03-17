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
        # Check if this is an HTTPS request through proxy
        if hasattr(self.context, 'tls_config') and self.context.tls_config:
            # For HTTPS through proxy, we need to do TLS handshake through the tunnel
            return self._send_https_through_proxy()
        # For HTTP through proxy, send directly
        self.conn.sendall(self.context.message)
        return self.conn

    def _send_https_through_proxy(self):
        """
        Send HTTPS request through proxy tunnel
        :return:
        """
        # At this point, the CONNECT tunnel should be established
        # Now we need to perform TLS handshake through the tunnel

        # Use the existing HttpsSocket implementation through the tunnel
        # This avoids duplicating the TLS logic
        return self._create_https_socket_through_tunnel()

    def _create_https_socket_through_tunnel(self):
        """
        Create an HTTPS socket that works through the proxy tunnel
        """
        from ja3requests.sockets.https import HttpsSocket  # pylint: disable=import-outside-toplevel
        from ja3requests.protocol.tls import TLS  # pylint: disable=import-outside-toplevel

        # Create a proxy-wrapped context that uses the tunnel connection
        class TunnelContext:
            """Context wrapper that routes through a proxy tunnel connection."""

            def __init__(self, original_context, tunnel_conn):
                self.original_context = original_context
                self.tunnel_conn = tunnel_conn
                # Copy all attributes from original context
                for attr in dir(original_context):
                    if not attr.startswith('_'):
                        setattr(self, attr, getattr(original_context, attr))

        tunnel_context = TunnelContext(self.context, self.conn)

        # Create an HTTPS socket that uses the tunnel connection
        class TunnelHttpsSocket(HttpsSocket):
            """HTTPS socket that performs TLS handshake through a proxy tunnel."""

            def __init__(self, context, tunnel_conn):
                super().__init__(context)
                self.tunnel_conn = tunnel_conn

            def new_conn(self):
                # Instead of creating a new connection, use the tunnel connection
                self.conn = self.tunnel_conn

                # Now perform TLS handshake through the tunnel
                tls = TLS(self.conn)

                # Set up TLS configuration
                tls_config = getattr(self.context, 'tls_config', None)
                if tls_config and not getattr(tls_config, 'server_name', None):
                    tls_config.server_name = self.context.destination_address

                tls.set_payload(tls_config=tls_config)
                handshake_success = tls.handshake()

                if not handshake_success:
                    self.conn.close()
                    raise ConnectionError("TLS handshake failed through proxy tunnel")

                # Store TLS instance
                self.tls = tls
                return self

        # Create the tunnel HTTPS socket and establish connection
        tunnel_https_socket = TunnelHttpsSocket(tunnel_context, self.conn)
        tunnel_https_socket.new_conn()

        # Send the request through the TLS connection
        return tunnel_https_socket.send()
