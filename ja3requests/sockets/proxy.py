"""
Ja3Requests.sockets.proxy
~~~~~~~~~~~~~~~~~~~~~~~~~

This module of Proxy Socket.
"""

from base64 import b64encode
from copy import copy
import time
from ja3requests._upload import UploadSource
from ja3requests.sockets._upload import UploadExchange, upload_headers
from ja3requests.base import BaseSocket
from ja3requests.contexts.context import HTTPSContext
from ja3requests.utils import _encode_http1_headers, _validated_header_items
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

        # Validate the caller's final fields before any proxy I/O, including
        # hook edits. CONNECT authentication belongs only to the proxy.
        headers = dict(self.context.headers or {})
        validated = _validated_header_items(headers)
        host = self.context.destination_address
        authority = (
            f"[{host}]:{self.context.port}"
            if ':' in host
            else f"{host}:{self.context.port}"
        )
        tunnel_headers = {"Host": authority}
        auth = next(
            (
                headers[name] if isinstance(headers[name], bytes) else value
                for name, value in validated
                if name.lower() == 'proxy-authorization'
            ),
            None,
        )
        if auth:
            # Keep complete field values (including make_headers() output),
            # while retaining the legacy bare Basic-token input.
            if len(auth.split(None, 1)) == 1:
                auth = (b"Basic " if isinstance(auth, bytes) else "Basic ") + auth
            tunnel_headers["Proxy-Authorization"] = auth
        else:
            auth = ""
            if self.proxy_username:
                auth += self.proxy_username
            if self.proxy_password:
                auth += f":{self.proxy_password}"

            if len(auth) > 0:
                tunnel_headers["Proxy-Authorization"] = (
                    "Basic " + b64encode(auth.encode()).decode()
                )

        message = (
            f"CONNECT {authority} HTTP/1.1\r\n".encode()
            + _encode_http1_headers(tunnel_headers)
            + b"\r\n\r\n"
        )
        timeout = self.context.connect_timeout
        deadline = None if timeout is None else time.monotonic() + timeout
        self.conn = self._new_conn(self.proxy_host, self.proxy_port)

        try:
            try:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('CONNECT deadline expired')
                    self.conn.settimeout(remaining)
                self.conn.sendall(message)
                response = self._read_connect_response(deadline)
            except (TimeoutError, ConnectionRefusedError, UnicodeError) as err:
                raise ProxyTimeoutError("Proxy server connection time out") from err

            status = response.split(b'\r\n', 1)[0].split(b' ', 2)
            if (
                len(status) < 2
                or not status[0].startswith(b'HTTP/')
                or len(status[1]) != 3
                or not status[1].isdigit()
            ):
                raise ProxyError('Invalid HTTP proxy response status')
            status_code = int(status[1])
            if status_code != 200:
                if status_code in (400, 403, 405):
                    error = "The HTTP proxy server may not be supported"
                elif status_code == 407:
                    error = f"Tunnel connection failed: status_code = {status_code}, Unauthorized"
                else:
                    error = f"Tunnel connection failed: status_code = {status_code}"
                raise ProxyError(error)

            # Preserve caller metadata for retries; destination fields exclude
            # proxy credentials on every HTTP1/H2 and upload serialization path.
            self.context = copy(self.context)
            self.context._headers = {
                name: value
                for name, value in headers.items()
                if name.lower() != 'proxy-authorization'
            }
            self.context._message = None
            return self
        except BaseException:
            self.close()
            raise

    def _read_connect_response(self, deadline):
        response = bytearray()
        while not response.endswith(b'\r\n\r\n'):
            if len(response) >= 65536:
                raise ProxyError('CONNECT response headers exceed 65536 bytes')
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('CONNECT deadline expired')
                self.conn.settimeout(remaining)
            # Read exactly to the header boundary. Tunnel bytes stay on the
            # raw socket used by both plain HTTP and the TLS handshake.
            part = self.conn.recv(1)
            if not part:
                raise ProxyError('Proxy closed before CONNECT response headers')
            response.extend(part)
        return bytes(response)

    def send(self):
        """
        Connection send message
        :return:
        """
        self.conn.settimeout(getattr(self.context, 'read_timeout', None))
        # The transport type requires TLS even when no config was supplied.
        if isinstance(self.context, HTTPSContext):
            # For HTTPS through proxy, we need to do TLS handshake through the tunnel
            return self._send_https_through_proxy()
        # For HTTP through proxy, send directly
        if isinstance(self.context.data, UploadSource):
            return UploadExchange(
                self.context,
                self.conn,
                self.conn,
                self.conn.sendall,
                self.release_response,
            ).start(upload_headers(self.context))
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
        from ja3requests.sockets.https import (
            HttpsSocket,
        )  # pylint: disable=import-outside-toplevel

        sock = HttpsSocket(self.context)
        sock.conn = self.conn
        sock.tls = sock._create_tls()
        if not sock.tls.handshake():
            self.conn.close()
            raise ConnectionError("TLS handshake failed through proxy tunnel")
        return sock.send()
