"""
Ja3Requests.sockets.socks
~~~~~~~~~~~~~~~~~~~~~~~~~

SOCKS4/SOCKS5 proxy socket implementation.
"""

import struct
import socket
from ja3requests.base import BaseSocket
from ja3requests.protocol.exceptions import (
    SocketException,
    ProxyError,
    ProxyTimeoutError,
)


# SOCKS5 constants
SOCKS5_VERSION = 0x05
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_PASSWORD = 0x02
SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REPLY_SUCCESS = 0x00

# SOCKS4 constants
SOCKS4_VERSION = 0x04
SOCKS4_CMD_CONNECT = 0x01
SOCKS4_REPLY_GRANTED = 0x5A


class SocksProxySocket(BaseSocket):
    """
    SOCKS4/SOCKS5 Proxy Socket.

    Supports:
    - SOCKS5 with no auth or username/password auth (RFC 1928, RFC 1929)
    - SOCKS4/SOCKS4a with optional user ID
    """

    def __init__(self, context, socks_version=5):
        super().__init__(context)
        self.socks_version = socks_version

        if self.context.proxy:
            self.proxy_host, self.proxy_port = self.context.proxy.split(":")
        else:
            self.proxy_host, self.proxy_port = None, None

        if self.context.proxy_auth:
            if ":" in self.context.proxy_auth:
                self.proxy_username, self.proxy_password = self.context.proxy_auth.split(":", 1)
            else:
                self.proxy_username, self.proxy_password = self.context.proxy_auth, None
        else:
            self.proxy_username, self.proxy_password = None, None

    def new_conn(self):
        if not self.proxy_host or not self.proxy_port:
            raise SocketException("SOCKS proxy requires host and port.")

        self.conn = self._new_conn(self.proxy_host, self.proxy_port)

        try:
            if self.socks_version == 5:
                self._socks5_handshake()
            elif self.socks_version == 4:
                self._socks4_handshake()
            else:
                raise ProxyError(f"Unsupported SOCKS version: {self.socks_version}")
        except (TimeoutError, ConnectionRefusedError, OSError) as err:
            raise ProxyTimeoutError("SOCKS proxy connection failed") from err

        return self

    def _socks5_handshake(self):
        """Perform SOCKS5 handshake (RFC 1928)."""
        dest_host = self.context.destination_address
        dest_port = self.context.port

        # Step 1: Method selection
        has_auth = self.proxy_username is not None
        if has_auth:
            # Offer both no-auth and username/password
            self.conn.sendall(struct.pack("BBB", SOCKS5_VERSION, 2, SOCKS5_AUTH_NONE) +
                              struct.pack("B", SOCKS5_AUTH_PASSWORD))
        else:
            self.conn.sendall(struct.pack("BBB", SOCKS5_VERSION, 1, SOCKS5_AUTH_NONE))

        # Receive method selection response
        resp = self._recv_exact_socks(2)
        version, method = struct.unpack("BB", resp)

        if version != SOCKS5_VERSION:
            raise ProxyError(f"SOCKS5: unexpected version {version}")

        if method == SOCKS5_AUTH_NO_ACCEPTABLE:
            raise ProxyError("SOCKS5: no acceptable authentication method")

        # Step 2: Authentication (if required)
        if method == SOCKS5_AUTH_PASSWORD:
            if not has_auth:
                raise ProxyError("SOCKS5: server requires authentication but no credentials provided")
            self._socks5_auth()
        elif method != SOCKS5_AUTH_NONE:
            raise ProxyError(f"SOCKS5: unsupported auth method {method}")

        # Step 3: Connect request
        # Use domain name (ATYP=0x03) to let proxy resolve DNS
        dest_bytes = dest_host.encode("utf-8")
        request = struct.pack("BBBB", SOCKS5_VERSION, SOCKS5_CMD_CONNECT, 0x00, SOCKS5_ATYP_DOMAIN)
        request += struct.pack("B", len(dest_bytes)) + dest_bytes
        request += struct.pack("!H", dest_port)
        self.conn.sendall(request)

        # Receive connect response
        resp = self._recv_exact_socks(4)
        version, reply, _, atyp = struct.unpack("BBBB", resp)

        if reply != SOCKS5_REPLY_SUCCESS:
            error_messages = {
                0x01: "general SOCKS server failure",
                0x02: "connection not allowed by ruleset",
                0x03: "network unreachable",
                0x04: "host unreachable",
                0x05: "connection refused",
                0x06: "TTL expired",
                0x07: "command not supported",
                0x08: "address type not supported",
            }
            msg = error_messages.get(reply, f"unknown error (0x{reply:02X})")
            raise ProxyError(f"SOCKS5 connect failed: {msg}")

        # Read and discard bound address
        if atyp == SOCKS5_ATYP_IPV4:
            self._recv_exact_socks(4 + 2)  # 4 bytes IP + 2 bytes port
        elif atyp == SOCKS5_ATYP_DOMAIN:
            addr_len = struct.unpack("B", self._recv_exact_socks(1))[0]
            self._recv_exact_socks(addr_len + 2)  # domain + port
        elif atyp == SOCKS5_ATYP_IPV6:
            self._recv_exact_socks(16 + 2)  # 16 bytes IP + 2 bytes port

    def _socks5_auth(self):
        """SOCKS5 username/password authentication (RFC 1929)."""
        username = self.proxy_username.encode("utf-8")
        password = (self.proxy_password or "").encode("utf-8")

        auth_request = struct.pack("BB", 0x01, len(username)) + username
        auth_request += struct.pack("B", len(password)) + password
        self.conn.sendall(auth_request)

        resp = self._recv_exact_socks(2)
        version, status = struct.unpack("BB", resp)
        if status != 0x00:
            raise ProxyError("SOCKS5 authentication failed")

    def _socks4_handshake(self):
        """Perform SOCKS4/SOCKS4a handshake."""
        dest_host = self.context.destination_address
        dest_port = self.context.port

        user_id = (self.proxy_username or "").encode("utf-8")

        # Try to resolve as IP for SOCKS4, fall back to SOCKS4a
        try:
            addr = socket.inet_aton(dest_host)
            # SOCKS4: real IP
            request = struct.pack("!BBH", SOCKS4_VERSION, SOCKS4_CMD_CONNECT, dest_port)
            request += addr
            request += user_id + b"\x00"
        except OSError:
            # SOCKS4a: use 0.0.0.x IP and append hostname
            request = struct.pack("!BBH", SOCKS4_VERSION, SOCKS4_CMD_CONNECT, dest_port)
            request += b"\x00\x00\x00\x01"  # invalid IP signals SOCKS4a
            request += user_id + b"\x00"
            request += dest_host.encode("utf-8") + b"\x00"

        self.conn.sendall(request)

        # Receive response (8 bytes)
        resp = self._recv_exact_socks(8)
        _, status = struct.unpack("!BH", resp[:3])
        # Note: SOCKS4 reply version byte is 0x00, status at byte 1
        status = resp[1]

        if status != SOCKS4_REPLY_GRANTED:
            error_messages = {
                0x5B: "request rejected or failed",
                0x5C: "cannot connect to identd on the client",
                0x5D: "client identd reports different user-id",
            }
            msg = error_messages.get(status, f"unknown error (0x{status:02X})")
            raise ProxyError(f"SOCKS4 connect failed: {msg}")

    def _recv_exact_socks(self, n):
        """Read exactly n bytes from the SOCKS proxy connection."""
        data = b""
        while len(data) < n:
            chunk = self.conn.recv(n - len(data))
            if not chunk:
                raise ProxyError("SOCKS proxy closed connection unexpectedly")
            data += chunk
        return data

    def send(self):
        """
        Send data through the established SOCKS tunnel.
        :return:
        """
        # For HTTPS through SOCKS, TLS handshake happens after SOCKS connect
        if hasattr(self.context, 'tls_config') and self.context.tls_config:
            return self._send_https_through_socks()

        # For HTTP through SOCKS, send directly
        self.conn.sendall(self.context.message)
        return self.conn

    def _send_https_through_socks(self):
        """Perform TLS handshake through the SOCKS tunnel."""
        from ja3requests.sockets.https import HttpsSocket  # pylint: disable=import-outside-toplevel
        from ja3requests.protocol.tls import TLS  # pylint: disable=import-outside-toplevel

        tls = TLS(self.conn)
        tls_config = self.context.tls_config
        if tls_config and not getattr(tls_config, 'server_name', None):
            tls_config.server_name = self.context.destination_address

        tls.set_payload(tls_config=tls_config)
        if not tls.handshake():
            self.conn.close()
            raise ConnectionError("TLS handshake failed through SOCKS tunnel")

        # Create an HttpsSocket wrapper to handle encrypted send
        class SocksTLSSocket(HttpsSocket):
            """HttpsSocket that uses an existing SOCKS tunnel connection."""
            def __init__(self, context, conn, tls_ctx):
                super().__init__(context)
                self.conn = conn
                self.tls = tls_ctx

        sock = SocksTLSSocket(self.context, self.conn, tls)
        return sock.send()
