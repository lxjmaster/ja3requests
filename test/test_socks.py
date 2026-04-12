"""Tests for SOCKS4/SOCKS5 proxy support (#12)."""

import struct
import socket
import unittest

from ja3requests.sockets.socks import (
    SocksProxySocket,
    SOCKS5_VERSION,
    SOCKS5_AUTH_NONE,
    SOCKS5_AUTH_PASSWORD,
    SOCKS5_REPLY_SUCCESS,
    SOCKS4_VERSION,
    SOCKS4_CMD_CONNECT,
    SOCKS4_REPLY_GRANTED,
)
from ja3requests.protocol.exceptions import ProxyError


class TestProxySchemeDetection(unittest.TestCase):
    """Test proxy_scheme property on context."""

    def _make_context(self, proxy_value):
        from ja3requests.base.__contexts import BaseContext

        class TestContext(BaseContext):
            def set_payload(self, **kwargs):
                pass

        ctx = TestContext()
        ctx._proxy = proxy_value
        return ctx

    def test_socks5_scheme(self):
        ctx = self._make_context("socks5://127.0.0.1:1080")
        self.assertEqual(ctx.proxy_scheme, "socks5")

    def test_socks4_scheme(self):
        ctx = self._make_context("socks4://127.0.0.1:1080")
        self.assertEqual(ctx.proxy_scheme, "socks4")

    def test_http_scheme(self):
        ctx = self._make_context("http://127.0.0.1:8080")
        self.assertEqual(ctx.proxy_scheme, "http")

    def test_no_scheme(self):
        ctx = self._make_context("127.0.0.1:8080")
        self.assertIsNone(ctx.proxy_scheme)

    def test_none_proxy(self):
        ctx = self._make_context(None)
        self.assertIsNone(ctx.proxy_scheme)


class TestProxyHostParsing(unittest.TestCase):
    """Test proxy host/port parsing with scheme URLs."""

    def _make_context(self, proxy_value):
        from ja3requests.base.__contexts import BaseContext

        class TestContext(BaseContext):
            def set_payload(self, **kwargs):
                pass

        ctx = TestContext()
        ctx._proxy = proxy_value
        return ctx

    def test_socks5_host_port(self):
        ctx = self._make_context("socks5://127.0.0.1:1080")
        self.assertEqual(ctx.proxy, "127.0.0.1:1080")

    def test_socks5_with_auth(self):
        ctx = self._make_context("socks5://user:pass@127.0.0.1:1080")
        self.assertEqual(ctx.proxy, "127.0.0.1:1080")
        self.assertEqual(ctx.proxy_auth, "user:pass")

    def test_plain_proxy_unchanged(self):
        ctx = self._make_context("127.0.0.1:8080")
        self.assertEqual(ctx.proxy, "127.0.0.1:8080")

    def test_plain_proxy_with_auth(self):
        ctx = self._make_context("user:pass@127.0.0.1:8080")
        self.assertEqual(ctx.proxy, "127.0.0.1:8080")
        self.assertEqual(ctx.proxy_auth, "user:pass")


class TestSOCKS5Handshake(unittest.TestCase):
    """Test SOCKS5 protocol messages (unit-level with socket pairs)."""

    def test_socks5_no_auth_connect(self):
        """SOCKS5 no-auth handshake produces correct wire format."""
        s_client, s_server = socket.socketpair()
        try:
            from ja3requests.base.__contexts import BaseContext

            class TestContext(BaseContext):
                def set_payload(self, **kwargs):
                    pass

            ctx = TestContext()
            ctx._proxy = "127.0.0.1:1080"
            ctx._destination_address = "example.com"
            ctx._port = 443

            sock = SocksProxySocket(ctx, socks_version=5)
            sock.conn = s_client

            # Server side: respond to method selection
            import threading

            def server_side():
                # Read method selection
                data = s_server.recv(16)
                self.assertEqual(data[0], SOCKS5_VERSION)  # version
                # Respond: no auth required
                s_server.sendall(struct.pack("BB", SOCKS5_VERSION, SOCKS5_AUTH_NONE))

                # Read connect request
                data = s_server.recv(256)
                self.assertEqual(data[0], SOCKS5_VERSION)  # version
                self.assertEqual(data[1], 0x01)  # CONNECT
                self.assertEqual(data[3], 0x03)  # DOMAIN

                # Respond: success with bound addr
                resp = struct.pack("BBBB", SOCKS5_VERSION, SOCKS5_REPLY_SUCCESS, 0x00, 0x01)
                resp += b"\x00\x00\x00\x00"  # bound addr (0.0.0.0)
                resp += struct.pack("!H", 0)  # bound port
                s_server.sendall(resp)

            t = threading.Thread(target=server_side)
            t.start()

            sock._socks5_handshake()
            t.join(timeout=2)

        finally:
            s_client.close()
            s_server.close()

    def test_socks5_auth_connect(self):
        """SOCKS5 username/password auth produces correct wire format."""
        s_client, s_server = socket.socketpair()
        try:
            from ja3requests.base.__contexts import BaseContext

            class TestContext(BaseContext):
                def set_payload(self, **kwargs):
                    pass

            ctx = TestContext()
            ctx._proxy = "socks5://testuser:testpass@127.0.0.1:1080"
            ctx._destination_address = "example.com"
            ctx._port = 80

            sock = SocksProxySocket(ctx, socks_version=5)
            sock.conn = s_client

            import threading

            def server_side():
                # Method selection
                s_server.recv(16)
                s_server.sendall(struct.pack("BB", SOCKS5_VERSION, SOCKS5_AUTH_PASSWORD))

                # Auth
                auth_data = s_server.recv(256)
                self.assertEqual(auth_data[0], 0x01)  # auth version
                ulen = auth_data[1]
                username = auth_data[2:2 + ulen].decode()
                self.assertEqual(username, "testuser")
                # Respond: auth success
                s_server.sendall(struct.pack("BB", 0x01, 0x00))

                # Connect request
                s_server.recv(256)
                resp = struct.pack("BBBB", SOCKS5_VERSION, SOCKS5_REPLY_SUCCESS, 0x00, 0x01)
                resp += b"\x00\x00\x00\x00" + struct.pack("!H", 0)
                s_server.sendall(resp)

            t = threading.Thread(target=server_side)
            t.start()

            sock._socks5_handshake()
            t.join(timeout=2)

        finally:
            s_client.close()
            s_server.close()

    def test_socks5_connect_refused(self):
        """SOCKS5 connection refused error."""
        s_client, s_server = socket.socketpair()
        try:
            from ja3requests.base.__contexts import BaseContext

            class TestContext(BaseContext):
                def set_payload(self, **kwargs):
                    pass

            ctx = TestContext()
            ctx._proxy = "127.0.0.1:1080"
            ctx._destination_address = "example.com"
            ctx._port = 443

            sock = SocksProxySocket(ctx, socks_version=5)
            sock.conn = s_client

            import threading

            def server_side():
                s_server.recv(16)
                s_server.sendall(struct.pack("BB", SOCKS5_VERSION, SOCKS5_AUTH_NONE))
                s_server.recv(256)
                # Reply: connection refused (0x05)
                resp = struct.pack("BBBB", SOCKS5_VERSION, 0x05, 0x00, 0x01)
                resp += b"\x00\x00\x00\x00" + struct.pack("!H", 0)
                s_server.sendall(resp)

            t = threading.Thread(target=server_side)
            t.start()

            with self.assertRaises(ProxyError) as cm:
                sock._socks5_handshake()
            self.assertIn("connection refused", str(cm.exception))
            t.join(timeout=2)

        finally:
            s_client.close()
            s_server.close()


class TestSOCKS4Handshake(unittest.TestCase):
    """Test SOCKS4/4a protocol messages."""

    def test_socks4a_connect(self):
        """SOCKS4a handshake with hostname."""
        s_client, s_server = socket.socketpair()
        try:
            from ja3requests.base.__contexts import BaseContext

            class TestContext(BaseContext):
                def set_payload(self, **kwargs):
                    pass

            ctx = TestContext()
            ctx._proxy = "127.0.0.1:1080"
            ctx._destination_address = "example.com"
            ctx._port = 80

            sock = SocksProxySocket(ctx, socks_version=4)
            sock.conn = s_client

            import threading

            def server_side():
                data = s_server.recv(256)
                self.assertEqual(data[0], SOCKS4_VERSION)
                self.assertEqual(data[1], SOCKS4_CMD_CONNECT)
                # Reply: granted
                resp = struct.pack("!BBH", 0x00, SOCKS4_REPLY_GRANTED, 0)
                resp += b"\x00\x00\x00\x00"
                s_server.sendall(resp)

            t = threading.Thread(target=server_side)
            t.start()

            sock._socks4_handshake()
            t.join(timeout=2)

        finally:
            s_client.close()
            s_server.close()

    def test_socks4_rejected(self):
        """SOCKS4 request rejected."""
        s_client, s_server = socket.socketpair()
        try:
            from ja3requests.base.__contexts import BaseContext

            class TestContext(BaseContext):
                def set_payload(self, **kwargs):
                    pass

            ctx = TestContext()
            ctx._proxy = "127.0.0.1:1080"
            ctx._destination_address = "example.com"
            ctx._port = 80

            sock = SocksProxySocket(ctx, socks_version=4)
            sock.conn = s_client

            import threading

            def server_side():
                s_server.recv(256)
                resp = struct.pack("!BBH", 0x00, 0x5B, 0)  # rejected
                resp += b"\x00\x00\x00\x00"
                s_server.sendall(resp)

            t = threading.Thread(target=server_side)
            t.start()

            with self.assertRaises(ProxyError) as cm:
                sock._socks4_handshake()
            self.assertIn("rejected", str(cm.exception))
            t.join(timeout=2)

        finally:
            s_client.close()
            s_server.close()


class TestRequestRouting(unittest.TestCase):
    """Test that SOCKS proxy is routed correctly in request classes."""

    def test_https_request_imports_socks(self):
        from ja3requests.requests.https import SocksProxySocket as Imported
        self.assertIs(Imported, SocksProxySocket)

    def test_http_request_imports_socks(self):
        from ja3requests.requests.http import SocksProxySocket as Imported
        self.assertIs(Imported, SocksProxySocket)


if __name__ == "__main__":
    unittest.main()
