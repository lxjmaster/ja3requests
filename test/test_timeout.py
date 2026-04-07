"""Tests for timeout control improvement (#10)."""

import unittest

from ja3requests.sessions import Session
from ja3requests.requests.request import Request


class FakeContext:
    """Minimal context for testing timeout properties."""

    def __init__(self):
        self._timeout = None

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, attr):
        self._timeout = attr

    @property
    def connect_timeout(self):
        if isinstance(self._timeout, tuple):
            return self._timeout[0]
        return self._timeout

    @property
    def read_timeout(self):
        if isinstance(self._timeout, tuple):
            return self._timeout[1] if len(self._timeout) > 1 else self._timeout[0]
        return self._timeout


class TestTimeoutTupleSupport(unittest.TestCase):
    """Test that timeout can be a tuple (connect, read)."""

    def test_single_float_timeout(self):
        """Single float applies to both connect and read."""
        from ja3requests.base.__contexts import BaseContext

        class TestContext(BaseContext):
            def set_payload(self, **kwargs):
                pass

        ctx = TestContext()
        ctx.timeout = 10.0
        self.assertEqual(ctx.connect_timeout, 10.0)
        self.assertEqual(ctx.read_timeout, 10.0)

    def test_tuple_timeout(self):
        """Tuple separates connect and read timeouts."""
        from ja3requests.base.__contexts import BaseContext

        class TestContext(BaseContext):
            def set_payload(self, **kwargs):
                pass

        ctx = TestContext()
        ctx.timeout = (5.0, 30.0)
        self.assertEqual(ctx.connect_timeout, 5.0)
        self.assertEqual(ctx.read_timeout, 30.0)

    def test_none_timeout(self):
        """None timeout returns None for both."""
        from ja3requests.base.__contexts import BaseContext

        class TestContext(BaseContext):
            def set_payload(self, **kwargs):
                pass

        ctx = TestContext()
        ctx.timeout = None
        self.assertIsNone(ctx.connect_timeout)
        self.assertIsNone(ctx.read_timeout)


class TestTimeoutPassthrough(unittest.TestCase):
    """Test timeout flows through Session -> Request."""

    def test_single_timeout_reaches_request(self):
        req = Request(method="GET", url="http://example.com", timeout=10.0)
        self.assertEqual(req.timeout, 10.0)

    def test_tuple_timeout_reaches_request(self):
        req = Request(method="GET", url="http://example.com", timeout=(5, 30))
        self.assertEqual(req.timeout, (5, 30))

    def test_session_request_signature_accepts_timeout(self):
        """Session.request() accepts timeout parameter."""
        import inspect
        sig = inspect.signature(Session.request)
        self.assertIn("timeout", sig.parameters)


class TestTLSHandshakeTimeout(unittest.TestCase):
    """Test TLS handshake uses configurable timeout."""

    def test_tls_accepts_handshake_timeout(self):
        """TLS constructor accepts handshake_timeout parameter."""
        from ja3requests.protocol.tls import TLS
        import socket

        # Create a dummy socket pair for testing
        s1, s2 = socket.socketpair()
        try:
            tls = TLS(s1, handshake_timeout=10.0)
            self.assertEqual(tls._handshake_timeout, 10.0)
        finally:
            s1.close()
            s2.close()

    def test_tls_default_handshake_timeout_none(self):
        """Default handshake timeout is None."""
        from ja3requests.protocol.tls import TLS
        import socket

        s1, s2 = socket.socketpair()
        try:
            tls = TLS(s1)
            self.assertIsNone(tls._handshake_timeout)
        finally:
            s1.close()
            s2.close()


class TestFakeContextTimeoutProperties(unittest.TestCase):
    """Test the timeout property helpers directly."""

    def test_single_value(self):
        ctx = FakeContext()
        ctx.timeout = 5.0
        self.assertEqual(ctx.connect_timeout, 5.0)
        self.assertEqual(ctx.read_timeout, 5.0)

    def test_tuple_value(self):
        ctx = FakeContext()
        ctx.timeout = (3.0, 20.0)
        self.assertEqual(ctx.connect_timeout, 3.0)
        self.assertEqual(ctx.read_timeout, 20.0)

    def test_single_element_tuple(self):
        ctx = FakeContext()
        ctx.timeout = (5.0,)
        self.assertEqual(ctx.connect_timeout, 5.0)
        self.assertEqual(ctx.read_timeout, 5.0)

    def test_none_value(self):
        ctx = FakeContext()
        ctx.timeout = None
        self.assertIsNone(ctx.connect_timeout)
        self.assertIsNone(ctx.read_timeout)

    def test_zero_timeout(self):
        ctx = FakeContext()
        ctx.timeout = 0
        self.assertEqual(ctx.connect_timeout, 0)
        self.assertEqual(ctx.read_timeout, 0)


if __name__ == "__main__":
    unittest.main()
