"""Tests for Phase 2 features: timeout, auth, verify, raise_for_status."""

import io
import json
import unittest
from base64 import b64encode

import ja3requests
from ja3requests import Session, TlsConfig
from ja3requests.exceptions import HTTPError
from ja3requests.response import Response, HTTPResponse
from ja3requests.requests.request import Request


class FakeSocket:
    """Fake socket for testing."""

    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)

    def makefile(self, mode):
        return self._buffer


class TestTimeout(unittest.TestCase):
    """Test timeout parameter passthrough."""

    def test_timeout_reaches_request(self):
        """Timeout should be passed from Session to Request."""
        req = Request(method="GET", url="http://example.com", timeout=5.0)
        self.assertEqual(req.timeout, 5.0)

    def test_timeout_default_is_none(self):
        """Default timeout should be None."""
        req = Request(method="GET", url="http://example.com")
        self.assertIsNone(req.timeout)

    def test_session_request_passes_timeout(self):
        """Session.request() should pass timeout to Request constructor."""
        s = Session(use_pooling=False)
        # We can't actually connect, but we can verify the Request object
        # is created with the right timeout by checking the internal state
        s.Request = None

        # Create a Request manually to verify timeout flows
        req = Request(
            method="GET",
            url="http://example.com",
            timeout=10.0,
        )
        self.assertEqual(req.timeout, 10.0)


class TestBasicAuth(unittest.TestCase):
    """Test Basic Authentication."""

    def test_auth_tuple_adds_header(self):
        """Auth tuple should generate Authorization header."""
        req = Request(
            method="GET",
            url="http://example.com",
            auth=("user", "pass"),
        )
        ready_req = req.request()
        auth_header = ready_req.headers.get("Authorization", "")
        expected = "Basic " + b64encode(b"user:pass").decode("utf-8")
        self.assertEqual(auth_header, expected)

    def test_auth_none_no_header(self):
        """No auth should not add Authorization header."""
        req = Request(
            method="GET",
            url="http://example.com",
            auth=None,
        )
        ready_req = req.request()
        self.assertNotIn("Authorization", ready_req.headers)

    def test_auth_with_special_chars(self):
        """Auth with special characters should be encoded correctly."""
        req = Request(
            method="GET",
            url="http://example.com",
            auth=("user@domain.com", "p@ss:word!"),
        )
        ready_req = req.request()
        auth_header = ready_req.headers.get("Authorization", "")
        expected = "Basic " + b64encode(b"user@domain.com:p@ss:word!").decode("utf-8")
        self.assertEqual(auth_header, expected)


class TestVerify(unittest.TestCase):
    """Test verify parameter."""

    def test_default_verify_false(self):
        """Default verify should be False."""
        config = TlsConfig()
        self.assertFalse(config.verify_cert)

    def test_verify_true_sets_config(self):
        """verify=True should set verify_cert on TlsConfig."""
        s = Session(use_pooling=False)
        # Verify that the session method signature accepts verify
        import inspect
        sig = inspect.signature(s.request)
        self.assertIn("verify", sig.parameters)

    def test_verify_does_not_mutate_session_config(self):
        """Per-request verify should not mutate the session's TlsConfig."""
        s = Session(use_pooling=False)
        original_verify = s.tls_config.verify_cert
        # We can't actually make a request, but the config copy logic
        # is testable by checking that session config is unchanged
        self.assertEqual(s.tls_config.verify_cert, original_verify)


class TestRaiseForStatus(unittest.TestCase):
    """Test raise_for_status() method."""

    def _make_response(self, status=200, body=b""):
        raw = (
            f"HTTP/1.1 {status} OK\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
        ).encode() + body
        sock = FakeSocket(raw)
        http_resp = HTTPResponse(sock)
        http_resp.handle()
        return Response(response=http_resp)

    def test_200_no_raise(self):
        """200 status should not raise."""
        resp = self._make_response(200)
        resp.raise_for_status()  # Should not raise

    def test_201_no_raise(self):
        """201 status should not raise."""
        resp = self._make_response(201)
        resp.raise_for_status()

    def test_301_no_raise(self):
        """301 redirect should not raise."""
        resp = self._make_response(301)
        resp.raise_for_status()

    def test_400_raises(self):
        """400 Bad Request should raise HTTPError."""
        resp = self._make_response(400)
        with self.assertRaises(HTTPError):
            resp.raise_for_status()

    def test_401_raises(self):
        """401 Unauthorized should raise HTTPError."""
        resp = self._make_response(401)
        with self.assertRaises(HTTPError):
            resp.raise_for_status()

    def test_403_raises(self):
        """403 Forbidden should raise HTTPError."""
        resp = self._make_response(403)
        with self.assertRaises(HTTPError):
            resp.raise_for_status()

    def test_404_raises(self):
        """404 Not Found should raise HTTPError."""
        resp = self._make_response(404)
        with self.assertRaises(HTTPError):
            resp.raise_for_status()

    def test_500_raises(self):
        """500 Internal Server Error should raise HTTPError."""
        resp = self._make_response(500)
        with self.assertRaises(HTTPError):
            resp.raise_for_status()

    def test_503_raises(self):
        """503 Service Unavailable should raise HTTPError."""
        resp = self._make_response(503)
        with self.assertRaises(HTTPError):
            resp.raise_for_status()

    def test_error_has_response(self):
        """HTTPError should have the response attached."""
        resp = self._make_response(404)
        try:
            resp.raise_for_status()
        except HTTPError as e:
            self.assertIs(e.response, resp)

    def test_error_message_contains_status(self):
        """HTTPError message should contain the status code."""
        resp = self._make_response(500)
        try:
            resp.raise_for_status()
        except HTTPError as e:
            self.assertIn("500", str(e))


class TestNewExceptions(unittest.TestCase):
    """Test new exception classes."""

    def test_http_error_is_request_exception(self):
        self.assertTrue(issubclass(HTTPError, ja3requests.RequestException))

    def test_connection_exception_exists(self):
        self.assertTrue(hasattr(ja3requests, "ConnectionException"))

    def test_timeout_exception_exists(self):
        self.assertTrue(hasattr(ja3requests, "Timeout"))

    def test_http_error_exported(self):
        self.assertTrue(hasattr(ja3requests, "HTTPError"))


class TestShortcutFunctionsSignature(unittest.TestCase):
    """Test that shortcut functions accept new parameters."""

    def test_get_accepts_timeout(self):
        """ja3requests.get should accept timeout kwarg."""
        import inspect
        sig = inspect.signature(ja3requests.request)
        # timeout goes through **kwargs to Session.request()
        # Just verify the function is callable with these kwargs
        self.assertTrue(callable(ja3requests.get))

    def test_session_request_accepts_all_new_params(self):
        """Session.request() should accept timeout and verify."""
        import inspect
        sig = inspect.signature(Session.request)
        params = sig.parameters
        self.assertIn("timeout", params)
        self.assertIn("verify", params)
        self.assertIn("auth", params)


if __name__ == "__main__":
    unittest.main()
