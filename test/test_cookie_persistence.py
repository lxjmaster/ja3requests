"""Tests for session-level cookie persistence (#5)."""

import io
import unittest

from ja3requests.sessions import Session
from ja3requests.response import Response, HTTPResponse
from ja3requests.cookies import Ja3RequestsCookieJar, create_cookie


class FakeSocket:
    """Fake socket for testing response parsing."""

    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)

    def makefile(self, mode):
        return self._buffer


def make_http_response(status=200, headers=None, body=b""):
    """Build a raw HTTP response and return an HTTPResponse object."""
    headers = headers or {}
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    raw = (
        f"HTTP/1.1 {status} OK\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{header_lines}"
        f"\r\n"
    ).encode() + body
    sock = FakeSocket(raw)
    resp = HTTPResponse(sock)
    resp.handle()
    return resp


class TestSessionCookieInit(unittest.TestCase):
    """Test session cookie jar initialization."""

    def test_session_has_cookie_jar(self):
        s = Session(use_pooling=False)
        self.assertIsInstance(s._cookies, Ja3RequestsCookieJar)

    def test_session_cookie_jar_initially_empty(self):
        s = Session(use_pooling=False)
        self.assertEqual(len(list(s._cookies)), 0)


class TestResponseCookiePersistence(unittest.TestCase):
    """Test that response cookies are persisted to session."""

    def test_set_cookie_persisted_to_session(self):
        """Response Set-Cookie should be saved to session._cookies."""
        s = Session(use_pooling=False)
        http_resp = make_http_response(
            200,
            headers={"Set-Cookie": "session_id=abc123; Path=/"},
        )
        resp = Response(response=http_resp)
        # Simulate what Session.send() does
        from ja3requests.cookies import merge_cookies
        if resp.cookies:
            merge_cookies(s._cookies, resp.cookies)

        self.assertEqual(s._cookies.get("session_id"), "abc123")

    def test_multiple_cookies_persisted(self):
        """Multiple Set-Cookie headers should all be persisted."""
        s = Session(use_pooling=False)

        # First response sets cookie A
        http_resp1 = make_http_response(
            200, headers={"Set-Cookie": "a=1; Path=/"}
        )
        resp1 = Response(response=http_resp1)
        from ja3requests.cookies import merge_cookies
        if resp1.cookies:
            merge_cookies(s._cookies, resp1.cookies)

        # Second response sets cookie B
        http_resp2 = make_http_response(
            200, headers={"Set-Cookie": "b=2; Path=/"}
        )
        resp2 = Response(response=http_resp2)
        if resp2.cookies:
            merge_cookies(s._cookies, resp2.cookies)

        self.assertEqual(s._cookies.get("a"), "1")
        self.assertEqual(s._cookies.get("b"), "2")

    def test_cookie_overwrite(self):
        """A new response should overwrite an existing cookie with the same name."""
        s = Session(use_pooling=False)
        from ja3requests.cookies import merge_cookies

        # First response
        http_resp1 = make_http_response(
            200, headers={"Set-Cookie": "token=old; Path=/"}
        )
        resp1 = Response(response=http_resp1)
        merge_cookies(s._cookies, resp1.cookies)

        # Second response overwrites
        http_resp2 = make_http_response(
            200, headers={"Set-Cookie": "token=new; Path=/"}
        )
        resp2 = Response(response=http_resp2)
        merge_cookies(s._cookies, resp2.cookies)

        self.assertEqual(s._cookies.get("token"), "new")


class TestSessionCookieMerge(unittest.TestCase):
    """Test that session cookies are merged with per-request cookies."""

    def test_session_cookies_merge_with_request_cookies(self):
        """Session cookies and per-request cookies should be merged."""
        s = Session(use_pooling=False)

        # Pre-populate session cookies
        s._cookies.set("session_cookie", "from_session")

        # Per-request cookies
        request_cookies = {"request_cookie": "from_request"}

        # Simulate what Session.request() does
        merged = Ja3RequestsCookieJar()
        from ja3requests.cookies import merge_cookies
        merge_cookies(merged, s._cookies)
        merge_cookies(merged, request_cookies)

        self.assertEqual(merged.get("session_cookie"), "from_session")
        self.assertEqual(merged.get("request_cookie"), "from_request")

    def test_session_cookies_preserved_on_conflict(self):
        """Session cookies should be preserved when per-request dict has same name."""
        s = Session(use_pooling=False)

        s._cookies.set("shared", "session_value")

        request_cookies = {"shared": "request_value"}

        merged = Ja3RequestsCookieJar()
        from ja3requests.cookies import merge_cookies
        merge_cookies(merged, s._cookies)
        merge_cookies(merged, request_cookies)

        # Session cookies are added first; merge_cookies with dict uses overwrite=False
        self.assertEqual(merged.get("shared"), "session_value")


class TestContextManagerCookies(unittest.TestCase):
    """Test cookies work correctly with context manager."""

    def test_cookies_accessible_via_context(self):
        with Session(use_pooling=False) as s:
            s._cookies.set("test", "value")
            self.assertEqual(s._cookies.get("test"), "value")


class TestCookieJarDictInterface(unittest.TestCase):
    """Test the dict-like interface of session cookies."""

    def test_set_and_get(self):
        s = Session(use_pooling=False)
        s._cookies["key"] = "value"
        self.assertEqual(s._cookies["key"], "value")

    def test_items(self):
        s = Session(use_pooling=False)
        s._cookies["a"] = "1"
        s._cookies["b"] = "2"
        items = dict(s._cookies.items())
        self.assertEqual(items, {"a": "1", "b": "2"})

    def test_delete(self):
        s = Session(use_pooling=False)
        s._cookies["temp"] = "val"
        del s._cookies["temp"]
        with self.assertRaises(KeyError):
            _ = s._cookies["temp"]


if __name__ == "__main__":
    unittest.main()
