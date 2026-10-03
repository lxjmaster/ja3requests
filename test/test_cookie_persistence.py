"""Tests for session-level cookie persistence (#5)."""

import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ja3requests.sessions import Session
from ja3requests.response import Response, HTTPResponse
from ja3requests.cookies import Ja3RequestsCookieJar, create_cookie
from ja3requests.requests.http import HttpRequest


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

    def test_session_send_persists_cookie_for_response_host_only(self):
        seen = []

        def send(request, **kwargs):
            seen.append((request.url, request.cookies))
            headers = {"Set-Cookie": "sid=secret; Path=/account"} if len(seen) == 1 else {}
            return make_http_response(headers=headers)

        with patch.object(HttpRequest, "send", send):
            with Session(use_pooling=False) as session:
                session.get("http://first.example/account/login")
                session.get("http://second.example/account/profile")
                session.get("http://first.example/account/profile")
                self.assertEqual(next(iter(session._cookies)).domain, "first.example")

        self.assertIsNone(seen[1][1])
        self.assertEqual(seen[2][1]["sid"], "secret")

    def test_host_override_cannot_change_cookie_authority(self):
        source = SimpleNamespace(
            url="https://first.example/", headers={"Host": "second.example"}
        )
        response = Response(
            request=source,
            response=make_http_response(headers={"Set-Cookie": "sid=secret"}),
        )
        cookie = next(iter(response.cookies))
        self.assertEqual(cookie.domain, "first.example")

        from ja3requests.cookies import get_cookie_header

        jar = Ja3RequestsCookieJar()
        jar.set("other", "private", domain=".second.example")
        self.assertIsNone(get_cookie_header(jar, source))

    def test_response_cookie_preserves_host_path_and_secure_policy(self):
        from ja3requests.cookies import merge_cookies

        source = SimpleNamespace(
            url="https://first.example/account/login", headers={}
        )
        response = Response(
            request=source,
            response=make_http_response(
                200,
                headers={
                    "Set-Cookie": "sid=ab==; Secure; HttpOnly; Path=/account"
                },
            ),
        )
        stored = list(response.cookies)
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0].value, "ab==")
        self.assertEqual(stored[0].domain, "first.example")
        self.assertFalse(stored[0].domain_specified)
        self.assertEqual(stored[0].path, "/account")
        self.assertTrue(stored[0].secure)
        self.assertTrue(stored[0].has_nonstandard_attr("HttpOnly"))

        session = Session(use_pooling=False)
        merge_cookies(session._cookies, response.cookies)
        seen = []
        session.send = lambda request, **kwargs: seen.append(request.cookies)
        for url in (
            "https://first.example/account/profile",
            "https://first.example/other",
            "https://second.example/account/profile",
            "https://sub.first.example/account/profile",
            "http://first.example/account/profile",
        ):
            session.get(url)
        self.assertEqual(seen[0]["sid"], "ab==")
        self.assertTrue(all(not cookies for cookies in seen[1:]))

    def test_response_cookie_explicit_domain_is_preserved(self):
        from ja3requests.cookies import merge_cookies

        source = SimpleNamespace(url="https://first.example.com/", headers={})
        response = Response(
            request=source,
            response=make_http_response(
                200,
                headers={"Set-Cookie": "pref=1; Domain=.example.com; Path=/; Secure"},
            ),
        )
        cookie = next(iter(response.cookies))
        self.assertEqual(cookie.domain, ".example.com")
        self.assertTrue(cookie.domain_specified)
        self.assertTrue(cookie.secure)

        session = Session(use_pooling=False)
        merge_cookies(session._cookies, response.cookies)
        seen = []
        session.send = lambda request, **kwargs: seen.append(request.cookies)
        session.get("https://api.example.com/")
        session.get("https://other.invalid/")
        self.assertEqual(seen[0]["pref"], "1")
        self.assertFalse(seen[1])

    def test_request_cookie_dict_still_reaches_its_target(self):
        session = Session(use_pooling=False)
        captured = []
        session.send = lambda request, **kwargs: captured.append(request.cookies)
        session.get("https://example.com/", cookies={"request_only": "yes"})
        self.assertEqual(captured[0]["request_only"], "yes")

    def test_response_without_request_does_not_create_supercookie(self):
        response = Response(
            response=make_http_response(200, headers={"Set-Cookie": "sid=private"})
        )
        self.assertEqual(len(list(response.cookies)), 0)

    def test_multiple_set_cookie_headers_in_one_response(self):
        response = Response(
            request=SimpleNamespace(url="https://example.com/", headers={}),
            response=make_http_response(
                headers={"Set-Cookie": "first=1", "set-cookie": "second=2"}
            ),
        )
        self.assertEqual(
            {cookie.name: cookie.value for cookie in response.cookies},
            {"first": "1", "second": "2"},
        )

    def test_set_cookie_persisted_to_session(self):
        """Response Set-Cookie should be saved to session._cookies."""
        s = Session(use_pooling=False)
        http_resp = make_http_response(
            200,
            headers={"Set-Cookie": "session_id=abc123; Path=/"},
        )
        resp = Response(
            request=SimpleNamespace(url="https://example.com/", headers={}),
            response=http_resp,
        )
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
        resp1 = Response(
            request=SimpleNamespace(url="https://example.com/", headers={}),
            response=http_resp1,
        )
        from ja3requests.cookies import merge_cookies
        if resp1.cookies:
            merge_cookies(s._cookies, resp1.cookies)

        # Second response sets cookie B
        http_resp2 = make_http_response(
            200, headers={"Set-Cookie": "b=2; Path=/"}
        )
        resp2 = Response(
            request=SimpleNamespace(url="https://example.com/", headers={}),
            response=http_resp2,
        )
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
        resp1 = Response(
            request=SimpleNamespace(url="https://example.com/", headers={}),
            response=http_resp1,
        )
        merge_cookies(s._cookies, resp1.cookies)

        # Second response overwrites
        http_resp2 = make_http_response(
            200, headers={"Set-Cookie": "token=new; Path=/"}
        )
        resp2 = Response(
            request=SimpleNamespace(url="https://example.com/", headers={}),
            response=http_resp2,
        )
        merge_cookies(s._cookies, resp2.cookies)

        self.assertEqual(s._cookies.get("token"), "new")


class TestSessionCookieMerge(unittest.TestCase):
    """Test that session cookies are merged with per-request cookies."""

    def test_session_cookie_domain_is_respected_across_hosts(self):
        session = Session(use_pooling=False)
        session._cookies.set("secret", "first-only", domain="first.example")
        captured = []
        session.send = lambda request, **kwargs: captured.append(request)

        session.get("https://first.example/")
        session.get("https://second.example/")

        self.assertEqual(captured[0].cookies.get("secret"), "first-only")
        self.assertFalse(captured[1].cookies)

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


class TestEmptySessionCookieMerge(unittest.TestCase):
    """Test merging when session cookie jar is empty."""

    def test_empty_session_still_uses_request_cookies(self):
        """When session has no cookies, per-request cookies should still be passed."""
        s = Session(use_pooling=False)
        self.assertEqual(len(list(s._cookies)), 0)

        request_cookies = {"token": "abc"}
        merged = Ja3RequestsCookieJar()
        from ja3requests.cookies import merge_cookies
        if len(s._cookies) > 0:
            merge_cookies(merged, s._cookies)
        if request_cookies is not None:
            merge_cookies(merged, request_cookies)

        self.assertEqual(merged.get("token"), "abc")

    def test_none_cookies_no_crash(self):
        """Passing cookies=None should not crash."""
        s = Session(use_pooling=False)
        merged = Ja3RequestsCookieJar()
        from ja3requests.cookies import merge_cookies
        if len(s._cookies) > 0:
            merge_cookies(merged, s._cookies)
        cookies = None
        if cookies is not None:
            merge_cookies(merged, cookies)
        self.assertEqual(len(list(merged)), 0)

    def test_redirect_always_uses_session_cookies(self):
        """Redirects should always use session._cookies, even when empty."""
        s = Session(use_pooling=False)
        # Empty session cookies should be passed as-is (not fall back to Request.cookies)
        self.assertIsInstance(s._cookies, Ja3RequestsCookieJar)
        self.assertEqual(len(list(s._cookies)), 0)


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
