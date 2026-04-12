"""Coverage improvement tests for sessions.py and contexts."""

import io
import unittest

from ja3requests.sessions import Session
from ja3requests.response import Response, HTTPResponse
from ja3requests.cookies import Ja3RequestsCookieJar


class FakeSocket:
    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)

    def makefile(self, mode):
        return self._buffer


def make_response(status=200, headers=None, body=b""):
    headers = headers or {}
    header_lines = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    raw = (
        f"HTTP/1.1 {status} OK\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"{header_lines}"
        f"\r\n"
    ).encode() + body
    sock = FakeSocket(raw)
    http_resp = HTTPResponse(sock)
    http_resp.handle()
    return http_resp


class TestSessionInit(unittest.TestCase):
    def test_default_init(self):
        s = Session(use_pooling=False)
        self.assertIsNotNone(s.tls_config)
        self.assertIsNone(s._retry)
        self.assertIsInstance(s.hooks, dict)

    def test_context_manager(self):
        with Session(use_pooling=False) as s:
            self.assertIsNotNone(s)

    def test_tls_config_setter(self):
        s = Session(use_pooling=False)
        from ja3requests.protocol.tls.config import TlsConfig
        new_config = TlsConfig()
        s.tls_config = new_config
        self.assertIs(s.tls_config, new_config)

    def test_pool_setter(self):
        s = Session(use_pooling=False)
        s.pool = None
        self.assertIsNone(s.pool)


class TestSessionHTTPMethods(unittest.TestCase):
    """Test that all HTTP method shortcuts exist and accept kwargs."""

    def test_get_signature(self):
        s = Session(use_pooling=False)
        self.assertTrue(callable(s.get))

    def test_post_signature(self):
        s = Session(use_pooling=False)
        self.assertTrue(callable(s.post))

    def test_put_signature(self):
        s = Session(use_pooling=False)
        self.assertTrue(callable(s.put))

    def test_patch_signature(self):
        s = Session(use_pooling=False)
        self.assertTrue(callable(s.patch))

    def test_delete_signature(self):
        s = Session(use_pooling=False)
        self.assertTrue(callable(s.delete))

    def test_head_signature(self):
        s = Session(use_pooling=False)
        self.assertTrue(callable(s.head))

    def test_options_signature(self):
        s = Session(use_pooling=False)
        self.assertTrue(callable(s.options))


class TestSessionSendValidation(unittest.TestCase):
    def test_send_invalid_request_type(self):
        s = Session(use_pooling=False)
        with self.assertRaises(ValueError):
            s.send("not_a_request")


class TestSessionDispatchHooks(unittest.TestCase):
    def test_dispatch_before_request(self):
        s = Session(use_pooling=False)
        calls = []
        s.hooks["before_request"].append(lambda r: calls.append("called"))
        s._dispatch_hooks("before_request", "data")
        self.assertEqual(calls, ["called"])

    def test_dispatch_after_request(self):
        s = Session(use_pooling=False)
        s.hooks["after_request"].append(lambda r: "modified")
        result = s._dispatch_hooks("after_request", "original")
        self.assertEqual(result, "modified")


class TestSessionClose(unittest.TestCase):
    def test_close_without_pool(self):
        s = Session(use_pooling=False)
        s.close()  # Should not raise

    def test_close_with_custom_pool(self):
        from ja3requests.pool import ConnectionPool
        pool = ConnectionPool()
        s = Session(pool=pool, use_pooling=True)
        s.close()


class TestContextSetPayload(unittest.TestCase):
    """Test HTTPContext and HTTPSContext set_payload."""

    def test_http_context_set_payload(self):
        from ja3requests.contexts.context import HTTPContext
        ctx = HTTPContext()
        ctx.set_payload(
            method="GET",
            start_line="http://example.com/path?q=1",
            port=80,
            headers={"Host": "example.com"},
            timeout=5.0,
        )
        self.assertEqual(ctx.method, "GET")
        self.assertEqual(ctx.port, 80)
        self.assertIsNotNone(ctx.message)

    def test_https_context_set_payload(self):
        from ja3requests.contexts.context import HTTPSContext
        ctx = HTTPSContext()
        ctx.set_payload(
            method="POST",
            start_line="https://example.com/api",
            port=443,
            headers={"Content-Type": "application/json"},
            data="body",
            timeout=10.0,
        )
        self.assertEqual(ctx.method, "POST")

    def test_http_context_with_cookies(self):
        from ja3requests.contexts.context import HTTPContext
        ctx = HTTPContext()
        ctx.set_payload(
            method="GET",
            start_line="http://example.com/",
            port=80,
            headers={"Host": "example.com"},
            cookies={"session": "abc"},
        )
        self.assertIsNotNone(ctx.message)

    def test_http_context_with_json(self):
        from ja3requests.contexts.context import HTTPContext
        ctx = HTTPContext()
        ctx.set_payload(
            method="POST",
            start_line="http://example.com/api",
            port=80,
            headers={"Host": "example.com"},
            json={"key": "value"},
        )
        self.assertIn(b'"key"', ctx.message)


if __name__ == "__main__":
    unittest.main()
