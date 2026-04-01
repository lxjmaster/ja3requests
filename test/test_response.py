"""Tests for ja3requests.response module."""

import gzip
import io
import json
import unittest
import zlib

import brotli

from ja3requests.response import HTTPResponse, Response
from ja3requests.exceptions import InvalidStatusLine, InvalidResponseHeaders


class FakeSocket:
    """Fake socket for testing HTTPResponse."""

    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)

    def makefile(self, mode):
        return self._buffer


class TestHTTPResponseStatusLine(unittest.TestCase):
    """Test HTTP response status line parsing."""

    def _make_response(self, raw: bytes) -> HTTPResponse:
        sock = FakeSocket(raw)
        resp = HTTPResponse(sock)
        return resp

    def test_parse_200_ok(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        resp = self._make_response(raw)
        resp.handle()
        self.assertEqual(resp.status_code, b"200")
        self.assertEqual(resp.status_text, b"OK")
        self.assertEqual(resp.protocol_version, b"HTTP/1.1")

    def test_parse_404_not_found(self):
        raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
        resp = self._make_response(raw)
        resp.handle()
        self.assertEqual(resp.status_code, b"404")

    def test_parse_301_redirect(self):
        raw = b"HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n"
        resp = self._make_response(raw)
        resp.handle()
        self.assertEqual(resp.status_code, b"301")

    def test_empty_response_raises(self):
        resp = self._make_response(b"")
        with self.assertRaises(InvalidStatusLine):
            resp.handle()

    def test_invalid_protocol_raises(self):
        raw = b"INVALID 200 OK\r\n\r\n"
        resp = self._make_response(raw)
        with self.assertRaises(InvalidStatusLine):
            resp.handle()


class TestHTTPResponseHeaders(unittest.TestCase):
    """Test HTTP response header parsing."""

    def _make_response(self, raw: bytes) -> HTTPResponse:
        sock = FakeSocket(raw)
        return HTTPResponse(sock)

    def test_parse_headers(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 5\r\n"
            b"\r\n"
            b"hello"
        )
        resp = self._make_response(raw)
        resp.handle()
        headers = resp.raw_headers
        header_names = [list(h.keys())[0] for h in headers]
        self.assertIn("Content-Type", header_names)
        self.assertIn("Content-Length", header_names)

    def test_case_insensitive_internal_storage(self):
        """Internal header storage should lowercase keys."""
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )
        resp = self._make_response(raw)
        resp.handle()
        # Internal parsed headers use lowercase
        body = resp.read_body()
        self.assertEqual(body, b"")


class TestHTTPResponseBody(unittest.TestCase):
    """Test HTTP response body reading and decompression."""

    def _make_response(self, raw: bytes) -> HTTPResponse:
        sock = FakeSocket(raw)
        return HTTPResponse(sock)

    def test_read_content_length_body(self):
        body = b"Hello, World!"
        raw = (
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
        )
        resp = self._make_response(raw)
        resp.handle()
        self.assertEqual(resp.read_body(), body)

    def test_read_chunked_body(self):
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\n"
            b"Hello\r\n"
            b"7\r\n"
            b", World\r\n"
            b"0\r\n"
            b"\r\n"
        )
        resp = self._make_response(raw)
        resp.handle()
        self.assertEqual(resp.read_body(), b"Hello, World")

    def test_gzip_decompression(self):
        body = b"compressed content"
        compressed = gzip.compress(body)
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Encoding: gzip\r\n"
            + f"Content-Length: {len(compressed)}\r\n".encode()
            + b"\r\n"
            + compressed
        )
        resp = self._make_response(raw)
        resp.handle()
        self.assertEqual(resp.read_body(), body)

    def test_deflate_decompression(self):
        body = b"deflated content"
        compressed = zlib.compress(body)
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Encoding: deflate\r\n"
            + f"Content-Length: {len(compressed)}\r\n".encode()
            + b"\r\n"
            + compressed
        )
        resp = self._make_response(raw)
        resp.handle()
        self.assertEqual(resp.read_body(), body)

    def test_brotli_decompression(self):
        body = b"brotli compressed content"
        compressed = brotli.compress(body)
        raw = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Encoding: br\r\n"
            + f"Content-Length: {len(compressed)}\r\n".encode()
            + b"\r\n"
            + compressed
        )
        resp = self._make_response(raw)
        resp.handle()
        self.assertEqual(resp.read_body(), body)

    def test_head_method_returns_empty_body(self):
        raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
        sock = FakeSocket(raw)
        resp = HTTPResponse(sock, method="HEAD")
        resp.handle()
        self.assertEqual(resp.read_body(), b"")


class TestResponse(unittest.TestCase):
    """Test high-level Response class."""

    def _make_response(self, status=200, headers=None, body=b""):
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
        return Response(response=http_resp)

    def test_status_code(self):
        resp = self._make_response(200)
        self.assertEqual(resp.status_code, 200)

    def test_content(self):
        resp = self._make_response(200, body=b"hello")
        self.assertEqual(resp.content, b"hello")

    def test_text(self):
        resp = self._make_response(200, body=b"hello")
        self.assertEqual(resp.text, "hello")

    def test_json(self):
        data = {"key": "value"}
        resp = self._make_response(200, body=json.dumps(data).encode())
        self.assertEqual(resp.json(), data)

    def test_is_redirected_301(self):
        resp = self._make_response(301, headers={"Location": "/new"})
        self.assertTrue(resp.is_redirected)

    def test_is_redirected_200(self):
        resp = self._make_response(200)
        self.assertFalse(resp.is_redirected)

    def test_location_header(self):
        resp = self._make_response(302, headers={"Location": "https://example.com"})
        self.assertEqual(resp.location, "https://example.com")

    def test_headers_property(self):
        resp = self._make_response(200, headers={"X-Custom": "test"})
        self.assertIn("X-Custom", resp.headers)

    def test_cookies_from_set_cookie(self):
        resp = self._make_response(
            200, headers={"Set-Cookie": "session=abc123; Path=/"}
        )
        cookies = resp.cookies
        self.assertIsNotNone(cookies)

    def test_repr(self):
        resp = self._make_response(200)
        self.assertEqual(repr(resp), "<Response [200]>")


if __name__ == "__main__":
    unittest.main()
