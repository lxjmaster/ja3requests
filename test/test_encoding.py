"""Tests for response text encoding auto-detection (#7)."""

import io
import unittest

from ja3requests.response import Response, HTTPResponse


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
    return Response(response=http_resp)


class TestEncodingDetection(unittest.TestCase):
    """Test charset detection from Content-Type header."""

    def test_default_encoding_utf8(self):
        resp = make_response(200, body=b"hello")
        self.assertEqual(resp.encoding, "utf-8")

    def test_detect_charset_from_content_type(self):
        resp = make_response(
            200,
            headers={"Content-Type": "text/html; charset=gbk"},
            body="你好".encode("gbk"),
        )
        self.assertEqual(resp.encoding, "gbk")

    def test_detect_charset_iso8859(self):
        resp = make_response(
            200,
            headers={"Content-Type": "text/html; charset=iso-8859-1"},
            body="caf\xe9".encode("iso-8859-1"),
        )
        self.assertEqual(resp.encoding, "iso-8859-1")

    def test_charset_case_insensitive(self):
        resp = make_response(
            200,
            headers={"Content-Type": "text/html; Charset=UTF-16"},
            body=b"",
        )
        self.assertEqual(resp.encoding, "UTF-16")

    def test_content_type_without_charset(self):
        resp = make_response(
            200,
            headers={"Content-Type": "application/json"},
            body=b'{"key": "value"}',
        )
        self.assertEqual(resp.encoding, "utf-8")

    def test_charset_with_quotes(self):
        resp = make_response(
            200,
            headers={"Content-Type": 'text/html; charset="utf-8"'},
            body=b"test",
        )
        self.assertEqual(resp.encoding, "utf-8")

    def test_multiple_content_type_params(self):
        resp = make_response(
            200,
            headers={"Content-Type": "text/html; charset=shift_jis; boundary=something"},
            body="テスト".encode("shift_jis"),
        )
        self.assertEqual(resp.encoding, "shift_jis")


class TestEncodingOverride(unittest.TestCase):
    """Test manual encoding override."""

    def test_set_encoding(self):
        resp = make_response(200, body=b"test")
        resp.encoding = "ascii"
        self.assertEqual(resp.encoding, "ascii")

    def test_override_beats_header(self):
        resp = make_response(
            200,
            headers={"Content-Type": "text/html; charset=gbk"},
            body=b"test",
        )
        resp.encoding = "utf-8"
        self.assertEqual(resp.encoding, "utf-8")


class TestTextDecoding(unittest.TestCase):
    """Test that .text uses the correct encoding."""

    def test_text_with_utf8(self):
        body = "你好世界".encode("utf-8")
        resp = make_response(200, body=body)
        self.assertEqual(resp.text, "你好世界")

    def test_text_with_gbk(self):
        body = "你好世界".encode("gbk")
        resp = make_response(
            200,
            headers={"Content-Type": "text/html; charset=gbk"},
            body=body,
        )
        self.assertEqual(resp.text, "你好世界")

    def test_text_with_iso8859(self):
        body = "café".encode("iso-8859-1")
        resp = make_response(
            200,
            headers={"Content-Type": "text/html; charset=iso-8859-1"},
            body=body,
        )
        self.assertEqual(resp.text, "café")

    def test_text_with_manual_override(self):
        body = "hello".encode("ascii")
        resp = make_response(200, body=body)
        resp.encoding = "ascii"
        self.assertEqual(resp.text, "hello")

    def test_text_wrong_encoding_raises(self):
        """Using wrong encoding should raise or produce garbled text."""
        body = "你好".encode("gbk")
        resp = make_response(200, body=body)
        # Default utf-8 can't decode gbk bytes
        with self.assertRaises(UnicodeDecodeError):
            _ = resp.text


if __name__ == "__main__":
    unittest.main()
