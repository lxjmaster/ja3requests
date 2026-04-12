"""Tests for streaming response support (#9)."""

import io
import unittest

from ja3requests.response import Response, HTTPResponse


class FakeSocket:
    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)

    def makefile(self, mode):
        return self._buffer


def make_response(status=200, headers=None, body=b"", stream=False):
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
    return Response(response=http_resp, stream=stream)


class TestNonStreamingDefault(unittest.TestCase):
    """Default (non-streaming) behavior should be unchanged."""

    def test_body_read_immediately(self):
        resp = make_response(body=b"hello world")
        self.assertEqual(resp.content, b"hello world")
        self.assertTrue(resp._body_consumed)

    def test_text_works(self):
        resp = make_response(body=b"hello")
        self.assertEqual(resp.text, "hello")

    def test_json_works(self):
        resp = make_response(body=b'{"key": "value"}')
        self.assertEqual(resp.json(), {"key": "value"})


class TestStreamingResponse(unittest.TestCase):
    """Test stream=True defers body reading."""

    def test_stream_defers_body(self):
        resp = make_response(body=b"hello", stream=True)
        self.assertFalse(resp._body_consumed)

    def test_content_triggers_read(self):
        resp = make_response(body=b"hello", stream=True)
        self.assertFalse(resp._body_consumed)
        # Accessing .content triggers read
        self.assertEqual(resp.content, b"hello")
        self.assertTrue(resp._body_consumed)


class TestIterContent(unittest.TestCase):
    """Test iter_content yields chunks."""

    def test_iter_content_single_chunk(self):
        resp = make_response(body=b"hello")
        chunks = list(resp.iter_content(chunk_size=1024))
        self.assertEqual(chunks, [b"hello"])

    def test_iter_content_multiple_chunks(self):
        data = b"abcdefghij"  # 10 bytes
        resp = make_response(body=data)
        chunks = list(resp.iter_content(chunk_size=3))
        self.assertEqual(chunks, [b"abc", b"def", b"ghi", b"j"])

    def test_iter_content_exact_chunk(self):
        data = b"abcdef"  # 6 bytes
        resp = make_response(body=data)
        chunks = list(resp.iter_content(chunk_size=3))
        self.assertEqual(chunks, [b"abc", b"def"])

    def test_iter_content_empty_body(self):
        resp = make_response(body=b"")
        chunks = list(resp.iter_content(chunk_size=1024))
        self.assertEqual(chunks, [])

    def test_iter_content_stream_mode(self):
        resp = make_response(body=b"streaming data", stream=True)
        self.assertFalse(resp._body_consumed)
        chunks = list(resp.iter_content(chunk_size=5))
        self.assertTrue(resp._body_consumed)
        self.assertEqual(b"".join(chunks), b"streaming data")

    def test_iter_content_chunk_size_1(self):
        resp = make_response(body=b"abc")
        chunks = list(resp.iter_content(chunk_size=1))
        self.assertEqual(chunks, [b"a", b"b", b"c"])


class TestIterLines(unittest.TestCase):
    """Test iter_lines yields lines."""

    def test_iter_lines_basic(self):
        resp = make_response(body=b"line1\nline2\nline3")
        lines = list(resp.iter_lines())
        self.assertEqual(lines, [b"line1", b"line2", b"line3"])

    def test_iter_lines_trailing_newline(self):
        resp = make_response(body=b"line1\nline2\n")
        lines = list(resp.iter_lines())
        # Trailing empty pending is discarded (empty bytes are falsy)
        self.assertEqual(lines, [b"line1", b"line2"])

    def test_iter_lines_single_line(self):
        resp = make_response(body=b"no newline")
        lines = list(resp.iter_lines())
        self.assertEqual(lines, [b"no newline"])

    def test_iter_lines_empty_body(self):
        resp = make_response(body=b"")
        lines = list(resp.iter_lines())
        self.assertEqual(lines, [])

    def test_iter_lines_custom_delimiter(self):
        resp = make_response(body=b"a|b|c")
        lines = list(resp.iter_lines(delimiter=b"|"))
        self.assertEqual(lines, [b"a", b"b", b"c"])

    def test_iter_lines_crlf(self):
        resp = make_response(body=b"line1\r\nline2\r\n")
        lines = list(resp.iter_lines(delimiter=b"\r\n"))
        self.assertEqual(lines, [b"line1", b"line2"])


class TestResponseClose(unittest.TestCase):
    """Test Response.close()."""

    def test_close_clears_fp(self):
        resp = make_response(body=b"data")
        resp.close()
        self.assertIsNone(resp.response.fp)

    def test_close_idempotent(self):
        resp = make_response(body=b"data")
        resp.close()
        resp.close()  # should not raise


if __name__ == "__main__":
    unittest.main()
