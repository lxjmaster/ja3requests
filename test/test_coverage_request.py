"""Coverage improvement tests for requests/request.py and sessions.py."""

import io
import unittest
from base64 import b64encode

from ja3requests.requests.request import Request
from ja3requests.exceptions import (
    NotAllowedRequestMethod,
    MissingScheme,
    NotAllowedScheme,
    InvalidParams,
    InvalidData,
)


class TestRequestValidation(unittest.TestCase):
    """Test request validation in Request.request()."""

    def test_invalid_method(self):
        with self.assertRaises(NotAllowedRequestMethod):
            Request(method="INVALID", url="http://example.com").request()

    def test_missing_scheme(self):
        with self.assertRaises(MissingScheme):
            Request(method="GET", url="example.com").request()

    def test_not_allowed_scheme(self):
        with self.assertRaises(NotAllowedScheme):
            Request(method="GET", url="ftp://example.com").request()

    def test_get_request(self):
        req = Request(method="GET", url="http://example.com").request()
        self.assertEqual(req.method, "GET")

    def test_post_request(self):
        req = Request(method="POST", url="http://example.com", data={"k": "v"}).request()
        self.assertEqual(req.method, "POST")

    def test_put_request(self):
        req = Request(method="PUT", url="http://example.com").request()
        self.assertIsNotNone(req)

    def test_patch_request(self):
        req = Request(method="PATCH", url="http://example.com").request()
        self.assertIsNotNone(req)

    def test_delete_request(self):
        req = Request(method="DELETE", url="http://example.com").request()
        self.assertIsNotNone(req)

    def test_head_request(self):
        req = Request(method="HEAD", url="http://example.com").request()
        self.assertIsNotNone(req)

    def test_options_request(self):
        req = Request(method="OPTIONS", url="http://example.com").request()
        self.assertIsNotNone(req)

    def test_https_request(self):
        req = Request(method="GET", url="https://example.com").request()
        self.assertEqual(req.scheme, "https")

    def test_http_request(self):
        req = Request(method="GET", url="http://example.com").request()
        self.assertEqual(req.scheme, "http")


class TestRequestParams(unittest.TestCase):
    """Test params handling."""

    def test_dict_params(self):
        req = Request(method="GET", url="http://example.com", params={"q": "test"})
        r = req.request()
        self.assertIsNotNone(r)

    def test_invalid_params_type(self):
        with self.assertRaises(InvalidParams):
            Request(method="GET", url="http://example.com", params=123).request()


class TestRequestData(unittest.TestCase):
    """Test data handling."""

    def test_dict_data(self):
        req = Request(method="POST", url="http://example.com", data={"k": "v"})
        r = req.request()
        self.assertIsNotNone(r)

    def test_string_data(self):
        req = Request(method="POST", url="http://example.com", data="raw body")
        r = req.request()
        self.assertIsNotNone(r)

    def test_invalid_data_type(self):
        with self.assertRaises(InvalidData):
            Request(method="POST", url="http://example.com", data=12345).request()


class TestRequestHeaders(unittest.TestCase):
    """Test header handling."""

    def test_custom_headers(self):
        req = Request(
            method="GET", url="http://example.com",
            headers={"X-Custom": "value"}
        )
        r = req.request()
        self.assertEqual(r.headers.get("X-Custom"), "value")

    def test_default_headers(self):
        req = Request(method="GET", url="http://example.com")
        r = req.request()
        self.assertIn("User-Agent", r.headers)


class TestRequestCookies(unittest.TestCase):
    """Test cookie handling in request."""

    def test_dict_cookies(self):
        req = Request(
            method="GET", url="http://example.com",
            cookies={"session": "abc"}
        )
        r = req.request()
        self.assertIsNotNone(r)

    def test_string_cookies(self):
        req = Request(
            method="GET", url="http://example.com",
            cookies="name=value"
        )
        r = req.request()
        self.assertIsNotNone(r)


class TestRequestJson(unittest.TestCase):
    """Test JSON body handling."""

    def test_json_body(self):
        req = Request(
            method="POST", url="http://example.com",
            json={"key": "value"}
        )
        r = req.request()
        self.assertIsNotNone(r)


class TestRequestAuth(unittest.TestCase):
    """Test auth handling."""

    def test_basic_auth(self):
        req = Request(
            method="GET", url="http://example.com",
            auth=("user", "pass")
        )
        r = req.request()
        expected = "Basic " + b64encode(b"user:pass").decode()
        self.assertEqual(r.headers.get("Authorization"), expected)


class TestRequestProxy(unittest.TestCase):
    """Test proxy validation."""

    def test_valid_proxy(self):
        req = Request(
            method="GET", url="http://example.com",
            proxies={"http": "127.0.0.1:8080"}
        )
        r = req.request()
        self.assertIsNotNone(r)

    def test_invalid_proxy_type(self):
        with self.assertRaises(AttributeError):
            Request(
                method="GET", url="http://example.com",
                proxies="not_a_dict"
            ).request()

    def test_invalid_proxy_key(self):
        with self.assertRaises(AttributeError):
            Request(
                method="GET", url="http://example.com",
                proxies={"ftp": "host:port"}
            ).request()


class TestRequestTimeout(unittest.TestCase):
    """Test timeout passthrough."""

    def test_timeout_set(self):
        req = Request(method="GET", url="http://example.com", timeout=5.0)
        self.assertEqual(req.timeout, 5.0)

    def test_timeout_tuple(self):
        req = Request(method="GET", url="http://example.com", timeout=(5, 30))
        self.assertEqual(req.timeout, (5, 30))


if __name__ == "__main__":
    unittest.main()
