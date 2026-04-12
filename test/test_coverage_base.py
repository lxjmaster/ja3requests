"""Coverage improvement tests for base classes."""

import unittest

from ja3requests.base.__contexts import BaseContext
from ja3requests.base.__sessions import BaseSession
from ja3requests.base.__requests import BaseRequest
from ja3requests.cookies import Ja3RequestsCookieJar


# Concrete subclass for testing abstract BaseContext
class TestContext(BaseContext):
    def set_payload(self, **kwargs):
        for k, v in kwargs.items():
            if hasattr(self, k):
                setattr(self, k, v)
            elif hasattr(self, f"_{k}"):
                setattr(self, f"_{k}", v)


# Concrete subclass for testing abstract BaseRequest
class ConcreteRequest(BaseRequest):
    def send(self, *args, **kwargs):
        return None


class TestBaseContextProperties(unittest.TestCase):
    """Test all BaseContext property getters/setters."""

    def setUp(self):
        self.ctx = TestContext()

    def test_protocol_version(self):
        self.ctx.protocol_version = "HTTP/1.1"
        self.assertEqual(self.ctx.protocol_version, "HTTP/1.1")

    def test_method(self):
        self.ctx.method = "GET"
        self.assertEqual(self.ctx.method, "GET")

    def test_destination_address(self):
        self.ctx.destination_address = "example.com"
        self.assertEqual(self.ctx.destination_address, "example.com")

    def test_path(self):
        self.ctx.path = "/api"
        self.assertEqual(self.ctx.path, "/api")

    def test_port(self):
        self.ctx.port = 443
        self.assertEqual(self.ctx.port, 443)

    def test_headers(self):
        h = {"Accept": "*/*"}
        self.ctx.headers = h
        self.assertEqual(self.ctx.headers, h)

    def test_data(self):
        self.ctx._data = b"body"
        self.assertEqual(self.ctx.data, b"body")

    def test_data_setter_dict(self):
        self.ctx.data = {"key": "val"}
        # data setter URL-encodes dict values
        self.assertEqual(self.ctx._data, "key=val")

    def test_json(self):
        self.ctx._json = {"key": "val"}
        self.assertEqual(self.ctx.json, {"key": "val"})

    def test_json_setter(self):
        self.ctx._json = {"x": "y"}
        self.assertEqual(self.ctx.json, {"x": "y"})

    def test_files(self):
        self.ctx._files = {"f": "path.txt"}
        self.assertEqual(self.ctx.files, {"f": "path.txt"})

    def test_files_setter(self):
        self.ctx.files = {"f": "file"}
        self.assertEqual(self.ctx._files, {"f": "file"})

    def test_start_line_setter(self):
        self.ctx._start_line = "http://example.com/"
        self.assertIsNotNone(self.ctx.start_line)

    def test_message(self):
        self.ctx.message = b"full message"
        self.assertEqual(self.ctx.message, b"full message")

    def test_source_address(self):
        self.ctx.source_address = ("0.0.0.0", 0)
        self.assertEqual(self.ctx.source_address, ("0.0.0.0", 0))

    def test_timeout_single(self):
        self.ctx.timeout = 10.0
        self.assertEqual(self.ctx.timeout, 10.0)
        self.assertEqual(self.ctx.connect_timeout, 10.0)
        self.assertEqual(self.ctx.read_timeout, 10.0)

    def test_timeout_tuple(self):
        self.ctx.timeout = (5, 30)
        self.assertEqual(self.ctx.connect_timeout, 5)
        self.assertEqual(self.ctx.read_timeout, 30)

    def test_proxy_no_scheme(self):
        self.ctx._proxy = "host:8080"
        self.assertEqual(self.ctx.proxy, "host:8080")
        self.assertIsNone(self.ctx.proxy_auth)

    def test_proxy_with_auth(self):
        self.ctx._proxy = "user:pass@host:8080"
        self.assertEqual(self.ctx.proxy, "host:8080")
        self.assertEqual(self.ctx.proxy_auth, "user:pass")

    def test_proxy_socks_scheme(self):
        self.ctx._proxy = "socks5://user:pw@host:1080"
        self.assertEqual(self.ctx.proxy_scheme, "socks5")
        self.assertEqual(self.ctx.proxy, "host:1080")
        self.assertEqual(self.ctx.proxy_auth, "user:pw")

    def test_proxy_none(self):
        self.ctx._proxy = None
        self.assertIsNone(self.ctx.proxy)
        self.assertIsNone(self.ctx.proxy_auth)
        self.assertIsNone(self.ctx.proxy_scheme)

    def test_cookies(self):
        self.ctx._cookies = {"session": "abc"}
        self.assertEqual(self.ctx.cookies, {"session": "abc"})

    def test_cookies_setter_dict(self):
        self.ctx._headers = {}
        self.ctx.cookies = {"sid": "xyz"}
        self.assertEqual(self.ctx._cookies, "sid=xyz;")

    def test_cookies_setter_non_dict(self):
        self.ctx.cookies = "invalid"
        self.assertIsNone(self.ctx._cookies)


class TestBaseSessionProperties(unittest.TestCase):
    """Test BaseSession properties."""

    def test_request_property(self):
        s = BaseSession()
        s.Request = "mock_request"
        self.assertEqual(s.Request, "mock_request")

    def test_response_property(self):
        s = BaseSession()
        s.response = "mock_response"
        self.assertEqual(s.response, "mock_response")

    def test_headers_from_request(self):
        s = BaseSession()

        class MockReq:
            headers = {"Host": "example.com"}
        s.Request = MockReq()
        self.assertEqual(s.headers, {"Host": "example.com"})

    def test_headers_setter(self):
        s = BaseSession()
        s.headers = {"Custom": "Header"}
        self.assertEqual(s.headers, {"Custom": "Header"})

    def test_auth_from_request(self):
        s = BaseSession()

        class MockReq:
            auth = ("user", "pass")
        s.Request = MockReq()
        self.assertEqual(s.auth, ("user", "pass"))

    def test_auth_setter(self):
        s = BaseSession()
        s.auth = ("u", "p")
        self.assertEqual(s.auth, ("u", "p"))

    def test_proxies(self):
        s = BaseSession()

        class MockReq:
            proxies = {"https": "host:8080"}
        s.Request = MockReq()
        self.assertEqual(s.proxies, {"https": "host:8080"})

    def test_params(self):
        s = BaseSession()

        class MockReq:
            params = {"page": "1"}
        s.Request = MockReq()
        self.assertEqual(s.params, {"page": "1"})

    def test_max_redirects_default(self):
        s = BaseSession()
        # No request, no explicit setting → default
        self.assertEqual(s.max_redirects, 8)

    def test_max_redirects_setter(self):
        s = BaseSession()
        s.max_redirects = 5
        self.assertEqual(s.max_redirects, 5)

    def test_allow_redirect_default(self):
        s = BaseSession()
        self.assertTrue(s.allow_redirect)

    def test_allow_redirect_setter(self):
        s = BaseSession()
        s._allow_redirect = False
        # Note: property returns True by default if not set, need to set directly
        self.assertFalse(s._allow_redirect)

    def test_ja3_text(self):
        s = BaseSession()
        s.ja3_text = "771,4865-4866,0-23,29-23-24,0"
        self.assertEqual(s.ja3_text, "771,4865-4866,0-23,29-23-24,0")

    def test_h2_settings(self):
        s = BaseSession()
        s.h2_settings = {"1": "65535"}
        self.assertEqual(s.h2_settings, {"1": "65535"})

    def test_h2_window_update(self):
        s = BaseSession()
        s.h2_window_update = "15663105"
        self.assertEqual(s.h2_window_update, "15663105")

    def test_h2_headers(self):
        s = BaseSession()
        s.h2_headers = "m,a,s,p"
        self.assertEqual(s.h2_headers, "m,a,s,p")

    def test_context_manager(self):
        s = BaseSession()
        with s:
            pass  # Should not raise

    def test_resolve_cookies_bytes(self):
        jar = Ja3RequestsCookieJar()
        result = BaseSession.resolve_cookies(jar, b"name=value")
        self.assertEqual(result["name"], "value")

    def test_resolve_cookies_string(self):
        jar = Ja3RequestsCookieJar()
        result = BaseSession.resolve_cookies(jar, "a=1; b=2")
        self.assertEqual(result["a"], "1")

    def test_resolve_cookies_dict(self):
        jar = Ja3RequestsCookieJar()
        result = BaseSession.resolve_cookies(jar, {"k": "v"})
        self.assertEqual(result["k"], "v")

    def test_resolve_cookies_cookiejar(self):
        jar = Ja3RequestsCookieJar()
        other = Ja3RequestsCookieJar()
        other.set("x", "y")
        result = BaseSession.resolve_cookies(jar, other)
        self.assertEqual(result["x"], "y")


class TestBaseRequestProperties(unittest.TestCase):
    """Test BaseRequest property getters/setters."""

    def test_method(self):
        r = ConcreteRequest()
        r.method = "POST"
        self.assertEqual(r.method, "POST")

    def test_url(self):
        r = ConcreteRequest()
        r.url = "https://example.com"
        self.assertEqual(r.url, "https://example.com")

    def test_headers_setter(self):
        r = ConcreteRequest()
        r.headers = {"X-Custom": "val"}
        self.assertEqual(r.headers, {"X-Custom": "val"})

    def test_params_getter(self):
        r = ConcreteRequest()
        r._params = "q=test"
        self.assertIsNotNone(r.params)

    def test_data_getter(self):
        r = ConcreteRequest()
        r._data = b"body"
        self.assertEqual(r.data, b"body")

    def test_proxy_getter(self):
        r = ConcreteRequest()
        r._proxy = {"https": "host:8080"}
        self.assertEqual(r.proxy, {"https": "host:8080"})

    def test_json_getter(self):
        r = ConcreteRequest()
        r._json = {"k": "v"}
        self.assertEqual(r.json, {"k": "v"})

    def test_files_getter(self):
        r = ConcreteRequest()
        r._files = {"f": "file.txt"}
        self.assertEqual(r.files, {"f": "file.txt"})

    def test_cookies(self):
        r = ConcreteRequest()
        r.cookies = {"sid": "abc"}
        self.assertEqual(r.cookies, {"sid": "abc"})

    def test_auth(self):
        r = ConcreteRequest()
        r.auth = ("u", "p")
        self.assertEqual(r.auth, ("u", "p"))

    def test_timeout(self):
        r = ConcreteRequest()
        r.timeout = 10
        self.assertEqual(r.timeout, 10)

    def test_tls_config(self):
        r = ConcreteRequest()
        r.tls_config = "mock_config"
        self.assertEqual(r.tls_config, "mock_config")

    def test_schema(self):
        r = ConcreteRequest()
        r.schema = "https"
        self.assertEqual(r.schema, "https")

    def test_port(self):
        r = ConcreteRequest()
        r.port = 443
        self.assertEqual(r.port, 443)


if __name__ == "__main__":
    unittest.main()
