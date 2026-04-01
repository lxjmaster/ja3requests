"""Tests for ja3requests top-level API (module-level shortcuts)."""

import unittest

import ja3requests
from ja3requests import Session, TlsConfig, Response
from ja3requests.exceptions import (
    RequestException,
    MissingScheme,
    NotAllowedScheme,
    NotAllowedRequestMethod,
    TLSError,
    TLSHandshakeError,
)


class TestModuleExports(unittest.TestCase):
    """Test that expected names are exported from ja3requests."""

    def test_session_class(self):
        self.assertTrue(hasattr(ja3requests, "Session"))

    def test_tls_config_class(self):
        self.assertTrue(hasattr(ja3requests, "TlsConfig"))

    def test_response_class(self):
        self.assertTrue(hasattr(ja3requests, "Response"))

    def test_session_factory(self):
        s = ja3requests.session()
        self.assertIsInstance(s, Session)

    def test_shortcut_functions_exist(self):
        for method in ["get", "post", "put", "patch", "delete", "head", "options", "request"]:
            self.assertTrue(
                hasattr(ja3requests, method),
                f"ja3requests.{method} should exist",
            )
            self.assertTrue(callable(getattr(ja3requests, method)))

    def test_exception_exports(self):
        for exc in [
            "RequestException",
            "MissingScheme",
            "NotAllowedScheme",
            "NotAllowedRequestMethod",
            "TLSError",
            "TLSHandshakeError",
        ]:
            self.assertTrue(
                hasattr(ja3requests, exc),
                f"ja3requests.{exc} should be exported",
            )


class TestSessionFactory(unittest.TestCase):
    """Test session() factory function."""

    def test_session_returns_session(self):
        s = ja3requests.session()
        self.assertIsInstance(s, Session)

    def test_session_with_tls_config(self):
        config = TlsConfig().create_firefox_config()
        s = ja3requests.session(tls_config=config)
        self.assertIsInstance(s, Session)
        self.assertEqual(len(s.tls_config.cipher_suites), 8)

    def test_session_context_manager(self):
        with ja3requests.session() as s:
            self.assertIsInstance(s, Session)


class TestSessionTlsConfig(unittest.TestCase):
    """Test Session TLS configuration."""

    def test_default_tls_config(self):
        s = Session()
        self.assertIsInstance(s.tls_config, TlsConfig)

    def test_custom_tls_config(self):
        config = TlsConfig().create_chrome_config()
        s = Session(tls_config=config)
        self.assertEqual(len(s.tls_config.cipher_suites), 8)

    def test_tls_config_setter(self):
        s = Session()
        new_config = TlsConfig().create_firefox_config()
        s.tls_config = new_config
        self.assertEqual(s.tls_config.alpn_protocols, ["h2", "http/1.1"])


class TestSessionPooling(unittest.TestCase):
    """Test Session connection pooling."""

    def test_default_pooling_enabled(self):
        s = Session()
        self.assertIsNotNone(s.pool)

    def test_disable_pooling(self):
        s = Session(use_pooling=False)
        self.assertIsNone(s.pool)

    def test_pool_setter(self):
        from ja3requests.pool import ConnectionPool

        s = Session()
        custom_pool = ConnectionPool(max_connections_per_host=5)
        s.pool = custom_pool
        self.assertIs(s.pool, custom_pool)


if __name__ == "__main__":
    unittest.main()
