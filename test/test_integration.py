"""Tests for final integration: TLS 1.3 wiring, H2 settings, Client Cert."""

import os
import socket
import struct
import unittest

from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.sessions import Session


class TestTLS13HandshakeBranching(unittest.TestCase):
    """Test that TLS.handshake() routes to TLS 1.3 when configured."""

    def test_tls12_uses_tls12_path(self):
        """TLS 1.2 config should use _handshake_tls12."""
        s1, s2 = socket.socketpair()
        try:
            config = TlsConfig()
            config.tls_version = 0x0303
            tls = TLS(s1)
            tls.set_payload(tls_config=config)
            self.assertFalse(tls._is_tls13)
            # Verify _handshake_tls12 method exists
            self.assertTrue(hasattr(tls, '_handshake_tls12'))
        finally:
            s1.close()
            s2.close()

    def test_tls13_uses_tls13_path(self):
        """TLS 1.3 config should use _handshake_tls13."""
        s1, s2 = socket.socketpair()
        try:
            config = TlsConfig()
            config.tls_version = 0x0304
            config.server_name = "test.com"
            tls = TLS(s1)
            tls.set_payload(tls_config=config)
            self.assertTrue(tls._is_tls13)
            self.assertTrue(hasattr(tls, '_handshake_tls13'))
            self.assertIsNotNone(tls._tls13_private_key)
        finally:
            s1.close()
            s2.close()

    def test_tls13_handshake_stores_attributes(self):
        """After TLS 1.3 setup, key attributes should be initialized."""
        s1, s2 = socket.socketpair()
        try:
            config = TlsConfig()
            config.tls_version = 0x0304
            config.server_name = "example.com"
            tls = TLS(s1)
            tls.set_payload(tls_config=config)

            self.assertIsNotNone(tls._tls13_private_key)
            self.assertIsNotNone(tls._tls13_key_share_group)
            self.assertIsNone(tls._negotiated_protocol)
        finally:
            s1.close()
            s2.close()


class TestH2SettingsIntegration(unittest.TestCase):
    """Test H2 settings flow from TlsConfig through to H2Connection."""

    def test_tls_config_h2_settings(self):
        config = TlsConfig()
        settings = {0x01: 65535, 0x03: 1000, 0x04: 6291456}
        config.h2_settings = settings
        self.assertEqual(config.h2_settings, settings)

    def test_tls_config_h2_window_update(self):
        config = TlsConfig()
        config.h2_window_update = 15663105
        self.assertEqual(config.h2_window_update, 15663105)

    def test_session_tls_config_has_h2(self):
        s = Session(use_pooling=False)
        s.tls_config.h2_settings = {0x01: 65535}
        self.assertEqual(s.tls_config.h2_settings, {0x01: 65535})

    def test_chrome_h2_fingerprint(self):
        """Simulate Chrome's H2 fingerprint configuration."""
        config = TlsConfig().create_chrome_config()
        config.h2_settings = {
            0x01: 65536,     # HEADER_TABLE_SIZE
            0x02: 0,         # ENABLE_PUSH
            0x03: 1000,      # MAX_CONCURRENT_STREAMS
            0x04: 6291456,   # INITIAL_WINDOW_SIZE
            0x06: 262144,    # MAX_HEADER_LIST_SIZE
        }
        config.h2_window_update = 15663105

        self.assertEqual(config.h2_settings[0x04], 6291456)
        self.assertEqual(config.h2_window_update, 15663105)


class TestHttpsSocketH2Methods(unittest.TestCase):
    """Test HttpsSocket has H2 methods."""

    def test_send_h1_exists(self):
        from ja3requests.sockets.https import HttpsSocket
        self.assertTrue(hasattr(HttpsSocket, '_send_h1'))

    def test_send_h2_exists(self):
        from ja3requests.sockets.https import HttpsSocket
        self.assertTrue(hasattr(HttpsSocket, '_send_h2'))

    def test_decrypt_single_record_exists(self):
        from ja3requests.sockets.https import HttpsSocket
        self.assertTrue(hasattr(HttpsSocket, '_decrypt_single_record'))


class TestTLS13WithSessionCache(unittest.TestCase):
    """Test TLS 1.3 uses session cache."""

    def test_tls13_with_cache(self):
        from ja3requests.protocol.tls.session_cache import TLSSessionCache

        s1, s2 = socket.socketpair()
        try:
            cache = TLSSessionCache()
            config = TlsConfig()
            config.tls_version = 0x0304
            config.server_name = "cached.example.com"
            config.session_cache = cache

            tls = TLS(s1, session_cache=cache, server_host="cached.example.com", server_port=443)
            tls.set_payload(tls_config=config)
            self.assertTrue(tls._is_tls13)
            self.assertIs(tls._session_cache, cache)
        finally:
            s1.close()
            s2.close()


class TestBrowserFingerprints(unittest.TestCase):
    """Test that browser presets produce valid configs."""

    def test_firefox_config(self):
        config = TlsConfig().create_firefox_config()
        self.assertEqual(len(config.cipher_suites), 8)
        self.assertEqual(config.alpn_protocols, ['h2', 'http/1.1'])

    def test_chrome_config(self):
        config = TlsConfig().create_chrome_config()
        self.assertEqual(len(config.cipher_suites), 8)

    def test_tls13_firefox(self):
        """Firefox-like TLS 1.3 config."""
        config = TlsConfig().create_firefox_config()
        config.tls_version = 0x0304
        ja3 = config.get_ja3_string()
        self.assertIn("772", ja3)  # 0x0304 = 772

    def test_full_fingerprint_workflow(self):
        """Full workflow: create config, generate JA3, create session."""
        config = TlsConfig().create_chrome_config()
        config.h2_settings = {0x01: 65536, 0x03: 1000}
        config.h2_window_update = 15663105

        s = Session(tls_config=config, use_pooling=False)
        ja3 = s.tls_config.get_ja3_string()
        self.assertIsInstance(ja3, str)
        self.assertEqual(s.tls_config.h2_settings[0x01], 65536)


if __name__ == "__main__":
    unittest.main()
