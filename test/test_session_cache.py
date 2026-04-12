"""Tests for TLS Session Resumption (#14)."""

import time
import unittest

from ja3requests.protocol.tls.session_cache import TLSSessionCache, TLSSessionEntry
from ja3requests.protocol.tls.config import TlsConfig


class TestTLSSessionEntry(unittest.TestCase):
    """Test TLSSessionEntry."""

    def test_create_entry(self):
        entry = TLSSessionEntry(b"\x01\x02\x03", b"\xaa" * 48, 0xC02F)
        self.assertEqual(entry.session_id, b"\x01\x02\x03")
        self.assertEqual(entry.master_secret, b"\xaa" * 48)
        self.assertEqual(entry.cipher_suite, 0xC02F)

    def test_not_expired(self):
        entry = TLSSessionEntry(b"\x01", b"\x02", 0x002F)
        self.assertFalse(entry.is_expired(3600))

    def test_expired(self):
        entry = TLSSessionEntry(b"\x01", b"\x02", 0x002F)
        entry.created_at = time.time() - 7200  # 2 hours ago
        self.assertTrue(entry.is_expired(3600))

    def test_repr(self):
        entry = TLSSessionEntry(b"\x01\x02\x03\x04\x05\x06\x07\x08", b"\x00", 0xC02F)
        r = repr(entry)
        self.assertIn("TLSSessionEntry", r)
        self.assertIn("C02F", r)


class TestTLSSessionCache(unittest.TestCase):
    """Test TLSSessionCache."""

    def test_put_and_get(self):
        cache = TLSSessionCache()
        cache.put("example.com", 443, b"\x01\x02", b"\xaa" * 48, 0xC02F)
        entry = cache.get("example.com", 443)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.session_id, b"\x01\x02")
        self.assertEqual(entry.master_secret, b"\xaa" * 48)

    def test_get_missing(self):
        cache = TLSSessionCache()
        self.assertIsNone(cache.get("unknown.com", 443))

    def test_case_insensitive_host(self):
        cache = TLSSessionCache()
        cache.put("Example.COM", 443, b"\x01", b"\x02", 0x002F)
        entry = cache.get("example.com", 443)
        self.assertIsNotNone(entry)

    def test_different_ports(self):
        cache = TLSSessionCache()
        cache.put("host.com", 443, b"\x01", b"\x02", 0x002F)
        cache.put("host.com", 8443, b"\x03", b"\x04", 0x002F)
        self.assertEqual(cache.get("host.com", 443).session_id, b"\x01")
        self.assertEqual(cache.get("host.com", 8443).session_id, b"\x03")

    def test_expired_entry_removed(self):
        cache = TLSSessionCache(ttl=1.0)
        cache.put("example.com", 443, b"\x01", b"\x02", 0x002F)
        # Manually expire
        key = ("example.com", 443)
        cache._cache[key].created_at = time.time() - 2.0
        self.assertIsNone(cache.get("example.com", 443))
        self.assertEqual(len(cache), 0)

    def test_overwrite_existing(self):
        cache = TLSSessionCache()
        cache.put("host.com", 443, b"\x01", b"\xaa", 0x002F)
        cache.put("host.com", 443, b"\x02", b"\xbb", 0xC02F)
        entry = cache.get("host.com", 443)
        self.assertEqual(entry.session_id, b"\x02")

    def test_max_size_eviction(self):
        cache = TLSSessionCache(max_size=2)
        cache.put("a.com", 443, b"\x01", b"\x02", 0x002F)
        cache.put("b.com", 443, b"\x03", b"\x04", 0x002F)
        cache.put("c.com", 443, b"\x05", b"\x06", 0x002F)
        self.assertEqual(len(cache), 2)
        # Oldest (a.com) should be evicted
        self.assertIsNone(cache.get("a.com", 443))

    def test_remove(self):
        cache = TLSSessionCache()
        cache.put("host.com", 443, b"\x01", b"\x02", 0x002F)
        cache.remove("host.com", 443)
        self.assertIsNone(cache.get("host.com", 443))

    def test_clear(self):
        cache = TLSSessionCache()
        cache.put("a.com", 443, b"\x01", b"\x02", 0x002F)
        cache.put("b.com", 443, b"\x03", b"\x04", 0x002F)
        cache.clear()
        self.assertEqual(len(cache), 0)

    def test_cleanup_expired(self):
        cache = TLSSessionCache(ttl=1.0)
        cache.put("a.com", 443, b"\x01", b"\x02", 0x002F)
        cache.put("b.com", 443, b"\x03", b"\x04", 0x002F)
        # Expire only a.com
        cache._cache[("a.com", 443)].created_at = time.time() - 2.0
        cache.cleanup_expired()
        self.assertEqual(len(cache), 1)
        self.assertIsNone(cache.get("a.com", 443))
        self.assertIsNotNone(cache.get("b.com", 443))

    def test_empty_session_id_not_cached(self):
        cache = TLSSessionCache()
        cache.put("host.com", 443, b"", b"\x02", 0x002F)
        self.assertIsNone(cache.get("host.com", 443))

    def test_none_session_id_not_cached(self):
        cache = TLSSessionCache()
        cache.put("host.com", 443, None, b"\x02", 0x002F)
        self.assertIsNone(cache.get("host.com", 443))

    def test_repr(self):
        cache = TLSSessionCache(max_size=50, ttl=1800)
        r = repr(cache)
        self.assertIn("TLSSessionCache", r)
        self.assertIn("50", r)


class TestTlsConfigSessionCache(unittest.TestCase):
    """Test TlsConfig session_cache property."""

    def test_default_no_cache(self):
        config = TlsConfig()
        self.assertIsNone(config.session_cache)

    def test_set_cache(self):
        config = TlsConfig()
        cache = TLSSessionCache()
        config.session_cache = cache
        self.assertIs(config.session_cache, cache)


class TestSessionAutoCache(unittest.TestCase):
    """Test Session auto-creates session cache."""

    def test_session_has_cache(self):
        from ja3requests.sessions import Session
        s = Session(use_pooling=False)
        self.assertIsInstance(s._tls_config.session_cache, TLSSessionCache)

    def test_custom_config_gets_cache(self):
        from ja3requests.sessions import Session
        config = TlsConfig()
        self.assertIsNone(config.session_cache)
        s = Session(tls_config=config, use_pooling=False)
        # Session should have added cache
        self.assertIsNotNone(s._tls_config.session_cache)

    def test_existing_cache_preserved(self):
        from ja3requests.sessions import Session
        config = TlsConfig()
        custom_cache = TLSSessionCache(max_size=5)
        config.session_cache = custom_cache
        s = Session(tls_config=config, use_pooling=False)
        self.assertIs(s._tls_config.session_cache, custom_cache)


class TestTLSSessionIDInHandshake(unittest.TestCase):
    """Test TLS object integrates with session cache."""

    def test_tls_accepts_session_cache(self):
        import socket
        from ja3requests.protocol.tls import TLS

        s1, s2 = socket.socketpair()
        try:
            cache = TLSSessionCache()
            tls = TLS(s1, session_cache=cache, server_host="example.com", server_port=443)
            self.assertIs(tls._session_cache, cache)
            self.assertEqual(tls._server_host, "example.com")
        finally:
            s1.close()
            s2.close()

    def test_save_session_to_cache(self):
        import socket
        from ja3requests.protocol.tls import TLS

        s1, s2 = socket.socketpair()
        try:
            cache = TLSSessionCache()
            tls = TLS(s1, session_cache=cache, server_host="test.com", server_port=443)
            tls._server_session_id = b"\xaa\xbb\xcc\xdd"
            tls._master_secret = b"\x00" * 48
            tls._selected_cipher_suite = 0xC02F
            tls._save_session_to_cache()

            entry = cache.get("test.com", 443)
            self.assertIsNotNone(entry)
            self.assertEqual(entry.session_id, b"\xaa\xbb\xcc\xdd")
            self.assertEqual(entry.master_secret, b"\x00" * 48)
        finally:
            s1.close()
            s2.close()

    def test_no_save_without_session_id(self):
        import socket
        from ja3requests.protocol.tls import TLS

        s1, s2 = socket.socketpair()
        try:
            cache = TLSSessionCache()
            tls = TLS(s1, session_cache=cache, server_host="test.com", server_port=443)
            tls._server_session_id = None
            tls._master_secret = b"\x00" * 48
            tls._save_session_to_cache()
            self.assertIsNone(cache.get("test.com", 443))
        finally:
            s1.close()
            s2.close()


if __name__ == "__main__":
    unittest.main()
