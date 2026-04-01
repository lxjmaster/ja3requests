"""Tests for ja3requests.protocol.tls.config module."""

import unittest

from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.protocol.tls.cipher_suites.suites import (
    RsaWithAes128CbcSha,
    EcdheRsaWithAes128GcmSha256,
)


class TestTlsConfigDefaults(unittest.TestCase):
    """Test TlsConfig default values."""

    def setUp(self):
        self.config = TlsConfig()

    def test_default_version(self):
        self.assertEqual(self.config.tls_version, 0x0303)

    def test_default_cipher_suites(self):
        self.assertEqual(len(self.config.cipher_suites), 1)
        self.assertIsInstance(self.config.cipher_suites[0], RsaWithAes128CbcSha)

    def test_default_compression(self):
        self.assertEqual(self.config.compression_methods, [0])

    def test_default_no_grease(self):
        self.assertFalse(self.config.use_grease)

    def test_default_no_alpn(self):
        self.assertEqual(self.config.alpn_protocols, [])

    def test_default_no_sni(self):
        self.assertIsNone(self.config.server_name)

    def test_default_no_verify(self):
        self.assertFalse(self.config.verify_cert)


class TestTlsConfigSetters(unittest.TestCase):
    """Test TlsConfig property setters."""

    def setUp(self):
        self.config = TlsConfig()

    def test_set_tls_version(self):
        self.config.tls_version = 0x0304
        self.assertEqual(self.config.tls_version, 0x0304)

    def test_set_server_name(self):
        self.config.server_name = "example.com"
        self.assertEqual(self.config.server_name, "example.com")

    def test_set_alpn_protocols(self):
        self.config.alpn_protocols = ["h2", "http/1.1"]
        self.assertEqual(self.config.alpn_protocols, ["h2", "http/1.1"])

    def test_set_supported_groups(self):
        self.config.supported_groups = [23, 24, 25]
        self.assertEqual(self.config.supported_groups, [23, 24, 25])

    def test_set_use_grease(self):
        self.config.use_grease = True
        self.assertTrue(self.config.use_grease)

    def test_set_verify_cert(self):
        self.config.verify_cert = True
        self.assertTrue(self.config.verify_cert)

    def test_client_random_must_be_32_bytes(self):
        with self.assertRaises(ValueError):
            self.config.client_random = b"\x00" * 16

    def test_client_random_valid(self):
        random = b"\x01" * 32
        self.config.client_random = random
        self.assertEqual(self.config.client_random, random)

    def test_server_random_must_be_32_bytes(self):
        with self.assertRaises(ValueError):
            self.config.server_random = b"\x00" * 16


class TestTlsConfigCipherSuiteOps(unittest.TestCase):
    """Test cipher suite add/remove operations."""

    def setUp(self):
        self.config = TlsConfig()

    def test_add_cipher_suite(self):
        suite = EcdheRsaWithAes128GcmSha256()
        self.config.add_cipher_suite(suite)
        self.assertEqual(len(self.config.cipher_suites), 2)

    def test_remove_cipher_suite(self):
        initial = self.config.cipher_suites[0]
        self.config.remove_cipher_suite(initial)
        self.assertEqual(len(self.config.cipher_suites), 0)

    def test_get_cipher_suite_values(self):
        values = self.config.get_cipher_suite_values()
        self.assertIsInstance(values, list)
        self.assertEqual(values[0], RsaWithAes128CbcSha().value)

    def test_get_cipher_suite_values_with_grease(self):
        self.config.use_grease = True
        values = self.config.get_cipher_suite_values()
        # GREASE value + default cipher suite
        self.assertEqual(len(values), 2)


class TestTlsConfigPresets(unittest.TestCase):
    """Test browser preset configurations."""

    def test_firefox_config(self):
        config = TlsConfig().create_firefox_config()
        self.assertEqual(config.tls_version, 0x0303)
        self.assertEqual(len(config.cipher_suites), 8)
        self.assertEqual(config.supported_groups, [23, 24, 25])
        self.assertEqual(config.alpn_protocols, ["h2", "http/1.1"])

    def test_chrome_config(self):
        config = TlsConfig().create_chrome_config()
        self.assertEqual(config.tls_version, 0x0303)
        self.assertEqual(len(config.cipher_suites), 8)
        self.assertEqual(config.alpn_protocols, ["h2", "http/1.1"])

    def test_custom_config(self):
        config = TlsConfig().create_custom_config(
            tls_version=0x0303,
            supported_groups=[23, 29],
            alpn_protocols=["http/1.1"],
            server_name="test.example.com",
        )
        self.assertEqual(config.supported_groups, [23, 29])
        self.assertEqual(config.alpn_protocols, ["http/1.1"])
        self.assertEqual(config.server_name, "test.example.com")

    def test_custom_config_partial_update(self):
        """Custom config should only update specified fields."""
        config = TlsConfig()
        original_version = config.tls_version
        config.create_custom_config(server_name="example.com")
        self.assertEqual(config.tls_version, original_version)
        self.assertEqual(config.server_name, "example.com")


class TestTlsConfigJA3(unittest.TestCase):
    """Test JA3 fingerprint string generation."""

    def test_ja3_string_format(self):
        """JA3 string should have 5 comma-separated fields."""
        config = TlsConfig()
        ja3 = config.get_ja3_string()
        parts = ja3.split(",")
        self.assertEqual(len(parts), 5)

    def test_ja3_string_version(self):
        config = TlsConfig()
        ja3 = config.get_ja3_string()
        version = ja3.split(",")[0]
        self.assertEqual(version, str(0x0303))

    def test_ja3_string_changes_with_config(self):
        """Different configs should produce different JA3 strings."""
        config1 = TlsConfig()
        config2 = TlsConfig().create_firefox_config()
        self.assertNotEqual(config1.get_ja3_string(), config2.get_ja3_string())


if __name__ == "__main__":
    unittest.main()
