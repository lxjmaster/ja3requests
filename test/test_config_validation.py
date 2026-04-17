"""Tests for TlsConfig validation (#32)."""

import unittest

from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.protocol.tls.cipher_suites.suites import RsaWithAes128CbcSha


class TestValidateVersions(unittest.TestCase):
    def test_valid_tls12(self):
        c = TlsConfig()
        c.tls_version = 0x0303
        self.assertEqual(c.validate(), [])

    def test_valid_tls13(self):
        c = TlsConfig()
        c.tls_version = 0x0304
        c.supported_groups = [29, 23]
        self.assertEqual(c.validate(), [])

    def test_invalid_version(self):
        c = TlsConfig()
        c.tls_version = 0x9999
        issues = c.validate()
        self.assertTrue(any("Invalid TLS version" in i for i in issues))

    def test_strict_raises(self):
        c = TlsConfig()
        c.tls_version = 0x9999
        with self.assertRaises(ValueError):
            c.validate(strict=True)


class TestValidateCipherSuites(unittest.TestCase):
    def test_valid_suites(self):
        c = TlsConfig()
        self.assertEqual(c.validate(), [])

    def test_no_suites(self):
        c = TlsConfig()
        c._cipher_suites = []
        issues = c.validate()
        self.assertTrue(any("No cipher suites" in i for i in issues))

    def test_invalid_suite_object(self):
        c = TlsConfig()
        c._cipher_suites = ["not_a_suite"]
        issues = c.validate()
        self.assertTrue(any("missing 'value'" in i for i in issues))


class TestValidateGroups(unittest.TestCase):
    def test_valid_groups(self):
        c = TlsConfig()
        c.supported_groups = [23, 24, 29]
        self.assertEqual(c.validate(), [])

    def test_invalid_group(self):
        c = TlsConfig()
        c.supported_groups = [99999]
        issues = c.validate()
        self.assertTrue(any("Unknown supported group" in i for i in issues))


class TestValidateSignatureAlgorithms(unittest.TestCase):
    def test_valid_sig_algs(self):
        c = TlsConfig()
        c.signature_algorithms = [0x0401, 0x0501]
        self.assertEqual(c.validate(), [])

    def test_invalid_sig_alg(self):
        c = TlsConfig()
        c.signature_algorithms = [0x1FFFF]
        issues = c.validate()
        self.assertTrue(any("Invalid signature algorithm" in i for i in issues))


class TestValidateALPN(unittest.TestCase):
    def test_valid_alpn(self):
        c = TlsConfig()
        c.alpn_protocols = ["h2", "http/1.1"]
        self.assertEqual(c.validate(), [])

    def test_empty_protocol(self):
        c = TlsConfig()
        c.alpn_protocols = [""]
        issues = c.validate()
        self.assertTrue(any("Invalid ALPN" in i for i in issues))

    def test_non_string_protocol(self):
        c = TlsConfig()
        c.alpn_protocols = [123]
        issues = c.validate()
        self.assertTrue(any("Invalid ALPN" in i for i in issues))


class TestValidateTLS13Requirements(unittest.TestCase):
    def test_tls13_needs_groups(self):
        c = TlsConfig()
        c.tls_version = 0x0304
        c.supported_groups = []
        issues = c.validate()
        self.assertTrue(any("TLS 1.3 requires" in i for i in issues))


class TestBrowserPresetValidation(unittest.TestCase):
    def test_all_presets_pass_validation(self):
        from ja3requests.protocol.tls.browser_presets import PRESETS
        for (browser, version) in PRESETS:
            config = TlsConfig.from_browser(browser, version)
            issues = config.validate()
            self.assertEqual(issues, [], f"{browser} {version} failed: {issues}")


if __name__ == "__main__":
    unittest.main()
