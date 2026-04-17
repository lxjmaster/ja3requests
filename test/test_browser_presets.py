"""Tests for browser fingerprint presets (#31)."""

import unittest

from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.protocol.tls.browser_presets import get_preset, list_browsers, PRESETS


class TestListBrowsers(unittest.TestCase):
    def test_all_browsers_listed(self):
        browsers = list_browsers()
        self.assertIn("chrome", browsers)
        self.assertIn("firefox", browsers)
        self.assertIn("safari", browsers)
        self.assertIn("edge", browsers)

    def test_chrome_has_versions(self):
        browsers = list_browsers()
        self.assertIn(120, browsers["chrome"])
        self.assertIn(124, browsers["chrome"])

    def test_firefox_has_versions(self):
        browsers = list_browsers()
        self.assertIn(121, browsers["firefox"])


class TestGetPreset(unittest.TestCase):
    def test_chrome_120(self):
        p = get_preset("chrome", 120)
        self.assertEqual(p["tls_version"], 0x0304)
        self.assertTrue(len(p["cipher_suites"]) >= 5)
        self.assertIn("h2", p["alpn_protocols"])

    def test_firefox_121(self):
        p = get_preset("firefox", 121)
        self.assertEqual(p["tls_version"], 0x0304)
        self.assertFalse(p["use_grease"])

    def test_safari_17(self):
        p = get_preset("safari", 17)
        self.assertEqual(p["tls_version"], 0x0304)
        self.assertTrue(p["use_grease"])

    def test_edge_120(self):
        p = get_preset("edge", 120)
        self.assertIsNotNone(p["h2_settings"])

    def test_latest_version_default(self):
        p = get_preset("chrome")
        self.assertIsNotNone(p)

    def test_unknown_browser_raises(self):
        with self.assertRaises(ValueError) as ctx:
            get_preset("opera")
        self.assertIn("opera", str(ctx.exception))

    def test_unknown_version_raises(self):
        with self.assertRaises(ValueError) as ctx:
            get_preset("chrome", 999)
        self.assertIn("999", str(ctx.exception))

    def test_case_insensitive(self):
        p = get_preset("Chrome", 120)
        self.assertIsNotNone(p)


class TestFromBrowser(unittest.TestCase):
    """Test TlsConfig.from_browser() class method."""

    def test_chrome_120(self):
        config = TlsConfig.from_browser("chrome", 120)
        self.assertEqual(config.tls_version, 0x0304)
        self.assertTrue(len(config.cipher_suites) >= 5)
        self.assertIn("h2", config.alpn_protocols)
        self.assertTrue(config.use_grease)
        self.assertIsNotNone(config.h2_settings)

    def test_firefox_121(self):
        config = TlsConfig.from_browser("firefox", 121)
        self.assertEqual(config.tls_version, 0x0304)
        self.assertFalse(config.use_grease)
        self.assertIn(25, config.supported_groups)  # P-521

    def test_safari_17(self):
        config = TlsConfig.from_browser("safari", 17)
        self.assertIsNotNone(config.h2_window_update)

    def test_default_latest(self):
        config = TlsConfig.from_browser("chrome")
        self.assertIsNotNone(config)

    def test_with_server_name(self):
        config = TlsConfig.from_browser("chrome", 120, server_name="example.com")
        self.assertEqual(config.server_name, "example.com")

    def test_returns_independent_instances(self):
        c1 = TlsConfig.from_browser("chrome", 120)
        c2 = TlsConfig.from_browser("chrome", 120)
        c1.server_name = "a.com"
        self.assertIsNone(c2.server_name)

    def test_ja3_string_differs_per_browser(self):
        chrome = TlsConfig.from_browser("chrome", 120)
        firefox = TlsConfig.from_browser("firefox", 121)
        self.assertNotEqual(chrome.get_ja3_string(), firefox.get_ja3_string())

    def test_ja3_string_format(self):
        config = TlsConfig.from_browser("chrome", 120)
        ja3 = config.get_ja3_string()
        parts = ja3.split(",")
        self.assertEqual(len(parts), 5)

    def test_h2_settings_from_preset(self):
        config = TlsConfig.from_browser("chrome", 120)
        self.assertEqual(config.h2_settings[0x04], 6291456)
        self.assertEqual(config.h2_window_update, 15663105)

    def test_extensions_from_preset(self):
        config = TlsConfig.from_browser("chrome", 120)
        self.assertTrue(len(config.extensions) > 0)

    def test_signature_algorithms_set(self):
        config = TlsConfig.from_browser("firefox", 121)
        self.assertTrue(len(config.signature_algorithms) > 0)
        self.assertIn(0x0403, config.signature_algorithms)

    def test_all_presets_produce_valid_config(self):
        for (browser, version) in PRESETS:
            config = TlsConfig.from_browser(browser, version)
            ja3 = config.get_ja3_string()
            self.assertEqual(len(ja3.split(",")), 5, f"Invalid JA3 for {browser} {version}")


if __name__ == "__main__":
    unittest.main()
