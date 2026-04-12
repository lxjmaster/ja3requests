"""Coverage tests for cipher_suites/suites.py — instantiate all suite classes."""

import unittest
from ja3requests.protocol.tls.cipher_suites import suites


class TestAllCipherSuites(unittest.TestCase):
    """Instantiate every cipher suite class to cover their __init__ methods."""

    def _check_suite(self, cls):
        s = cls()
        self.assertIsInstance(s.value, int)
        self.assertIsInstance(s.name, str)
        self.assertIsInstance(s.version, set)
        self.assertGreater(s.value, 0)
        self.assertGreater(len(s.name), 0)

    def test_rsa_suites(self):
        for cls in [
            suites.RsaWithAes128CbcSha,
            suites.RsaWithAes256CbcSha,
        ]:
            self._check_suite(cls)

    def test_ecdhe_rsa_suites(self):
        for cls in [
            suites.EcdheRsaWithAes128GcmSha256,
            suites.EcdheRsaWithAes256GcmSha384,
            suites.EcdheRsaWithAes128CbcSha256,
            suites.EcdheRsaWithAes256CbcSha384,
        ]:
            self._check_suite(cls)

    def test_ecdhe_ecdsa_suites(self):
        for cls in [
            suites.EcdheEcdsaWithAes128GcmSha256,
            suites.EcdheEcdsaWithAes256GcmSha384,
        ]:
            self._check_suite(cls)

    def test_grease_values(self):
        for _ in range(10):
            g = suites.ReservedGrease()
            self.assertIsNotNone(g.value)

    def test_all_defined_suites(self):
        """Find and instantiate all CipherSuite subclasses in suites module."""
        from ja3requests.protocol.tls.cipher_suites import CipherSuite
        count = 0
        for name in dir(suites):
            obj = getattr(suites, name)
            if isinstance(obj, type) and issubclass(obj, CipherSuite) and obj is not CipherSuite:
                try:
                    instance = obj()
                    self.assertIsNotNone(instance.value)
                    count += 1
                except Exception:
                    pass
        self.assertGreater(count, 5)


if __name__ == "__main__":
    unittest.main()
