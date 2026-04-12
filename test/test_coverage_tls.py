"""Coverage improvement tests for TLS layers, cipher suites, debug, contexts."""

import struct
import unittest

from ja3requests.protocol.tls.cipher_suites.suites import (
    RsaWithAes128CbcSha,
    RsaWithAes256CbcSha,
    EcdheRsaWithAes128GcmSha256,
    EcdheRsaWithAes256GcmSha384,
    EcdheEcdsaWithAes128GcmSha256,
    EcdheEcdsaWithAes256GcmSha384,
    EcdheRsaWithAes128CbcSha256,
    EcdheRsaWithAes256CbcSha384,
    ReservedGrease,
)
from ja3requests.protocol.tls.cipher_suites import CipherSuite
from ja3requests.protocol.tls.layers import HandShake, Random
from ja3requests.protocol.tls.layers.client_hello import ClientHello
from ja3requests.protocol.tls.layers.server_hello import ServerHello
from ja3requests.protocol.tls.layers.server_hello_done import ServerHelloDone
from ja3requests.protocol.tls.layers.certificate import Certificate
from ja3requests.protocol.tls.layers.certificate_request import CertificateRequest
from ja3requests.protocol.tls.layers.server_key_exchange import ServerKeyExchange
from ja3requests.protocol.tls.debug import debug, debug_hex
from ja3requests.contexts.context import HTTPContext, HTTPSContext


class TestCipherSuiteProperties(unittest.TestCase):
    """Test cipher suite value/name/version properties."""

    def test_rsa_aes128_cbc_sha(self):
        s = RsaWithAes128CbcSha()
        self.assertEqual(s.value, 0x002F)
        self.assertIn("AES_128_CBC_SHA", s.name)
        self.assertIn(1.2, s.version)

    def test_rsa_aes256_cbc_sha(self):
        s = RsaWithAes256CbcSha()
        self.assertEqual(s.value, 0x0035)

    def test_ecdhe_rsa_aes128_gcm(self):
        s = EcdheRsaWithAes128GcmSha256()
        self.assertEqual(s.value, 0xC02F)

    def test_ecdhe_rsa_aes256_gcm(self):
        s = EcdheRsaWithAes256GcmSha384()
        self.assertEqual(s.value, 0xC030)

    def test_ecdhe_ecdsa_aes128_gcm(self):
        s = EcdheEcdsaWithAes128GcmSha256()
        self.assertEqual(s.value, 0xC02B)

    def test_ecdhe_ecdsa_aes256_gcm(self):
        s = EcdheEcdsaWithAes256GcmSha384()
        self.assertEqual(s.value, 0xC02C)

    def test_ecdhe_rsa_aes128_cbc_sha256(self):
        s = EcdheRsaWithAes128CbcSha256()
        self.assertEqual(s.value, 0xC027)

    def test_ecdhe_rsa_aes256_cbc_sha384(self):
        s = EcdheRsaWithAes256CbcSha384()
        self.assertEqual(s.value, 0xC028)

    def test_grease(self):
        s = ReservedGrease()
        self.assertIn(s.value, [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
                                0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
                                0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA])

    def test_cipher_suite_repr(self):
        s = RsaWithAes128CbcSha()
        r = repr(s) if hasattr(s, '__repr__') else str(s)
        self.assertIsNotNone(r)


class TestCipherSuiteBase(unittest.TestCase):
    """Test cipher suite properties."""

    def test_value_is_int(self):
        s = RsaWithAes128CbcSha()
        self.assertIsInstance(s.value, int)

    def test_name_is_string(self):
        s = RsaWithAes128CbcSha()
        self.assertIsInstance(s.name, str)

    def test_version_is_set(self):
        s = RsaWithAes128CbcSha()
        self.assertIsInstance(s.version, set)


class TestRandom(unittest.TestCase):
    """Test TLS Random structure."""

    def test_random_length(self):
        r = Random()
        self.assertEqual(len(r.bytes()), 32)

    def test_random_bytes_method(self):
        r = Random()
        b = bytes(r)
        self.assertEqual(len(b), 32)

    def test_unix_time(self):
        t = Random.get_unix_time()
        self.assertIsInstance(t, int)
        self.assertGreater(t, 0)


class TestClientHello(unittest.TestCase):
    """Test ClientHello message construction."""

    def test_handshake_type(self):
        ch = ClientHello()
        self.assertEqual(ch.handshake_type, struct.pack("B", 1))

    def test_version_default(self):
        ch = ClientHello()
        self.assertEqual(ch.version, b"\x03\x03")

    def test_version_setter(self):
        ch = ClientHello()
        ch.version = b"\x03\x01"
        self.assertEqual(ch.version, b"\x03\x01")

    def test_session_id_default(self):
        ch = ClientHello()
        self.assertEqual(ch.session_id, b"\x00")

    def test_message_is_bytes(self):
        ch = ClientHello()
        msg = ch.message
        self.assertIsInstance(msg, bytes)
        # Starts with TLS record header: 0x16 (handshake)
        self.assertEqual(msg[0], 0x16)

    def test_handshake_message(self):
        ch = ClientHello()
        hm = ch.handshake_message
        self.assertEqual(hm[0], 1)  # ClientHello type

    def test_length(self):
        ch = ClientHello()
        length_bytes = ch.length()
        self.assertEqual(len(length_bytes), 3)

    def test_with_cipher_suites(self):
        ch = ClientHello(cipher_suites=[RsaWithAes128CbcSha()])
        self.assertIsNotNone(ch.cipher_suites)

    def test_content(self):
        ch = ClientHello()
        content = ch.content()
        self.assertIsInstance(content, bytes)
        self.assertGreater(len(content), 0)


class TestServerHello(unittest.TestCase):
    """Test ServerHello."""

    def test_handshake_type(self):
        sh = ServerHello()
        self.assertEqual(sh.handshake_type, struct.pack("B", 2))


class TestServerHelloDone(unittest.TestCase):
    """Test ServerHelloDone."""

    def test_handshake_type(self):
        shd = ServerHelloDone()
        self.assertEqual(shd.handshake_type, struct.pack("B", 14))


class TestCertificate(unittest.TestCase):
    """Test Certificate layer."""

    def test_handshake_type(self):
        c = Certificate()
        self.assertEqual(c.handshake_type, struct.pack("B", 11))


class TestCertificateRequest(unittest.TestCase):
    """Test CertificateRequest layer."""

    def test_handshake_type(self):
        cr = CertificateRequest()
        self.assertEqual(cr.handshake_type, struct.pack("B", 13))


class TestServerKeyExchange(unittest.TestCase):
    """Test ServerKeyExchange layer."""

    def test_handshake_type(self):
        ske = ServerKeyExchange()
        self.assertEqual(ske.handshake_type, struct.pack("B", 12))


class TestDebug(unittest.TestCase):
    """Test debug module."""

    def test_debug_no_crash(self):
        debug("test message")
        debug("test message", level=2)

    def test_debug_hex_no_crash(self):
        debug_hex("label", b"\x01\x02\x03")


class TestHTTPContext(unittest.TestCase):
    """Test HTTPContext."""

    def test_create(self):
        ctx = HTTPContext()
        self.assertIsNotNone(ctx)

    def test_set_payload(self):
        ctx = HTTPContext()
        ctx.set_payload(
            method="GET",
            start_line="http://example.com/",
            port=80,
            headers={"Host": "example.com"},
        )
        self.assertEqual(ctx.method, "GET")


class TestHTTPSContext(unittest.TestCase):
    """Test HTTPSContext."""

    def test_create(self):
        ctx = HTTPSContext()
        self.assertIsNotNone(ctx)

    def test_create_with_protocol(self):
        ctx = HTTPSContext(protocol="HTTP/1.1")
        self.assertIsNotNone(ctx)


if __name__ == "__main__":
    unittest.main()
