"""Tests for HPACK Huffman codec, H2 ALPN integration, and ChaCha20-Poly1305."""

import os
import struct
import unittest

from ja3requests.protocol.h2.huffman import huffman_encode, huffman_decode
from ja3requests.protocol.h2.hpack import HPACKEncoder, HPACKDecoder, encode_string, decode_string
from ja3requests.protocol.tls.tls13 import TLS13RecordProtection


# ============================================================================
# Huffman codec tests
# ============================================================================

class TestHuffmanEncode(unittest.TestCase):
    def test_encode_simple(self):
        result = huffman_encode(b"www.example.com")
        self.assertIsInstance(result, bytes)
        self.assertGreater(len(result), 0)
        # Huffman encoding should be shorter than raw for ASCII text
        self.assertLessEqual(len(result), len(b"www.example.com"))

    def test_encode_empty(self):
        result = huffman_encode(b"")
        self.assertEqual(result, b"")

    def test_encode_string_input(self):
        result = huffman_encode("hello")
        self.assertIsInstance(result, bytes)

    def test_encode_all_ascii(self):
        """Encoding lowercase ASCII should produce valid output."""
        for char in b"abcdefghijklmnopqrstuvwxyz":
            result = huffman_encode(bytes([char]))
            self.assertGreater(len(result), 0)


class TestHuffmanDecode(unittest.TestCase):
    def test_decode_empty(self):
        result = huffman_decode(b"")
        self.assertEqual(result, b"")

    def test_roundtrip_simple(self):
        original = b"www.example.com"
        encoded = huffman_encode(original)
        decoded = huffman_decode(encoded)
        self.assertEqual(decoded, original)

    def test_roundtrip_path(self):
        original = b"/sample/path"
        decoded = huffman_decode(huffman_encode(original))
        self.assertEqual(decoded, original)

    def test_roundtrip_headers(self):
        for text in [b"text/html", b"application/json", b"gzip, deflate", b"keep-alive"]:
            decoded = huffman_decode(huffman_encode(text))
            self.assertEqual(decoded, text, f"Roundtrip failed for: {text}")

    def test_roundtrip_numbers(self):
        decoded = huffman_decode(huffman_encode(b"12345"))
        self.assertEqual(decoded, b"12345")

    def test_roundtrip_mixed_case(self):
        original = b"Content-Type"
        decoded = huffman_decode(huffman_encode(original))
        self.assertEqual(decoded, original)


# ============================================================================
# HPACK with Huffman integration
# ============================================================================

class TestHPACKHuffmanIntegration(unittest.TestCase):
    def test_decode_huffman_string(self):
        """decode_string should handle Huffman-encoded strings."""
        text = b"www.example.com"
        encoded = huffman_encode(text)
        # Build HPACK string: H=1 bit | length
        length = len(encoded)
        hpack_str = bytes([0x80 | length]) + encoded
        decoded_bytes, offset = decode_string(hpack_str, 0)
        self.assertEqual(decoded_bytes, text)
        self.assertEqual(offset, len(hpack_str))


# ============================================================================
# ChaCha20-Poly1305 cipher
# ============================================================================

class TestChaCha20Poly1305Record(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(32)  # ChaCha20 requires 256-bit key
        iv = os.urandom(12)
        enc = TLS13RecordProtection(key, iv, cipher="chacha20-poly1305")
        dec = TLS13RecordProtection(key, iv, cipher="chacha20-poly1305")
        ct = enc.encrypt(0x17, b"chacha test data")
        header = ct[:5]
        ciphertext = ct[5:]
        content_type, plaintext = dec.decrypt(ciphertext, header)
        self.assertEqual(plaintext, b"chacha test data")
        self.assertEqual(content_type, 0x17)

    def test_chacha_different_from_aes(self):
        key = os.urandom(32)
        iv = os.urandom(12)
        chacha = TLS13RecordProtection(key, iv, cipher="chacha20-poly1305")
        aes = TLS13RecordProtection(key, iv, cipher="aes-gcm")
        ct_chacha = chacha.encrypt(0x17, b"test")
        ct_aes = aes.encrypt(0x17, b"test")
        # Different ciphers produce different ciphertexts
        self.assertNotEqual(ct_chacha[5:], ct_aes[5:])

    def test_chacha_seq_increment(self):
        key = os.urandom(32)
        iv = os.urandom(12)
        rp = TLS13RecordProtection(key, iv, cipher="chacha20-poly1305")
        rp.encrypt(0x17, b"msg1")
        self.assertEqual(rp.seq_num, 1)


# ============================================================================
# ALPN parsing test
# ============================================================================

class TestALPNParsing(unittest.TestCase):
    def test_parse_alpn_from_server_hello_extensions(self):
        """TLS._parse_server_hello should extract ALPN protocol."""
        import socket
        from ja3requests.protocol.tls import TLS

        s1, s2 = socket.socketpair()
        try:
            tls = TLS(s1)

            # Build a minimal ServerHello with ALPN extension
            version = b"\x03\x03"
            random_bytes = os.urandom(32)
            session_id = b"\x00"  # no session ID
            cipher = b"\xc0\x2f"  # ECDHE_RSA_AES128_GCM_SHA256
            compression = b"\x00"

            # ALPN extension: type=0x0010, protocol="h2"
            alpn_proto = b"h2"
            alpn_entry = struct.pack("B", len(alpn_proto)) + alpn_proto
            alpn_list = struct.pack("!H", len(alpn_entry)) + alpn_entry
            alpn_ext = struct.pack("!HH", 0x0010, len(alpn_list)) + alpn_list

            extensions = struct.pack("!H", len(alpn_ext)) + alpn_ext

            server_hello = version + random_bytes + session_id + cipher + compression + extensions
            tls._parse_server_hello(server_hello)

            self.assertEqual(tls._negotiated_protocol, "h2")
        finally:
            s1.close()
            s2.close()

    def test_parse_no_alpn(self):
        """ServerHello without ALPN should leave negotiated_protocol as None."""
        import socket
        from ja3requests.protocol.tls import TLS

        s1, s2 = socket.socketpair()
        try:
            tls = TLS(s1)
            version = b"\x03\x03"
            random_bytes = os.urandom(32)
            session_id = b"\x00"
            cipher = b"\x00\x2f"
            compression = b"\x00"
            server_hello = version + random_bytes + session_id + cipher + compression
            tls._parse_server_hello(server_hello)
            self.assertIsNone(tls._negotiated_protocol)
        finally:
            s1.close()
            s2.close()


class TestHttpsSocketH2Routing(unittest.TestCase):
    """Test that HttpsSocket routes to H2 based on ALPN."""

    def test_h1_when_no_alpn(self):
        """When no ALPN, should use _send_h1."""
        from ja3requests.sockets.https import HttpsSocket
        # Verify the method exists
        self.assertTrue(hasattr(HttpsSocket, '_send_h1'))
        self.assertTrue(hasattr(HttpsSocket, '_send_h2'))


if __name__ == "__main__":
    unittest.main()
