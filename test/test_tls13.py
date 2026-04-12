"""Tests for TLS 1.3 implementation (#6)."""

import hashlib
import hmac
import struct
import os
import unittest

from ja3requests.protocol.tls.tls13 import (
    HKDF,
    TLS13KeySchedule,
    TLS13KeyExchange,
    TLS13RecordProtection,
)
from ja3requests.protocol.tls.extensions import (
    SupportedVersionsExtension,
    KeyShareExtension,
    PSKKeyExchangeModesExtension,
)


# ============================================================================
# HKDF Tests
# ============================================================================

class TestHKDFExtract(unittest.TestCase):
    """Test HKDF-Extract."""

    def test_extract_deterministic(self):
        result1 = HKDF.extract(b"salt", b"ikm")
        result2 = HKDF.extract(b"salt", b"ikm")
        self.assertEqual(result1, result2)

    def test_extract_output_length(self):
        result = HKDF.extract(b"salt", b"ikm")
        self.assertEqual(len(result), 32)  # SHA-256 digest

    def test_extract_different_salts_differ(self):
        r1 = HKDF.extract(b"salt1", b"ikm")
        r2 = HKDF.extract(b"salt2", b"ikm")
        self.assertNotEqual(r1, r2)

    def test_extract_none_salt_uses_zeros(self):
        result = HKDF.extract(None, b"ikm")
        expected = HKDF.extract(b"\x00" * 32, b"ikm")
        self.assertEqual(result, expected)

    def test_extract_sha384(self):
        result = HKDF.extract(b"salt", b"ikm", hashlib.sha384)
        self.assertEqual(len(result), 48)


class TestHKDFExpand(unittest.TestCase):
    """Test HKDF-Expand."""

    def test_expand_output_length(self):
        prk = HKDF.extract(b"salt", b"ikm")
        result = HKDF.expand(prk, b"info", 42)
        self.assertEqual(len(result), 42)

    def test_expand_different_lengths(self):
        prk = HKDF.extract(b"salt", b"ikm")
        r16 = HKDF.expand(prk, b"info", 16)
        r32 = HKDF.expand(prk, b"info", 32)
        # Shorter should be prefix of longer
        self.assertEqual(r16, r32[:16])

    def test_expand_different_info(self):
        prk = HKDF.extract(b"salt", b"ikm")
        r1 = HKDF.expand(prk, b"info1", 32)
        r2 = HKDF.expand(prk, b"info2", 32)
        self.assertNotEqual(r1, r2)


class TestHKDFExpandLabel(unittest.TestCase):
    """Test HKDF-Expand-Label for TLS 1.3."""

    def test_expand_label_output_length(self):
        prk = os.urandom(32)
        result = HKDF.expand_label(prk, "key", b"", 16)
        self.assertEqual(len(result), 16)

    def test_expand_label_different_labels(self):
        prk = os.urandom(32)
        r1 = HKDF.expand_label(prk, "key", b"", 16)
        r2 = HKDF.expand_label(prk, "iv", b"", 16)
        self.assertNotEqual(r1, r2)

    def test_expand_label_with_context(self):
        prk = os.urandom(32)
        r1 = HKDF.expand_label(prk, "key", b"context1", 16)
        r2 = HKDF.expand_label(prk, "key", b"context2", 16)
        self.assertNotEqual(r1, r2)

    def test_expand_label_deterministic(self):
        prk = b"\x01" * 32
        r1 = HKDF.expand_label(prk, "test", b"ctx", 16)
        r2 = HKDF.expand_label(prk, "test", b"ctx", 16)
        self.assertEqual(r1, r2)


class TestDeriveSecret(unittest.TestCase):
    """Test Derive-Secret."""

    def test_derive_secret_output_length(self):
        secret = os.urandom(32)
        result = HKDF.derive_secret(secret, "label", b"messages")
        self.assertEqual(len(result), 32)  # SHA-256

    def test_derive_secret_different_messages(self):
        secret = os.urandom(32)
        r1 = HKDF.derive_secret(secret, "label", b"msg1")
        r2 = HKDF.derive_secret(secret, "label", b"msg2")
        self.assertNotEqual(r1, r2)


# ============================================================================
# Key Schedule Tests
# ============================================================================

class TestTLS13KeySchedule(unittest.TestCase):
    """Test the full TLS 1.3 key schedule."""

    def test_early_secret(self):
        ks = TLS13KeySchedule()
        es = ks.compute_early_secret()
        self.assertEqual(len(es), 32)
        self.assertIsNotNone(ks.early_secret)

    def test_handshake_secret(self):
        ks = TLS13KeySchedule()
        ks.compute_early_secret()
        shared = os.urandom(32)
        hs = ks.compute_handshake_secret(shared, b"hello_messages")
        self.assertEqual(len(hs), 32)
        self.assertIsNotNone(ks.client_handshake_traffic_secret)
        self.assertIsNotNone(ks.server_handshake_traffic_secret)

    def test_master_secret(self):
        ks = TLS13KeySchedule()
        ks.compute_early_secret()
        ks.compute_handshake_secret(os.urandom(32), b"hello")
        ms = ks.compute_master_secret(b"all_handshake_messages")
        self.assertEqual(len(ms), 32)
        self.assertIsNotNone(ks.client_application_traffic_secret)
        self.assertIsNotNone(ks.server_application_traffic_secret)

    def test_traffic_key_derivation(self):
        ks = TLS13KeySchedule()
        ks.compute_early_secret()
        ks.compute_handshake_secret(os.urandom(32))
        key, iv = ks.derive_traffic_keys(ks.server_handshake_traffic_secret)
        self.assertEqual(len(key), 16)
        self.assertEqual(len(iv), 12)

    def test_traffic_key_256bit(self):
        ks = TLS13KeySchedule()
        ks.compute_early_secret()
        ks.compute_handshake_secret(os.urandom(32))
        key, iv = ks.derive_traffic_keys(ks.server_handshake_traffic_secret, key_length=32)
        self.assertEqual(len(key), 32)

    def test_finished_key(self):
        ks = TLS13KeySchedule()
        ks.compute_early_secret()
        ks.compute_handshake_secret(os.urandom(32))
        fk = ks.compute_finished_key(ks.client_handshake_traffic_secret)
        self.assertEqual(len(fk), 32)

    def test_finished_verify_data(self):
        ks = TLS13KeySchedule()
        ks.compute_early_secret()
        ks.compute_handshake_secret(os.urandom(32))
        fk = ks.compute_finished_key(ks.client_handshake_traffic_secret)
        vd = ks.compute_finished_verify_data(fk, b"handshake_context")
        self.assertEqual(len(vd), 32)

    def test_full_key_schedule_deterministic(self):
        """Same inputs produce same outputs."""
        shared = b"\x42" * 32
        for _ in range(2):
            ks = TLS13KeySchedule()
            ks.compute_early_secret()
            ks.compute_handshake_secret(shared, b"hello")
            ms1 = ks.compute_master_secret(b"all")

        ks2 = TLS13KeySchedule()
        ks2.compute_early_secret()
        ks2.compute_handshake_secret(shared, b"hello")
        ms2 = ks2.compute_master_secret(b"all")
        self.assertEqual(ms1, ms2)

    def test_different_shared_secret_produces_different_keys(self):
        ks1 = TLS13KeySchedule()
        ks1.compute_early_secret()
        ks1.compute_handshake_secret(b"\x01" * 32)

        ks2 = TLS13KeySchedule()
        ks2.compute_early_secret()
        ks2.compute_handshake_secret(b"\x02" * 32)

        self.assertNotEqual(
            ks1.client_handshake_traffic_secret,
            ks2.client_handshake_traffic_secret,
        )


# ============================================================================
# Key Exchange Tests
# ============================================================================

class TestTLS13KeyExchange(unittest.TestCase):
    """Test TLS 1.3 ECDHE key exchange."""

    def test_x25519_keypair(self):
        priv, pub = TLS13KeyExchange.generate_x25519_keypair()
        self.assertEqual(len(pub), 32)
        self.assertIsNotNone(priv)

    def test_x25519_shared_secret(self):
        priv1, pub1 = TLS13KeyExchange.generate_x25519_keypair()
        priv2, pub2 = TLS13KeyExchange.generate_x25519_keypair()
        ss1 = TLS13KeyExchange.compute_x25519_shared_secret(priv1, pub2)
        ss2 = TLS13KeyExchange.compute_x25519_shared_secret(priv2, pub1)
        self.assertEqual(ss1, ss2)  # Both sides compute same secret
        self.assertEqual(len(ss1), 32)

    def test_secp256r1_keypair(self):
        priv, pub = TLS13KeyExchange.generate_secp256r1_keypair()
        self.assertEqual(len(pub), 65)  # Uncompressed point
        self.assertEqual(pub[0], 0x04)  # Uncompressed prefix

    def test_secp256r1_shared_secret(self):
        priv1, pub1 = TLS13KeyExchange.generate_secp256r1_keypair()
        priv2, pub2 = TLS13KeyExchange.generate_secp256r1_keypair()
        ss1 = TLS13KeyExchange.compute_secp256r1_shared_secret(priv1, pub2)
        ss2 = TLS13KeyExchange.compute_secp256r1_shared_secret(priv2, pub1)
        self.assertEqual(ss1, ss2)
        self.assertEqual(len(ss1), 32)


# ============================================================================
# Record Protection Tests
# ============================================================================

class TestTLS13RecordProtection(unittest.TestCase):
    """Test TLS 1.3 record encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        key = os.urandom(16)
        iv = os.urandom(12)
        enc = TLS13RecordProtection(key, iv)
        dec = TLS13RecordProtection(key, iv)

        ciphertext_record = enc.encrypt(0x17, b"hello world")
        # Extract ciphertext (skip 5-byte header)
        header = ciphertext_record[:5]
        ciphertext = ciphertext_record[5:]
        content_type, plaintext = dec.decrypt(ciphertext, header)
        self.assertEqual(plaintext, b"hello world")
        self.assertEqual(content_type, 0x17)

    def test_sequence_number_increments(self):
        key = os.urandom(16)
        iv = os.urandom(12)
        rp = TLS13RecordProtection(key, iv)
        self.assertEqual(rp.seq_num, 0)
        rp.encrypt(0x17, b"msg1")
        self.assertEqual(rp.seq_num, 1)
        rp.encrypt(0x17, b"msg2")
        self.assertEqual(rp.seq_num, 2)

    def test_different_messages_different_ciphertext(self):
        key = os.urandom(16)
        iv = os.urandom(12)
        rp = TLS13RecordProtection(key, iv)
        ct1 = rp.encrypt(0x17, b"message1")
        ct2 = rp.encrypt(0x17, b"message2")
        self.assertNotEqual(ct1, ct2)

    def test_256bit_key(self):
        key = os.urandom(32)
        iv = os.urandom(12)
        enc = TLS13RecordProtection(key, iv)
        dec = TLS13RecordProtection(key, iv)
        ct = enc.encrypt(0x16, b"handshake data")
        header = ct[:5]
        ciphertext = ct[5:]
        content_type, plaintext = dec.decrypt(ciphertext, header)
        self.assertEqual(plaintext, b"handshake data")
        self.assertEqual(content_type, 0x16)

    def test_record_header_format(self):
        key = os.urandom(16)
        iv = os.urandom(12)
        rp = TLS13RecordProtection(key, iv)
        ct = rp.encrypt(0x17, b"data")
        # Header: type=0x17 (app data), version=0x0303, length
        self.assertEqual(ct[0], 0x17)
        self.assertEqual(ct[1:3], b"\x03\x03")


# ============================================================================
# Extension Tests
# ============================================================================

class TestSupportedVersionsExtension(unittest.TestCase):
    """Test supported_versions extension."""

    def test_extension_type(self):
        self.assertEqual(SupportedVersionsExtension.extension_type, 0x002B)

    def test_default_versions(self):
        ext = SupportedVersionsExtension()
        self.assertEqual(ext.versions, [0x0304, 0x0303])

    def test_encode(self):
        ext = SupportedVersionsExtension([0x0304, 0x0303])
        data = ext.encode()
        # 1 byte length + 2 bytes per version
        self.assertEqual(data[0], 4)  # 2 versions * 2 bytes
        v1 = struct.unpack("!H", data[1:3])[0]
        v2 = struct.unpack("!H", data[3:5])[0]
        self.assertEqual(v1, 0x0304)
        self.assertEqual(v2, 0x0303)

    def test_to_bytes(self):
        ext = SupportedVersionsExtension()
        raw = ext.to_bytes()
        ext_type = struct.unpack("!H", raw[:2])[0]
        self.assertEqual(ext_type, 0x002B)


class TestKeyShareExtension(unittest.TestCase):
    """Test key_share extension."""

    def test_extension_type(self):
        self.assertEqual(KeyShareExtension.extension_type, 0x0033)

    def test_encode_x25519(self):
        pub = os.urandom(32)
        ext = KeyShareExtension([(0x001D, pub)])
        data = ext.encode()
        # 2 bytes entries length, then: 2 bytes group + 2 bytes key length + key
        entries_len = struct.unpack("!H", data[:2])[0]
        self.assertEqual(entries_len, 2 + 2 + 32)
        group = struct.unpack("!H", data[2:4])[0]
        self.assertEqual(group, 0x001D)
        key_len = struct.unpack("!H", data[4:6])[0]
        self.assertEqual(key_len, 32)

    def test_encode_multiple_shares(self):
        ext = KeyShareExtension([
            (0x001D, os.urandom(32)),
            (0x0017, os.urandom(65)),
        ])
        data = ext.encode()
        entries_len = struct.unpack("!H", data[:2])[0]
        expected = (2 + 2 + 32) + (2 + 2 + 65)
        self.assertEqual(entries_len, expected)


class TestPSKKeyExchangeModesExtension(unittest.TestCase):
    """Test psk_key_exchange_modes extension."""

    def test_extension_type(self):
        self.assertEqual(PSKKeyExchangeModesExtension.extension_type, 0x002D)

    def test_default_mode(self):
        ext = PSKKeyExchangeModesExtension()
        data = ext.encode()
        self.assertEqual(data[0], 1)  # 1 mode
        self.assertEqual(data[1], 1)  # psk_dhe_ke


# ============================================================================
# TLS Integration Tests
# ============================================================================

class TestTLS13SetupInTLS(unittest.TestCase):
    """Test TLS 1.3 setup in TLS class."""

    def test_tls13_flag_set(self):
        import socket
        from ja3requests.protocol.tls import TLS
        from ja3requests.protocol.tls.config import TlsConfig

        s1, s2 = socket.socketpair()
        try:
            config = TlsConfig()
            config.tls_version = 0x0304
            config.server_name = "example.com"
            tls = TLS(s1)
            tls.set_payload(tls_config=config)
            self.assertTrue(tls._is_tls13)
            self.assertIsNotNone(tls._tls13_private_key)
        finally:
            s1.close()
            s2.close()

    def test_tls12_flag_not_set(self):
        import socket
        from ja3requests.protocol.tls import TLS
        from ja3requests.protocol.tls.config import TlsConfig

        s1, s2 = socket.socketpair()
        try:
            config = TlsConfig()
            config.tls_version = 0x0303
            tls = TLS(s1)
            tls.set_payload(tls_config=config)
            self.assertFalse(tls._is_tls13)
        finally:
            s1.close()
            s2.close()

    def test_tls13_client_hello_has_supported_versions(self):
        import socket
        from ja3requests.protocol.tls import TLS
        from ja3requests.protocol.tls.config import TlsConfig

        s1, s2 = socket.socketpair()
        try:
            config = TlsConfig()
            config.tls_version = 0x0304
            config.server_name = "example.com"
            tls = TLS(s1)
            tls.set_payload(tls_config=config)
            # Check ClientHello extensions contain supported_versions (0x002B)
            ext_data = tls._body.extensions
            self.assertIn(struct.pack("!H", 0x002B), ext_data)
        finally:
            s1.close()
            s2.close()

    def test_tls13_client_hello_has_key_share(self):
        import socket
        from ja3requests.protocol.tls import TLS
        from ja3requests.protocol.tls.config import TlsConfig

        s1, s2 = socket.socketpair()
        try:
            config = TlsConfig()
            config.tls_version = 0x0304
            config.server_name = "example.com"
            tls = TLS(s1)
            tls.set_payload(tls_config=config)
            ext_data = tls._body.extensions
            # key_share extension type 0x0033
            self.assertIn(struct.pack("!H", 0x0033), ext_data)
        finally:
            s1.close()
            s2.close()

    def test_tls13_client_hello_version_is_0303(self):
        """TLS 1.3 ClientHello version field should be 0x0303 for compatibility."""
        import socket
        from ja3requests.protocol.tls import TLS
        from ja3requests.protocol.tls.config import TlsConfig

        s1, s2 = socket.socketpair()
        try:
            config = TlsConfig()
            config.tls_version = 0x0304
            config.server_name = "example.com"
            tls = TLS(s1)
            tls.set_payload(tls_config=config)
            # ClientHello.version should be 0x0303, not 0x0304
            self.assertEqual(tls._body.version, b"\x03\x03")
        finally:
            s1.close()
            s2.close()


if __name__ == "__main__":
    unittest.main()
