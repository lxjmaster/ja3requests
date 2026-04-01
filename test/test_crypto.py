"""Tests for ja3requests.protocol.tls.crypto module."""

import os
import unittest

from ja3requests.protocol.tls.crypto import (
    TLSCrypto,
    RSAKeyExchange,
    ECDHEKeyExchange,
    AESCipher,
    get_cipher_info,
    is_gcm_cipher_suite,
)
from ja3requests.exceptions import TLSEncryptionError, TLSDecryptionError


class TestTLSCryptoPRF(unittest.TestCase):
    """Test PRF (Pseudo-Random Function) implementations."""

    def test_prf_deterministic(self):
        """PRF with same inputs should produce same output."""
        secret = b"test_secret_key_for_prf"
        label = b"test label"
        seed = b"test_seed_value"
        result1 = TLSCrypto.prf(secret, label, seed, 48)
        result2 = TLSCrypto.prf(secret, label, seed, 48)
        self.assertEqual(result1, result2)

    def test_prf_output_length(self):
        """PRF should return exact requested length."""
        secret = b"secret"
        label = b"label"
        seed = b"seed"
        for length in [12, 32, 48, 64, 128]:
            result = TLSCrypto.prf(secret, label, seed, length)
            self.assertEqual(len(result), length)

    def test_prf_different_labels_differ(self):
        """Different labels should produce different outputs."""
        secret = b"secret"
        seed = b"seed"
        result1 = TLSCrypto.prf(secret, b"client finished", seed, 12)
        result2 = TLSCrypto.prf(secret, b"server finished", seed, 12)
        self.assertNotEqual(result1, result2)

    def test_prf_sha1_deterministic(self):
        """SHA1 PRF with same inputs should produce same output."""
        secret = b"test_secret"
        label = b"test label"
        seed = b"test_seed"
        result1 = TLSCrypto.prf_sha1(secret, label, seed, 48)
        result2 = TLSCrypto.prf_sha1(secret, label, seed, 48)
        self.assertEqual(result1, result2)

    def test_prf_sha1_differs_from_sha256(self):
        """SHA1 PRF and SHA256 PRF should produce different outputs."""
        secret = b"secret"
        label = b"label"
        seed = b"seed"
        sha256_result = TLSCrypto.prf(secret, label, seed, 48)
        sha1_result = TLSCrypto.prf_sha1(secret, label, seed, 48)
        self.assertNotEqual(sha256_result, sha1_result)


class TestTLSCryptoMasterSecret(unittest.TestCase):
    """Test master secret generation."""

    def test_master_secret_length(self):
        """Master secret must be exactly 48 bytes."""
        premaster = os.urandom(48)
        client_random = os.urandom(32)
        server_random = os.urandom(32)
        master = TLSCrypto.generate_master_secret(premaster, client_random, server_random)
        self.assertEqual(len(master), 48)

    def test_master_secret_deterministic(self):
        """Same inputs should produce same master secret."""
        premaster = b"\x03\x03" + b"\x01" * 46
        client_random = b"\x02" * 32
        server_random = b"\x03" * 32
        ms1 = TLSCrypto.generate_master_secret(premaster, client_random, server_random)
        ms2 = TLSCrypto.generate_master_secret(premaster, client_random, server_random)
        self.assertEqual(ms1, ms2)

    def test_master_secret_different_randoms_differ(self):
        """Different randoms should produce different master secrets."""
        premaster = b"\x03\x03" + b"\x01" * 46
        ms1 = TLSCrypto.generate_master_secret(premaster, b"\x02" * 32, b"\x03" * 32)
        ms2 = TLSCrypto.generate_master_secret(premaster, b"\x04" * 32, b"\x05" * 32)
        self.assertNotEqual(ms1, ms2)


class TestTLSCryptoKeyDerivation(unittest.TestCase):
    """Test key block generation and key derivation."""

    def test_key_block_length(self):
        """Key block should match requested length."""
        master = os.urandom(48)
        client_random = os.urandom(32)
        server_random = os.urandom(32)
        for length in [72, 104, 128]:
            kb = TLSCrypto.generate_key_block(master, client_random, server_random, length)
            self.assertEqual(len(kb), length)

    def test_derive_keys_cbc_rsa_aes128(self):
        """Derive keys for TLS_RSA_WITH_AES_128_CBC_SHA (0x002F)."""
        # mac=20, key=16, iv=16 → total = 2*20 + 2*16 + 2*16 = 104
        key_block = os.urandom(104)
        keys = TLSCrypto.derive_keys(key_block, 0x002F)
        self.assertEqual(len(keys["client_mac_secret"]), 20)
        self.assertEqual(len(keys["server_mac_secret"]), 20)
        self.assertEqual(len(keys["client_key"]), 16)
        self.assertEqual(len(keys["server_key"]), 16)
        self.assertEqual(len(keys["client_iv"]), 16)
        self.assertEqual(len(keys["server_iv"]), 16)

    def test_derive_keys_gcm_ecdhe_aes128(self):
        """Derive keys for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)."""
        # mac=0, key=16, iv=4 → total = 2*16 + 2*4 = 40
        key_block = os.urandom(40)
        keys = TLSCrypto.derive_keys(key_block, 0xC02F)
        self.assertNotIn("client_mac_secret", keys)
        self.assertNotIn("server_mac_secret", keys)
        self.assertEqual(len(keys["client_key"]), 16)
        self.assertEqual(len(keys["server_key"]), 16)
        self.assertEqual(len(keys["client_iv"]), 4)
        self.assertEqual(len(keys["server_iv"]), 4)

    def test_derive_keys_gcm_aes256(self):
        """Derive keys for TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)."""
        # mac=0, key=32, iv=4 → total = 2*32 + 2*4 = 72
        key_block = os.urandom(72)
        keys = TLSCrypto.derive_keys(key_block, 0xC030)
        self.assertEqual(len(keys["client_key"]), 32)
        self.assertEqual(len(keys["server_key"]), 32)
        self.assertEqual(len(keys["client_iv"]), 4)
        self.assertEqual(len(keys["server_iv"]), 4)

    def test_derive_keys_unknown_suite_uses_defaults(self):
        """Unknown cipher suite should fall back to default key lengths."""
        key_block = os.urandom(104)
        keys = TLSCrypto.derive_keys(key_block, 0xFFFF)
        self.assertEqual(len(keys["client_mac_secret"]), 20)
        self.assertEqual(len(keys["client_key"]), 16)
        self.assertEqual(len(keys["client_iv"]), 16)


class TestTLSCryptoVerifyData(unittest.TestCase):
    """Test Finished message verify_data computation."""

    def test_verify_data_length(self):
        """Verify data must be 12 bytes for TLS 1.2."""
        master = os.urandom(48)
        messages = b"fake handshake messages"
        vd = TLSCrypto.compute_verify_data(master, messages, is_client=True)
        self.assertEqual(len(vd), 12)

    def test_client_server_verify_data_differ(self):
        """Client and server verify_data must differ (different labels)."""
        master = os.urandom(48)
        messages = b"fake handshake messages"
        client_vd = TLSCrypto.compute_verify_data(master, messages, is_client=True)
        server_vd = TLSCrypto.compute_verify_data(master, messages, is_client=False)
        self.assertNotEqual(client_vd, server_vd)

    def test_verify_data_deterministic(self):
        """Same inputs should produce same verify_data."""
        master = b"\x01" * 48
        messages = b"test messages"
        vd1 = TLSCrypto.compute_verify_data(master, messages)
        vd2 = TLSCrypto.compute_verify_data(master, messages)
        self.assertEqual(vd1, vd2)


class TestPremasterSecret(unittest.TestCase):
    """Test premaster secret generation."""

    def test_premaster_secret_length(self):
        """Premaster secret must be 48 bytes."""
        pms = TLSCrypto.generate_premaster_secret()
        self.assertEqual(len(pms), 48)

    def test_premaster_secret_version(self):
        """First 2 bytes should be TLS 1.2 version (0x0303)."""
        pms = TLSCrypto.generate_premaster_secret()
        self.assertEqual(pms[:2], b"\x03\x03")

    def test_premaster_secret_random(self):
        """Each generation should produce different random bytes."""
        pms1 = TLSCrypto.generate_premaster_secret()
        pms2 = TLSCrypto.generate_premaster_secret()
        self.assertNotEqual(pms1, pms2)


class TestECDHEKeyExchange(unittest.TestCase):
    """Test ECDHE key exchange."""

    def test_secp256r1_keypair(self):
        """Generate secp256r1 keypair."""
        private_key, public_key_bytes = ECDHEKeyExchange.generate_keypair(23)
        self.assertIsNotNone(private_key)
        # Uncompressed point: 0x04 + 32 bytes x + 32 bytes y = 65
        self.assertEqual(len(public_key_bytes), 65)
        self.assertEqual(public_key_bytes[0], 0x04)

    def test_secp384r1_keypair(self):
        """Generate secp384r1 keypair."""
        private_key, public_key_bytes = ECDHEKeyExchange.generate_keypair(24)
        self.assertIsNotNone(private_key)
        # 0x04 + 48 + 48 = 97
        self.assertEqual(len(public_key_bytes), 97)

    def test_x25519_keypair(self):
        """Generate X25519 keypair."""
        private_key, public_key_bytes = ECDHEKeyExchange.generate_keypair(29)
        self.assertIsNotNone(private_key)
        self.assertEqual(len(public_key_bytes), 32)

    def test_ecdhe_shared_secret_secp256r1(self):
        """Two parties should derive the same shared secret."""
        priv_a, pub_a = ECDHEKeyExchange.generate_keypair(23)
        priv_b, pub_b = ECDHEKeyExchange.generate_keypair(23)
        secret_a = ECDHEKeyExchange.compute_shared_secret(priv_a, pub_b, 23)
        secret_b = ECDHEKeyExchange.compute_shared_secret(priv_b, pub_a, 23)
        self.assertEqual(secret_a, secret_b)

    def test_ecdhe_shared_secret_x25519(self):
        """Two parties should derive the same shared secret with X25519."""
        priv_a, pub_a = ECDHEKeyExchange.generate_keypair(29)
        priv_b, pub_b = ECDHEKeyExchange.generate_keypair(29)
        secret_a = ECDHEKeyExchange.compute_shared_secret(priv_a, pub_b, 29)
        secret_b = ECDHEKeyExchange.compute_shared_secret(priv_b, pub_a, 29)
        self.assertEqual(secret_a, secret_b)

    def test_unsupported_curve_raises(self):
        """Unsupported curve ID should raise ValueError."""
        with self.assertRaises(ValueError):
            ECDHEKeyExchange.generate_keypair(999)

    def test_parse_server_ecdhe_params(self):
        """Parse ECDHE params from ServerKeyExchange data."""
        # Build a fake ServerKeyExchange ECDHE params:
        # curve_type=3 (named_curve), curve_id=23 (secp256r1), pubkey
        _, pub_bytes = ECDHEKeyExchange.generate_keypair(23)
        data = bytes([3])  # named_curve
        data += (23).to_bytes(2, "big")  # curve_id
        data += bytes([len(pub_bytes)])  # pubkey length
        data += pub_bytes
        result = ECDHEKeyExchange.parse_server_ecdhe_params(data)
        self.assertEqual(result["curve_type"], 3)
        self.assertEqual(result["curve_id"], 23)
        self.assertEqual(result["public_key"], pub_bytes)

    def test_parse_unsupported_curve_type(self):
        """Non-named_curve type should return None."""
        data = bytes([1, 0, 23, 0])  # curve_type=1 (not named_curve)
        result = ECDHEKeyExchange.parse_server_ecdhe_params(data)
        self.assertIsNone(result)


class TestAESCipherCBC(unittest.TestCase):
    """Test AES-CBC encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt should return original plaintext."""
        key = os.urandom(16)
        iv = os.urandom(16)
        plaintext = b"Hello, TLS world!"
        ciphertext = AESCipher.encrypt_cbc(plaintext, key, iv)
        decrypted = AESCipher.decrypt_cbc(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_decrypt_256bit_key(self):
        """AES-256 CBC roundtrip."""
        key = os.urandom(32)
        iv = os.urandom(16)
        plaintext = b"Test with AES-256 key"
        ciphertext = AESCipher.encrypt_cbc(plaintext, key, iv)
        decrypted = AESCipher.decrypt_cbc(ciphertext, key, iv)
        self.assertEqual(decrypted, plaintext)

    def test_no_padding_mode(self):
        """No-padding mode for TLS manual padding."""
        key = os.urandom(16)
        iv = os.urandom(16)
        # Must be multiple of 16
        plaintext = b"x" * 32
        ciphertext = AESCipher.encrypt_cbc(plaintext, key, iv, add_padding=False)
        decrypted = AESCipher.decrypt_cbc(ciphertext, key, iv, remove_padding=False)
        self.assertEqual(decrypted, plaintext)

    def test_no_padding_non_aligned_raises(self):
        """Non-aligned plaintext without padding should raise."""
        key = os.urandom(16)
        iv = os.urandom(16)
        with self.assertRaises(TLSEncryptionError):
            AESCipher.encrypt_cbc(b"short", key, iv, add_padding=False)

    def test_wrong_key_decrypt_raises(self):
        """Decryption with wrong key should raise."""
        key1 = os.urandom(16)
        key2 = os.urandom(16)
        iv = os.urandom(16)
        ciphertext = AESCipher.encrypt_cbc(b"test data here!!", key1, iv)
        with self.assertRaises(TLSDecryptionError):
            AESCipher.decrypt_cbc(ciphertext, key2, iv)

    def test_ciphertext_differs_from_plaintext(self):
        """Ciphertext should not equal plaintext."""
        key = os.urandom(16)
        iv = os.urandom(16)
        plaintext = b"x" * 16
        ciphertext = AESCipher.encrypt_cbc(plaintext, key, iv, add_padding=False)
        self.assertNotEqual(ciphertext, plaintext)


class TestAESCipherGCM(unittest.TestCase):
    """Test AES-GCM encryption/decryption."""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt should return original plaintext."""
        key = os.urandom(16)
        iv = os.urandom(12)
        plaintext = b"Hello, AES-GCM!"
        ciphertext, tag = AESCipher.encrypt_gcm(plaintext, key, iv)
        decrypted = AESCipher.decrypt_gcm(ciphertext, key, iv, tag)
        self.assertEqual(decrypted, plaintext)

    def test_gcm_with_aad(self):
        """GCM with additional authenticated data."""
        key = os.urandom(16)
        iv = os.urandom(12)
        plaintext = b"test data"
        aad = b"additional data"
        ciphertext, tag = AESCipher.encrypt_gcm(plaintext, key, iv, aad)
        decrypted = AESCipher.decrypt_gcm(ciphertext, key, iv, tag, aad)
        self.assertEqual(decrypted, plaintext)

    def test_gcm_wrong_tag_raises(self):
        """Wrong auth tag should raise."""
        key = os.urandom(16)
        iv = os.urandom(12)
        ciphertext, _ = AESCipher.encrypt_gcm(b"test", key, iv)
        fake_tag = os.urandom(16)
        with self.assertRaises(TLSDecryptionError):
            AESCipher.decrypt_gcm(ciphertext, key, iv, fake_tag)

    def test_gcm_wrong_aad_raises(self):
        """Wrong AAD should raise (authentication failure)."""
        key = os.urandom(16)
        iv = os.urandom(12)
        plaintext = b"data"
        aad = b"correct aad"
        ciphertext, tag = AESCipher.encrypt_gcm(plaintext, key, iv, aad)
        with self.assertRaises(TLSDecryptionError):
            AESCipher.decrypt_gcm(ciphertext, key, iv, tag, b"wrong aad")

    def test_gcm_tag_length(self):
        """Auth tag should be 16 bytes."""
        key = os.urandom(16)
        iv = os.urandom(12)
        _, tag = AESCipher.encrypt_gcm(b"test", key, iv)
        self.assertEqual(len(tag), 16)

    def test_gcm_256bit_key(self):
        """AES-256-GCM roundtrip."""
        key = os.urandom(32)
        iv = os.urandom(12)
        plaintext = b"AES-256-GCM test"
        ciphertext, tag = AESCipher.encrypt_gcm(plaintext, key, iv)
        decrypted = AESCipher.decrypt_gcm(ciphertext, key, iv, tag)
        self.assertEqual(decrypted, plaintext)


class TestCipherInfo(unittest.TestCase):
    """Test cipher suite info utility."""

    def test_known_cipher_suite(self):
        """Known cipher suite should return info dict."""
        info = get_cipher_info(0x002F)
        self.assertIsInstance(info, dict)

    def test_gcm_detection(self):
        """GCM cipher suites should be detected correctly."""
        self.assertTrue(is_gcm_cipher_suite(0xC02F))
        self.assertTrue(is_gcm_cipher_suite(0xC030))
        self.assertTrue(is_gcm_cipher_suite(0x009C))
        self.assertFalse(is_gcm_cipher_suite(0x002F))
        self.assertFalse(is_gcm_cipher_suite(0xC013))


if __name__ == "__main__":
    unittest.main()
