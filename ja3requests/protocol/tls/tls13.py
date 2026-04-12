"""
ja3requests.protocol.tls.tls13
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

TLS 1.3 (RFC 8446) implementation: HKDF key schedule, handshake, and record layer.
"""

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.asymmetric import x25519, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

from ja3requests.protocol.tls.debug import debug


# ============================================================================
# HKDF Key Schedule (RFC 5869 + TLS 1.3 RFC 8446 Section 7.1)
# ============================================================================

class HKDF:
    """HKDF (HMAC-based Key Derivation Function) for TLS 1.3."""

    @staticmethod
    def extract(salt, ikm, hash_algo=hashlib.sha256):
        """
        HKDF-Extract: extract a pseudorandom key from input keying material.

        :param salt: Optional salt (if None, uses zero-filled bytes)
        :param ikm: Input keying material
        :param hash_algo: Hash algorithm (default: SHA-256)
        :return: Pseudorandom key (PRK)
        """
        if salt is None:
            salt = b"\x00" * hash_algo().digest_size
        return hmac.new(salt, ikm, hash_algo).digest()

    @staticmethod
    def expand(prk, info, length, hash_algo=hashlib.sha256):
        """
        HKDF-Expand: expand a PRK into output keying material.

        :param prk: Pseudorandom key from HKDF-Extract
        :param info: Context/application-specific info
        :param length: Output length in bytes
        :param hash_algo: Hash algorithm
        :return: Output keying material
        """
        hash_len = hash_algo().digest_size
        n = (length + hash_len - 1) // hash_len
        okm = b""
        t = b""

        for i in range(1, n + 1):
            t = hmac.new(prk, t + info + struct.pack("B", i), hash_algo).digest()
            okm += t

        return okm[:length]

    @staticmethod
    def expand_label(prk, label, context, length, hash_algo=hashlib.sha256):
        """
        HKDF-Expand-Label for TLS 1.3 (RFC 8446 Section 7.1).

        HkdfLabel = struct {
            uint16 length;
            opaque label<7..255> = "tls13 " + Label;
            opaque context<0..255> = Context;
        };

        :param prk: Secret
        :param label: Label string (without "tls13 " prefix)
        :param context: Context bytes (usually transcript hash)
        :param length: Desired output length
        :return: Derived key material
        """
        tls_label = b"tls13 " + label.encode() if isinstance(label, str) else b"tls13 " + label
        hkdf_label = struct.pack("!H", length)
        hkdf_label += struct.pack("B", len(tls_label)) + tls_label
        hkdf_label += struct.pack("B", len(context)) + context
        return HKDF.expand(prk, hkdf_label, length, hash_algo)

    @staticmethod
    def derive_secret(secret, label, messages, hash_algo=hashlib.sha256):
        """
        Derive-Secret for TLS 1.3.

        Derive-Secret(Secret, Label, Messages) =
            HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)

        :param secret: The current secret
        :param label: Label string
        :param messages: Concatenated handshake messages (or b"" for empty)
        :param hash_algo: Hash algorithm
        :return: Derived secret
        """
        transcript_hash = hash_algo(messages).digest()
        return HKDF.expand_label(secret, label, transcript_hash, hash_algo().digest_size, hash_algo)


# ============================================================================
# TLS 1.3 Key Schedule (RFC 8446 Section 7.1)
# ============================================================================

class TLS13KeySchedule:
    """
    TLS 1.3 Key Schedule.

    Implements the full key derivation chain:
        Early Secret → Handshake Secret → Master Secret
    And derives traffic keys for each phase.
    """

    def __init__(self, hash_algo=hashlib.sha256):
        self.hash_algo = hash_algo
        self.hash_len = hash_algo().digest_size

        # Secrets at each stage
        self.early_secret = None
        self.handshake_secret = None
        self.master_secret = None

        # Traffic secrets
        self.client_handshake_traffic_secret = None
        self.server_handshake_traffic_secret = None
        self.client_application_traffic_secret = None
        self.server_application_traffic_secret = None

    def compute_early_secret(self, psk=None):
        """
        Compute Early Secret.

        Early Secret = HKDF-Extract(salt=0, IKM=PSK or 0)
        """
        ikm = psk or (b"\x00" * self.hash_len)
        self.early_secret = HKDF.extract(None, ikm, self.hash_algo)
        debug(f"TLS 1.3 Early Secret: {self.early_secret.hex()[:32]}...")
        return self.early_secret

    def compute_handshake_secret(self, shared_secret, hello_messages=b""):
        """
        Compute Handshake Secret.

        derived = Derive-Secret(early_secret, "derived", "")
        Handshake Secret = HKDF-Extract(salt=derived, IKM=shared_secret)
        """
        if self.early_secret is None:
            self.compute_early_secret()

        derived = HKDF.derive_secret(self.early_secret, "derived", b"", self.hash_algo)
        self.handshake_secret = HKDF.extract(derived, shared_secret, self.hash_algo)
        debug(f"TLS 1.3 Handshake Secret: {self.handshake_secret.hex()[:32]}...")

        # Derive handshake traffic secrets
        self.client_handshake_traffic_secret = HKDF.derive_secret(
            self.handshake_secret, "c hs traffic", hello_messages, self.hash_algo
        )
        self.server_handshake_traffic_secret = HKDF.derive_secret(
            self.handshake_secret, "s hs traffic", hello_messages, self.hash_algo
        )

        return self.handshake_secret

    def compute_master_secret(self, handshake_messages=b""):
        """
        Compute Master Secret.

        derived = Derive-Secret(handshake_secret, "derived", "")
        Master Secret = HKDF-Extract(salt=derived, IKM=0)
        """
        derived = HKDF.derive_secret(self.handshake_secret, "derived", b"", self.hash_algo)
        self.master_secret = HKDF.extract(derived, b"\x00" * self.hash_len, self.hash_algo)
        debug(f"TLS 1.3 Master Secret: {self.master_secret.hex()[:32]}...")

        # Derive application traffic secrets
        self.client_application_traffic_secret = HKDF.derive_secret(
            self.master_secret, "c ap traffic", handshake_messages, self.hash_algo
        )
        self.server_application_traffic_secret = HKDF.derive_secret(
            self.master_secret, "s ap traffic", handshake_messages, self.hash_algo
        )

        return self.master_secret

    def derive_traffic_keys(self, secret, key_length=16, iv_length=12):
        """
        Derive traffic key and IV from a traffic secret.

        key = HKDF-Expand-Label(Secret, "key", "", key_length)
        iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)
        """
        key = HKDF.expand_label(secret, "key", b"", key_length, self.hash_algo)
        iv = HKDF.expand_label(secret, "iv", b"", iv_length, self.hash_algo)
        return key, iv

    def compute_finished_key(self, base_key):
        """
        Derive Finished key from a handshake traffic secret.

        finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
        """
        return HKDF.expand_label(base_key, "finished", b"", self.hash_len, self.hash_algo)

    def compute_finished_verify_data(self, finished_key, handshake_context):
        """
        Compute Finished verify_data.

        verify_data = HMAC(finished_key, Transcript-Hash(handshake_context))
        """
        transcript_hash = self.hash_algo(handshake_context).digest()
        return hmac.new(finished_key, transcript_hash, self.hash_algo).digest()


# ============================================================================
# TLS 1.3 ECDHE Key Exchange
# ============================================================================

class TLS13KeyExchange:
    """TLS 1.3 ECDHE key exchange for key_share extension."""

    @staticmethod
    def generate_x25519_keypair():
        """Generate X25519 private/public key pair."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return private_key, public_bytes

    @staticmethod
    def generate_secp256r1_keypair():
        """Generate secp256r1 (P-256) key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        return private_key, public_bytes

    @staticmethod
    def compute_x25519_shared_secret(private_key, peer_public_bytes):
        """Compute shared secret from X25519 key exchange."""
        peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
        return private_key.exchange(peer_public)

    @staticmethod
    def compute_secp256r1_shared_secret(private_key, peer_public_bytes):
        """Compute shared secret from secp256r1 key exchange."""
        peer_public = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), peer_public_bytes
        )
        return private_key.exchange(ec.ECDH(), peer_public)


# ============================================================================
# TLS 1.3 Record Layer Encryption
# ============================================================================

class TLS13RecordProtection:
    """TLS 1.3 record layer encryption/decryption using AES-GCM."""

    def __init__(self, key, iv):
        self.key = key
        self.iv = iv
        self.seq_num = 0
        self._aesgcm = AESGCM(key)

    def _compute_nonce(self):
        """Compute per-record nonce: IV XOR sequence number."""
        seq_bytes = self.seq_num.to_bytes(len(self.iv), byteorder='big')
        nonce = bytes(a ^ b for a, b in zip(self.iv, seq_bytes))
        self.seq_num += 1
        return nonce

    def encrypt(self, content_type, plaintext):
        """
        Encrypt a TLS 1.3 record.

        TLSInnerPlaintext = plaintext + content_type(1 byte)
        TLSCiphertext = AES-GCM(nonce, aad=header, plaintext=TLSInnerPlaintext)
        """
        # TLSInnerPlaintext: data + content type byte
        inner = plaintext + struct.pack("B", content_type)
        nonce = self._compute_nonce()

        # Build header first to use as AAD
        # Encrypted length = inner length + 16 bytes GCM tag
        length = len(inner) + 16
        header = struct.pack("!BHH", 0x17, 0x0303, length)

        encrypted = self._aesgcm.encrypt(nonce, inner, header)

        return header + encrypted

    def decrypt(self, ciphertext, record_header=None):
        """
        Decrypt a TLS 1.3 record.

        Returns (content_type, plaintext).
        """
        nonce = self._compute_nonce()
        aad = record_header  # AAD is the 5-byte record header in TLS 1.3

        inner = self._aesgcm.decrypt(nonce, ciphertext, aad)

        # Strip padding zeros and extract content type (last non-zero byte)
        # TLSInnerPlaintext: content + content_type + zeros
        i = len(inner) - 1
        while i >= 0 and inner[i] == 0:
            i -= 1

        if i < 0:
            raise ValueError("TLS 1.3: empty inner plaintext")

        content_type = inner[i]
        plaintext = inner[:i]
        return content_type, plaintext
