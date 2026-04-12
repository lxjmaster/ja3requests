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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
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

    def __init__(self, key, iv, cipher="aes-gcm"):
        self.key = key
        self.iv = iv
        self.seq_num = 0
        self._cipher_name = cipher
        if cipher == "chacha20-poly1305":
            self._aead = ChaCha20Poly1305(key)
        else:
            self._aead = AESGCM(key)

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

        encrypted = self._aead.encrypt(nonce, inner, header)

        return header + encrypted

    def decrypt(self, ciphertext, record_header=None):
        """
        Decrypt a TLS 1.3 record.

        Returns (content_type, plaintext).
        """
        nonce = self._compute_nonce()
        aad = record_header  # AAD is the 5-byte record header in TLS 1.3

        inner = self._aead.decrypt(nonce, ciphertext, aad)

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


# ============================================================================
# TLS 1.3 Handshake Handler
# ============================================================================

# Named group IDs
GROUP_X25519 = 0x001D
GROUP_SECP256R1 = 0x0017

# Cipher suite → (key_length, hash_algo)
TLS13_CIPHER_PARAMS = {
    0x1301: (16, hashlib.sha256),  # TLS_AES_128_GCM_SHA256
    0x1302: (32, hashlib.sha384),  # TLS_AES_256_GCM_SHA384
    0x1303: (32, hashlib.sha256),  # TLS_CHACHA20_POLY1305_SHA256
}


class TLS13Handshake:
    """
    TLS 1.3 handshake state machine.

    Orchestrates: ClientHello → ServerHello → [encrypted handshake] → Finished
    Using the HKDF key schedule, key exchange, and record protection primitives.
    """

    def __init__(self, conn, private_key, key_share_group, client_hello_bytes):
        """
        :param conn: Raw TCP socket
        :param private_key: ECDHE private key (from ClientHello key_share)
        :param key_share_group: Named group ID used in key_share
        :param client_hello_bytes: Raw ClientHello handshake message (for transcript)
        """
        self.conn = conn
        self._private_key = private_key
        self._key_share_group = key_share_group
        self._transcript = client_hello_bytes  # Accumulates handshake messages
        self._key_schedule = None
        self._server_handshake_rp = None  # Record protection for decrypting server
        self._client_handshake_rp = None  # Record protection for encrypting to server
        self._server_app_rp = None
        self._client_app_rp = None
        self._cipher_suite = None
        self._hash_algo = hashlib.sha256
        self._key_length = 16
        self._cipher_type = "aes-gcm"

    def process_server_hello(self, server_hello_data):
        """
        Parse ServerHello, extract key_share, compute shared secret,
        and derive handshake traffic keys.

        :param server_hello_data: Raw ServerHello handshake message bytes
        :return: True if successful
        """
        self._transcript += server_hello_data

        # Parse ServerHello to extract cipher suite and key_share
        offset = 0
        if len(server_hello_data) < 38:
            return False

        # Version (2) + Random (32) = 34 bytes
        offset = 2 + 32

        # Session ID
        if offset >= len(server_hello_data):
            return False
        sid_len = server_hello_data[offset]
        offset += 1 + sid_len

        # Cipher suite
        if offset + 2 > len(server_hello_data):
            return False
        self._cipher_suite = struct.unpack("!H", server_hello_data[offset:offset + 2])[0]
        offset += 2

        # Compression
        offset += 1

        # Configure cipher parameters
        if self._cipher_suite in TLS13_CIPHER_PARAMS:
            self._key_length, self._hash_algo = TLS13_CIPHER_PARAMS[self._cipher_suite]
        if self._cipher_suite == 0x1303:
            self._cipher_type = "chacha20-poly1305"

        # Parse extensions to find key_share
        server_public_key = None
        server_group = None
        if offset + 2 <= len(server_hello_data):
            ext_length = struct.unpack("!H", server_hello_data[offset:offset + 2])[0]
            offset += 2
            ext_end = offset + ext_length

            while offset + 4 <= ext_end:
                ext_type = struct.unpack("!H", server_hello_data[offset:offset + 2])[0]
                ext_len = struct.unpack("!H", server_hello_data[offset + 2:offset + 4])[0]
                offset += 4
                ext_data = server_hello_data[offset:offset + ext_len]
                offset += ext_len

                if ext_type == 0x0033:  # key_share
                    if len(ext_data) >= 4:
                        server_group = struct.unpack("!H", ext_data[:2])[0]
                        key_len = struct.unpack("!H", ext_data[2:4])[0]
                        server_public_key = ext_data[4:4 + key_len]

        if server_public_key is None:
            debug("TLS 1.3: No key_share in ServerHello")
            return False

        # Compute shared secret
        if server_group == GROUP_X25519:
            shared_secret = TLS13KeyExchange.compute_x25519_shared_secret(
                self._private_key, server_public_key
            )
        elif server_group == GROUP_SECP256R1:
            shared_secret = TLS13KeyExchange.compute_secp256r1_shared_secret(
                self._private_key, server_public_key
            )
        else:
            debug(f"TLS 1.3: Unsupported group 0x{server_group:04X}")
            return False

        debug(f"TLS 1.3: Shared secret computed ({len(shared_secret)} bytes)")

        # Derive handshake traffic keys
        self._key_schedule = TLS13KeySchedule(self._hash_algo)
        self._key_schedule.compute_early_secret()
        self._key_schedule.compute_handshake_secret(shared_secret, self._transcript)

        # Create record protection for handshake phase
        s_key, s_iv = self._key_schedule.derive_traffic_keys(
            self._key_schedule.server_handshake_traffic_secret, self._key_length
        )
        c_key, c_iv = self._key_schedule.derive_traffic_keys(
            self._key_schedule.client_handshake_traffic_secret, self._key_length
        )

        self._server_handshake_rp = TLS13RecordProtection(s_key, s_iv, self._cipher_type)
        self._client_handshake_rp = TLS13RecordProtection(c_key, c_iv, self._cipher_type)

        debug("TLS 1.3: Handshake traffic keys derived")
        return True

    def decrypt_handshake_record(self, ciphertext, record_header):
        """Decrypt a server handshake record and add to transcript."""
        content_type, plaintext = self._server_handshake_rp.decrypt(ciphertext, record_header)
        if content_type == 0x16:  # Handshake
            self._transcript += plaintext
        return content_type, plaintext

    def parse_encrypted_handshake(self, plaintext):
        """
        Parse decrypted handshake messages (EncryptedExtensions,
        Certificate, CertificateVerify, Finished).

        :return: List of (msg_type, msg_data) tuples
        """
        messages = []
        offset = 0
        while offset + 4 <= len(plaintext):
            msg_type = plaintext[offset]
            msg_len = struct.unpack("!I", b"\x00" + plaintext[offset + 1:offset + 4])[0]
            offset += 4
            msg_data = plaintext[offset:offset + msg_len]
            offset += msg_len
            messages.append((msg_type, msg_data))
            debug(f"TLS 1.3: Parsed handshake message type={msg_type} len={msg_len}")
        return messages

    def verify_server_finished(self, finished_data):
        """
        Verify the server's Finished message.

        :param finished_data: The verify_data from server's Finished message
        :return: True if valid
        """
        finished_key = self._key_schedule.compute_finished_key(
            self._key_schedule.server_handshake_traffic_secret
        )
        # Transcript up to (but not including) server Finished
        expected = self._key_schedule.compute_finished_verify_data(
            finished_key, self._transcript
        )
        return hmac.compare_digest(finished_data, expected)

    def build_client_finished(self):
        """
        Build and encrypt the client's Finished message.

        :return: Encrypted TLS record bytes ready to send
        """
        finished_key = self._key_schedule.compute_finished_key(
            self._key_schedule.client_handshake_traffic_secret
        )
        verify_data = self._key_schedule.compute_finished_verify_data(
            finished_key, self._transcript
        )

        # Finished message: type(1) + length(3) + verify_data
        finished_msg = struct.pack("B", 20)  # Finished type
        finished_msg += struct.pack("!I", len(verify_data))[1:]
        finished_msg += verify_data

        self._transcript += finished_msg

        # Encrypt with client handshake key
        return self._client_handshake_rp.encrypt(0x16, finished_msg)

    def derive_application_keys(self):
        """
        Derive application traffic keys after handshake completion.

        :return: (client_app_rp, server_app_rp)
        """
        self._key_schedule.compute_master_secret(self._transcript)

        s_key, s_iv = self._key_schedule.derive_traffic_keys(
            self._key_schedule.server_application_traffic_secret, self._key_length
        )
        c_key, c_iv = self._key_schedule.derive_traffic_keys(
            self._key_schedule.client_application_traffic_secret, self._key_length
        )

        self._server_app_rp = TLS13RecordProtection(s_key, s_iv, self._cipher_type)
        self._client_app_rp = TLS13RecordProtection(c_key, c_iv, self._cipher_type)

        debug("TLS 1.3: Application traffic keys derived")
        return self._client_app_rp, self._server_app_rp
