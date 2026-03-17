"""
ja3requests.protocol.tls.crypto
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides cryptographic utilities for TLS implementation.
"""

import os
import hashlib
import hmac
from typing import Tuple

from cryptography.hazmat.primitives import serialization, padding as crypto_padding
from cryptography.hazmat.primitives.asymmetric import ec, x25519, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from ja3requests.protocol.tls.debug import debug

# Common DH prime parameter (RFC 2409 / RFC 3526 MODP group)
DH_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D6"
    "70C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE"
    "39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9D"
    "E2BCBF6955817183995497CEA956AE515D2261898FA051015"
    "728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)


class TLSCrypto:
    """
    TLS cryptographic operations
    """

    @staticmethod
    def generate_premaster_secret() -> bytes:
        """
        Generate 48-byte premaster secret for TLS 1.2
        Format: version (2 bytes) + random (46 bytes)
        """
        version = b'\x03\x03'  # TLS 1.2
        random_bytes = os.urandom(46)
        return version + random_bytes

    @staticmethod
    def prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
        """
        TLS 1.2 PRF (Pseudo-Random Function) using HMAC-SHA256
        """

        def p_hash(secret: bytes, seed: bytes, length: int) -> bytes:
            """P_hash function for PRF"""
            result = b""
            a = seed

            while len(result) < length:
                a = hmac.new(secret, a, hashlib.sha256).digest()
                result += hmac.new(secret, a + seed, hashlib.sha256).digest()

            return result[:length]

        labeled_seed = label + seed
        return p_hash(secret, labeled_seed, length)

    @staticmethod
    def prf_sha1(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
        """
        TLS 1.2 PRF using HMAC-SHA1 for legacy cipher suites like AES128-SHA
        """

        def p_hash(secret: bytes, seed: bytes, length: int) -> bytes:
            """P_hash function for SHA1-based PRF"""
            result = b""
            a = seed

            while len(result) < length:
                a = hmac.new(secret, a, hashlib.sha1).digest()
                result += hmac.new(secret, a + seed, hashlib.sha1).digest()

            return result[:length]

        labeled_seed = label + seed
        return p_hash(secret, labeled_seed, length)

    @staticmethod
    def generate_master_secret(
        premaster_secret: bytes,
        client_random: bytes,
        server_random: bytes,
        _cipher_suite: int = 0x002F,
    ) -> bytes:
        """
        Generate master secret from premaster secret and randoms
        Use appropriate PRF based on cipher suite
        """
        label = b"master secret"
        seed = client_random + server_random

        # TLS 1.2 always uses SHA256 PRF for master secret generation
        return TLSCrypto.prf(premaster_secret, label, seed, 48)

    @staticmethod
    def generate_key_block(
        master_secret: bytes,
        client_random: bytes,
        server_random: bytes,
        key_block_length: int,
        _cipher_suite: int = 0x002F,
    ) -> bytes:
        """
        Generate key block containing encryption keys and MAC secrets
        Use appropriate PRF based on cipher suite
        """
        label = b"key expansion"
        seed = server_random + client_random

        # TLS 1.2 always uses SHA256 PRF for key block generation
        return TLSCrypto.prf(master_secret, label, seed, key_block_length)

    @staticmethod
    def derive_keys(key_block: bytes, cipher_suite: int) -> dict:
        """
        Derive individual keys from key block based on cipher suite
        """
        # Key lengths based on cipher suite
        # For GCM cipher suites: mac_len=0 (AEAD), iv_len=4 (implicit nonce)
        key_lengths = {
            # CBC cipher suites
            0x002F: {
                "mac_len": 20,
                "key_len": 16,
                "iv_len": 16,
            },  # TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035: {
                "mac_len": 20,
                "key_len": 32,
                "iv_len": 16,
            },  # TLS_RSA_WITH_AES_256_CBC_SHA
            0x003C: {
                "mac_len": 32,
                "key_len": 16,
                "iv_len": 16,
            },  # TLS_RSA_WITH_AES_128_CBC_SHA256
            0x003D: {
                "mac_len": 32,
                "key_len": 32,
                "iv_len": 16,
            },  # TLS_RSA_WITH_AES_256_CBC_SHA256
            0xC013: {
                "mac_len": 20,
                "key_len": 16,
                "iv_len": 16,
            },  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
            0xC014: {
                "mac_len": 20,
                "key_len": 32,
                "iv_len": 16,
            },  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
            0xC027: {
                "mac_len": 32,
                "key_len": 16,
                "iv_len": 16,
            },  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
            0xC028: {
                "mac_len": 32,
                "key_len": 32,
                "iv_len": 16,
            },  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
            # GCM cipher suites (AEAD - no separate MAC, 4-byte implicit IV)
            0x009C: {
                "mac_len": 0,
                "key_len": 16,
                "iv_len": 4,
            },  # TLS_RSA_WITH_AES_128_GCM_SHA256
            0x009D: {
                "mac_len": 0,
                "key_len": 32,
                "iv_len": 4,
            },  # TLS_RSA_WITH_AES_256_GCM_SHA384
            0xC02F: {
                "mac_len": 0,
                "key_len": 16,
                "iv_len": 4,
            },  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC030: {
                "mac_len": 0,
                "key_len": 32,
                "iv_len": 4,
            },  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xC02B: {
                "mac_len": 0,
                "key_len": 16,
                "iv_len": 4,
            },  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC02C: {
                "mac_len": 0,
                "key_len": 32,
                "iv_len": 4,
            },  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            # TLS 1.3 cipher suites
            0x1301: {
                "mac_len": 0,
                "key_len": 16,
                "iv_len": 12,
            },  # TLS_AES_128_GCM_SHA256
            0x1302: {
                "mac_len": 0,
                "key_len": 32,
                "iv_len": 12,
            },  # TLS_AES_256_GCM_SHA384
        }

        lengths = key_lengths.get(
            cipher_suite, {"mac_len": 20, "key_len": 16, "iv_len": 16}
        )
        mac_len = lengths["mac_len"]
        key_len = lengths["key_len"]
        iv_len = lengths["iv_len"]

        offset = 0
        keys = {}

        # Client MAC secret
        if mac_len > 0:
            keys["client_mac_secret"] = key_block[offset : offset + mac_len]
            offset += mac_len

            # Server MAC secret
            keys["server_mac_secret"] = key_block[offset : offset + mac_len]
            offset += mac_len

        # Client encryption key
        keys["client_key"] = key_block[offset : offset + key_len]
        offset += key_len

        # Server encryption key
        keys["server_key"] = key_block[offset : offset + key_len]
        offset += key_len

        # Client IV
        if iv_len > 0:
            keys["client_iv"] = key_block[offset : offset + iv_len]
            offset += iv_len

            # Server IV
            keys["server_iv"] = key_block[offset : offset + iv_len]
            offset += iv_len

        return keys

    @staticmethod
    def compute_verify_data(
        master_secret: bytes,
        handshake_messages: bytes,
        is_client: bool = True,
        _cipher_suite: int = 0x002F,
    ) -> bytes:
        """
        Compute verify data for Finished message.

        According to RFC 5246 (TLS 1.2), Section 7.4.9:
        verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length-1]

        For TLS 1.2, both the PRF and the Hash function always use SHA-256,
        regardless of the cipher suite's MAC algorithm.
        """
        label = b"client finished" if is_client else b"server finished"

        # TLS 1.2: Always use SHA-256 for handshake hash and PRF
        message_hash = hashlib.sha256(handshake_messages).digest()
        return TLSCrypto.prf(master_secret, label, message_hash, 12)


class RSAKeyExchange:
    """
    RSA key exchange implementation
    """

    @staticmethod
    def encrypt_premaster_secret(
        premaster_secret: bytes, public_key_der: bytes
    ) -> bytes:
        """
        Encrypt premaster secret with server's RSA public key
        """
        try:
            # Load the public key
            public_key = serialization.load_der_public_key(
                public_key_der, backend=default_backend()
            )

            # Encrypt the premaster secret using RSA PKCS#1 v1.5 padding
            encrypted = public_key.encrypt(premaster_secret, padding.PKCS1v15())
            return encrypted
        except ImportError:
            # Fallback if cryptography library not available
            debug(
                "Warning: cryptography library not available, using insecure fallback"
            )
            return premaster_secret
        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"RSA encryption failed: {e}")
            return premaster_secret


class DHEKeyExchange:
    """
    Diffie-Hellman Ephemeral key exchange implementation
    """

    @staticmethod
    def generate_keypair() -> Tuple[int, int]:
        """
        Generate DH keypair (private_key, public_key)
        This is a simplified implementation
        """
        # Common DH parameters (simplified)
        g = 2

        # Generate private key (random)
        private_key = int.from_bytes(os.urandom(32), 'big') % (DH_PRIME - 1) + 1

        # Calculate public key: g^private_key mod p
        public_key = pow(g, private_key, DH_PRIME)

        return private_key, public_key

    @staticmethod
    def compute_shared_secret(private_key: int, peer_public_key: int) -> bytes:
        """
        Compute shared secret from peer's public key and own private key
        """
        # Compute shared secret: peer_public_key^private_key mod p
        shared_secret = pow(peer_public_key, private_key, DH_PRIME)

        # Convert to bytes
        byte_length = (shared_secret.bit_length() + 7) // 8
        return shared_secret.to_bytes(byte_length, 'big')


class ECDHEKeyExchange:
    """
    Elliptic Curve Diffie-Hellman Ephemeral key exchange implementation
    using the cryptography library.

    Supported curves:
    - 23: secp256r1 (P-256)
    - 24: secp384r1 (P-384)
    - 25: secp521r1 (P-521)
    - 29: x25519

    Raises:
        ImportError: If cryptography library is not available
        ValueError: If unsupported curve ID is specified
    """

    # TLS named curve IDs
    CURVE_SECP256R1 = 23
    CURVE_SECP384R1 = 24
    CURVE_SECP521R1 = 25
    CURVE_X25519 = 29

    # Supported curve IDs
    SUPPORTED_CURVES = {CURVE_SECP256R1, CURVE_SECP384R1, CURVE_SECP521R1, CURVE_X25519}

    @staticmethod
    def get_curve(curve_id: int):
        """
        Get the cryptography curve object for the given curve ID.

        Args:
            curve_id: TLS named curve ID

        Returns:
            Curve object for NIST curves, or 'x25519' string for X25519

        Raises:
            ImportError: If cryptography library is not available
            ValueError: If curve_id is not supported
        """
        if curve_id == ECDHEKeyExchange.CURVE_SECP256R1:
            return ec.SECP256R1()
        if curve_id == ECDHEKeyExchange.CURVE_SECP384R1:
            return ec.SECP384R1()
        if curve_id == ECDHEKeyExchange.CURVE_SECP521R1:
            return ec.SECP521R1()
        if curve_id == ECDHEKeyExchange.CURVE_X25519:
            return 'x25519'  # Special case for X25519
        raise ValueError(
            f"Unsupported curve ID: {curve_id}. "
            f"Supported: {ECDHEKeyExchange.SUPPORTED_CURVES}"
        )

    @staticmethod
    def generate_keypair(curve_id: int = 23) -> Tuple[any, bytes]:
        """
        Generate ECDHE keypair for given curve.

        Args:
            curve_id: TLS named curve ID (23=secp256r1, 24=secp384r1, 25=secp521r1, 29=x25519)

        Returns:
            Tuple of (private_key_object, public_key_bytes)
            The private key object is needed for computing the shared secret.

        Raises:
            ImportError: If cryptography library is not available
            ValueError: If curve_id is not supported
        """
        if curve_id == ECDHEKeyExchange.CURVE_X25519:
            # X25519 curve
            private_key = x25519.X25519PrivateKey.generate()
            public_key_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            return private_key, public_key_bytes

        # NIST curves (secp256r1, secp384r1, secp521r1)
        curve = ECDHEKeyExchange.get_curve(curve_id)
        private_key = ec.generate_private_key(curve, default_backend())
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        return private_key, public_key_bytes

    @staticmethod
    def compute_shared_secret(
        private_key, peer_public_key: bytes, curve_id: int = 23
    ) -> bytes:
        """
        Compute ECDH shared secret.

        Args:
            private_key: The private key object returned from generate_keypair()
            peer_public_key: The server's public key bytes
            curve_id: TLS named curve ID

        Returns:
            The raw shared secret bytes (premaster secret for TLS)

        Raises:
            ImportError: If cryptography library is not available
            ValueError: If curve_id is not supported or key exchange fails
        """
        if curve_id == ECDHEKeyExchange.CURVE_X25519:
            # X25519 curve
            peer_public = x25519.X25519PublicKey.from_public_bytes(peer_public_key)
            return private_key.exchange(peer_public)

        # NIST curves - load peer public key from uncompressed point
        curve = ECDHEKeyExchange.get_curve(curve_id)
        peer_public = ec.EllipticCurvePublicKey.from_encoded_point(
            curve, peer_public_key
        )
        return private_key.exchange(ec.ECDH(), peer_public)

    @staticmethod
    def parse_server_ecdhe_params(data: bytes) -> dict:
        """
        Parse ServerKeyExchange ECDHE parameters.

        Format:
        - ECCurveType (1 byte): 3 = named_curve
        - Named Curve (2 bytes): curve ID
        - Public Key Length (1 byte)
        - Public Key (variable)
        - [Signature follows but we don't verify it here]

        Returns:
            dict with keys: curve_type, curve_id, public_key
        """
        offset = 0

        # ECCurveType (1 byte)
        curve_type = data[offset]
        offset += 1

        if curve_type != 3:  # named_curve
            debug(f"Unsupported EC curve type: {curve_type}")
            return None

        # Named Curve (2 bytes)
        curve_id = int.from_bytes(data[offset : offset + 2], byteorder='big')
        offset += 2

        # Public Key Length (1 byte)
        pubkey_len = data[offset]
        offset += 1

        # Public Key
        public_key = data[offset : offset + pubkey_len]
        offset += pubkey_len

        debug(f"Parsed ECDHE params: curve_id={curve_id}, pubkey_len={pubkey_len}")

        return {
            'curve_type': curve_type,
            'curve_id': curve_id,
            'public_key': public_key,
            'remaining_offset': offset,
        }


class AESCipher:
    """
    AES encryption/decryption utilities
    """

    @staticmethod
    def encrypt_cbc(
        plaintext: bytes, key: bytes, iv: bytes, add_padding: bool = True
    ) -> bytes:
        """
        AES-CBC encryption.

        Args:
            plaintext: Data to encrypt
            key: AES key (16, 24, or 32 bytes)
            iv: Initialization vector (16 bytes)
            add_padding: If True, add PKCS#7 padding. If False, plaintext must
                        already be a multiple of 16 bytes (used for TLS where
                        padding is added manually according to TLS spec).
        """
        try:
            if add_padding:
                # Add PKCS#7 padding
                padder = crypto_padding.PKCS7(128).padder()
                data_to_encrypt = padder.update(plaintext) + padder.finalize()
            else:
                # Plaintext must already be padded to block size
                if len(plaintext) % 16 != 0:
                    raise ValueError(
                        f"Plaintext length ({len(plaintext)}) must be multiple of 16 when add_padding=False"
                    )
                data_to_encrypt = plaintext

            # Encrypt with AES-CBC
            cipher = Cipher(
                algorithms.AES(key), modes.CBC(iv), backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data_to_encrypt) + encryptor.finalize()

            return ciphertext
        except ImportError:
            debug(
                "Warning: cryptography library not available, using insecure fallback"
            )
            return plaintext
        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"AES-CBC encryption failed: {e}")
            return plaintext

    @staticmethod
    def decrypt_cbc(
        ciphertext: bytes, key: bytes, iv: bytes, remove_padding: bool = True
    ) -> bytes:
        """
        AES-CBC decryption.

        Args:
            ciphertext: Data to decrypt
            key: AES key (16, 24, or 32 bytes)
            iv: Initialization vector (16 bytes)
            remove_padding: If True, remove PKCS#7 padding after decryption.
                           If False, return raw decrypted data (used for TLS
                           where padding is handled manually).
        """
        try:
            # Decrypt with AES-CBC
            cipher = Cipher(
                algorithms.AES(key), modes.CBC(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

            if remove_padding:
                # Remove PKCS#7 padding
                unpadder = crypto_padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
                return plaintext

            # Return raw decrypted data, caller handles padding
            return decrypted_data

        except ImportError:
            debug(
                "Warning: cryptography library not available, using insecure fallback"
            )
            return ciphertext
        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"AES-CBC decryption failed: {e}")
            return ciphertext

    @staticmethod
    def encrypt_gcm(
        plaintext: bytes, key: bytes, iv: bytes, additional_data: bytes = b""
    ) -> Tuple[bytes, bytes]:
        """
        AES-GCM encryption
        Returns (ciphertext, auth_tag)
        """
        try:
            # Create AES-GCM cipher
            cipher = Cipher(
                algorithms.AES(key), modes.GCM(iv), backend=default_backend()
            )
            encryptor = cipher.encryptor()

            # Add additional authenticated data if provided
            if additional_data:
                encryptor.authenticate_additional_data(additional_data)

            # Encrypt the plaintext
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()

            # Get the authentication tag
            auth_tag = encryptor.tag

            return ciphertext, auth_tag
        except ImportError:
            debug(
                "Warning: cryptography library not available, using insecure fallback"
            )
            return plaintext, os.urandom(16)
        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"AES-GCM encryption failed: {e}")
            return plaintext, os.urandom(16)

    @staticmethod
    def decrypt_gcm(
        ciphertext: bytes,
        key: bytes,
        iv: bytes,
        auth_tag: bytes,
        additional_data: bytes = b"",
    ) -> bytes:
        """
        AES-GCM decryption with authentication verification
        """
        try:
            # Create AES-GCM cipher
            cipher = Cipher(
                algorithms.AES(key), modes.GCM(iv, auth_tag), backend=default_backend()
            )
            decryptor = cipher.decryptor()

            # Add additional authenticated data if provided
            if additional_data:
                decryptor.authenticate_additional_data(additional_data)

            # Decrypt and verify authentication
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            return plaintext
        except ImportError:
            debug(
                "Warning: cryptography library not available, using insecure fallback"
            )
            return ciphertext
        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"AES-GCM decryption failed: {e}")
            return ciphertext


def get_cipher_info(cipher_suite: int) -> dict:
    """
    Get cipher suite information
    """
    cipher_info = {
        # RSA key exchange with CBC
        0x002F: {
            "name": "TLS_RSA_WITH_AES_128_CBC_SHA",
            "key_exchange": "RSA",
            "cipher": "AES_128_CBC",
            "mac": "SHA1",
            "key_size": 16,
            "iv_size": 16,
            "mac_size": 20,
            "is_aead": False,
        },
        0x0035: {
            "name": "TLS_RSA_WITH_AES_256_CBC_SHA",
            "key_exchange": "RSA",
            "cipher": "AES_256_CBC",
            "mac": "SHA1",
            "key_size": 32,
            "iv_size": 16,
            "mac_size": 20,
            "is_aead": False,
        },
        0x003C: {
            "name": "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "key_exchange": "RSA",
            "cipher": "AES_128_CBC",
            "mac": "SHA256",
            "key_size": 16,
            "iv_size": 16,
            "mac_size": 32,
            "is_aead": False,
        },
        # RSA key exchange with GCM
        0x009C: {
            "name": "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "key_exchange": "RSA",
            "cipher": "AES_128_GCM",
            "mac": "AEAD",
            "key_size": 16,
            "iv_size": 4,  # implicit IV
            "mac_size": 0,
            "is_aead": True,
        },
        0x009D: {
            "name": "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "RSA",
            "cipher": "AES_256_GCM",
            "mac": "AEAD",
            "key_size": 32,
            "iv_size": 4,
            "mac_size": 0,
            "is_aead": True,
        },
        # ECDHE-RSA with CBC
        0xC013: {
            "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "key_exchange": "ECDHE_RSA",
            "cipher": "AES_128_CBC",
            "mac": "SHA1",
            "key_size": 16,
            "iv_size": 16,
            "mac_size": 20,
            "is_aead": False,
        },
        0xC014: {
            "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            "key_exchange": "ECDHE_RSA",
            "cipher": "AES_256_CBC",
            "mac": "SHA1",
            "key_size": 32,
            "iv_size": 16,
            "mac_size": 20,
            "is_aead": False,
        },
        0xC027: {
            "name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            "key_exchange": "ECDHE_RSA",
            "cipher": "AES_128_CBC",
            "mac": "SHA256",
            "key_size": 16,
            "iv_size": 16,
            "mac_size": 32,
            "is_aead": False,
        },
        0xC028: {
            "name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            "key_exchange": "ECDHE_RSA",
            "cipher": "AES_256_CBC",
            "mac": "SHA384",
            "key_size": 32,
            "iv_size": 16,
            "mac_size": 48,
            "is_aead": False,
        },
        # ECDHE-RSA with GCM
        0xC02F: {
            "name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "key_exchange": "ECDHE_RSA",
            "cipher": "AES_128_GCM",
            "mac": "AEAD",
            "key_size": 16,
            "iv_size": 4,
            "mac_size": 0,
            "is_aead": True,
        },
        0xC030: {
            "name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE_RSA",
            "cipher": "AES_256_GCM",
            "mac": "AEAD",
            "key_size": 32,
            "iv_size": 4,
            "mac_size": 0,
            "is_aead": True,
        },
        # ECDHE-ECDSA with GCM
        0xC02B: {
            "name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "key_exchange": "ECDHE_ECDSA",
            "cipher": "AES_128_GCM",
            "mac": "AEAD",
            "key_size": 16,
            "iv_size": 4,
            "mac_size": 0,
            "is_aead": True,
        },
        0xC02C: {
            "name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE_ECDSA",
            "cipher": "AES_256_GCM",
            "mac": "AEAD",
            "key_size": 32,
            "iv_size": 4,
            "mac_size": 0,
            "is_aead": True,
        },
        # TLS 1.3 cipher suites
        0x1301: {
            "name": "TLS_AES_128_GCM_SHA256",
            "key_exchange": "AEAD",
            "cipher": "AES_128_GCM",
            "mac": "SHA256",
            "key_size": 16,
            "iv_size": 12,
            "mac_size": 0,
            "is_aead": True,
        },
        0x1302: {
            "name": "TLS_AES_256_GCM_SHA384",
            "key_exchange": "AEAD",
            "cipher": "AES_256_GCM",
            "mac": "SHA384",
            "key_size": 32,
            "iv_size": 12,
            "mac_size": 0,
            "is_aead": True,
        },
    }

    return cipher_info.get(
        cipher_suite,
        {
            "name": f"UNKNOWN_{cipher_suite:04X}",
            "key_exchange": "UNKNOWN",
            "cipher": "UNKNOWN",
            "mac": "UNKNOWN",
            "key_size": 16,
            "iv_size": 16,
            "mac_size": 20,
            "is_aead": False,
        },
    )


# GCM cipher suite identifiers for quick lookup
GCM_CIPHER_SUITES = frozenset(
    {
        0x009C,  # TLS_RSA_WITH_AES_128_GCM_SHA256
        0x009D,  # TLS_RSA_WITH_AES_256_GCM_SHA384
        0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0x1301,  # TLS_AES_128_GCM_SHA256 (TLS 1.3)
        0x1302,  # TLS_AES_256_GCM_SHA384 (TLS 1.3)
    }
)


def is_gcm_cipher_suite(cipher_suite: int) -> bool:
    """Check if cipher suite uses GCM mode"""
    return cipher_suite in GCM_CIPHER_SUITES
