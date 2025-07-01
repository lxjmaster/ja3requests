"""
ja3requests.protocol.tls.crypto
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module provides cryptographic utilities for TLS implementation.
"""

import os
import hashlib
import hmac
from typing import Tuple, Optional


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
    def generate_master_secret(premaster_secret: bytes, 
                              client_random: bytes, 
                              server_random: bytes) -> bytes:
        """
        Generate master secret from premaster secret and randoms
        """
        label = b"master secret"
        seed = client_random + server_random
        return TLSCrypto.prf(premaster_secret, label, seed, 48)
    
    @staticmethod
    def generate_key_block(master_secret: bytes,
                          client_random: bytes,
                          server_random: bytes,
                          key_block_length: int) -> bytes:
        """
        Generate key block containing encryption keys and MAC secrets
        """
        label = b"key expansion"
        seed = server_random + client_random
        return TLSCrypto.prf(master_secret, label, seed, key_block_length)
    
    @staticmethod
    def derive_keys(key_block: bytes, cipher_suite: int) -> dict:
        """
        Derive individual keys from key block based on cipher suite
        """
        # Key lengths based on cipher suite
        key_lengths = {
            0x002F: {"mac_len": 20, "key_len": 16, "iv_len": 16},  # AES128-SHA
            0x0035: {"mac_len": 20, "key_len": 32, "iv_len": 16},  # AES256-SHA
            0x003C: {"mac_len": 32, "key_len": 16, "iv_len": 16},  # AES128-SHA256
            0x003D: {"mac_len": 32, "key_len": 32, "iv_len": 16},  # AES256-SHA256
            0x1301: {"mac_len": 0, "key_len": 16, "iv_len": 12},   # AES128-GCM-SHA256
            0x1302: {"mac_len": 0, "key_len": 32, "iv_len": 12},   # AES256-GCM-SHA384
        }
        
        lengths = key_lengths.get(cipher_suite, {"mac_len": 20, "key_len": 16, "iv_len": 16})
        mac_len = lengths["mac_len"]
        key_len = lengths["key_len"]
        iv_len = lengths["iv_len"]
        
        offset = 0
        keys = {}
        
        # Client MAC secret
        if mac_len > 0:
            keys["client_mac_secret"] = key_block[offset:offset + mac_len]
            offset += mac_len
            
            # Server MAC secret
            keys["server_mac_secret"] = key_block[offset:offset + mac_len]
            offset += mac_len
        
        # Client encryption key
        keys["client_key"] = key_block[offset:offset + key_len]
        offset += key_len
        
        # Server encryption key
        keys["server_key"] = key_block[offset:offset + key_len]
        offset += key_len
        
        # Client IV
        if iv_len > 0:
            keys["client_iv"] = key_block[offset:offset + iv_len]
            offset += iv_len
            
            # Server IV
            keys["server_iv"] = key_block[offset:offset + iv_len]
            offset += iv_len
        
        return keys
    
    @staticmethod
    def compute_verify_data(master_secret: bytes, 
                           handshake_messages: bytes, 
                           is_client: bool = True) -> bytes:
        """
        Compute verify data for Finished message
        """
        label = b"client finished" if is_client else b"server finished"
        message_hash = hashlib.sha256(handshake_messages).digest()
        return TLSCrypto.prf(master_secret, label, message_hash, 12)


class RSAKeyExchange:
    """
    RSA key exchange implementation
    """
    
    @staticmethod
    def encrypt_premaster_secret(premaster_secret: bytes, 
                                public_key_der: bytes) -> bytes:
        """
        Encrypt premaster secret with server's RSA public key
        This is a placeholder - in real implementation would use cryptography library
        """
        # Placeholder for RSA encryption
        # In real implementation:
        # from cryptography.hazmat.primitives import serialization
        # from cryptography.hazmat.primitives.asymmetric import rsa, padding
        # from cryptography.hazmat.primitives import hashes
        
        # public_key = serialization.load_der_public_key(public_key_der)
        # encrypted = public_key.encrypt(
        #     premaster_secret,
        #     padding.PKCS1v15()
        # )
        # return encrypted
        
        # For now, return the premaster secret as-is (not secure!)
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
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        g = 2
        
        # Generate private key (random)
        private_key = int.from_bytes(os.urandom(32), 'big') % (p - 1) + 1
        
        # Calculate public key: g^private_key mod p
        public_key = pow(g, private_key, p)
        
        return private_key, public_key
    
    @staticmethod
    def compute_shared_secret(private_key: int, 
                             peer_public_key: int) -> bytes:
        """
        Compute shared secret from peer's public key and own private key
        """
        p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        
        # Compute shared secret: peer_public_key^private_key mod p
        shared_secret = pow(peer_public_key, private_key, p)
        
        # Convert to bytes
        byte_length = (shared_secret.bit_length() + 7) // 8
        return shared_secret.to_bytes(byte_length, 'big')


class ECDHEKeyExchange:
    """
    Elliptic Curve Diffie-Hellman Ephemeral key exchange implementation
    """
    
    @staticmethod
    def generate_keypair(curve_id: int = 23) -> Tuple[bytes, bytes]:
        """
        Generate ECDHE keypair for given curve
        curve_id 23 = secp256r1
        This is a placeholder implementation
        """
        # In real implementation, would use cryptography library:
        # from cryptography.hazmat.primitives.asymmetric import ec
        # from cryptography.hazmat.primitives import serialization
        
        # private_key = ec.generate_private_key(ec.SECP256R1())
        # public_key = private_key.public_key()
        
        # private_bytes = private_key.private_bytes(
        #     encoding=serialization.Encoding.Raw,
        #     format=serialization.PrivateFormat.Raw,
        #     encryption_algorithm=serialization.NoEncryption()
        # )
        
        # public_bytes = public_key.public_bytes(
        #     encoding=serialization.Encoding.X962,
        #     format=serialization.PublicFormat.UncompressedPoint
        # )
        
        # return private_bytes, public_bytes
        
        # Placeholder implementation
        private_key = os.urandom(32)
        public_key = os.urandom(65)  # Uncompressed point for secp256r1
        return private_key, public_key
    
    @staticmethod
    def compute_shared_secret(private_key: bytes, 
                             peer_public_key: bytes) -> bytes:
        """
        Compute ECDH shared secret
        """
        # Placeholder - in real implementation would use proper ECDH
        return hashlib.sha256(private_key + peer_public_key).digest()


class AESCipher:
    """
    AES encryption/decryption utilities
    """
    
    @staticmethod
    def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        AES-CBC encryption
        This is a placeholder - in real implementation would use cryptography library
        """
        # from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        # from cryptography.hazmat.backends import default_backend
        
        # cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        # encryptor = cipher.encryptor()
        # return encryptor.update(plaintext) + encryptor.finalize()
        
        # Placeholder
        return plaintext
    
    @staticmethod
    def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """
        AES-CBC decryption
        """
        # Placeholder
        return ciphertext
    
    @staticmethod
    def encrypt_gcm(plaintext: bytes, key: bytes, iv: bytes, 
                   additional_data: bytes = b"") -> Tuple[bytes, bytes]:
        """
        AES-GCM encryption
        Returns (ciphertext, auth_tag)
        """
        # Placeholder
        return plaintext, os.urandom(16)
    
    @staticmethod
    def decrypt_gcm(ciphertext: bytes, key: bytes, iv: bytes, 
                   auth_tag: bytes, additional_data: bytes = b"") -> bytes:
        """
        AES-GCM decryption
        """
        # Placeholder
        return ciphertext


def get_cipher_info(cipher_suite: int) -> dict:
    """
    Get cipher suite information
    """
    cipher_info = {
        0x002F: {  # TLS_RSA_WITH_AES_128_CBC_SHA
            "name": "TLS_RSA_WITH_AES_128_CBC_SHA",
            "key_exchange": "RSA",
            "cipher": "AES_128_CBC",
            "mac": "SHA1",
            "key_size": 16,
            "iv_size": 16,
            "mac_size": 20
        },
        0x0035: {  # TLS_RSA_WITH_AES_256_CBC_SHA
            "name": "TLS_RSA_WITH_AES_256_CBC_SHA", 
            "key_exchange": "RSA",
            "cipher": "AES_256_CBC",
            "mac": "SHA1",
            "key_size": 32,
            "iv_size": 16,
            "mac_size": 20
        },
        0x003C: {  # TLS_RSA_WITH_AES_128_CBC_SHA256
            "name": "TLS_RSA_WITH_AES_128_CBC_SHA256",
            "key_exchange": "RSA", 
            "cipher": "AES_128_CBC",
            "mac": "SHA256",
            "key_size": 16,
            "iv_size": 16,
            "mac_size": 32
        },
        0x1301: {  # TLS_AES_128_GCM_SHA256
            "name": "TLS_AES_128_GCM_SHA256",
            "key_exchange": "AEAD",
            "cipher": "AES_128_GCM", 
            "mac": "SHA256",
            "key_size": 16,
            "iv_size": 12,
            "mac_size": 0  # AEAD
        },
        0x1302: {  # TLS_AES_256_GCM_SHA384
            "name": "TLS_AES_256_GCM_SHA384",
            "key_exchange": "AEAD",
            "cipher": "AES_256_GCM",
            "mac": "SHA384", 
            "key_size": 32,
            "iv_size": 12,
            "mac_size": 0  # AEAD
        }
    }
    
    return cipher_info.get(cipher_suite, {
        "name": f"UNKNOWN_{cipher_suite:04X}",
        "key_exchange": "UNKNOWN",
        "cipher": "UNKNOWN",
        "mac": "UNKNOWN",
        "key_size": 16,
        "iv_size": 16,
        "mac_size": 20
    })