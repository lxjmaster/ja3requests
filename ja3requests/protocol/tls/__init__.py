# pylint: disable=too-many-lines
"""TLS handshake implementation with JA3 fingerprint customization.

This module provides a custom TLS 1.2 handshake implementation that supports
both RSA and ECDHE key exchange, allowing JA3 fingerprint configuration.
"""
import hashlib
import hmac
import os
import struct
import time
import traceback

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ja3requests.exceptions import TLSEncryptionError, TLSHandshakeError, TLSKeyError
from ja3requests.protocol.tls.layers import HandShake
from ja3requests.protocol.tls.debug import debug, debug_hex
from ja3requests.protocol.tls.layers.client_hello import ClientHello
from ja3requests.protocol.tls.layers.server_hello import ServerHello
from ja3requests.protocol.tls.layers.certificate import Certificate
from ja3requests.protocol.tls.layers.server_key_exchange import ServerKeyExchange
from ja3requests.protocol.tls.layers.certificate_request import CertificateRequest
from ja3requests.protocol.tls.layers.server_hello_done import ServerHelloDone
from ja3requests.protocol.tls.security_warnings import (
    warn_no_certificate_verification,
)
from .crypto import (
    TLSCrypto,
    RSAKeyExchange,
    ECDHEKeyExchange,
    AESCipher,
    get_cipher_info,
    is_gcm_cipher_suite,
)
from .certificate_verify import CertificateVerifier

# ECDHE Cipher Suite Constants
# These cipher suites use Elliptic Curve Diffie-Hellman Ephemeral key exchange
ECDHE_CIPHER_SUITES = frozenset(
    {
        0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xC030,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        0xC027,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        0xC028,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        0xC009,  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
        0xC00A,  # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
        0xC02B,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xC02C,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    }
)


class TLS:
    """TLS 1.2 handshake handler with support for custom JA3 fingerprints."""

    def __init__(self, conn):
        self._tls_version = None
        self._body = None
        self.conn = conn
        self._master_secret = None
        self._client_random = None
        self._server_random = None
        self._cipher_suite = None
        self._server_name = None
        self._supported_groups = None
        self._signature_algorithms = None
        self._cipher_suites = None

        # Sequence numbers for record layer encryption/decryption
        # These are reset to 0 after ChangeCipherSpec
        self._client_seq_num = 0  # For encrypting client -> server messages
        self._server_seq_num = 0  # For decrypting server -> client messages

    @property
    def tls_version(self) -> bytes:
        """Return the TLS version bytes, defaulting to TLS 1.2."""
        if not self._tls_version:
            self._tls_version = struct.pack("I", 771)[:2]
        return self._tls_version

    @tls_version.setter
    def tls_version(self, attr: bytes):
        self._tls_version = attr

    @property
    def body(self) -> HandShake:
        """Return the ClientHello handshake body, creating it if needed."""
        if self._body is None:
            self._body = ClientHello(
                self.tls_version,
            )
        return self._body

    @body.setter
    def body(self, attr: HandShake):
        self._body = attr

    def set_payload(self, tls_config=None):
        """
        Set TLS payload configuration for handshake
        :param tls_config: TlsConfig object containing handshake parameters
        """
        if tls_config:
            # Set TLS version
            if hasattr(tls_config, 'tls_version') and tls_config.tls_version:
                if isinstance(tls_config.tls_version, int):
                    self._tls_version = tls_config.tls_version.to_bytes(
                        2, byteorder='big'
                    )
                else:
                    self._tls_version = tls_config.tls_version

            # Set cipher suites
            if hasattr(tls_config, 'cipher_suites') and tls_config.cipher_suites:
                self._cipher_suites = tls_config.cipher_suites

            # Set client random if provided
            if hasattr(tls_config, 'client_random') and tls_config.client_random:
                self._client_random = tls_config.client_random

            # Set server name for SNI
            if hasattr(tls_config, 'server_name') and tls_config.server_name:
                self._server_name = tls_config.server_name

            # Set supported groups (allow empty list)
            if hasattr(tls_config, 'supported_groups'):
                self._supported_groups = tls_config.supported_groups

            # Set signature algorithms (allow empty list)
            if hasattr(tls_config, 'signature_algorithms'):
                self._signature_algorithms = tls_config.signature_algorithms

            # Set certificate verification options
            if hasattr(tls_config, 'verify_cert'):
                self._verify_cert = tls_config.verify_cert
            else:
                self._verify_cert = False  # Default to False for backward compatibility

            # Update client hello with new configuration
            self._body = ClientHello(
                self.tls_version,
                cipher_suites=self._cipher_suites,
                client_random=self._client_random,
                server_name=self._server_name,
                supported_groups=self._supported_groups,
                signature_algorithms=self._signature_algorithms,
                alpn_protocols=getattr(tls_config, 'alpn_protocols', None),
                use_grease=getattr(tls_config, 'use_grease', True),
            )

    def handshake(self):
        """
        Complete TLS handshake process with improved error handling and parsing
        """
        try:
            # Initialize handshake message tracking
            self._handshake_messages = b''

            # Step 1: Send Client Hello
            client_hello = self.body
            self._client_random = client_hello.random
            debug("Sending Client Hello...")
            debug(f"Client Hello message hex: {client_hello.message.hex()}")
            debug(f"Client Hello length: {len(client_hello.message)} bytes")
            self.conn.sendall(client_hello.message)

            # Add Client Hello to handshake messages (without TLS record header)
            self._handshake_messages += client_hello.handshake_message

            # Step 2-6: Receive server handshake messages
            self._parse_server_handshake_messages()

            # Step 7-9: Send client finishing messages
            self._send_client_finishing_messages()

            # Step 10: Wait for server's response to our Finished message
            try:
                # Give server time to process our messages
                time.sleep(0.3)

                # Check for server's response with longer timeout
                self.conn.settimeout(5.0)

                # Try to properly handle server's Change Cipher Spec + Finished
                success = self._wait_for_server_handshake_completion()
                if success:
                    debug("✅ Full TLS handshake completed successfully!")
                    self.conn.settimeout(None)
                    return True
                raise TLSHandshakeError("Server did not complete handshake")
            finally:
                self.conn.settimeout(None)

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"TLS Handshake failed: {e}")
            return False

    def _parse_server_handshake_messages(
        self,
    ):  # pylint: disable=too-many-branches,too-many-statements,too-many-nested-blocks
        """
        Parse incoming server handshake messages with improved error handling
        """
        buffer = b""
        _received_messages = set()
        timeout_count = 0
        max_timeout = 10

        # Set socket timeout for receiving
        self.conn.settimeout(1.0)

        while True:
            try:
                # Receive data
                data = self.conn.recv(4096)
                if not data:
                    timeout_count += 1
                    if timeout_count >= max_timeout:
                        debug("Timeout waiting for server handshake messages")
                        break
                    continue

                timeout_count = 0  # Reset timeout counter
                buffer += data
                debug(f"Received {len(data)} bytes from server")
                debug(f"Buffer now has {len(buffer)} bytes: {buffer[:50].hex()}...")

                # Parse TLS records from buffer
                while len(buffer) >= 5:  # Minimum TLS record header size
                    record_type = buffer[0]
                    _tls_version = buffer[1:3]

                    # Ensure we have enough bytes for length
                    if len(buffer) < 5:
                        break

                    record_length = struct.unpack("!H", buffer[3:5])[0]

                    if len(buffer) < 5 + record_length:
                        # Need more data
                        break

                    record_data = buffer[5 : 5 + record_length]
                    buffer = buffer[5 + record_length :]

                    debug(
                        f"Processing TLS record: type={record_type}, length={record_length}"
                    )

                    if record_type == 22:  # Handshake message
                        self._process_handshake_record(record_data)
                    elif record_type == 21:  # Alert
                        if len(record_data) >= 2:
                            alert_level = record_data[0]
                            alert_description = record_data[1]
                            debug(
                                f"Received TLS Alert: level={alert_level}, description={alert_description}"
                            )
                            if alert_level == 2:  # Fatal alert
                                raise ConnectionError(
                                    f"TLS Fatal Alert: {alert_description}"
                                )

                    # Check if we've received all expected messages
                    if (
                        hasattr(self, '_server_hello_done_received')
                        and self._server_hello_done_received
                    ):
                        debug("Received ServerHelloDone, handshake messages complete")
                        self.conn.settimeout(None)  # Reset timeout
                        return

            except Exception as e:  # pylint: disable=broad-exception-caught
                if "timed out" in str(e):
                    timeout_count += 1
                    if timeout_count >= max_timeout:
                        debug("Timeout waiting for server handshake messages")
                        break
                    continue
                debug(f"Error parsing server messages: {e}")
                self.conn.settimeout(None)  # Reset timeout
                raise

        self.conn.settimeout(None)  # Reset timeout

    def _process_handshake_record(self, record_data):
        """
        Process handshake messages within a TLS record
        """
        offset = 0
        while offset < len(record_data):
            if offset + 4 > len(record_data):
                break

            msg_type = record_data[offset]

            # Ensure we have enough bytes for length field
            if offset + 4 > len(record_data):
                break

            length_bytes = record_data[offset + 1 : offset + 4]
            if len(length_bytes) != 3:
                break

            msg_length = struct.unpack("!I", b'\x00' + length_bytes)[0]

            if offset + 4 + msg_length > len(record_data):
                break

            msg_data = record_data[offset + 4 : offset + 4 + msg_length]

            # Add handshake message to running hash (excluding record header)
            handshake_msg = record_data[offset : offset + 4 + msg_length]
            if hasattr(self, '_handshake_messages'):
                self._handshake_messages += handshake_msg

            if msg_type == 2:  # ServerHello
                self._parse_server_hello(msg_data)
                debug("Received Server Hello")
            elif msg_type == 11:  # Certificate
                self._parse_certificate(msg_data)
                debug("Received Certificate")
            elif msg_type == 12:  # ServerKeyExchange
                self._parse_server_key_exchange(msg_data)
                debug("Received Server Key Exchange")
            elif msg_type == 13:  # CertificateRequest
                self._parse_certificate_request(msg_data)
                debug("Received Certificate Request")
            elif msg_type == 14:  # ServerHelloDone
                self._parse_server_hello_done(msg_data)
                debug("Received Server Hello Done")
                self._server_hello_done_received = True
                return

            offset += 4 + msg_length

    def _parse_server_hello(self, data):
        """Parse ServerHello message"""
        if len(data) < 38:  # Minimum size for ServerHello
            debug(f"ServerHello data too short: {len(data)} bytes")
            return

        offset = 0
        # TLS version (2 bytes)
        if offset + 2 > len(data):
            return
        _server_version = data[offset : offset + 2]
        offset += 2

        # Server random (32 bytes)
        if offset + 32 > len(data):
            return
        self._server_random = data[offset : offset + 32]
        offset += 32

        # Session ID
        if offset + 1 > len(data):
            return
        session_id_length = data[offset]
        offset += 1
        if session_id_length > 0:
            if offset + session_id_length > len(data):
                return
            _session_id = data[offset : offset + session_id_length]
            offset += session_id_length

        # Cipher suite (2 bytes)
        if offset + 2 > len(data):
            return
        cipher_bytes = data[offset : offset + 2]
        if len(cipher_bytes) == 2:
            self._selected_cipher_suite = struct.unpack("!H", cipher_bytes)[0]
            debug(f"Server selected cipher suite: 0x{self._selected_cipher_suite:04X}")
        offset += 2

        # Compression method (1 byte)
        if offset < len(data):
            _compression_method = data[offset]
            offset += 1

    def _parse_certificate(self, data):
        """Parse Certificate message, verify certificate, and extract server public key"""
        try:
            # Store raw certificate data for verification
            self._certificate_data = data

            # Verify certificate if verification is enabled
            if getattr(self, '_verify_cert', True):
                self._verify_server_certificate(data)

            # Extract server's public key from certificate
            self._server_public_key = self._extract_server_public_key(data)

            if self._server_public_key:
                debug("Successfully extracted server public key from certificate")
            else:
                debug("Failed to extract server public key from certificate")
                warn_no_certificate_verification()

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"Error parsing certificate: {e}")
            warn_no_certificate_verification()

    def _parse_server_key_exchange(self, data):
        """Parse ServerKeyExchange message for ECDHE or DHE key exchange"""
        # Determine key exchange type based on cipher suite
        cipher_suite = getattr(self, '_selected_cipher_suite', 0)

        if cipher_suite in ECDHE_CIPHER_SUITES:
            # Parse ECDHE ServerKeyExchange
            self._key_exchange_type = 'ECDHE'
            ecdhe_params = ECDHEKeyExchange.parse_server_ecdhe_params(data)

            if ecdhe_params:
                self._ecdhe_curve_id = ecdhe_params['curve_id']
                self._ecdhe_server_pubkey = ecdhe_params['public_key']
                debug(f"ECDHE key exchange: curve_id={self._ecdhe_curve_id}")
                debug(
                    f"Server ECDHE public key length: {len(self._ecdhe_server_pubkey)}"
                )
            else:
                debug("Failed to parse ECDHE parameters")
        else:
            # DHE or RSA key exchange (existing handling)
            self._key_exchange_type = 'RSA'
            debug(f"RSA key exchange for cipher suite 0x{cipher_suite:04X}")

    def _parse_certificate_request(self, _data):
        """Parse CertificateRequest message"""
        self._client_cert_requested = True

    def _parse_server_hello_done(self, _data):
        """Parse ServerHelloDone message"""
        # This message has no content, just set the flag
        self._server_hello_done_received = True
        debug("Received ServerHelloDone - ready to send client finishing messages")

    def _send_client_finishing_messages(self):
        """
        Send client finishing messages
        """
        # Send empty Certificate if requested
        if hasattr(self, '_client_cert_requested'):
            empty_cert = self._build_empty_certificate()
            self.conn.sendall(empty_cert)
            debug("Sent empty Certificate")

        # Send ClientKeyExchange
        client_key_exchange = self._build_client_key_exchange()
        self.conn.sendall(client_key_exchange)
        debug("Sent Client Key Exchange")

        # Send ChangeCipherSpec
        change_cipher_spec = b'\x14\x03\x03\x00\x01\x01'
        self.conn.sendall(change_cipher_spec)
        debug("Sent Change Cipher Spec")

        # Reset sequence numbers for encrypted messages
        # Client sequence number resets after we send ChangeCipherSpec
        self._client_seq_num = 0
        # Server sequence number will reset when we receive their ChangeCipherSpec
        self._server_seq_num = 0
        debug("Reset sequence numbers for encrypted messages")

        # Send Finished (first encrypted message with seq num 0)
        finished_message = self._build_finished_message()
        self.conn.sendall(finished_message)
        debug("Sent Finished")

    def _wait_for_server_handshake_completion(
        self,
    ):  # pylint: disable=too-many-branches,too-many-return-statements,too-many-nested-blocks
        """
        Wait for server's final handshake messages (ChangeCipherSpec + Finished)
        Returns True if server accepts the handshake, False otherwise
        """
        try:
            # Try to read server's response with reasonable timeout
            buffer = b""
            received_change_cipher_spec = False
            received_finished = False

            # Read with timeout, expecting server's response
            try:
                data = self.conn.recv(4096)
                if data:
                    buffer += data
                    debug(f"Received {len(data)} bytes from server after our Finished")
                else:
                    debug("No response from server after our Finished")
                    return False
            except Exception as recv_error:  # pylint: disable=broad-exception-caught
                debug(f"Error receiving server response: {recv_error}")
                return False

            # Parse TLS records from buffer
            offset = 0
            while offset < len(buffer):
                if offset + 5 > len(buffer):
                    break

                record_type = buffer[offset]
                record_length = struct.unpack("!H", buffer[offset + 3 : offset + 5])[0]

                if offset + 5 + record_length > len(buffer):
                    # Incomplete record, might need more data
                    break

                record_data = buffer[offset + 5 : offset + 5 + record_length]

                debug(
                    f"Processing server record: type={record_type}, length={record_length}"
                )

                if record_type == 20:  # ChangeCipherSpec
                    debug("✅ Received server ChangeCipherSpec")
                    received_change_cipher_spec = True
                    # Reset server sequence number for encrypted messages
                    self._server_seq_num = 0
                elif record_type == 22:  # Handshake (encrypted Finished)
                    debug("✅ Received server encrypted Finished")
                    received_finished = True
                    # Server's Finished message uses seq=0, increment for next message
                    self._server_seq_num = 1
                elif record_type == 21:  # Alert
                    if len(record_data) >= 2:
                        alert_level = record_data[0]
                        alert_description = record_data[1]
                        debug(
                            f"Received TLS Alert: level={alert_level}, description={alert_description}"
                        )
                        if alert_level == 2:  # Fatal alert
                            if alert_description == 20:  # bad_record_mac
                                debug(
                                    "Server rejected our Finished message (bad_record_mac)"
                                )
                                # This is expected with our current implementation
                                return False
                            debug(f"Server sent fatal alert: {alert_description}")
                            return False
                        debug(f"Server sent warning alert: {alert_description}")

                offset += 5 + record_length

            # If we received both messages, handshake is complete
            if received_change_cipher_spec and received_finished:
                return True
            debug(
                f"Incomplete handshake: ChangeCipherSpec={received_change_cipher_spec}, Finished={received_finished}"
            )
            return False

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"Failed to wait for server handshake completion: {e}")
            return False

    def _build_empty_certificate(self):
        """Build an empty certificate message"""
        # Certificate message with empty certificate list
        cert_list_length = b'\x00\x00\x00'  # 0 length certificate list
        cert_msg = b'\x0b' + struct.pack("!I", 3)[1:] + cert_list_length

        # Wrap in TLS record
        record = b'\x16\x03\x03' + struct.pack("!H", len(cert_msg)) + cert_msg
        return record

    def _build_client_key_exchange(self):
        """Build ClientKeyExchange message with RSA or ECDHE key exchange"""
        key_exchange_type = getattr(self, '_key_exchange_type', 'RSA')

        if key_exchange_type == 'ECDHE':
            # ECDHE key exchange
            return self._build_ecdhe_client_key_exchange()
        # RSA key exchange (default)
        return self._build_rsa_client_key_exchange()

    def _build_ecdhe_client_key_exchange(self):
        """Build ClientKeyExchange message for ECDHE key exchange.

        Raises:
            ValueError: If no server ECDHE public key is available
            ImportError: If cryptography library is not available (falls back to RSA)
        """
        curve_id = getattr(self, '_ecdhe_curve_id', 23)  # Default to secp256r1
        server_pubkey = getattr(self, '_ecdhe_server_pubkey', None)

        if not server_pubkey:
            # This is a protocol error - server selected ECDHE but didn't send key
            raise ValueError(
                "Server selected ECDHE cipher suite but did not provide public key"
            )

        try:
            # Generate our ECDHE keypair
            private_key, public_key = ECDHEKeyExchange.generate_keypair(curve_id)
            self._ecdhe_private_key = private_key
            self._ecdhe_public_key = public_key

            debug(f"Generated ECDHE keypair: public_key length={len(public_key)}")

            # Compute shared secret (premaster secret)
            self._premaster_secret = ECDHEKeyExchange.compute_shared_secret(
                private_key, server_pubkey, curve_id
            )
            debug(f"Computed ECDHE shared secret: {len(self._premaster_secret)} bytes")

            # Generate master secret
            if not (hasattr(self, '_server_random') and self._server_random):
                raise TLSHandshakeError(
                    "No server random available for master secret generation"
                )
            self._master_secret = TLSCrypto.generate_master_secret(
                self._premaster_secret, self._client_random, self._server_random
            )
            debug(f"Generated master secret: {len(self._master_secret)} bytes")

            # Generate session keys
            self._generate_session_keys()

            # Build ClientKeyExchange message for ECDHE
            # Format: length (1 byte) + public_key
            key_exchange_data = bytes([len(public_key)]) + public_key
            msg = (
                b'\x10'
                + struct.pack("!I", len(key_exchange_data))[1:]
                + key_exchange_data
            )

            # Store for handshake hash calculation
            if not hasattr(self, '_handshake_messages'):
                self._handshake_messages = b''
            self._handshake_messages += msg

            # Wrap in TLS record
            record = b'\x16\x03\x03' + struct.pack("!H", len(msg)) + msg
            return record

        except ImportError as e:
            # Fall back to RSA only if cryptography library is not available
            debug(
                f"ECDHE unavailable (missing cryptography library), falling back to RSA: {e}"
            )
            return self._build_rsa_client_key_exchange()

    def _build_rsa_client_key_exchange(self):
        """Build ClientKeyExchange message with RSA encryption"""
        # Generate proper premaster secret
        self._premaster_secret = TLSCrypto.generate_premaster_secret()

        # Encrypt with server's public key
        if not (hasattr(self, '_server_public_key') and self._server_public_key):
            raise TLSKeyError("No server public key available for RSA key exchange")
        try:
            encrypted_premaster = RSAKeyExchange.encrypt_premaster_secret(
                self._premaster_secret, self._server_public_key
            )
            debug("Successfully encrypted premaster secret")
        except Exception as e:
            raise TLSEncryptionError(f"Failed to encrypt premaster secret: {e}") from e

        # Generate master secret
        if not (hasattr(self, '_server_random') and self._server_random):
            raise TLSHandshakeError(
                "No server random available for master secret generation"
            )
        self._master_secret = TLSCrypto.generate_master_secret(
            self._premaster_secret, self._client_random, self._server_random
        )
        debug(
            f"Generated master secret from premaster: {len(self._master_secret)} bytes"
        )

        # Generate session keys
        self._generate_session_keys()

        key_exchange_data = (
            struct.pack("!H", len(encrypted_premaster)) + encrypted_premaster
        )
        msg = (
            b'\x10' + struct.pack("!I", len(key_exchange_data))[1:] + key_exchange_data
        )

        # Store this message for handshake hash calculation
        if not hasattr(self, '_handshake_messages'):
            self._handshake_messages = b''
        self._handshake_messages += msg

        # Wrap in TLS record
        record = b'\x16\x03\x03' + struct.pack("!H", len(msg)) + msg
        return record

    def _build_finished_message(self):
        """Build Finished message with proper verify data"""
        if not (
            hasattr(self, '_master_secret') and hasattr(self, '_handshake_messages')
        ):
            raise TLSHandshakeError(
                "Cannot build Finished: missing master secret or handshake messages"
            )
        # Calculate proper verify data using PRF
        debug(
            f"Handshake messages for verify data: {len(self._handshake_messages)} bytes"
        )
        debug(f"Handshake messages hex: {self._handshake_messages.hex()}")
        cipher_suite = getattr(self, '_selected_cipher_suite', 0x002F)
        verify_data = TLSCrypto.compute_verify_data(
            self._master_secret,
            self._handshake_messages,
            is_client=True,
            _cipher_suite=cipher_suite,
        )
        debug(f"Generated verify data: {verify_data.hex()}")

        msg = b'\x14' + struct.pack("!I", len(verify_data))[1:] + verify_data

        # Note: Don't add Finished message to handshake_messages until after encryption
        # The verify data is calculated from all handshake messages EXCLUDING this Finished message

        # Try to encrypt the Finished message properly
        # For GCM: need _client_write_key and _client_write_iv
        # For CBC: need _client_write_key and _client_write_mac_key
        is_gcm = getattr(self, '_is_gcm', False)
        has_key = hasattr(self, '_client_write_key') and self._client_write_key
        has_iv = hasattr(self, '_client_write_iv') and self._client_write_iv
        has_mac = hasattr(self, '_client_write_mac_key') and self._client_write_mac_key

        can_encrypt = has_key and (is_gcm and has_iv or not is_gcm and has_mac)

        if not can_encrypt:
            raise TLSKeyError("Cannot encrypt Finished: encryption keys not available")
        try:
            # Use proper TLS record layer encryption
            encrypted_record = self._encrypt_finished_message(msg)
            debug(
                f"Successfully encrypted Finished message: {len(encrypted_record)} bytes"
            )
            return encrypted_record
        except (TLSEncryptionError, TLSKeyError):
            raise
        except Exception as e:
            raise TLSEncryptionError(f"Failed to encrypt Finished message: {e}") from e

    def _generate_session_keys(self):
        """Generate session keys from master secret"""
        if not hasattr(self, '_master_secret'):
            debug("Warning: No master secret available for key generation")
            return

        # Determine key block length based on selected cipher suite
        cipher_suite = getattr(
            self, '_selected_cipher_suite', 0x002F
        )  # Default to AES128-SHA

        cipher_info = get_cipher_info(cipher_suite)
        is_gcm = is_gcm_cipher_suite(cipher_suite)

        # Key lengths based on cipher info
        if is_gcm:
            # GCM: no MAC key, 4-byte implicit IV
            mac_key_length = 0
            enc_key_length = cipher_info["key_size"]
            iv_length = 4  # implicit nonce for GCM
        else:
            # CBC: MAC key + 16-byte IV
            mac_key_length = cipher_info["mac_size"]
            enc_key_length = cipher_info["key_size"]
            iv_length = 16

        key_block_length = 2 * (mac_key_length + enc_key_length + iv_length)
        self._is_gcm = is_gcm

        # Generate key block
        if not (hasattr(self, '_server_random') and self._server_random):
            raise TLSHandshakeError(
                "Cannot generate session keys: server random not available"
            )
        key_block = TLSCrypto.generate_key_block(
            self._master_secret,
            self._client_random,
            self._server_random,
            key_block_length,
        )

        # Derive individual keys
        keys = TLSCrypto.derive_keys(key_block, cipher_suite)

        # Store keys for record layer encryption/decryption
        self._client_write_mac_key = keys.get('client_mac_secret', b'')
        self._server_write_mac_key = keys.get('server_mac_secret', b'')
        self._client_write_key = keys.get('client_key', b'')
        self._server_write_key = keys.get('server_key', b'')
        self._client_write_iv = keys.get('client_iv', b'')
        self._server_write_iv = keys.get('server_iv', b'')

        debug(f"Generated session keys for cipher suite 0x{cipher_suite:04X}")

    def _encrypt_handshake_message(self, handshake_msg: bytes) -> bytes:
        """
        Encrypt a handshake message using TLS record layer encryption
        """
        # pylint: disable=too-many-locals
        # TLS record header for handshake
        content_type = 0x16  # Handshake
        version = b'\x03\x03'  # TLS 1.2

        # For TLS 1.2 with AES-CBC, we need to:
        # 1. Compute MAC
        # 2. Add padding
        # 3. Encrypt (MAC + data + padding)

        # Sequence number for MAC calculation (client sending)
        # This should be 0 for the first encrypted message (Finished)
        if not hasattr(self, '_client_seq_num'):
            self._client_seq_num = 0
        seq_num = self._client_seq_num

        # Create MAC input: seq_num(8) + type(1) + version(2) + length(2) + data
        mac_input = (
            seq_num.to_bytes(8, byteorder='big')
            + content_type.to_bytes(1, byteorder='big')
            + version
            + len(handshake_msg).to_bytes(2, byteorder='big')
            + handshake_msg
        )

        # Compute HMAC
        mac = hmac.new(self._client_write_mac_key, mac_input, hashlib.sha1).digest()

        # Combine message + MAC
        plaintext = handshake_msg + mac

        # Add PKCS#7 padding for AES-CBC (block size 16)
        block_size = 16
        padding_length = block_size - (len(plaintext) % block_size)
        padding = bytes([padding_length - 1] * padding_length)
        plaintext_padded = plaintext + padding

        # Encrypt using AES-CBC
        # Generate random IV for this record
        iv = os.urandom(16)
        # Use add_padding=False since we already added TLS-specific padding above
        ciphertext = AESCipher.encrypt_cbc(
            plaintext_padded, self._client_write_key, iv, add_padding=False
        )

        # TLS record: type + version + length + IV + ciphertext
        encrypted_data = iv + ciphertext
        record = (
            content_type.to_bytes(1, byteorder='big')
            + version
            + len(encrypted_data).to_bytes(2, byteorder='big')
            + encrypted_data
        )

        # Increment sequence number for next message
        self._client_seq_num += 1

        return record

    def _encrypt_finished_message(self, handshake_msg: bytes) -> bytes:
        """
        Properly encrypt Finished message according to TLS 1.2 specification.
        Supports both AES-CBC and AES-GCM cipher suites.
        """
        # Check if using GCM cipher suite
        if getattr(self, '_is_gcm', False):
            return self._encrypt_finished_message_gcm(handshake_msg)

        return self._encrypt_finished_message_cbc(handshake_msg)

    def _encrypt_finished_message_gcm(self, handshake_msg: bytes) -> bytes:
        """
        Encrypt Finished message using AES-GCM (AEAD).

        GCM record format:
        - explicit_nonce (8 bytes)
        - ciphertext (variable)
        - auth_tag (16 bytes)

        Nonce = implicit_iv (4 bytes from key derivation) + explicit_nonce (8 bytes)
        AAD = seq_num (8) + type (1) + version (2) + length (2)
        """
        content_type = 0x16  # Handshake
        version = b'\x03\x03'  # TLS 1.2

        if not hasattr(self, '_client_seq_num'):
            self._client_seq_num = 0

        # Generate explicit nonce (8 bytes, typically seq_num or random)
        explicit_nonce = self._client_seq_num.to_bytes(8, byteorder='big')

        # Full nonce = implicit_iv (4 bytes) + explicit_nonce (8 bytes) = 12 bytes
        nonce = self._client_write_iv + explicit_nonce

        # Build AAD (Additional Authenticated Data)
        # AAD = seq_num (8) + type (1) + version (2) + length (2)
        aad = (
            self._client_seq_num.to_bytes(8, byteorder='big')
            + bytes([content_type])
            + version
            + len(handshake_msg).to_bytes(2, byteorder='big')
        )

        # Encrypt with AES-GCM
        ciphertext, auth_tag = AESCipher.encrypt_gcm(
            handshake_msg, self._client_write_key, nonce, aad
        )

        # Record data = explicit_nonce + ciphertext + auth_tag
        encrypted_data = explicit_nonce + ciphertext + auth_tag

        # Build TLS record
        record = (
            bytes([content_type])
            + version
            + len(encrypted_data).to_bytes(2, byteorder='big')
            + encrypted_data
        )

        self._client_seq_num += 1
        debug(f"GCM encrypted record: {len(record)} bytes")
        return record

    def _encrypt_finished_message_cbc(self, handshake_msg: bytes) -> bytes:
        """
        Encrypt Finished message using AES-CBC with HMAC.
        """
        # pylint: disable=too-many-locals
        # TLS record parameters
        content_type = 0x16  # Handshake
        version = b'\x03\x03'  # TLS 1.2

        # Sequence number should already be set to 0 after Change Cipher Spec
        # Don't reinitialize it here to avoid overriding the correct value
        if not hasattr(self, '_client_seq_num'):
            # This should not happen if called correctly after Change Cipher Spec
            debug("Warning: _client_seq_num not initialized, setting to 0")
            self._client_seq_num = 0

        # For TLS 1.2 with AES-CBC, MAC is calculated EXACTLY as per RFC 5246:
        # HMAC(MAC_write_secret, seq_num + TLSCompressed.type + TLSCompressed.version + TLSCompressed.length + TLSCompressed.fragment)

        # Sequence number must be exactly 8 bytes, big-endian
        seq_num_bytes = self._client_seq_num.to_bytes(8, byteorder='big')

        # Content type is exactly 1 byte
        type_byte = bytes([content_type])

        # Version is exactly 2 bytes
        version_bytes = version

        # Length is exactly 2 bytes, big-endian
        length_bytes = len(handshake_msg).to_bytes(2, byteorder='big')

        # Fragment is the actual handshake message
        fragment = handshake_msg

        # Combine exactly as specified in RFC
        mac_input = seq_num_bytes + type_byte + version_bytes + length_bytes + fragment

        debug(f"MAC input length: {len(mac_input)} bytes")
        debug(f"Seq num: {seq_num_bytes.hex()}")
        debug(f"Type: {type_byte.hex()}")
        debug(f"Version: {version_bytes.hex()}")
        debug(f"Length: {length_bytes.hex()}")
        debug(f"Fragment length: {len(fragment)}")

        # Calculate HMAC-SHA1 (for cipher suite 0x002F)
        mac = hmac.new(self._client_write_mac_key, mac_input, hashlib.sha1).digest()
        debug(f"Calculated MAC: {mac.hex()}")

        # Concatenate message and MAC
        plaintext = handshake_msg + mac

        # Add PKCS#7 padding for AES-CBC (block size = 16)
        # IMPORTANT: TLS uses a specific padding scheme where padding length value = actual padding bytes - 1
        block_size = 16
        padding_length = block_size - (len(plaintext) % block_size)

        # TLS padding: each padding byte contains (padding_length - 1)
        padding_value = padding_length - 1
        padding = bytes([padding_value] * padding_length)
        padded_plaintext = plaintext + padding

        debug(f"Padding: {padding_length} bytes, value: {padding_value}")
        debug(
            f"Plaintext: {len(plaintext)} -> {len(padded_plaintext)} bytes after padding"
        )

        # Generate explicit IV for TLS 1.2 (16 bytes for AES)
        explicit_iv = os.urandom(16)

        # Encrypt using AES-CBC (without additional padding since we already added TLS padding)
        # Encrypt directly without additional PKCS#7 padding (we already padded manually)
        cipher = Cipher(
            algorithms.AES(self._client_write_key),
            modes.CBC(explicit_iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Construct TLS record: type + version + length + explicit_iv + ciphertext
        encrypted_data = explicit_iv + ciphertext
        record = (
            bytes([content_type])
            + version
            + len(encrypted_data).to_bytes(2, byteorder='big')
            + encrypted_data
        )

        # Increment sequence number for next message
        self._client_seq_num += 1

        debug(f"Encrypted record length: {len(record)} bytes")
        return record

    def _extract_server_public_key(self, certificate_data):
        """Extract server's public key from certificate"""
        try:
            debug(f"Certificate data length: {len(certificate_data)}")
            debug(f"First 20 bytes: {certificate_data[:20].hex()}")

            # Parse the certificates list
            # Format: [certificates_length (3 bytes)][certificate_1][certificate_2]...
            if len(certificate_data) < 3:
                debug("Certificate data too short for length header")
                return None

            # Read total certificates length
            certificates_length = struct.unpack("!I", b'\x00' + certificate_data[0:3])[
                0
            ]
            debug(f"Total certificates length: {certificates_length}")

            offset = 3
            if len(certificate_data) < offset + 3:
                debug("Certificate data too short for first certificate length")
                return None

            # Get first certificate length
            cert_length = struct.unpack(
                "!I", b'\x00' + certificate_data[offset : offset + 3]
            )[0]
            offset += 3
            debug(f"First certificate length: {cert_length}")

            if len(certificate_data) < offset + cert_length:
                debug(
                    f"Certificate data too short for certificate content: need {offset + cert_length}, have {len(certificate_data)}"
                )
                return None

            # Extract certificate data
            cert_der = certificate_data[offset : offset + cert_length]
            debug(f"Extracted certificate DER data: {len(cert_der)} bytes")

            # Parse certificate
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            debug(f"Certificate subject: {cert.subject}")
            debug(f"Certificate issuer: {cert.issuer}")

            # Extract public key
            public_key = cert.public_key()
            debug(f"Public key type: {type(public_key)}")

            # Serialize public key to DER format
            public_key_der = public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            debug(f"Public key DER length: {len(public_key_der)}")
            return public_key_der

        except ImportError:
            debug(
                "Warning: cryptography library not available, cannot extract server public key"
            )
            return None
        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"Failed to extract server public key: {e}")
            traceback.print_exc()
            return None

    def _verify_server_certificate(self, certificate_data: bytes):
        """
        Verify server certificate chain.

        Args:
            certificate_data: Raw certificate data from Certificate message
        """
        try:
            hostname = getattr(self, '_server_name', None)
            if not hostname:
                debug("No server name for certificate verification, skipping")
                return

            verifier = CertificateVerifier(verify=True)
            is_valid, error = verifier.verify_certificate(
                hostname=hostname,
                certificate_data=certificate_data,
                check_hostname=True,
                check_expiry=True,
            )

            if is_valid:
                debug(f"Certificate verification passed for {hostname}")
                self._cert_verified = True
            else:
                debug(f"Certificate verification failed: {error}")
                self._cert_verified = False
                self._cert_error = error
                # Don't raise exception - allow connection to continue
                # Users can check _cert_verified to see the result

        except ImportError as e:
            debug(f"Certificate verification module not available: {e}")
            self._cert_verified = False
        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"Certificate verification error: {e}")
            self._cert_verified = False
            self._cert_error = str(e)
