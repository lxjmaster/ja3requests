# pylint: disable=too-many-lines
"""TLS handshake implementation with JA3 fingerprint customization.

This module provides a custom TLS 1.2/1.3 handshake implementation that supports
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
from .certificate_verify import CertificateVerifier, verify_tls_signature

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

    def __init__(
        self,
        conn,
        handshake_timeout=None,
        session_cache=None,
        server_host=None,
        server_port=None,
    ):
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
        self._handshake_timeout = handshake_timeout
        self._session_cache = session_cache
        self._server_host = server_host
        self._server_port = server_port
        self._server_session_id = None  # session ID from ServerHello
        self._is_tls13 = False
        self._tls13_private_key = None
        self._tls13_key_share_group = None
        self._negotiated_protocol = None  # ALPN result (e.g., "h2", "http/1.1")

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

            # Load client certificate if configured
            if getattr(tls_config, 'client_cert', None):
                self._client_cert_pem = self._load_cert_data(tls_config.client_cert)
                self._client_key_pem = (
                    self._load_cert_data(getattr(tls_config, 'client_key', None))
                    if getattr(tls_config, 'client_key', None)
                    else None
                )

            # Update client hello with new configuration
            # For TLS 1.3, record layer version stays 0x0303 for compatibility
            client_hello_version = self.tls_version
            is_tls13 = (
                tls_config.tls_version == 0x0304
                if isinstance(tls_config.tls_version, int)
                else self.tls_version == b'\x03\x04'
            )
            if is_tls13:
                # TLS 1.3: ClientHello version must be 0x0303 (TLS 1.2) for compatibility
                client_hello_version = b'\x03\x03'

            # Merge TLS 1.3 extensions into custom extensions
            extensions = list(getattr(tls_config, 'extensions', None) or [])
            if is_tls13:
                self._setup_tls13_extensions(extensions, tls_config)

            self._body = ClientHello(
                client_hello_version,
                cipher_suites=self._cipher_suites,
                client_random=self._client_random,
                server_name=self._server_name,
                supported_groups=self._supported_groups,
                signature_algorithms=self._signature_algorithms,
                alpn_protocols=getattr(tls_config, 'alpn_protocols', None),
                use_grease=getattr(tls_config, 'use_grease', True),
                _extensions=extensions,
            )

            self._is_tls13 = is_tls13

            # Set cached session ID for resumption
            if (
                self._session_cache is not None
                and self._server_host
                and not self._verify_cert
            ):
                cached = self._session_cache.get(
                    self._server_host, self._server_port or 443
                )
                if cached:
                    debug(f"Using cached session ID for {self._server_host}")
                    self._body.session_id = cached.session_id

    def handshake(self):
        """
        Complete TLS handshake process.
        Automatically selects TLS 1.2 or 1.3 based on configuration.
        """
        try:
            # Initialize handshake message tracking
            self._handshake_messages = b''

            # Step 1: Send Client Hello
            client_hello = self.body
            self._client_random = client_hello.random
            debug("Sending Client Hello...")
            self.conn.sendall(client_hello.message)

            # Add Client Hello to handshake messages (without TLS record header)
            self._handshake_messages += client_hello.handshake_message

            if self._is_tls13:
                return self._handshake_tls13()

            return self._handshake_tls12()

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"TLS Handshake failed: {e}")
            return False

    def _handshake_tls13(self):
        """
        TLS 1.3 handshake flow after ClientHello is sent.
        Uses TLS13Handshake to manage key derivation and encrypted messages.
        """
        from ja3requests.protocol.tls.tls13 import (
            TLS13Handshake,
        )  # pylint: disable=import-outside-toplevel

        try:
            # Receive ServerHello (unencrypted)
            self.conn.settimeout(
                self._handshake_timeout if self._handshake_timeout is not None else 5.0
            )
            buffer = b""
            server_hello_msg = None

            # Read until we get a complete ServerHello
            while True:
                data = self.conn.recv(4096)
                if not data:
                    break
                buffer += data

                # Parse TLS records
                if len(buffer) >= 5:
                    record_type = buffer[0]
                    record_length = struct.unpack("!H", buffer[3:5])[0]
                    if len(buffer) >= 5 + record_length:
                        if record_type == 22:  # Handshake
                            record_data = buffer[5 : 5 + record_length]
                            if record_data[0] == 2:  # ServerHello
                                msg_len = struct.unpack(
                                    "!I", b"\x00" + record_data[1:4]
                                )[0]
                                server_hello_msg = record_data[4 : 4 + msg_len]
                                # Also parse with our existing method for cipher suite etc.
                                self._parse_server_hello(server_hello_msg)
                                buffer = buffer[5 + record_length :]
                        break

            if server_hello_msg is None:
                debug("TLS 1.3: No ServerHello received")
                return False

            # Initialize TLS 1.3 handshake handler
            hs = TLS13Handshake(
                self.conn,
                self._tls13_private_key,
                self._tls13_key_share_group,
                self._handshake_messages,
            )
            if getattr(self, '_verify_cert', False):
                hs._certificate_verifier = self._verify_server_certificate

            if not hs.process_server_hello(server_hello_msg):
                debug("TLS 1.3: Failed to process ServerHello")
                return False

            # Read and decrypt encrypted handshake messages
            # (EncryptedExtensions, Certificate, CertificateVerify, Finished)
            server_finished_received = False
            while not server_finished_received:
                if len(buffer) < 5 or len(buffer) < 5 + int.from_bytes(
                    buffer[3:5], 'big'
                ):
                    data = self.conn.recv(4096)
                    if not data:
                        break
                    buffer += data
                    continue

                # Parse TLS records from buffer
                offset = 0
                while offset + 5 <= len(buffer):
                    rec_type = buffer[offset]
                    rec_len = struct.unpack("!H", buffer[offset + 3 : offset + 5])[0]
                    if offset + 5 + rec_len > len(buffer):
                        break

                    record_header = buffer[offset : offset + 5]
                    ciphertext = buffer[offset + 5 : offset + 5 + rec_len]
                    offset += 5 + rec_len

                    if rec_type == 20:  # ChangeCipherSpec (compatibility)
                        continue

                    if rec_type == 0x17:  # Application data (encrypted handshake)
                        content_type, plaintext = hs.decrypt_handshake_record(
                            ciphertext, record_header
                        )
                        if content_type == 0x16:  # Handshake
                            messages = hs.parse_encrypted_handshake(plaintext)
                            for msg_type, msg_data in messages:
                                if msg_type == 20:  # Finished
                                    server_finished_received = True
                buffer = buffer[offset:]

            if not server_finished_received:
                debug("TLS 1.3: Server Finished not received")
                return False

            # Send client Finished
            finished_record = hs.build_client_finished()
            self.conn.sendall(finished_record)

            # Derive application traffic keys
            client_rp, server_rp = hs.derive_application_keys()

            # Store for use by HttpsSocket
            self._tls13_client_rp = client_rp
            self._tls13_server_rp = server_rp
            self._tls13_handshake = hs
            self._negotiated_protocol = hs._negotiated_protocol

            debug("✅ TLS 1.3 handshake completed successfully!")
            self._save_session_to_cache()
            self.conn.settimeout(None)
            return True

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"TLS 1.3 handshake failed: {e}")
            traceback.print_exc()
            return False
        finally:
            self.conn.settimeout(None)

    def _handshake_tls12(self):
        """TLS 1.2 handshake flow after ClientHello is sent."""
        try:
            # Step 2-6: Receive server handshake messages
            self._parse_server_handshake_messages()
            if getattr(self, '_verify_cert', False) and not getattr(
                self, '_cert_verified', False
            ):
                raise TLSHandshakeError("Server certificate was not verified")

            # Step 7-9: Send client finishing messages
            self._send_client_finishing_messages()

            # Step 10: Wait for server's response to our Finished message
            try:
                time.sleep(0.3)
                self.conn.settimeout(
                    self._handshake_timeout
                    if self._handshake_timeout is not None
                    else 5.0
                )
                success = self._wait_for_server_handshake_completion()
                if success:
                    debug("✅ Full TLS 1.2 handshake completed successfully!")
                    self._save_session_to_cache()
                    self.conn.settimeout(None)
                    return True
                raise TLSHandshakeError("Server did not complete handshake")
            finally:
                self.conn.settimeout(None)

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"TLS 1.2 Handshake failed: {e}")
            return False

    def _setup_tls13_extensions(self, extensions, tls_config):
        """Add TLS 1.3-specific extensions and generate key_share."""
        from ja3requests.protocol.tls.extensions import (  # pylint: disable=import-outside-toplevel
            SupportedVersionsExtension,
            KeyShareExtension,
            PSKKeyExchangeModesExtension,
        )
        from ja3requests.protocol.tls.tls13 import (
            TLS13KeyExchange,
        )  # pylint: disable=import-outside-toplevel

        existing_types = {
            ext.extension_type for ext in extensions if hasattr(ext, 'extension_type')
        }

        # supported_versions: advertise TLS 1.3 + 1.2
        if SupportedVersionsExtension.extension_type not in existing_types:
            extensions.append(SupportedVersionsExtension([0x0304, 0x0303]))

        # key_share: generate ECDHE key pair and include public key
        if KeyShareExtension.extension_type not in existing_types:
            # Default to x25519 (most widely supported for TLS 1.3)
            private_key, public_bytes = TLS13KeyExchange.generate_x25519_keypair()
            self._tls13_private_key = private_key
            self._tls13_key_share_group = 0x001D  # x25519
            extensions.append(KeyShareExtension([(0x001D, public_bytes)]))

        # psk_key_exchange_modes (required even without PSK for some servers)
        if PSKKeyExchangeModesExtension.extension_type not in existing_types:
            extensions.append(PSKKeyExchangeModesExtension([1]))  # psk_dhe_ke

    def _save_session_to_cache(self):
        """Save the current session to the session cache for future resumption."""
        if (
            self._session_cache is not None
            and self._server_host
            and self._server_session_id
            and self._master_secret
        ):
            cipher = getattr(self, '_selected_cipher_suite', 0)
            self._session_cache.put(
                self._server_host,
                self._server_port or 443,
                self._server_session_id,
                self._master_secret,
                cipher,
                tls_version=self._tls_version,
            )
            debug(f"Saved TLS session for {self._server_host}:{self._server_port}")

    def _parse_new_session_ticket(self, data):
        """
        Parse NewSessionTicket message (handshake type 4) and cache ticket.
        TLS 1.2: lifetime(4) + ticket_data
        """
        if len(data) < 6:
            return
        lifetime = struct.unpack("!I", data[:4])[0]
        ticket_len = struct.unpack("!H", data[4:6])[0]
        if len(data) < 6 + ticket_len:
            return
        ticket = data[6 : 6 + ticket_len]
        debug(
            f"Received NewSessionTicket: lifetime={lifetime}s, ticket_len={ticket_len}"
        )

        # Store ticket as session ID for resumption
        if (
            self._session_cache is not None
            and self._server_host
            and self._master_secret
        ):
            cipher = getattr(self, '_selected_cipher_suite', 0)
            self._session_cache.put(
                self._server_host,
                self._server_port or 443,
                ticket,  # Use ticket as session ID
                self._master_secret,
                cipher,
                tls_version=self._tls_version,
            )
            debug(f"Cached session ticket for {self._server_host}")

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
        recv_timeout = (
            min(self._handshake_timeout, 5.0)
            if self._handshake_timeout is not None
            else 1.0
        )
        self.conn.settimeout(recv_timeout)

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
            self._server_session_id = data[offset : offset + session_id_length]
            debug(f"Server session ID: {self._server_session_id.hex()[:16]}...")
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

        # Parse extensions (if present)
        if offset + 2 <= len(data):
            extensions_length = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
            ext_end = offset + extensions_length
            while offset + 4 <= ext_end:
                ext_type = struct.unpack("!H", data[offset : offset + 2])[0]
                ext_len = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
                offset += 4
                ext_data = data[offset : offset + ext_len]
                offset += ext_len

                # ALPN (0x0010): extract negotiated protocol
                if ext_type == 0x0010 and len(ext_data) >= 4:
                    proto_list_len = struct.unpack("!H", ext_data[:2])[0]
                    if proto_list_len > 0:
                        proto_len = ext_data[2]
                        self._negotiated_protocol = ext_data[3 : 3 + proto_len].decode(
                            "ascii"
                        )
                        debug(f"ALPN negotiated: {self._negotiated_protocol}")

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
            if getattr(self, '_verify_cert', False):
                raise TLSHandshakeError(f"Invalid server certificate: {e}") from e
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
                if getattr(self, '_verify_cert', False):
                    signed_end = 4 + data[3]
                    if signed_end + 4 > len(data):
                        raise TLSHandshakeError("Missing ServerKeyExchange signature")
                    scheme, size = struct.unpack(
                        '!HH', data[signed_end : signed_end + 4]
                    )
                    signature = data[signed_end + 4 :]
                    if len(signature) != size:
                        raise TLSHandshakeError("Truncated ServerKeyExchange signature")
                    verify_tls_signature(
                        serialization.load_der_public_key(self._server_public_key),
                        scheme,
                        signature,
                        self._client_random + self._server_random + data[:signed_end],
                    )
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

    def _parse_certificate_request(self, data):
        """
        Parse CertificateRequest message.
        Extracts certificate types, signature algorithms, and distinguished names.
        """
        self._client_cert_requested = True
        offset = 0

        # certificate_types (1-byte length + types)
        if offset < len(data):
            cert_types_len = data[offset]
            offset += 1
            self._cert_types = list(data[offset : offset + cert_types_len])
            offset += cert_types_len
            debug(f"CertificateRequest: cert_types={self._cert_types}")

        # signature_algorithms (2-byte length + algorithms)
        if offset + 2 <= len(data):
            sig_algs_len = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
            self._cert_sig_algs = []
            for i in range(0, sig_algs_len, 2):
                if offset + 2 <= len(data):
                    self._cert_sig_algs.append(
                        struct.unpack("!H", data[offset : offset + 2])[0]
                    )
                    offset += 2
            debug(
                f"CertificateRequest: sig_algs={[hex(a) for a in self._cert_sig_algs]}"
            )

        # distinguished_names (2-byte length + DN list) — optional, often empty
        if offset + 2 <= len(data):
            dn_len = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
            self._cert_dn_data = data[offset : offset + dn_len]

    def _parse_server_hello_done(self, _data):
        """Parse ServerHelloDone message"""
        # This message has no content, just set the flag
        self._server_hello_done_received = True
        debug("Received ServerHelloDone - ready to send client finishing messages")

    def _send_client_finishing_messages(self):
        """
        Send client finishing messages
        """
        # Send Certificate if requested
        if getattr(self, '_client_cert_requested', False):
            client_cert_pem = getattr(self, '_client_cert_pem', None)
            if client_cert_pem:
                cert_msg = self._build_client_certificate(client_cert_pem)
                self.conn.sendall(cert_msg)
                debug("Sent client Certificate")
            else:
                empty_cert = self._build_empty_certificate()
                self.conn.sendall(empty_cert)
                debug("Sent empty Certificate (no client cert configured)")

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

    def _read_server_handshake_record(self):
        """Read exactly one record without consuming later application data."""

        def read_exact(size):
            data = b''
            while len(data) < size:
                chunk = self.conn.recv(size - len(data))
                if not chunk:
                    raise TLSHandshakeError("Truncated server handshake record")
                data += chunk
            return data

        header = read_exact(5)
        length = int.from_bytes(header[3:5], 'big')
        if header[1:3] != b'\x03\x03' or length > 18432:
            raise TLSHandshakeError("Invalid TLS 1.2 record header")
        return header, read_exact(length)

    def _decrypt_server_handshake_record(self, header, encrypted):
        """Authenticate a TLS 1.2 handshake record using the server write keys."""
        prefix = self._server_seq_num.to_bytes(8, 'big') + header[:3]
        if self._is_gcm:
            if len(encrypted) < 24:
                raise TLSHandshakeError("Truncated GCM handshake record")
            explicit, ciphertext, tag = encrypted[:8], encrypted[8:-16], encrypted[-16:]
            aad = prefix + len(ciphertext).to_bytes(2, 'big')
            plaintext = AESCipher.decrypt_gcm(
                ciphertext,
                self._server_write_key,
                self._server_write_iv + explicit,
                tag,
                aad,
            )
        else:
            if len(encrypted) < 32 or len(encrypted) % 16:
                raise TLSHandshakeError("Invalid CBC handshake record length")
            padded = AESCipher.decrypt_cbc(
                encrypted[16:],
                self._server_write_key,
                encrypted[:16],
                remove_padding=False,
            )
            padding_length = padded[-1] + 1
            if padding_length > len(padded) or not hmac.compare_digest(
                padded[-padding_length:], bytes([padding_length - 1]) * padding_length
            ):
                raise TLSHandshakeError("Invalid CBC handshake padding")
            fragment = padded[:-padding_length]
            info = get_cipher_info(self._selected_cipher_suite)
            hash_algo = {
                'SHA1': hashlib.sha1,
                'SHA256': hashlib.sha256,
                'SHA384': hashlib.sha384,
            }[info['mac']]
            mac_length = hash_algo().digest_size
            if len(fragment) < mac_length:
                raise TLSHandshakeError("Truncated handshake MAC")
            plaintext, received_mac = fragment[:-mac_length], fragment[-mac_length:]
            mac_data = prefix + len(plaintext).to_bytes(2, 'big') + plaintext
            expected_mac = hmac.new(
                self._server_write_mac_key, mac_data, hash_algo
            ).digest()
            if not hmac.compare_digest(received_mac, expected_mac):
                raise TLSHandshakeError("Invalid handshake MAC")
        self._server_seq_num += 1
        return plaintext

    def _verify_server_finished(self, message, transcript):
        """Check the Finished message against the transcript through client Finished."""
        if len(message) != 16 or message[:4] != b'\x14\x00\x00\x0c':
            raise TLSHandshakeError("Invalid server Finished message")
        expected = TLSCrypto.compute_verify_data(
            self._master_secret,
            transcript,
            is_client=False,
            _cipher_suite=self._selected_cipher_suite,
        )
        if not hmac.compare_digest(message[4:], expected):
            raise TLSHandshakeError("Invalid server Finished verify_data")

    def _wait_for_server_handshake_completion(self):
        """Require ChangeCipherSpec and an authenticated server Finished."""
        try:
            received_ccs = False
            pending = b''
            transcript = self._handshake_messages
            while True:
                header, payload = self._read_server_handshake_record()
                if header[0] == 20:
                    if received_ccs or payload != b'\x01' or pending:
                        raise TLSHandshakeError("Unexpected ChangeCipherSpec")
                    received_ccs = True
                    self._server_seq_num = 0
                    continue
                if header[0] != 22:
                    raise TLSHandshakeError(
                        "Expected server Finished, received other record type"
                    )
                if received_ccs:
                    payload = self._decrypt_server_handshake_record(header, payload)
                pending += payload
                while len(pending) >= 4:
                    kind = pending[0]
                    size = int.from_bytes(pending[1:4], 'big')
                    if received_ccs:
                        if kind != 20 or size != 12:
                            raise TLSHandshakeError(
                                "Expected encrypted server Finished"
                            )
                    elif kind != 4 or size < 6 or size > 65541:
                        raise TLSHandshakeError(
                            "Expected NewSessionTicket before ChangeCipherSpec"
                        )
                    if len(pending) < 4 + size:
                        break
                    message, pending = pending[: 4 + size], pending[4 + size :]
                    if received_ccs:
                        self._verify_server_finished(message, transcript)
                        if pending:
                            raise TLSHandshakeError(
                                "Unexpected messages after server Finished"
                            )
                        self._handshake_messages = transcript + message
                        return True
                    if int.from_bytes(message[8:10], 'big') != len(message) - 10:
                        raise TLSHandshakeError("Invalid NewSessionTicket length")
                    transcript += message
        except Exception as error:  # pylint: disable=broad-exception-caught
            debug(f"Failed to authenticate server Finished: {error}")
            return False

    @staticmethod
    def _load_cert_data(cert_input):
        """Load certificate/key data from file path or raw bytes/string."""
        if cert_input is None:
            return None
        if isinstance(cert_input, bytes):
            return cert_input
        if isinstance(cert_input, str):
            import os  # pylint: disable=import-outside-toplevel

            if os.path.isfile(cert_input):
                with open(cert_input, 'rb') as f:
                    return f.read()
            return cert_input.encode('utf-8')
        return None

    def _build_empty_certificate(self):
        """Build an empty certificate message"""
        cert_list_length = b'\x00\x00\x00'  # 0 length certificate list
        cert_msg = b'\x0b' + struct.pack("!I", 3)[1:] + cert_list_length
        record = b'\x16\x03\x03' + struct.pack("!H", len(cert_msg)) + cert_msg
        return record

    def _build_client_certificate(self, cert_pem):
        """
        Build a Certificate message with the client's certificate.
        Parses PEM to extract DER-encoded certificate(s).
        """
        import base64  # pylint: disable=import-outside-toplevel

        # Extract DER certificates from PEM
        certs_der = []
        if isinstance(cert_pem, bytes):
            cert_pem = cert_pem.decode('utf-8', errors='replace')

        in_cert = False
        cert_lines = []
        for line in cert_pem.splitlines():
            if '-----BEGIN CERTIFICATE-----' in line:
                in_cert = True
                cert_lines = []
            elif '-----END CERTIFICATE-----' in line:
                in_cert = False
                der = base64.b64decode(''.join(cert_lines))
                certs_der.append(der)
            elif in_cert:
                cert_lines.append(line.strip())

        if not certs_der:
            return self._build_empty_certificate()

        # Build certificate list: each cert is 3-byte length + DER data
        cert_list = b""
        for der in certs_der:
            cert_list += struct.pack("!I", len(der))[1:] + der  # 3-byte length

        # Certificate message: type(11) + 3-byte total length + 3-byte list length + certs
        list_length = struct.pack("!I", len(cert_list))[1:]
        cert_msg = (
            b'\x0b'
            + struct.pack("!I", len(cert_list) + 3)[1:]
            + list_length
            + cert_list
        )

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
            # The server's Finished authenticates our Finished as well.
            self._handshake_messages += msg
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
        """Validate the destination identity and stop the handshake on failure."""
        self._cert_verified = False
        hostname = self._server_host or self._server_name
        if not hostname:
            raise TLSHandshakeError("No hostname for certificate verification")
        self._certificate_data = certificate_data
        valid, error = CertificateVerifier(verify=True).verify_certificate(
            hostname, certificate_data
        )
        if not valid:
            self._cert_error = error
            raise TLSHandshakeError(f"Certificate verification failed: {error}")
        self._cert_verified = True
        self._verified_hostname = hostname
