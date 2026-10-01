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
import copy
import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
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

HELLO_RETRY_REQUEST_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
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
        self._payload_configured = False
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
        self._tls13_private_keys = {}
        self._server_legacy_version = None
        self._server_supported_version = None
        self._offered_extended_master_secret = False
        self._extended_master_secret = False
        self._negotiated_protocol = None  # ALPN result (e.g., "h2", "http/1.1")
        self._tls13_psk = None
        self._tls13_pending_record_data = b""
        self._tls12_pending_record_data = b""
        self._offered_session = None
        self._resumed_session = None
        self._server_offered_session_ticket = False
        self._new_session_ticket = (0, b'')

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
        if tls_config is None:
            from .config import TlsConfig  # pylint: disable=import-outside-toplevel

            tls_config = TlsConfig()
        if tls_config:
            self._payload_configured = True
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

            # The destination supplies SNI when the configuration has no explicit override.
            self._server_name = (
                getattr(tls_config, 'server_name', None) or self._server_host
            )

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
                self._verify_cert = True

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
            self._offered_extended_master_secret = any(
                getattr(ext, 'extension_type', None) == 0x0017 for ext in extensions
            )
            if is_tls13:
                self._setup_tls13_extensions(extensions, tls_config)
                self._select_tls13_ticket(extensions)

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
            self._select_tls12_session()

    def _select_tls12_session(self):
        """Offer a policy-compatible EMS ticket or Session ID."""
        self._offered_session = None
        if self._session_cache is None or self._server_host is None:
            return
        ticket_extension = next(
            (
                ext
                for ext in self.body._custom_extensions
                if getattr(ext, 'extension_type', None) == 0x0023
            ),
            None,
        )
        ticket = (
            self._session_cache.get_tls12_ticket(
                self._server_host, self._server_port or 443
            )
            if ticket_extension is not None
            else None
        )
        offered = {
            suite.value if hasattr(suite, 'value') else suite
            for suite in self._cipher_suites
        }

        def compatible(entry):
            return (
                entry is not None
                and entry.tls_version == b'\x03\x03'
                and entry.extended_master_secret
                and self._offered_extended_master_secret
                and entry.cipher_suite in offered
                and len(entry.master_secret) == 48
                and entry.sni == self._server_name
                and not getattr(self, '_client_cert_pem', None)
                and (
                    not getattr(self, '_verify_cert', False)
                    or (entry.verified and entry.verified_hostname == self._server_host)
                )
            )

        if not compatible(ticket):
            ticket = None
        entry = ticket or self._session_cache.get(
            self._server_host, self._server_port or 443
        )
        if not compatible(entry) or (
            ticket is None and (entry.is_ticket or not 1 <= len(entry.session_id) <= 32)
        ):
            return
        if ticket is not None:
            from ja3requests.protocol.tls.extensions import (  # pylint: disable=import-outside-toplevel
                SessionTicketExtension,
            )

            self.body._custom_extensions = [
                SessionTicketExtension(entry.ticket) if ext is ticket_extension else ext
                for ext in self.body._custom_extensions
            ]
            self.body._build_extensions()
            self.body.session_id = os.urandom(32)
        else:
            self.body.session_id = entry.session_id
        self._offered_session = entry

    def handshake(self):
        """
        Complete TLS handshake process.
        Automatically selects TLS 1.2 or 1.3 based on configuration.
        """
        try:
            if not self._payload_configured:
                self.set_payload()
            # Initialize handshake message tracking
            self._handshake_messages = b''
            self._pending_server_handshake = b''

            # Step 1: Send Client Hello
            client_hello = self.body
            self._client_random = client_hello.random
            if self._tls13_psk is not None:
                self._bind_tls13_client_hello()
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

    def _selected_handshake_version(self):
        offered_suites = {
            suite.value if hasattr(suite, 'value') else suite
            for suite in self._cipher_suites
        }
        selected_suite = self._selected_cipher_suite
        if selected_suite not in offered_suites:
            raise TLSHandshakeError("Server selected an unoffered cipher suite")

        if self._server_supported_version is None:
            if (
                self._server_legacy_version != b'\x03\x03'
                or selected_suite in (0x1301, 0x1302, 0x1303)
                or self._server_random.endswith(b'DOWNGRD\x01')
            ):
                raise TLSHandshakeError("Invalid TLS 1.2 version selection")
            return b'\x03\x03'

        if self._server_supported_version != b'\x03\x04' or selected_suite not in (
            0x1301,
            0x1302,
            0x1303,
        ):
            raise TLSHandshakeError("Invalid TLS 1.3 version selection")
        return b'\x03\x04'

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
            server_hello_msg, first_records, buffer, trailing = (
                self._receive_server_hello()
            )
            retry_suite = None
            if server_hello_msg[2:34] == HELLO_RETRY_REQUEST_RANDOM:
                if trailing:
                    raise TLSHandshakeError(
                        "Unexpected plaintext after HelloRetryRequest"
                    )
                retry_suite, group, cookie = self._parse_hello_retry_request(
                    server_hello_msg
                )
                self._send_retried_client_hello(
                    server_hello_msg, retry_suite, group, cookie
                )
                server_hello_msg, first_records, buffer, trailing = (
                    self._receive_server_hello(buffer, allow_ccs=True)
                )
                if server_hello_msg[2:34] == HELLO_RETRY_REQUEST_RANDOM:
                    raise TLSHandshakeError("Second HelloRetryRequest")
            self._parse_server_hello(server_hello_msg)

            selected_version = self._selected_handshake_version()
            if retry_suite is not None and (
                selected_version != b'\x03\x04'
                or self._selected_cipher_suite != retry_suite
                or (self._server_session_id or b"")
                != (self.body.session_id if self.body.session_id != b"\x00" else b"")
            ):
                raise TLSHandshakeError(
                    "ServerHello changed HelloRetryRequest selection"
                )

            if selected_version == b'\x03\x03':
                self._is_tls13 = False
                self._tls_version = b'\x03\x03'
                return self._handshake_tls12(first_records + buffer)

            if trailing:
                raise TLSHandshakeError(
                    "Unexpected plaintext after TLS 1.3 ServerHello"
                )

            # Initialize TLS 1.3 handshake handler
            hs = TLS13Handshake(
                self.conn,
                self._tls13_private_key,
                self._tls13_key_share_group,
                self._handshake_messages,
                private_keys=self._tls13_private_keys,
                offered_psk=self._tls13_psk,
                post_handshake_auth=any(
                    getattr(ext, 'extension_type', None) == 0x0031
                    for ext in self.body._custom_extensions
                ),
                client_cert_pem=getattr(self, '_client_cert_pem', None),
                client_key_pem=getattr(self, '_client_key_pem', None),
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
                            if server_finished_received:
                                break
                buffer = buffer[offset:]

            if not server_finished_received:
                debug("TLS 1.3: Server Finished not received")
                return False

            client_authentication = hs.build_client_authentication(
                getattr(self, '_client_cert_pem', None),
                getattr(self, '_client_key_pem', None),
            )
            if client_authentication:
                self.conn.sendall(client_authentication)

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
            self._tls13_pending_record_data = buffer
            if hs._resumed:
                self._cert_verified = self._tls13_psk.verified
                self._verified_hostname = self._tls13_psk.verified_hostname
                self._server_cert_not_after = self._tls13_psk.certificate_expires_at
            if self._tls13_psk is not None and self._session_cache is not None:
                self._session_cache.remove_tls13(
                    self._server_host,
                    self._server_port or 443,
                    self._tls13_psk.ticket,
                )
            hs._ticket_callback = self._cache_tls13_ticket

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

    def _receive_server_hello(self, initial_data=b"", allow_ccs=False):
        """Reassemble the first handshake message across TLS records."""
        buffer = initial_data
        handshake = b""
        consumed = b""
        while True:
            while len(buffer) < 5:
                chunk = self.conn.recv(4096)
                if not chunk:
                    raise TLSHandshakeError("Truncated ServerHello record")
                buffer += chunk
            record_length = int.from_bytes(buffer[3:5], 'big')
            if record_length > 18432:
                raise TLSHandshakeError("Invalid ServerHello record length")
            while len(buffer) < 5 + record_length:
                chunk = self.conn.recv(4096)
                if not chunk:
                    raise TLSHandshakeError("Truncated ServerHello record")
                buffer += chunk
            record, buffer = buffer[: 5 + record_length], buffer[5 + record_length :]
            if allow_ccs and record[0] == 20 and record[5:] == b"\x01":
                continue
            if record[0] != 22:
                raise TLSHandshakeError("Expected ServerHello handshake record")
            consumed += record
            handshake += record[5:]
            if len(handshake) < 4:
                continue
            if handshake[0] != 2:
                raise TLSHandshakeError("Expected ServerHello handshake message")
            length = int.from_bytes(handshake[1:4], 'big')
            if len(handshake) >= 4 + length:
                return (
                    handshake[4 : 4 + length],
                    consumed,
                    buffer,
                    handshake[4 + length :],
                )

    def _parse_hello_retry_request(self, data):
        """Validate a TLS 1.3 retry request before changing ClientHello."""
        from ja3requests.protocol.tls.tls13 import (  # pylint: disable=import-outside-toplevel
            TLS13_CIPHER_PARAMS,
        )

        if len(data) < 40 or data[:34] != b"\x03\x03" + HELLO_RETRY_REQUEST_RANDOM:
            raise TLSHandshakeError("Invalid HelloRetryRequest")
        offset = 34
        session_id_length = data[offset]
        offset += 1
        expected_id = self.body.session_id
        if expected_id == b"\x00":
            expected_id = b""
        if (
            session_id_length > 32
            or data[offset : offset + session_id_length] != expected_id
        ):
            raise TLSHandshakeError("HelloRetryRequest changed session ID")
        offset += session_id_length
        if offset + 5 > len(data):
            raise TLSHandshakeError("Truncated HelloRetryRequest")
        suite = int.from_bytes(data[offset : offset + 2], "big")
        offered = {
            item.value if hasattr(item, "value") else item
            for item in self._cipher_suites
        }
        if suite not in TLS13_CIPHER_PARAMS or suite not in offered:
            raise TLSHandshakeError("HelloRetryRequest selected an unoffered suite")
        if data[offset + 2] != 0:
            raise TLSHandshakeError("Invalid HelloRetryRequest compression")
        offset += 3
        extension_length = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        if offset + extension_length != len(data):
            raise TLSHandshakeError("Invalid HelloRetryRequest extensions")
        extensions = {}
        while offset < len(data):
            if offset + 4 > len(data):
                raise TLSHandshakeError("Truncated HelloRetryRequest extension")
            kind, size = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4
            if kind in extensions or offset + size > len(data):
                raise TLSHandshakeError("Invalid HelloRetryRequest extension")
            extensions[kind] = data[offset : offset + size]
            offset += size
        if extensions.get(0x002B) != b"\x03\x04" or set(extensions) - {
            0x002B,
            0x002C,
            0x0033,
        }:
            raise TLSHandshakeError("Invalid HelloRetryRequest version or extension")
        share = extensions.get(0x0033)
        if share is not None and len(share) != 2:
            raise TLSHandshakeError("Invalid HelloRetryRequest key share")
        group = int.from_bytes(share, "big") if share is not None else None
        if group is not None and (
            group not in self._supported_groups
            or not self._tls13_private_keys
            or group in self._tls13_private_keys
            or group not in (23, 29)
        ):
            raise TLSHandshakeError("HelloRetryRequest selected an invalid group")
        cookie_extension = extensions.get(0x002C)
        cookie = None
        if cookie_extension is not None:
            if (
                len(cookie_extension) < 3
                or int.from_bytes(cookie_extension[:2], "big")
                != len(cookie_extension) - 2
            ):
                raise TLSHandshakeError("Invalid HelloRetryRequest cookie")
            cookie = cookie_extension[2:]
        if group is None and cookie is None:
            raise TLSHandshakeError("HelloRetryRequest made no change")
        return suite, group, cookie

    def _send_retried_client_hello(self, retry, suite, group, cookie):
        """Send ClientHello2 and replace ClientHello1 with message_hash."""
        from ja3requests.protocol.tls.extensions import (  # pylint: disable=import-outside-toplevel
            CookieExtension,
            KeyShareExtension,
        )
        from ja3requests.protocol.tls.tls13 import (  # pylint: disable=import-outside-toplevel
            TLS13KeyExchange,
            TLS13_CIPHER_PARAMS,
        )

        extensions = list(self.body._custom_extensions)
        if group is not None:
            if group == 29:
                private_key, public_bytes = TLS13KeyExchange.generate_x25519_keypair()
            else:
                private_key, public_bytes = (
                    TLS13KeyExchange.generate_secp256r1_keypair()
                )
            extensions = [
                (
                    KeyShareExtension([(group, public_bytes)])
                    if getattr(ext, "extension_type", None) == 0x0033
                    else ext
                )
                for ext in extensions
            ]
            self._tls13_private_keys = {group: private_key}
            self._tls13_private_key = private_key
            self._tls13_key_share_group = group
        if cookie is not None:
            extensions.append(CookieExtension(cookie))
        retried = copy.copy(self.body)
        retried._custom_extensions = extensions
        retried._build_extensions()
        hash_algo = TLS13_CIPHER_PARAMS[suite][1]
        digest = hash_algo(self._handshake_messages).digest()
        retry_message = b"\x02" + len(retry).to_bytes(3, "big") + retry
        transcript_prefix = (
            b"\xfe" + len(digest).to_bytes(3, "big") + digest + retry_message
        )
        self._body = retried
        if self._tls13_psk is not None:
            self._bind_tls13_client_hello(transcript_prefix)
        self._handshake_messages = transcript_prefix + retried.handshake_message
        self.conn.sendall(retried.message)

    def _handshake_tls12(self, initial_data=b""):
        """TLS 1.2 handshake flow after ClientHello is sent."""
        try:
            # Step 2-6: Receive server handshake messages
            self._parse_server_handshake_messages(initial_data)
            if getattr(self, '_verify_cert', False) and not getattr(
                self, '_cert_verified', False
            ):
                raise TLSHandshakeError("Server certificate was not verified")

            if self._resumed_session is not None:
                if not self._wait_for_server_handshake_completion():
                    raise TLSHandshakeError("Invalid resumed server Finished")
                self.conn.sendall(b'\x14\x03\x03\x00\x01\x01')
                self._client_seq_num = 0
                self.conn.sendall(self._build_finished_message())
                self._cache_new_tls12_ticket()
                debug("TLS 1.2 abbreviated handshake completed successfully")
                return True

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
                    if self._offered_session is not None:
                        if self._offered_session.is_ticket:
                            self._session_cache.remove_tls12_ticket(
                                self._server_host,
                                self._server_port or 443,
                                self._offered_session.ticket,
                            )
                        else:
                            self._session_cache.remove_tls12(
                                self._server_host,
                                self._server_port or 443,
                                self._offered_session.session_id,
                            )
                    new_ticket = self._new_session_ticket
                    if (
                        new_ticket[1]
                        and new_ticket[0]
                        and self._session_cache is not None
                    ):
                        self._cache_new_tls12_ticket()
                    else:
                        self._save_session_to_cache()
                    self.conn.settimeout(None)
                    return True
                raise TLSHandshakeError("Server did not complete handshake")
            finally:
                self.conn.settimeout(None)

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"TLS 1.2 Handshake failed: {e}")
            if self._resumed_session is not None and self._resumed_session.is_ticket:
                self._session_cache.remove_tls12_ticket(
                    self._server_host,
                    self._server_port or 443,
                    self._resumed_session.ticket,
                )
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

        self._tls13_private_keys = {}
        self._tls13_private_key = None
        self._tls13_key_share_group = None
        existing_types = {
            ext.extension_type for ext in extensions if hasattr(ext, 'extension_type')
        }

        # supported_versions: advertise TLS 1.3 + 1.2
        if SupportedVersionsExtension.extension_type not in existing_types:
            extensions.append(SupportedVersionsExtension([0x0304, 0x0303]))

        # key_share: include one share for each supported implemented group.
        if KeyShareExtension.extension_type not in existing_types:
            if not self._supported_groups:
                self._supported_groups = [0x001D]
            initial_groups = getattr(tls_config, "key_share_groups", None)
            if initial_groups is None:
                initial_groups = self._supported_groups
            elif (
                not initial_groups
                or len(initial_groups) != len(set(initial_groups))
                or not set(initial_groups).issubset(
                    set(self._supported_groups) & {0x0017, 0x001D}
                )
                or initial_groups
                != [
                    group for group in self._supported_groups if group in initial_groups
                ]
            ):
                raise TLSHandshakeError("Invalid initial TLS 1.3 key share groups")
            key_shares = []
            for group in initial_groups:
                if group in self._tls13_private_keys:
                    continue
                if group == 0x001D:
                    private_key, public_bytes = (
                        TLS13KeyExchange.generate_x25519_keypair()
                    )
                elif group == 0x0017:
                    private_key, public_bytes = (
                        TLS13KeyExchange.generate_secp256r1_keypair()
                    )
                else:
                    continue
                self._tls13_private_keys[group] = private_key
                key_shares.append((group, public_bytes))
            if not key_shares:
                raise TLSHandshakeError("No supported TLS 1.3 key share group")
            self._tls13_key_share_group = key_shares[0][0]
            self._tls13_private_key = self._tls13_private_keys[
                self._tls13_key_share_group
            ]
            extensions.append(KeyShareExtension(key_shares))

        # psk_key_exchange_modes (required even without PSK for some servers)
        if PSKKeyExchangeModesExtension.extension_type not in existing_types:
            extensions.append(PSKKeyExchangeModesExtension([1]))  # psk_dhe_ke

    def _select_tls13_ticket(self, extensions):
        """Offer one compatible ticket from this destination's in-memory cache."""
        from ja3requests.protocol.tls.extensions import (  # pylint: disable=import-outside-toplevel
            PreSharedKeyExtension,
        )
        from ja3requests.protocol.tls.tls13 import (  # pylint: disable=import-outside-toplevel
            TLS13_CIPHER_PARAMS,
        )

        self._tls13_psk = None
        if self._session_cache is None or self._server_host is None:
            return
        if any(getattr(ext, 'extension_type', None) == 0x0029 for ext in extensions):
            return
        ticket = self._session_cache.get_tls13(
            self._server_host, self._server_port or 443
        )
        offered_suites = {
            suite.value if hasattr(suite, 'value') else suite
            for suite in self._cipher_suites
        }
        if (
            ticket is None
            or getattr(self, '_client_cert_pem', None)
            or ticket.cipher_suite not in offered_suites
            or ticket.cipher_suite not in TLS13_CIPHER_PARAMS
            or ticket.sni != self._server_name
            or (
                getattr(self, '_verify_cert', False)
                and (
                    not ticket.verified or ticket.verified_hostname != self._server_host
                )
            )
        ):
            return
        hash_algo = TLS13_CIPHER_PARAMS[ticket.cipher_suite][1]
        extensions.append(
            PreSharedKeyExtension(
                ticket.ticket, ticket.obfuscated_age(), hash_algo().digest_size
            )
        )
        self._tls13_psk = ticket

    def _bind_tls13_client_hello(self, transcript_prefix=b""):
        """Fill the resumption binder over the truncated ClientHello."""
        from ja3requests.protocol.tls.tls13 import (  # pylint: disable=import-outside-toplevel
            HKDF,
            TLS13_CIPHER_PARAMS,
        )

        ticket = self._tls13_psk
        extension = next(
            ext
            for ext in self.body._custom_extensions
            if getattr(ext, 'extension_type', None) == 0x0029
        )
        hash_algo = TLS13_CIPHER_PARAMS[ticket.cipher_suite][1]
        hash_length = hash_algo().digest_size
        extension.age = ticket.obfuscated_age()
        extension.binder = b"\x00" * hash_length
        self.body._build_extensions()
        truncated = self.body.handshake_message[: -(3 + hash_length)]
        early = HKDF.extract(None, ticket.psk, hash_algo)
        binder_key = HKDF.derive_secret(early, "res binder", b"", hash_algo)
        finished_key = HKDF.expand_label(
            binder_key, "finished", b"", hash_length, hash_algo
        )
        extension.binder = hmac.new(
            finished_key,
            hash_algo(transcript_prefix + truncated).digest(),
            hash_algo,
        ).digest()
        self.body._build_extensions()

    def _cache_tls13_ticket(self, ticket, psk, cipher_suite, lifetime, age_add):
        if (
            self._session_cache is None
            or self._server_host is None
            or getattr(self, '_client_cert_pem', None)
        ):
            return
        self._session_cache.put_tls13(
            self._server_host,
            self._server_port or 443,
            ticket,
            psk,
            cipher_suite,
            lifetime,
            age_add,
            self._server_name,
            verified=getattr(self, '_cert_verified', False),
            verified_hostname=getattr(self, '_verified_hostname', None),
            certificate_expires_at=getattr(self, '_server_cert_not_after', None),
        )

    def _save_session_to_cache(self):
        """Save the current session to the session cache for future resumption."""
        if (
            self._session_cache is not None
            and self._server_host
            and self._server_session_id
            and self._master_secret
            and not (
                getattr(self, '_client_cert_requested', False)
                and getattr(self, '_client_cert_pem', None)
            )
        ):
            cipher = getattr(self, '_selected_cipher_suite', 0)
            self._session_cache.put(
                self._server_host,
                self._server_port or 443,
                self._server_session_id,
                self._master_secret,
                cipher,
                tls_version=self._tls_version,
                extended_master_secret=self._extended_master_secret,
                verified=getattr(self, '_cert_verified', False),
                verified_hostname=getattr(self, '_verified_hostname', None),
                certificate_expires_at=getattr(self, '_server_cert_not_after', None),
                sni=self._server_name,
            )
            debug(f"Saved TLS session for {self._server_host}:{self._server_port}")

    def _parse_new_session_ticket(self, data):
        """Parse the TLS 1.2 ticket, leaving cache writes until Finished."""
        if len(data) < 6:
            raise TLSHandshakeError("Invalid NewSessionTicket length")
        lifetime = struct.unpack("!I", data[:4])[0]
        ticket_len = struct.unpack("!H", data[4:6])[0]
        if len(data) != 6 + ticket_len:
            raise TLSHandshakeError("Invalid NewSessionTicket length")
        return lifetime, data[6:]

    def _cache_new_tls12_ticket(self):
        """Keep an authenticated ticket and its original verification policy."""
        new_ticket = self._new_session_ticket
        if (
            new_ticket[0]
            and new_ticket[1]
            and self._session_cache is not None
            and self._server_host
            and self._master_secret
            and not (
                getattr(self, '_client_cert_requested', False)
                and getattr(self, '_client_cert_pem', None)
            )
        ):
            lifetime, ticket = new_ticket
            self._session_cache.put_tls12_ticket(
                self._server_host,
                self._server_port or 443,
                ticket,
                self._master_secret,
                self._selected_cipher_suite,
                lifetime,
                tls_version=self._tls_version,
                extended_master_secret=self._extended_master_secret,
                verified=getattr(self, '_cert_verified', False),
                verified_hostname=getattr(self, '_verified_hostname', None),
                certificate_expires_at=getattr(self, '_server_cert_not_after', None),
                sni=self._server_name,
            )
            debug(f"Cached TLS 1.2 session ticket for {self._server_host}")

    def _parse_server_handshake_messages(
        self,
        initial_data=b"",
    ):  # pylint: disable=too-many-branches,too-many-statements,too-many-nested-blocks
        """
        Parse incoming server handshake messages with improved error handling
        """
        buffer = initial_data
        initial_pending = bool(initial_data)
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
                if initial_pending:
                    initial_pending = False
                else:
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
                        if self._resumed_session is not None:
                            trailing = self._pending_server_handshake
                            self._tls12_pending_record_data = (
                                b'\x16\x03\x03'
                                + len(trailing).to_bytes(2, 'big')
                                + trailing
                                if trailing
                                else b''
                            ) + buffer
                            self.conn.settimeout(None)
                            return
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
                    else:
                        raise TLSHandshakeError(
                            "Unexpected record before TLS 1.2 ServerHelloDone"
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
        raise TLSHandshakeError("Server handshake did not complete")

    def _process_handshake_record(self, record_data):
        """
        Process complete handshake messages across TLS record boundaries.
        """
        pending = getattr(self, '_pending_server_handshake', b'') + record_data
        offset = 0
        while offset + 4 <= len(pending):
            msg_type = pending[offset]
            msg_length = struct.unpack(
                "!I", b'\x00' + pending[offset + 1 : offset + 4]
            )[0]
            if offset + 4 + msg_length > len(pending):
                break

            msg_data = pending[offset + 4 : offset + 4 + msg_length]

            # Add handshake message to running hash (excluding record header)
            handshake_msg = pending[offset : offset + 4 + msg_length]
            if hasattr(self, '_handshake_messages'):
                self._handshake_messages += handshake_msg

            if msg_type == 2:  # ServerHello
                self._parse_server_hello(msg_data)
                self._check_resumed_server_hello()
                if self._resumed_session is not None:
                    self._pending_server_handshake = pending[offset + 4 + msg_length :]
                    return
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
                self._pending_server_handshake = pending[offset + 4 + msg_length :]
                return

            offset += 4 + msg_length
        self._pending_server_handshake = pending[offset:]

    def _check_resumed_server_hello(self):
        """Accept an echoed Session ID only with its original session policy."""
        entry = self._offered_session
        if entry is None or self._server_session_id != self.body.session_id:
            return
        if (
            self._server_legacy_version != b'\x03\x03'
            or self._selected_cipher_suite != entry.cipher_suite
            or self._extended_master_secret != entry.extended_master_secret
            or getattr(self, '_selected_compression_method', None) != 0
        ):
            raise TLSHandshakeError("Invalid resumed TLS 1.2 ServerHello")
        self._master_secret = entry.master_secret
        self._generate_session_keys()
        self._cert_verified = entry.verified
        self._verified_hostname = entry.verified_hostname
        self._server_cert_not_after = entry.certificate_expires_at
        self._resumed_session = entry

    def _parse_server_hello(self, data):
        """Parse ServerHello message"""
        if len(data) < 38:  # Minimum size for ServerHello
            debug(f"ServerHello data too short: {len(data)} bytes")
            return

        offset = 0
        # TLS version (2 bytes)
        if offset + 2 > len(data):
            return
        self._server_legacy_version = data[offset : offset + 2]
        self._server_supported_version = None
        self._extended_master_secret = False
        self._server_offered_session_ticket = False
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
        self._server_session_id = None
        if session_id_length > 32:
            raise TLSHandshakeError("Invalid ServerHello session ID length")
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
            if self._cipher_suites is not None:
                offered = {
                    suite.value if hasattr(suite, 'value') else suite
                    for suite in self._cipher_suites
                }
                if self._selected_cipher_suite not in offered:
                    raise TLSHandshakeError("Server selected an unoffered cipher suite")
        offset += 2

        # Compression method (1 byte)
        if offset < len(data):
            self._selected_compression_method = data[offset]
            offset += 1

        # Parse extensions (if present)
        if offset + 2 <= len(data):
            extensions_length = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2
            ext_end = offset + extensions_length
            if ext_end != len(data):
                raise TLSHandshakeError("Invalid ServerHello extension length")
            while offset + 4 <= ext_end:
                ext_type = struct.unpack("!H", data[offset : offset + 2])[0]
                ext_len = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
                offset += 4
                if offset + ext_len > ext_end:
                    raise TLSHandshakeError("Truncated ServerHello extension")
                ext_data = data[offset : offset + ext_len]
                offset += ext_len

                if ext_type == 0x002B:
                    self._server_supported_version = ext_data
                elif ext_type == 0x0017:
                    if ext_data or not self._offered_extended_master_secret:
                        raise TLSHandshakeError(
                            "Invalid extended master secret extension"
                        )
                    self._extended_master_secret = True
                elif ext_type == 0x0023:
                    if ext_data or not any(
                        getattr(ext, 'extension_type', None) == 0x0023
                        for ext in self.body._custom_extensions
                    ):
                        raise TLSHandshakeError("Invalid SessionTicket extension")
                    self._server_offered_session_ticket = True

                # ALPN (0x0010): extract negotiated protocol
                if ext_type == 0x0010 and len(ext_data) >= 4:
                    proto_list_len = struct.unpack("!H", ext_data[:2])[0]
                    if proto_list_len > 0:
                        proto_len = ext_data[2]
                        self._negotiated_protocol = ext_data[3 : 3 + proto_len].decode(
                            "ascii"
                        )
                        debug(f"ALPN negotiated: {self._negotiated_protocol}")
            if offset != ext_end:
                raise TLSHandshakeError("Truncated ServerHello extension")
        elif offset != len(data):
            raise TLSHandshakeError("Truncated ServerHello extension length")

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
                if not getattr(self, '_client_key_pem', None):
                    raise TLSHandshakeError("Client certificate requires a private key")
                certificate_record = self._build_client_certificate(client_cert_pem)
                debug("Sent client Certificate")
            else:
                certificate_record = self._build_empty_certificate()
                debug("Sent empty Certificate (no client cert configured)")
            self.conn.sendall(certificate_record)
            self._handshake_messages += certificate_record[5:]

        # Send ClientKeyExchange
        client_key_exchange = self._build_client_key_exchange()
        self.conn.sendall(client_key_exchange)
        debug("Sent Client Key Exchange")

        if getattr(self, '_client_cert_requested', False) and getattr(
            self, '_client_cert_pem', None
        ):
            self.conn.sendall(self._build_client_certificate_verify())

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

    def _build_client_certificate_verify(self):
        """Sign the TLS 1.2 transcript through ClientKeyExchange."""
        try:
            key = serialization.load_pem_private_key(
                self._client_key_pem, password=None
            )
        except (TypeError, ValueError) as error:
            raise TLSHandshakeError("Invalid client private key") from error

        for scheme in getattr(self, '_cert_sig_algs', []):
            hash_id = scheme & 0xFF if 0x0804 <= scheme <= 0x0806 else scheme >> 8
            digest_type = {4: hashes.SHA256, 5: hashes.SHA384, 6: hashes.SHA512}.get(
                hash_id
            )
            if digest_type is None:
                continue
            digest = digest_type()
            if isinstance(key, rsa.RSAPrivateKey) and scheme in (
                0x0401,
                0x0501,
                0x0601,
            ):
                signature = key.sign(
                    self._handshake_messages, padding.PKCS1v15(), digest
                )
            elif isinstance(key, rsa.RSAPrivateKey) and scheme in (
                0x0804,
                0x0805,
                0x0806,
            ):
                signature = key.sign(
                    self._handshake_messages,
                    padding.PSS(
                        mgf=padding.MGF1(digest), salt_length=digest.digest_size
                    ),
                    digest,
                )
            elif isinstance(key, ec.EllipticCurvePrivateKey) and scheme in (
                0x0403,
                0x0503,
                0x0603,
            ):
                signature = key.sign(self._handshake_messages, ec.ECDSA(digest))
            else:
                continue

            body = struct.pack('!HH', scheme, len(signature)) + signature
            message = b'\x0f' + len(body).to_bytes(3, 'big') + body
            self._handshake_messages += message
            return b'\x16\x03\x03' + len(message).to_bytes(2, 'big') + message

        raise TLSHandshakeError("No supported client certificate signature algorithm")

    def _read_server_handshake_record(self):
        """Read exactly one record without consuming later application data."""

        def read_exact(size):
            data = b''
            pending = self._tls12_pending_record_data
            if pending:
                data = pending[:size]
                self._tls12_pending_record_data = pending[size:]
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
            ticket = None
            while True:
                header, payload = self._read_server_handshake_record()
                if header[0] == 20:
                    if received_ccs or payload != b'\x01' or pending:
                        raise TLSHandshakeError("Unexpected ChangeCipherSpec")
                    if self._server_offered_session_ticket != (ticket is not None):
                        raise TLSHandshakeError(
                            "Missing or unsolicited NewSessionTicket"
                        )
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
                        self._new_session_ticket = ticket or (0, b'')
                        return True
                    if ticket is not None or not self._server_offered_session_ticket:
                        raise TLSHandshakeError("Unexpected NewSessionTicket")
                    ticket = self._parse_new_session_ticket(message[4:])
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

    def _derive_master_secret(self):
        if not self._server_random:
            raise TLSHandshakeError("No server random available for master secret")
        if self._extended_master_secret:
            hash_algo = TLSCrypto.prf_hash_for_cipher_suite(self._selected_cipher_suite)
            session_hash = hash_algo(self._handshake_messages).digest()
            self._master_secret = TLSCrypto.prf(
                self._premaster_secret,
                b"extended master secret",
                session_hash,
                48,
                hash_algo=hash_algo,
            )
        else:
            self._master_secret = TLSCrypto.generate_master_secret(
                self._premaster_secret,
                self._client_random,
                self._server_random,
                _cipher_suite=self._selected_cipher_suite,
            )
        self._generate_session_keys()

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
            self._derive_master_secret()
            debug(f"Generated master secret: {len(self._master_secret)} bytes")

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
        self._derive_master_secret()
        debug(
            f"Generated master secret from premaster: {len(self._master_secret)} bytes"
        )

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
            _cipher_suite=cipher_suite,
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
        leaf_size = int.from_bytes(certificate_data[3:6], 'big')
        leaf = x509.load_der_x509_certificate(certificate_data[6 : 6 + leaf_size])
        self._server_cert_not_after = leaf.not_valid_after_utc.timestamp()
