"""
Ja3Requests.sockets.https
~~~~~~~~~~~~~~~~~~~~~~~~~

This module of HTTPS Socket.
"""

import hashlib
import hmac
import os
import socket
import struct
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ja3requests.base import BaseSocket
from ja3requests.exceptions import (
    TLSDecryptionError,
    TLSKeyError,
    TLSMACVerificationError,
)
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.crypto import AESCipher
from ja3requests.protocol.tls.debug import debug


class HttpsSocket(BaseSocket):
    """
    HTTPS Socket with connection pooling support
    """

    def __init__(self, context, pool=None):
        super().__init__(context)
        self._pool = pool
        self._pooled_conn = None  # Reference to pooled connection wrapper
        self._reused = False  # Whether connection was reused from pool

    def new_conn(self):
        host = self.context.destination_address
        port = self.context.port

        # Try to get connection from pool
        if self._pool:
            pooled_conn = self._pool.get_connection(host, port, "https")
            if pooled_conn and pooled_conn.conn and pooled_conn.tls:
                debug(f"Reusing pooled connection to {host}:{port}")
                self.conn = pooled_conn.conn
                self.tls = pooled_conn.tls
                self._pooled_conn = pooled_conn
                self._reused = True
                return self

        # Create new connection
        debug(f"Connecting to {host}:{port}")
        self.conn = self._new_conn(host, port)

        # Get TLS config and set default server_name
        tls_config = getattr(self.context, 'tls_config', None)
        if tls_config and not getattr(tls_config, 'server_name', None):
            tls_config.server_name = host

        # TLS handshake
        handshake_timeout = getattr(self.context, 'connect_timeout', None)
        session_cache = getattr(tls_config, 'session_cache', None) if tls_config else None
        tls = TLS(
            self.conn,
            handshake_timeout=handshake_timeout,
            session_cache=session_cache,
            server_host=host,
            server_port=port,
        )

        # Set JA3 parameters
        tls.set_payload(tls_config=tls_config)
        handshake_success = tls.handshake()

        if not handshake_success:
            self.conn.close()
            raise ConnectionError(
                "TLS handshake failed - server rejected the connection"
            )

        self.tls = tls
        self._reused = False
        debug("TLS handshake completed, ready for encrypted HTTP communication")
        return self

    def return_to_pool(self):
        """Return connection to pool for reuse"""
        if self._pool and self.conn and self.tls:
            host = self.context.destination_address
            port = self.context.port

            # If this was a reused connection, return the original wrapper
            if self._reused and self._pooled_conn:
                success = self._pool.put_connection(
                    host,
                    port,
                    "https",
                    self.conn,
                    tls=self.tls,
                    pooled_conn=self._pooled_conn,
                )
            else:
                success = self._pool.put_connection(
                    host, port, "https", self.conn, tls=self.tls
                )

            if success:
                debug(f"Returned connection to pool: {host}:{port}")
                self.conn = None
                self.tls = None
                self._pooled_conn = None
            else:
                debug(f"Pool full, closing connection: {host}:{port}")
                self.close()

    def close(self):
        """Close the connection"""
        try:
            if self.conn:
                self.conn.close()
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        self.conn = None
        self.tls = None

    def send(self):
        """
        Send HTTP message over TLS connection.
        Routes to HTTP/2 if ALPN negotiated 'h2', otherwise HTTP/1.1.
        :return:
        """
        if not (hasattr(self, 'tls') and self.tls):
            debug("No TLS context available")
            self.conn.sendall(self.context.message)
            return self.conn

        # Check if ALPN negotiated HTTP/2
        negotiated = getattr(self.tls, '_negotiated_protocol', None)
        if negotiated == 'h2':
            return self._send_h2()

        return self._send_h1()

    def _send_h1(self):
        """Send HTTP/1.1 request over TLS."""
        try:
            # Brief delay for server to process our Finished message
            time.sleep(0.3)
            read_timeout = getattr(self.context, 'read_timeout', None)
            self.conn.settimeout(read_timeout if read_timeout is not None else 15.0)

            # Encrypt and send HTTP request
            encrypted_data = self._encrypt_application_data(self.context.message)
            debug(f"Sending encrypted HTTP request: {len(encrypted_data)} bytes")
            self.conn.sendall(encrypted_data)
            debug("HTTP request sent successfully")

            # Read and decrypt TLS response records using proper record-level reading
            result = self._handle_encrypted_response()
            if result:
                return result

            raise ConnectionError("No valid HTTP response received from server")

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"Encrypted communication failed: {e}")
            raise ConnectionError(f"TLS communication failed: {e}") from e
        finally:
            self.conn.settimeout(None)

    def _send_h2(self):
        """Send HTTP/2 request over TLS using H2Connection."""
        from ja3requests.protocol.h2.connection import H2Connection  # pylint: disable=import-outside-toplevel

        try:
            read_timeout = getattr(self.context, 'read_timeout', None)
            self.conn.settimeout(read_timeout if read_timeout is not None else 15.0)

            tls = self.tls

            def h2_send(data):
                encrypted = self._encrypt_application_data(data)
                self.conn.sendall(encrypted)

            def h2_recv(n):
                return self._decrypt_single_record() or b""

            # Get H2 fingerprint settings from session
            h2_settings = getattr(self.context, '_h2_settings', None)
            h2_window = getattr(self.context, '_h2_window_update', None)

            h2 = H2Connection(h2_send, h2_recv, settings=h2_settings)
            h2.initiate(
                window_update_increment=int(h2_window) if h2_window else None
            )

            # Parse HTTP request to extract method, path, headers
            method = getattr(self.context, 'method', 'GET')
            host = getattr(self.context, 'destination_address', '')
            path = getattr(self.context, 'path', '/')

            # Build headers from context
            req_headers = []
            ctx_headers = getattr(self.context, 'headers', None) or {}
            if isinstance(ctx_headers, dict):
                for k, v in ctx_headers.items():
                    req_headers.append((k, v))

            # Extract body
            body = getattr(self.context, '_data', None)
            if isinstance(body, str):
                body = body.encode('utf-8')

            stream_id = h2.send_request(method, host, path, headers=req_headers, body=body)
            resp_headers, resp_body = h2.receive_response(stream_id)

            # Convert H2 response to HTTP/1.1-like format for Response class compatibility
            status = "200"
            for name, value in resp_headers:
                if name == ":status":
                    status = value
                    break

            http_response = f"HTTP/1.1 {status} OK\r\n"
            for name, value in resp_headers:
                if not name.startswith(":"):
                    http_response += f"{name}: {value}\r\n"
            http_response += f"Content-Length: {len(resp_body)}\r\n"
            http_response += "\r\n"

            # Build a mock socket connection for HTTPSResponse
            response_data = http_response.encode() + resp_body
            return self._create_mock_connection(response_data)

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"H2 communication failed: {e}")
            raise ConnectionError(f"HTTP/2 communication failed: {e}") from e
        finally:
            self.conn.settimeout(None)

    def _decrypt_single_record(self):
        """Read and decrypt a single TLS record, return plaintext."""
        header = self._recv_exact(5)
        if not header or len(header) < 5:
            return None
        record_type = header[0]
        length = struct.unpack("!H", header[3:5])[0]
        payload = self._recv_exact(length)
        if not payload:
            return None
        try:
            plaintext = self._decrypt_record(payload, record_type)
            return plaintext
        except Exception:  # pylint: disable=broad-exception-caught
            return None

    def _handle_encrypted_response(
        self,
    ):  # pylint: disable=too-many-branches,too-many-nested-blocks
        """
        Handle encrypted TLS response from server.
        Reads complete TLS records using _recv_exact and decrypts them.
        """
        http_response_data = b""

        while True:
            # Read TLS record header (5 bytes: type + version + length)
            header = self._recv_exact(5)
            if not header:
                break

            record_type = header[0]
            record_length = int.from_bytes(header[3:5], byteorder='big')

            debug(f"TLS record: type=0x{record_type:02X}, length={record_length}")

            # Read the complete record payload
            record_data = self._recv_exact(record_length)
            if not record_data:
                debug("Failed to read complete TLS record payload")
                break

            if record_type == 0x17:  # Application data
                decrypted_data = self._decrypt_application_data(record_data)
                if decrypted_data:
                    http_response_data += decrypted_data
                    debug(f"Decrypted {len(decrypted_data)} bytes of HTTP data")

                    # Check if we have a complete HTTP response
                    if b'\r\n\r\n' in http_response_data:
                        header_end = http_response_data.find(b'\r\n\r\n') + 4
                        headers_part = http_response_data[:header_end]
                        body_part = http_response_data[header_end:]

                        # Check for chunked transfer encoding
                        headers_lower = headers_part.lower()
                        if b'transfer-encoding: chunked' in headers_lower:
                            # For chunked, check if we have the terminator
                            if body_part.endswith(b'0\r\n\r\n'):
                                break
                            # Keep reading more records
                            continue

                        # Check Content-Length
                        content_length = self._parse_content_length(headers_part)
                        if content_length is not None:
                            if len(body_part) >= content_length:
                                break
                            # Keep reading more records
                            continue

                        # No Content-Length and not chunked: connection-close semantics
                        # Keep reading until server closes

            elif record_type == 0x15:  # Alert
                if len(record_data) >= 2:
                    alert_level = record_data[0]
                    alert_desc = record_data[1]
                    debug(f"TLS alert: level={alert_level}, desc={alert_desc}")
                    if alert_level == 2:  # Fatal
                        break
                # Close notify (level=1, desc=0) means server is done
                if len(record_data) >= 2 and record_data[1] == 0:
                    break

            elif record_type == 0x16:  # Handshake (e.g. NewSessionTicket)
                debug("Received post-handshake message, skipping")
                continue
            else:
                debug(f"Unexpected TLS record type: 0x{record_type:02X}")

        if http_response_data:
            debug(f"Total decrypted HTTP response: {len(http_response_data)} bytes")
            return self._create_response_connection(http_response_data)

        return None

    def _recv_exact(self, length):
        """Receive exactly 'length' bytes from the connection"""
        data = b""
        while len(data) < length:
            try:
                chunk = self.conn.recv(length - len(data))
            except socket.timeout:
                debug(f"Socket timeout reading {length} bytes (got {len(data)})")
                return data if data else None
            if not chunk:
                return data if data else None
            data += chunk
        return data

    def _decrypt_application_data(self, encrypted_data):
        """Decrypt TLS application data record (supports both CBC and GCM)"""
        # Check if using GCM cipher suite
        if getattr(self.tls, '_is_gcm', False):
            return self._decrypt_application_data_gcm(encrypted_data)
        return self._decrypt_application_data_cbc(encrypted_data)

    def _decrypt_application_data_gcm(
        self, encrypted_data
    ):  # pylint: disable=too-many-locals
        """Decrypt TLS application data using AES-GCM"""
        try:
            # GCM record format: explicit_nonce (8) + ciphertext + auth_tag (16)
            if len(encrypted_data) < 24:  # 8 + 16 minimum
                raise TLSDecryptionError("Encrypted data too short for GCM")

            # Extract components
            explicit_nonce = encrypted_data[:8]
            ciphertext = encrypted_data[8:-16]
            auth_tag = encrypted_data[-16:]

            # Build full nonce: implicit_iv (4) + explicit_nonce (8) = 12 bytes
            server_write_iv = getattr(self.tls, '_server_write_iv', None)
            server_write_key = getattr(self.tls, '_server_write_key', None)

            if not server_write_key or not server_write_iv:
                raise TLSKeyError("Server GCM keys not available")

            nonce = server_write_iv + explicit_nonce

            # Build AAD
            content_type = 0x17  # Application data
            version = b'\x03\x03'  # TLS 1.2
            server_seq_num = getattr(self.tls, '_server_seq_num', 0)

            aad = (
                server_seq_num.to_bytes(8, byteorder='big')
                + bytes([content_type])
                + version
                + len(ciphertext).to_bytes(2, byteorder='big')
            )

            # Decrypt with AES-GCM
            plaintext = AESCipher.decrypt_gcm(
                ciphertext, server_write_key, nonce, auth_tag, aad
            )

            self.tls._server_seq_num += 1  # pylint: disable=protected-access
            debug(f"GCM decrypted {len(plaintext)} bytes")
            return plaintext

        except (TLSDecryptionError, TLSKeyError):
            raise
        except Exception as e:
            raise TLSDecryptionError(f"GCM decryption failed: {e}") from e

    def _decrypt_application_data_cbc(
        self, encrypted_data
    ):  # pylint: disable=too-many-locals
        """Decrypt TLS application data using AES-CBC with HMAC"""
        try:
            # Extract explicit IV (first 16 bytes) and ciphertext
            if len(encrypted_data) < 16:
                raise TLSDecryptionError("Encrypted data too short for CBC IV")

            explicit_iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            # Decrypt using server's keys
            server_write_key = getattr(self.tls, '_server_write_key', None)
            server_write_mac_key = getattr(self.tls, '_server_write_mac_key', None)

            if not server_write_key or not server_write_mac_key:
                raise TLSKeyError("Server encryption keys not available")

            # Decrypt the ciphertext without removing PKCS7 padding
            # (TLS uses its own padding scheme)
            plaintext_with_mac_and_padding = AESCipher.decrypt_cbc(
                ciphertext, server_write_key, explicit_iv, remove_padding=False
            )

            # Handle TLS padding removal
            if not plaintext_with_mac_and_padding:
                raise TLSDecryptionError("AES-CBC decryption returned empty result")

            # TLS padding: last byte indicates padding length - 1
            # So padding_length = last_byte + 1
            padding_length = plaintext_with_mac_and_padding[-1] + 1
            if padding_length > len(plaintext_with_mac_and_padding):
                raise TLSDecryptionError(
                    f"Invalid TLS padding length: {padding_length}"
                )

            plaintext_with_mac = plaintext_with_mac_and_padding[:-padding_length]

            # Separate MAC (last 20 bytes for SHA1) from plaintext
            mac_length = 20  # SHA1 MAC
            if len(plaintext_with_mac) < mac_length:
                raise TLSDecryptionError(
                    f"Data too short for MAC: {len(plaintext_with_mac)}"
                )

            plaintext = plaintext_with_mac[:-mac_length]
            received_mac = plaintext_with_mac[-mac_length:]

            # Verify MAC
            content_type = 0x17  # Application data
            version = b'\x03\x03'  # TLS 1.2
            server_seq_num = getattr(self.tls, '_server_seq_num', 0)

            mac_input = (
                server_seq_num.to_bytes(8, byteorder='big')
                + bytes([content_type])
                + version
                + len(plaintext).to_bytes(2, byteorder='big')
                + plaintext
            )

            expected_mac = hmac.new(
                server_write_mac_key, mac_input, hashlib.sha1
            ).digest()

            if received_mac != expected_mac:
                raise TLSMACVerificationError("CBC MAC verification failed")

            debug("MAC verification successful")

            # Increment server sequence number
            self.tls._server_seq_num += 1  # pylint: disable=protected-access

            debug(f"Successfully decrypted {len(plaintext)} bytes")
            return plaintext

        except (TLSDecryptionError, TLSKeyError, TLSMACVerificationError):
            raise
        except Exception as e:
            raise TLSDecryptionError(f"CBC decryption failed: {e}") from e

    def _parse_content_length(self, headers):
        """Parse Content-Length header from HTTP headers"""
        try:
            headers_str = headers.decode('utf-8', errors='ignore')
            for line in headers_str.split('\r\n'):
                if line.lower().startswith('content-length:'):
                    return int(line.split(':', 1)[1].strip())
        except (ValueError, UnicodeDecodeError):
            pass
        return None

    def _create_response_connection(self, http_data):
        """Create a mock connection with real HTTP response data"""

        class RealResponseConnection:
            """Mock connection wrapping real HTTP response data."""

            def __init__(self, data):
                self.response_data = data
                self.position = 0
                self.closed = False

            def recv(self, size):
                """Receive data from response buffer."""
                if self.closed or self.position >= len(self.response_data):
                    return b""
                end_pos = min(self.position + size, len(self.response_data))
                chunk = self.response_data[self.position : end_pos]
                self.position = end_pos
                return chunk

            def readline(self, max_size=None):
                """Read a line from the response data."""
                if self.closed or self.position >= len(self.response_data):
                    return b""
                start = self.position
                line_end = self.response_data.find(b'\r\n', start)
                if line_end == -1:
                    line_end = self.response_data.find(b'\n', start)
                    if line_end == -1:
                        line_end = len(self.response_data)
                        line = self.response_data[start:line_end]
                        self.position = line_end
                        return line
                    line = self.response_data[start : line_end + 1]
                    self.position = line_end + 1
                else:
                    line = self.response_data[start : line_end + 2]
                    self.position = line_end + 2
                if max_size and len(line) > max_size:
                    line = line[:max_size]
                    self.position = start + max_size
                return line

            def read(self, size=-1):
                """Read data from the response."""
                if self.closed or self.position >= len(self.response_data):
                    return b""
                if size == -1:
                    data = self.response_data[self.position :]
                    self.position = len(self.response_data)
                else:
                    end_pos = min(self.position + size, len(self.response_data))
                    data = self.response_data[self.position : end_pos]
                    self.position = end_pos
                return data

            def makefile(self, _mode="rb"):
                """Create a file-like object for the response data."""
                return self

            def close(self):
                """Close the connection."""
                self.closed = True

        debug(
            f"Created response connection with {len(http_data)} bytes of real HTTP data"
        )
        return RealResponseConnection(http_data)

    def _encrypt_application_data(self, data: bytes) -> bytes:
        """
        Encrypt HTTP data as TLS application data record (supports CBC and GCM)
        """
        if getattr(self.tls, '_is_gcm', False):
            return self._encrypt_application_data_gcm(data)
        return self._encrypt_application_data_cbc(data)

    def _encrypt_application_data_gcm(self, data: bytes) -> bytes:
        """Encrypt application data using AES-GCM"""
        # pylint: disable=protected-access
        content_type = 0x17  # Application data
        version = b'\x03\x03'  # TLS 1.2

        current_seq_num = getattr(self.tls, '_client_seq_num', 1)

        # Generate explicit nonce (8 bytes)
        explicit_nonce = current_seq_num.to_bytes(8, byteorder='big')

        # Full nonce = implicit_iv (4) + explicit_nonce (8)
        nonce = (
            self.tls._client_write_iv  # pylint: disable=protected-access
            + explicit_nonce
        )

        # Build AAD
        aad = (
            current_seq_num.to_bytes(8, byteorder='big')
            + bytes([content_type])
            + version
            + len(data).to_bytes(2, byteorder='big')
        )

        # Encrypt with AES-GCM
        client_write_key = (
            self.tls._client_write_key
        )  # pylint: disable=protected-access
        ciphertext, auth_tag = AESCipher.encrypt_gcm(data, client_write_key, nonce, aad)

        # Record data = explicit_nonce + ciphertext + auth_tag
        encrypted_data = explicit_nonce + ciphertext + auth_tag

        record = (
            bytes([content_type])
            + version
            + len(encrypted_data).to_bytes(2, byteorder='big')
            + encrypted_data
        )

        self.tls._client_seq_num += 1  # pylint: disable=protected-access
        return record

    def _encrypt_application_data_cbc(self, data: bytes) -> bytes:
        """Encrypt application data using AES-CBC with HMAC"""
        # pylint: disable=too-many-locals,protected-access
        content_type = 0x17  # Application data
        version = b'\x03\x03'  # TLS 1.2

        current_seq_num = getattr(self.tls, '_client_seq_num', 1)

        # Create MAC input for application data
        mac_input = (
            current_seq_num.to_bytes(8, byteorder='big')
            + bytes([content_type])
            + version
            + len(data).to_bytes(2, byteorder='big')
            + data
        )

        # Calculate HMAC
        client_mac_key = (
            self.tls._client_write_mac_key
        )  # pylint: disable=protected-access
        mac = hmac.new(client_mac_key, mac_input, hashlib.sha1).digest()

        # Combine data and MAC
        plaintext = data + mac

        # Add PKCS#7 padding
        block_size = 16
        padding_length = block_size - (len(plaintext) % block_size)
        padding = bytes([padding_length - 1] * padding_length)
        padded_plaintext = plaintext + padding

        # Generate explicit IV
        explicit_iv = os.urandom(16)

        # Encrypt
        cbc_write_key = self.tls._client_write_key  # pylint: disable=protected-access
        cipher = Cipher(
            algorithms.AES(cbc_write_key),
            modes.CBC(explicit_iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Construct TLS record
        encrypted_data = explicit_iv + ciphertext
        record = (
            bytes([content_type])
            + version
            + len(encrypted_data).to_bytes(2, byteorder='big')
            + encrypted_data
        )

        self.tls._client_seq_num += 1  # pylint: disable=protected-access
        return record
