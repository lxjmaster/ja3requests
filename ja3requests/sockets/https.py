"""
Ja3Requests.sockets.https
~~~~~~~~~~~~~~~~~~~~~~~~~

This module of HTTPS Socket.
"""

import hashlib
import hmac
import io
import os
import socket
import threading
import time
from ja3requests._upload import UploadSource
from ja3requests.exceptions import InvalidData, StreamConsumedError
from ja3requests.sockets._upload import UploadExchange, _H2WriteGuard, upload_headers

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ja3requests.base import BaseSocket
from ja3requests.exceptions import (
    TLSError,
    TLSDecryptionError,
    TLSKeyError,
)
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.crypto import AESCipher, _decrypt_tls12_cbc_record
from ja3requests.protocol.tls.debug import debug
from ja3requests.protocol.tls.extensions import Extension


class _TLSRecordReader(io.RawIOBase):
    """Expose the project's authenticated TLS records as incremental plaintext."""

    def __init__(self, transport, recv=None):
        super().__init__()
        self.transport = transport
        self.recv = recv
        self.pending = b""

    def readable(self):
        return True

    def readinto(self, buffer):
        if not buffer:
            return 0
        if not self.pending:
            try:
                self.pending = (
                    self.transport._decrypt_single_record()
                    if self.recv is None
                    else self.transport._decrypt_single_record(recv=self.recv)
                ) or b""
            except TLSError as error:
                raise ConnectionError(f"TLS response failed: {error}") from error
        size = min(len(buffer), len(self.pending))
        buffer[:size] = self.pending[:size]
        self.pending = self.pending[size:]
        return size


class _H2StreamReader(io.RawIOBase):
    """Adapt response headers while reading DATA directly from one H2 stream."""

    def __init__(self, h2, stream_id, headers, timeout):
        super().__init__()
        self.h2 = h2
        self.stream_id = stream_id
        self.timeout = timeout
        self.eof = False
        status = next(value for name, value in headers if name == ':status')
        lines = [f"HTTP/1.1 {status} OK\r\n"]
        lines.extend(
            f"{name}: {value}\r\n"
            for name, value in headers
            if not name.startswith(':')
        )
        self.pending = (''.join(lines) + '\r\n').encode()

    def readable(self):
        return True

    def readinto(self, buffer):
        if not buffer or self.eof:
            return 0
        if self.pending:
            data = self.pending[: len(buffer)]
            self.pending = self.pending[len(data) :]
        else:
            data = self.h2.read_stream(
                self.stream_id, len(buffer), timeout=self.timeout
            )
            if not data:
                self.eof = True
        buffer[: len(data)] = data
        return len(data)


class _ResponseConnection:
    """A file adapter whose response owns transport release, not an eager body."""

    def __init__(self, reader, release, body_framed=False, upload_owner=None):
        self.reader = reader
        self.release_response = release
        self.body_framed = body_framed
        self.upload_owner = upload_owner

    def makefile(self, mode='rb'):
        return io.BufferedReader(self.reader)


def _post_handshake_records(tls, plaintext):
    """Advance post-handshake state; the caller owns outbound serialization."""
    handshake = getattr(tls, '_tls13_handshake', None)
    if handshake is None:
        raise TLSDecryptionError("TLS 1.3 post-handshake state is unavailable")
    try:
        return handshake.process_post_handshake(plaintext)
    except ValueError as error:
        raise TLSDecryptionError("Invalid TLS 1.3 post-handshake message") from error


class HttpsSocket(BaseSocket):
    """
    HTTPS Socket with connection pooling support
    """

    def __init__(self, context, pool=None):
        super().__init__(context)
        self.tls = None
        self._pool = pool
        self._pooled_conn = None  # Reference to pooled connection wrapper
        self._reused = False  # Whether connection was reused from pool
        self._h2_pooled_conn = None
        self._h2_reservation = None
        self._h2_io_lock = threading.RLock()
        self._h2_write_guard = None

    @staticmethod
    def _tls_policy_key(config, host):
        if config is None:
            return None
        return (
            config.tls_version,
            tuple(
                suite.value if hasattr(suite, 'value') else suite
                for suite in config.cipher_suites
            ),
            tuple(config.supported_groups or ()),
            (
                tuple(config.key_share_groups)
                if getattr(config, 'key_share_groups', None) is not None
                else None
            ),
            tuple(config.signature_algorithms or ()),
            tuple(config.alpn_protocols or ()),
            tuple(
                ext.to_bytes()
                for ext in config.extensions
                if isinstance(ext, Extension)
            ),
            tuple(config.compression_methods or ()),
            config.session_id,
            config._session_id_configured,
            (
                tuple(config.extension_order)
                if config.extension_order is not None
                else None
            ),
            config.client_hello_record_version,
            config.client_random,
            config.server_random,
            config.server_name or host,
            config.use_grease,
            config.max_fragment_length,
            config.verify_cert,
            config.client_cert,
            config.client_key,
            tuple((config.h2_settings or {}).items()),
            config.h2_window_update,
        )

    def new_conn(self):
        host = self.context.destination_address
        port = self.context.port
        tls_config = getattr(self.context, 'tls_config', None)
        policy_key = self._tls_policy_key(tls_config, host)

        # Try to get connection from pool
        if self._pool:
            pooled_conn = self._pool.get_connection(host, port, "https")
            if (
                pooled_conn
                and getattr(pooled_conn.tls, '_pool_policy_key', None) != policy_key
            ):
                self._pool.discard_connection(pooled_conn)
                pooled_conn = None
            if pooled_conn and getattr(tls_config, 'verify_cert', False):
                tls = pooled_conn.tls
                if (
                    getattr(tls, '_cert_verified', False) is not True
                    or getattr(tls, '_verified_hostname', None) != host
                ):
                    # A connection created without authentication cannot satisfy
                    # a later verified request, even for the same pool key.
                    self._pool.discard_connection(pooled_conn)
                    pooled_conn = None
            if pooled_conn and pooled_conn.conn and pooled_conn.tls:
                debug(f"Reusing pooled connection to {host}:{port}")
                self.conn = pooled_conn.conn
                self.tls = pooled_conn.tls
                self._pooled_conn = pooled_conn
                self._reused = True
                return self

            if tls_config and 'h2' in (tls_config.alpn_protocols or ()):
                h2_pooled, reservation = self._pool.get_h2_or_reserve(
                    host,
                    port,
                    policy_key,
                    verified_host=host if tls_config.verify_cert else None,
                    timeout=getattr(self.context, 'connect_timeout', None),
                )
                if h2_pooled is not None:
                    self.conn = h2_pooled.conn
                    self.tls = h2_pooled.tls
                    self._h2_pooled_conn = h2_pooled
                    self._reused = True
                    return self
                self._h2_reservation = reservation

        # Create new connection
        debug(f"Connecting to {host}:{port}")
        try:
            self.conn = self._new_conn(host, port)
            handshake_timeout = getattr(self.context, 'connect_timeout', None)
            session_cache = (
                getattr(tls_config, 'session_cache', None) if tls_config else None
            )
            tls = TLS(
                self.conn,
                handshake_timeout=handshake_timeout,
                session_cache=session_cache,
                server_host=host,
                server_port=port,
            )
            tls._pool_policy_key = policy_key
            tls.set_payload(tls_config=tls_config)
            handshake_success = tls.handshake()
        except Exception:  # pylint: disable=broad-exception-caught
            self.close()
            raise

        if not handshake_success:
            self.close()
            raise ConnectionError(
                "TLS handshake failed - server rejected the connection"
            )

        self.tls = tls
        self._reused = False
        if getattr(tls, '_negotiated_protocol', None) != 'h2':
            self._release_h2_reservation()
        debug("TLS handshake completed, ready for encrypted HTTP communication")
        return self

    def _release_h2_reservation(self):
        if self._pool and self._h2_reservation is not None:
            self._pool.release_h2_reservation(self._h2_reservation)
            self._h2_reservation = None

    def return_to_pool(self):
        """Return connection to pool for reuse"""
        if self._h2_pooled_conn is not None:
            pooled = self._h2_pooled_conn
            self._pool.release_h2_stream(pooled)
            if pooled.transport_owner is not self:
                self.conn = None
                self.tls = None
                self._h2_pooled_conn = None
            return
        if self._pool and self.conn and self.tls:
            if getattr(self.tls, '_negotiated_protocol', None) == 'h2':
                h2 = getattr(self.tls, '_h2_connection', None)
                if h2 is None or h2._goaway_received:
                    self.close()
                    return
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
                h2 = getattr(self.tls, '_h2_connection', None)
                if h2 is not None:
                    h2.set_transport(None, None)
                self.conn = None
                self.tls = None
                self._pooled_conn = None
            else:
                debug(f"Pool full, closing connection: {host}:{port}")
                self.close()

    def release_response(self, reusable):
        """Release an HTTP/1 response only after framing completes."""
        if reusable and self._pool:
            self.return_to_pool()
        else:
            self.close()

    def close(self):
        """Close the connection"""
        try:
            if self._h2_write_guard is not None:
                self._h2_write_guard.close()
            if self._h2_pooled_conn is not None:
                self._pool.discard_h2_connection(self._h2_pooled_conn)
            elif self._pool and self._reused and self._pooled_conn:
                self._pool.discard_connection(self._pooled_conn)
            elif self.conn:
                if getattr(self.tls, '_negotiated_protocol', None) == 'h2':
                    try:
                        self.conn.shutdown(socket.SHUT_RDWR)
                    except (OSError, AttributeError):
                        pass
                self.conn.close()
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        self.conn = None
        self.tls = None
        self._pooled_conn = None
        self._h2_pooled_conn = None
        self._reused = False
        self._release_h2_reservation()

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
            read_timeout = getattr(self.context, 'read_timeout', None)
            self.conn.settimeout(read_timeout if read_timeout is not None else 15.0)

            if isinstance(self.context.data, UploadSource):

                def write(data):
                    with self._h2_io_lock:
                        for offset in range(0, len(data), 16384):
                            self.conn.sendall(
                                self._encrypt_application_data(
                                    data[offset : offset + 16384]
                                )
                            )

                headers = upload_headers(self.context)
                exchange = UploadExchange(
                    self.context,
                    self.conn,
                    None,
                    write,
                    self.release_response,
                )
                exchange.response = _ResponseConnection(
                    _TLSRecordReader(self, recv=exchange.recv), self.release_response
                )
                return exchange.start(headers)

            # Advance the record sequence once per bounded plaintext fragment.
            # Keep encryption and writes ordered with post-handshake replies.
            with self._h2_io_lock:
                message = self.context.message
                for offset in range(0, len(message), 16384):
                    encrypted_data = self._encrypt_application_data(
                        message[offset : offset + 16384]
                    )
                    self.conn.sendall(encrypted_data)
            debug("HTTP request sent successfully")

            return _ResponseConnection(_TLSRecordReader(self), self.release_response)

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"Encrypted communication failed: {e}")
            self.close()
            if isinstance(e, (InvalidData, StreamConsumedError)):
                raise
            raise ConnectionError(f"TLS communication failed: {e}") from e

    def _send_h2(self):
        """Send HTTP/2 request over TLS using H2Connection."""
        from ja3requests.protocol.h2.multiplex import (
            H2MultiplexConnection,
        )  # pylint: disable=import-outside-toplevel

        h2 = None
        stream_id = None
        multiplexed = self._pool is not None
        try:
            read_timeout = getattr(self.context, 'read_timeout', None)
            # One reader drives the connection; timeouts belong to each stream.
            self.conn.settimeout(None)

            tls = self.tls

            def h2_send(data, timeout=None):
                deadline = time.monotonic() + (15.0 if timeout is None else timeout)
                with self._h2_io_lock:
                    # HTTP/2 frames include a nine-byte header and may exceed
                    # one TLS plaintext record even at the default frame size.
                    for offset in range(0, len(data), 16384):
                        encrypted = self._encrypt_application_data(
                            data[offset : offset + 16384]
                        )
                        self._h2_write_guard.sendall(encrypted, deadline)

            def h2_recv(n):
                return self._decrypt_single_record() or b""

            # Get H2 fingerprint settings from TLS config
            tls_config = getattr(self.context, 'tls_config', None)
            h2_settings = (
                getattr(tls_config, 'h2_settings', None) if tls_config else None
            )
            h2_window = (
                getattr(tls_config, 'h2_window_update', None) if tls_config else None
            )

            h2 = getattr(tls, '_h2_connection', None)
            if h2 is None:
                self._h2_write_guard = _H2WriteGuard(self.conn)
                h2 = H2MultiplexConnection(
                    h2_send,
                    h2_recv,
                    settings=h2_settings,
                    send_with_timeout=h2_send,
                    close_transport=self._h2_write_guard.close,
                )
                h2.initiate(
                    window_update_increment=int(h2_window) if h2_window else None
                )
                tls._h2_connection = h2
                if multiplexed:
                    pooled = self._pool.put_h2_connection(
                        self.context.destination_address,
                        self.context.port,
                        "https",
                        self.conn,
                        tls=tls,
                        h2_connection=h2,
                        transport_owner=self,
                        acquire_initial=True,
                    )
                    if pooled is not None:
                        self._h2_pooled_conn = pooled
                        h2.set_pooled_connection(pooled)
                    self._release_h2_reservation()

            # Parse HTTP request to extract method, path, headers
            method = getattr(self.context, 'method', 'GET')
            host = getattr(self.context, 'destination_address', '')
            path = getattr(self.context, 'path', '/')

            # Build the body through the same context encoder used by HTTP/1.1.
            uploading = isinstance(self.context.data, UploadSource)
            if uploading:
                upload_headers(self.context, h2=True)
                body = self.context.data
            else:
                _ = self.context.message
                body = getattr(self.context, 'body', None)
            if isinstance(body, str):
                body = body.encode('utf-8')

            # Build headers from context
            req_headers = []
            ctx_headers = getattr(self.context, 'headers', None) or {}
            if isinstance(ctx_headers, dict):
                for k, v in ctx_headers.items():
                    req_headers.append((k, v))

            if uploading:
                stream_id = h2.begin_upload(
                    method,
                    host,
                    path,
                    headers=req_headers,
                    body=body,
                    timeout=read_timeout,
                    register=getattr(self.context, '_upload_register', None),
                )
                upload_owner = h2._uploads.get(stream_id)
            else:
                upload_owner = None
                stream_id = h2.send_request(
                    method,
                    host,
                    path,
                    headers=req_headers,
                    body=body,
                    timeout=read_timeout,
                )
            resp_headers = h2.receive_headers(stream_id, timeout=read_timeout)
            released = False

            def release_stream(reusable):
                nonlocal released
                if released:
                    return
                released = True
                h2.cancel_stream(stream_id)
                if self._h2_pooled_conn is not None and not h2.failed:
                    self.return_to_pool()
                else:
                    self.close()

            return _ResponseConnection(
                _H2StreamReader(h2, stream_id, resp_headers, read_timeout),
                release_stream,
                body_framed=True,
                upload_owner=upload_owner,
            )

        except Exception as e:  # pylint: disable=broad-exception-caught
            debug(f"H2 communication failed: {e}")
            if multiplexed and self._h2_pooled_conn is not None and not h2.failed:
                if stream_id is not None:
                    h2.cancel_stream(stream_id)
                self.return_to_pool()
            else:
                self.close()
            if isinstance(e, (InvalidData, StreamConsumedError)):
                raise
            raise ConnectionError(f"HTTP/2 communication failed: {e}") from e

    def _decrypt_single_record(self, recv=None):
        """Read and decrypt a single TLS record, return plaintext."""
        codec = TLSRecordCodec(self.tls)
        while True:
            header = self._recv_exact(5, recv=recv)
            if not header:
                codec.check_handshake_complete()
                return None
            length = codec.record_length(header)
            payload = self._recv_exact(length, recv=recv)
            record_type, payload = codec.decode_record(header, payload)
            if record_type == 0x16:
                self._handle_tls13_post_handshake(payload)
                continue
            if record_type == 0x15:
                return None
            if payload:
                return payload

    def _decrypt_tls13_record(self, header, payload):
        """Unwrap TLSInnerPlaintext using the negotiated application keys."""
        if header[0] != 0x17:
            raise TLSDecryptionError("Expected encrypted TLS 1.3 record")
        try:
            return self.tls._tls13_server_rp.decrypt(payload, header)
        except Exception as error:  # pylint: disable=broad-exception-caught
            raise TLSDecryptionError("TLS 1.3 record authentication failed") from error

    def _check_tls13_handshake_complete(self):
        handshake = getattr(self.tls, '_tls13_handshake', None)
        if handshake and handshake._pending_post_handshake:
            raise TLSDecryptionError("Incomplete TLS 1.3 post-handshake message")

    def _handle_tls13_post_handshake(self, plaintext):
        with self._h2_io_lock:
            replies = _post_handshake_records(self.tls, plaintext)
            for record in replies:
                if self._h2_write_guard is None:
                    self.conn.sendall(record)
                else:
                    self._h2_write_guard.sendall(record, time.monotonic() + 15.0)

    def send_key_update(self, request_update=False):
        """Send a TLS 1.3 KeyUpdate on the current connection."""
        tls = getattr(self, 'tls', None)
        handshake = getattr(tls, '_tls13_handshake', None)
        if not getattr(tls, '_is_tls13', False) or handshake is None:
            raise ValueError("TLS 1.3 application keys are not available")
        with self._h2_io_lock:
            record = handshake.build_key_update(request_update)
            if self._h2_write_guard is None:
                self.conn.sendall(record)
            else:
                self._h2_write_guard.sendall(record, time.monotonic() + 15.0)

    def _handle_encrypted_response(self):
        """
        Handle encrypted TLS response from server.
        Reads complete TLS records using _recv_exact and decrypts them.
        """
        http_response_data = b""

        while True:
            decrypted_data = self._decrypt_single_record()
            if decrypted_data is None:
                break
            http_response_data += decrypted_data
            debug(f"Decrypted {len(decrypted_data)} bytes of HTTP data")

            if b'\r\n\r\n' in http_response_data:
                header_end = http_response_data.find(b'\r\n\r\n') + 4
                headers_part = http_response_data[:header_end]
                body_part = http_response_data[header_end:]
                if b'transfer-encoding: chunked' in headers_part.lower():
                    if body_part.endswith(b'0\r\n\r\n'):
                        break
                    continue
                content_length = self._parse_content_length(headers_part)
                if content_length is not None and len(body_part) >= content_length:
                    break
                # EOF-delimited responses continue through authenticated alerts.

        if http_response_data:
            debug(f"Total decrypted HTTP response: {len(http_response_data)} bytes")
            return self._create_response_connection(http_response_data)

        return None

    def _recv_exact(self, length, recv=None):
        """Receive exactly 'length' bytes from the connection"""
        data = b""
        tls = getattr(self, 'tls', None)
        pending_attr = (
            '_tls13_pending_record_data'
            if getattr(tls, '_is_tls13', False)
            else '_tls12_pending_record_data'
        )
        pending = getattr(tls, pending_attr, b'')
        if pending:
            data = pending[:length]
            setattr(tls, pending_attr, pending[length:])
        while len(data) < length:
            chunk = (recv or self.conn.recv)(length - len(data))
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

    def _decrypt_application_data_cbc(self, encrypted_data):
        """Decrypt TLS application data using AES-CBC with HMAC"""
        try:
            server_write_key = getattr(self.tls, '_server_write_key', None)
            server_write_mac_key = getattr(self.tls, '_server_write_mac_key', None)

            if not server_write_key or not server_write_mac_key:
                raise TLSKeyError("Server encryption keys not available")

            server_seq_num = getattr(self.tls, '_server_seq_num', 0)
            plaintext = _decrypt_tls12_cbc_record(
                encrypted_data,
                server_write_key,
                server_write_mac_key,
                server_seq_num.to_bytes(8, 'big') + b'\x17\x03\x03',
            )
            self.tls._server_seq_num += 1  # pylint: disable=protected-access
            return plaintext
        except (TLSDecryptionError, TLSKeyError):
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
        if getattr(self.tls, '_is_tls13', False):
            return self.tls._tls13_client_rp.encrypt(0x17, data)
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


class TLSRecordCodec:
    """Byte-only access to the active TLS record implementation, without a socket.

    The synchronous adapter and native async transport share these exact crypto
    methods. Callers must serialize outbound state changes and their writes.
    """

    def __init__(self, tls):
        self.tls = tls

    encrypt = HttpsSocket._encrypt_application_data
    decrypt = HttpsSocket._decrypt_application_data
    decrypt_tls13 = HttpsSocket._decrypt_tls13_record
    check_handshake_complete = HttpsSocket._check_tls13_handshake_complete
    _encrypt_application_data_gcm = HttpsSocket._encrypt_application_data_gcm
    _encrypt_application_data_cbc = HttpsSocket._encrypt_application_data_cbc
    _decrypt_application_data_gcm = HttpsSocket._decrypt_application_data_gcm
    _decrypt_application_data_cbc = HttpsSocket._decrypt_application_data_cbc

    def record_length(self, header):
        """Validate the protected record header before a driver reads its body."""
        if len(header) != 5:
            raise TLSDecryptionError("Truncated TLS record header")
        length = int.from_bytes(header[3:5], 'big')
        maximum = 16640 if getattr(self.tls, '_is_tls13', False) else 18432
        if header[1:3] != b'\x03\x03' or length > maximum:
            raise TLSDecryptionError("Invalid TLS record header")
        return length

    def decode_record(self, header, payload):
        """Authenticate and classify a record without performing any I/O."""
        if payload is None or len(payload) != self.record_length(header):
            raise TLSDecryptionError("Truncated TLS record")
        kind = header[0]
        is_tls13 = getattr(self.tls, '_is_tls13', False)
        if is_tls13:
            kind, payload = self.decrypt_tls13(header, payload)
        elif kind == 23:
            payload = self.decrypt(payload)
        elif kind == 21:
            try:
                # Alerts use the same keys/sequence as application records, but
                # their actual record type is part of the MAC or AEAD input.
                payload = self.tls._decrypt_server_handshake_record(header, payload)
            except Exception as error:  # pylint: disable=broad-exception-caught
                raise TLSDecryptionError("TLS alert authentication failed") from error
        if len(payload) > 16384:
            raise TLSDecryptionError("TLS plaintext record exceeds the size limit")
        if is_tls13 and kind == 22:
            return kind, payload  # The driver serializes post-handshake replies.
        if kind == 21:
            self.check_handshake_complete()
            if len(payload) != 2:
                raise TLSDecryptionError("Invalid TLS alert")
            # TLS 1.3 alert severity follows its description; the level is legacy.
            if payload[1] != 0 or (not is_tls13 and payload[0] != 1):
                raise TLSDecryptionError(
                    "Peer sent a TLS alert (level=%d, description=%d)"
                    % (payload[0], payload[1])
                )
        elif kind == 23:
            self.check_handshake_complete()
        else:
            raise TLSDecryptionError("Unexpected TLS application record")
        return kind, payload

    def post_handshake(self, plaintext):
        """Return encrypted control replies while advancing shared key state."""
        return _post_handshake_records(self.tls, plaintext)
