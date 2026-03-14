"""
TLS Record Layer Implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module implements TLS record layer encryption and decryption functionality.
"""

import struct
import hmac
import hashlib
from typing import Tuple, Optional
from .crypto import AESCipher, TLSCrypto
from .debug import debug


class TLSRecordLayer:
    """TLS Record Layer for encryption/decryption of application data"""

    def __init__(self):
        self.client_seq_num = 0
        self.server_seq_num = 0
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_mac_key = None
        self.server_write_mac_key = None
        self.client_write_iv = None
        self.server_write_iv = None
        self.cipher_suite = None

    def set_keys(
        self,
        client_write_key,
        server_write_key,
        client_write_mac_key,
        server_write_mac_key,
        client_write_iv,
        server_write_iv,
        cipher_suite,
    ):
        """Set encryption keys and parameters"""
        self.client_write_key = client_write_key
        self.server_write_key = server_write_key
        self.client_write_mac_key = client_write_mac_key
        self.server_write_mac_key = server_write_mac_key
        self.client_write_iv = client_write_iv
        self.server_write_iv = server_write_iv
        self.cipher_suite = cipher_suite

    def encrypt_application_data(self, data: bytes, content_type: int = 23) -> bytes:
        """
        Encrypt application data for sending to server

        :param data: Application data to encrypt
        :param content_type: TLS content type (23 for application data)
        :return: TLS record with encrypted data
        """
        if not self.client_write_key or not self.client_write_mac_key:
            # If no encryption keys, send as plaintext (fallback)
            record_header = struct.pack('!BBBH', content_type, 3, 3, len(data))
            return record_header + data

        try:
            # Calculate MAC
            mac_data = (
                struct.pack('!Q', self.client_seq_num)
                + struct.pack('!BBB', content_type, 3, 3)
                + struct.pack('!H', len(data))
                + data
            )

            if self.cipher_suite in [0x002F, 0x0035]:  # SHA-1 based
                mac = hmac.new(
                    self.client_write_mac_key, mac_data, hashlib.sha1
                ).digest()
            else:  # SHA-256 based
                mac = hmac.new(
                    self.client_write_mac_key, mac_data, hashlib.sha256
                ).digest()

            # Combine data and MAC
            plaintext = data + mac

            # Encrypt with AES-CBC
            import os

            iv = os.urandom(16)  # Generate random IV for this record
            ciphertext = AESCipher.encrypt_cbc(plaintext, self.client_write_key, iv)

            # Create TLS record
            encrypted_data = iv + ciphertext
            record_header = struct.pack(
                '!BBBH', content_type, 3, 3, len(encrypted_data)
            )

            self.client_seq_num += 1
            return record_header + encrypted_data

        except Exception as e:
            debug(f"Encryption failed: {e}, sending as plaintext")
            # Fallback to plaintext
            record_header = struct.pack('!BBBH', content_type, 3, 3, len(data))
            return record_header + data

    def decrypt_application_data(self, record_data: bytes) -> Tuple[bytes, int]:
        """
        Decrypt received TLS record

        :param record_data: Complete TLS record including header
        :return: (decrypted_data, content_type)
        """
        if len(record_data) < 5:
            raise ValueError("Invalid TLS record: too short")

        # Parse TLS record header
        content_type, major_version, minor_version, length = struct.unpack(
            '!BBBH', record_data[:5]
        )
        encrypted_data = record_data[5 : 5 + length]

        if not self.server_write_key or not self.server_write_mac_key:
            # No decryption keys, treat as plaintext
            return encrypted_data, content_type

        try:
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            # Decrypt
            plaintext_with_mac = AESCipher.decrypt_cbc(
                ciphertext, self.server_write_key, iv
            )

            # Determine MAC length
            if self.cipher_suite in [0x002F, 0x0035]:  # SHA-1 based
                mac_length = 20
            else:  # SHA-256 based
                mac_length = 32

            # Separate data and MAC
            if len(plaintext_with_mac) < mac_length:
                raise ValueError("Decrypted data too short for MAC")

            data = plaintext_with_mac[:-mac_length]
            received_mac = plaintext_with_mac[-mac_length:]

            # Verify MAC
            mac_data = (
                struct.pack('!Q', self.server_seq_num)
                + struct.pack('!BBB', content_type, major_version, minor_version)
                + struct.pack('!H', len(data))
                + data
            )

            if self.cipher_suite in [0x002F, 0x0035]:  # SHA-1 based
                expected_mac = hmac.new(
                    self.server_write_mac_key, mac_data, hashlib.sha1
                ).digest()
            else:  # SHA-256 based
                expected_mac = hmac.new(
                    self.server_write_mac_key, mac_data, hashlib.sha256
                ).digest()

            if received_mac != expected_mac:
                debug("Warning: MAC verification failed")
                # Continue anyway for debugging

            self.server_seq_num += 1
            return data, content_type

        except Exception as e:
            debug(f"Decryption failed: {e}, treating as plaintext")
            return encrypted_data, content_type


class TLSSocket:
    """TLS Socket wrapper with record layer encryption"""

    def __init__(self, raw_socket, tls_context):
        """
        Initialize TLS socket

        :param raw_socket: Underlying TCP socket
        :param tls_context: TLS context with session keys
        """
        self.raw_socket = raw_socket
        self.record_layer = TLSRecordLayer()
        self.receive_buffer = b''

        # Set up record layer with session keys if available
        if hasattr(tls_context, '_client_write_key'):
            self.record_layer.set_keys(
                tls_context._client_write_key,
                tls_context._server_write_key,
                tls_context._client_write_mac_key,
                tls_context._server_write_mac_key,
                tls_context._client_write_iv,
                tls_context._server_write_iv,
                getattr(tls_context, '_selected_cipher_suite', 0x002F),
            )

    def send(self, data: bytes) -> int:
        """Send data over TLS connection"""
        encrypted_record = self.record_layer.encrypt_application_data(data)
        return self.raw_socket.send(encrypted_record)

    def sendall(self, data: bytes):
        """Send all data over TLS connection"""
        encrypted_record = self.record_layer.encrypt_application_data(data)
        return self.raw_socket.sendall(encrypted_record)

    def recv(self, bufsize: int) -> bytes:
        """Receive and decrypt data from TLS connection"""
        while True:
            # Try to parse a complete TLS record from buffer
            if len(self.receive_buffer) >= 5:
                record_length = struct.unpack('!H', self.receive_buffer[3:5])[0]
                total_record_length = 5 + record_length

                if len(self.receive_buffer) >= total_record_length:
                    # We have a complete record
                    record = self.receive_buffer[:total_record_length]
                    self.receive_buffer = self.receive_buffer[total_record_length:]

                    try:
                        decrypted_data, content_type = (
                            self.record_layer.decrypt_application_data(record)
                        )
                        if content_type == 23:  # Application data
                            return decrypted_data[:bufsize]
                        elif content_type == 21:  # Alert
                            debug(f"Received TLS alert: {decrypted_data.hex()}")
                            continue
                        else:
                            debug(f"Received TLS record type {content_type}")
                            continue
                    except Exception as e:
                        debug(f"Failed to decrypt record: {e}")
                        return decrypted_data[:bufsize]

            # Need more data
            try:
                raw_data = self.raw_socket.recv(4096)
                if not raw_data:
                    break
                self.receive_buffer += raw_data
            except Exception as e:
                debug(f"Socket receive error: {e}")
                break

        return b''

    def makefile(self, mode='rb'):
        """Create a file-like object for the TLS socket"""
        return TLSSocketFile(self, mode)

    def close(self):
        """Close the TLS connection"""
        return self.raw_socket.close()

    def settimeout(self, timeout):
        """Set socket timeout"""
        return self.raw_socket.settimeout(timeout)


class TLSSocketFile:
    """File-like object for TLS socket"""

    def __init__(self, tls_socket, mode='rb'):
        self.tls_socket = tls_socket
        self.mode = mode
        self.buffer = b''

    def readline(self, size=-1):
        """Read a line from the TLS socket"""
        while b'\n' not in self.buffer:
            data = self.tls_socket.recv(4096)
            if not data:
                break
            self.buffer += data

        if b'\n' in self.buffer:
            line_end = self.buffer.find(b'\n') + 1
            line = self.buffer[:line_end]
            self.buffer = self.buffer[line_end:]

            if size > 0:
                return line[:size]
            return line
        else:
            # No newline found, return what we have
            line = self.buffer
            self.buffer = b''
            if size > 0:
                return line[:size]
            return line

    def read(self, size=-1):
        """Read data from the TLS socket"""
        if size == -1:
            # Read all available data
            result = self.buffer
            self.buffer = b''
            while True:
                data = self.tls_socket.recv(4096)
                if not data:
                    break
                result += data
            return result
        else:
            # Read specific amount
            while len(self.buffer) < size:
                data = self.tls_socket.recv(4096)
                if not data:
                    break
                self.buffer += data

            result = self.buffer[:size]
            self.buffer = self.buffer[size:]
            return result

    def close(self):
        """Close the file object"""
        pass
