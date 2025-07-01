import os
import struct
from ja3requests.protocol.tls.layers import HandShake
from ja3requests.protocol.tls.layers.client_hello import ClientHello
from ja3requests.protocol.tls.layers.server_hello import ServerHello
from ja3requests.protocol.tls.layers.certificate import Certificate
from ja3requests.protocol.tls.layers.server_key_exchange import ServerKeyExchange
from ja3requests.protocol.tls.layers.certificate_request import CertificateRequest
from ja3requests.protocol.tls.layers.server_hello_done import ServerHelloDone
from ja3requests.protocol.tls.layers.client_key_exchange import ClientKeyExchange
from ja3requests.protocol.tls.layers.certificate_verify import CertificateVerify
from ja3requests.protocol.tls.layers.finished import Finished
from ja3requests.protocol.tls.security_warnings import (
    warn_insecure_implementation,
    warn_no_certificate_verification,
    warn_unencrypted_key_exchange,
    warn_invalid_finished_message
)


class TLS:

    def __init__(self, conn):
        # Show security warning on first use
        warn_insecure_implementation()
        
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

    @property
    def tls_version(self) -> bytes:
        if not self._tls_version:
            self._tls_version = struct.pack("I", 771)[:2]
        return self._tls_version

    @tls_version.setter
    def tls_version(self, attr: bytes):
        self._tls_version = attr

    @property
    def body(self) -> HandShake:
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
                    self._tls_version = tls_config.tls_version.to_bytes(2, byteorder='big')
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
            
            # Set supported groups
            if hasattr(tls_config, 'supported_groups') and tls_config.supported_groups:
                self._supported_groups = tls_config.supported_groups
            
            # Set signature algorithms
            if hasattr(tls_config, 'signature_algorithms') and tls_config.signature_algorithms:
                self._signature_algorithms = tls_config.signature_algorithms
            
            # Update client hello with new configuration
            self._body = ClientHello(
                self.tls_version,
                cipher_suites=self._cipher_suites,
                client_random=self._client_random,
                server_name=self._server_name,
                supported_groups=self._supported_groups,
                signature_algorithms=self._signature_algorithms,
                alpn_protocols=getattr(tls_config, 'alpn_protocols', None),
                use_grease=getattr(tls_config, 'use_grease', True)
            )

    def handshake(self):
        """
        Complete TLS handshake process with improved error handling and parsing
        """
        try:
            # Step 1: Send Client Hello
            client_hello = self.body
            self._client_random = client_hello.random
            print("Sending Client Hello...")
            self.conn.sendall(client_hello.message)

            # Step 2-6: Receive server handshake messages
            self._parse_server_handshake_messages()

            # Step 7-9: Send client finishing messages
            self._send_client_finishing_messages()

            print("TLS Handshake completed successfully")
            return True

        except Exception as e:
            print(f"TLS Handshake failed: {e}")
            return False

    def _parse_server_handshake_messages(self):
        """
        Parse incoming server handshake messages
        """
        buffer = b""
        while True:
            try:
                # Receive data
                data = self.conn.recv(4096)
                if not data:
                    break
                
                buffer += data
                
                # Parse TLS records from buffer
                while len(buffer) >= 5:  # Minimum TLS record header size
                    record_type = buffer[0]
                    tls_version = buffer[1:3]
                    
                    # Ensure we have enough bytes for length
                    if len(buffer) < 5:
                        break
                        
                    record_length = struct.unpack("!H", buffer[3:5])[0]
                    
                    if len(buffer) < 5 + record_length:
                        # Need more data
                        break
                    
                    record_data = buffer[5:5 + record_length]
                    buffer = buffer[5 + record_length:]
                    
                    if record_type == 22:  # Handshake message
                        self._process_handshake_record(record_data)
                    elif record_type == 21:  # Alert
                        if len(record_data) >= 2:
                            alert_level = record_data[0]
                            alert_description = record_data[1]
                            if alert_level == 2:  # Fatal alert
                                raise Exception(f"TLS Fatal Alert: {alert_description}")
                    
                    # Check if we've received ServerHelloDone
                    if hasattr(self, '_server_hello_done_received'):
                        return
                        
            except Exception as e:
                print(f"Error parsing server messages: {e}")
                raise e

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
                
            length_bytes = record_data[offset + 1:offset + 4]
            if len(length_bytes) != 3:
                break
                
            msg_length = struct.unpack("!I", b'\x00' + length_bytes)[0]
            
            if offset + 4 + msg_length > len(record_data):
                break
                
            msg_data = record_data[offset + 4:offset + 4 + msg_length]
            
            if msg_type == 2:  # ServerHello
                self._parse_server_hello(msg_data)
                print("Received Server Hello")
            elif msg_type == 11:  # Certificate
                self._parse_certificate(msg_data)
                print("Received Certificate")
            elif msg_type == 12:  # ServerKeyExchange
                self._parse_server_key_exchange(msg_data)
                print("Received Server Key Exchange")
            elif msg_type == 13:  # CertificateRequest
                self._parse_certificate_request(msg_data)
                print("Received Certificate Request")
            elif msg_type == 14:  # ServerHelloDone
                self._parse_server_hello_done(msg_data)
                print("Received Server Hello Done")
                self._server_hello_done_received = True
                return
            
            offset += 4 + msg_length

    def _parse_server_hello(self, data):
        """Parse ServerHello message"""
        if len(data) < 38:  # Minimum size for ServerHello
            print(f"ServerHello data too short: {len(data)} bytes")
            return
            
        offset = 0
        # TLS version (2 bytes)
        if offset + 2 > len(data):
            return
        server_version = data[offset:offset + 2]
        offset += 2
        
        # Server random (32 bytes)
        if offset + 32 > len(data):
            return
        self._server_random = data[offset:offset + 32]
        offset += 32
        
        # Session ID
        if offset + 1 > len(data):
            return
        session_id_length = data[offset]
        offset += 1
        if session_id_length > 0:
            if offset + session_id_length > len(data):
                return
            session_id = data[offset:offset + session_id_length]
            offset += session_id_length
        
        # Cipher suite (2 bytes)
        if offset + 2 > len(data):
            return
        cipher_bytes = data[offset:offset + 2]
        if len(cipher_bytes) == 2:
            self._cipher_suite = struct.unpack("!H", cipher_bytes)[0]
        offset += 2
        
        # Compression method (1 byte)
        if offset < len(data):
            compression_method = data[offset]
            offset += 1

    def _parse_certificate(self, data):
        """Parse Certificate message"""
        # TODO: Implement proper certificate parsing and validation
        warn_no_certificate_verification()

    def _parse_server_key_exchange(self, data):
        """Parse ServerKeyExchange message"""
        # For now, just acknowledge receipt
        pass

    def _parse_certificate_request(self, data):
        """Parse CertificateRequest message"""
        self._client_cert_requested = True

    def _parse_server_hello_done(self, data):
        """Parse ServerHelloDone message"""
        # This message has no content
        pass

    def _send_client_finishing_messages(self):
        """
        Send client finishing messages
        """
        # Send empty Certificate if requested
        if hasattr(self, '_client_cert_requested'):
            empty_cert = self._build_empty_certificate()
            self.conn.sendall(empty_cert)
            print("Sent empty Certificate")
        
        # Send ClientKeyExchange
        client_key_exchange = self._build_client_key_exchange()
        self.conn.sendall(client_key_exchange)
        print("Sent Client Key Exchange")
        
        # Send ChangeCipherSpec
        change_cipher_spec = b'\x14\x03\x03\x00\x01\x01'
        self.conn.sendall(change_cipher_spec)
        print("Sent Change Cipher Spec")
        
        # Send Finished
        finished_message = self._build_finished_message()
        self.conn.sendall(finished_message)
        print("Sent Finished")

    def _build_empty_certificate(self):
        """Build an empty certificate message"""
        # Certificate message with empty certificate list
        cert_list_length = b'\x00\x00\x00'  # 0 length certificate list
        cert_msg = b'\x0b' + struct.pack("!I", 3)[1:] + cert_list_length
        
        # Wrap in TLS record
        record = b'\x16\x03\x03' + struct.pack("!H", len(cert_msg)) + cert_msg
        return record

    def _build_client_key_exchange(self):
        """Build ClientKeyExchange message"""
        warn_unencrypted_key_exchange()
        
        premaster_secret = os.urandom(48)  # 48 bytes for TLS 1.2
        
        # TODO: Encrypt with server's public key
        encrypted_premaster = premaster_secret  # INSECURE: Should be encrypted!
        
        key_exchange_data = struct.pack("!H", len(encrypted_premaster)) + encrypted_premaster
        msg = b'\x10' + struct.pack("!I", len(key_exchange_data))[1:] + key_exchange_data
        
        # Wrap in TLS record
        record = b'\x16\x03\x03' + struct.pack("!H", len(msg)) + msg
        return record

    def _build_finished_message(self):
        """Build Finished message"""
        warn_invalid_finished_message()
        
        # TODO: Implement proper PRF calculation
        verify_data = os.urandom(12)  # INSECURE: Should be PRF result!
        
        msg = b'\x14' + struct.pack("!I", len(verify_data))[1:] + verify_data
        
        # Wrap in TLS record (this would normally be encrypted)
        record = b'\x16\x03\x03' + struct.pack("!H", len(msg)) + msg
        return record
