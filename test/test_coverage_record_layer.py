"""Coverage tests for TLS record_layer.py and remaining TLS layers."""

import os
import struct
import unittest

from ja3requests.protocol.tls.record_layer import TLSRecordLayer, TLSSocket, TLSSocketFile
from ja3requests.protocol.tls.layers.hello_request import HelloRequest
from ja3requests.protocol.tls.layers.server_hello import ServerHello
from ja3requests.protocol.tls.layers.server_hello_done import ServerHelloDone
from ja3requests.protocol.tls.layers.certificate import Certificate
from ja3requests.protocol.tls.layers.certificate_request import CertificateRequest
from ja3requests.protocol.tls.layers.server_key_exchange import ServerKeyExchange
from ja3requests.exceptions import TLSKeyError, TLSEncryptionError, TLSDecryptionError


class TestTLSRecordLayer(unittest.TestCase):
    """Test TLSRecordLayer encrypt/decrypt."""

    def setUp(self):
        self.rl = TLSRecordLayer()
        self.rl.set_keys(
            client_write_key=os.urandom(16),
            server_write_key=os.urandom(16),
            client_write_mac_key=os.urandom(20),
            server_write_mac_key=os.urandom(20),
            client_write_iv=os.urandom(16),
            server_write_iv=os.urandom(16),
            cipher_suite=0x002F,  # RSA_WITH_AES_128_CBC_SHA
        )

    def test_set_keys(self):
        self.assertIsNotNone(self.rl.client_write_key)
        self.assertIsNotNone(self.rl.server_write_key)

    def test_encrypt_produces_record(self):
        encrypted = self.rl.encrypt_application_data(b"hello")
        # Should be a TLS record: type(1) + version(2) + length(2) + data
        self.assertGreater(len(encrypted), 5)
        self.assertEqual(encrypted[0], 23)  # application data
        self.assertEqual(encrypted[1:3], b"\x03\x03")  # TLS 1.2

    def test_encrypt_increments_seq_num(self):
        self.assertEqual(self.rl.client_seq_num, 0)
        self.rl.encrypt_application_data(b"msg1")
        self.assertEqual(self.rl.client_seq_num, 1)
        self.rl.encrypt_application_data(b"msg2")
        self.assertEqual(self.rl.client_seq_num, 2)

    def test_encrypt_without_keys_raises(self):
        rl = TLSRecordLayer()
        with self.assertRaises(TLSKeyError):
            rl.encrypt_application_data(b"data")

    def test_decrypt_roundtrip(self):
        """Encrypt then decrypt should return original data."""
        # Use same keys for both sides for roundtrip test
        rl = TLSRecordLayer()
        key = os.urandom(16)
        mac_key = os.urandom(20)
        iv = os.urandom(16)
        rl.set_keys(
            client_write_key=key,
            server_write_key=key,
            client_write_mac_key=mac_key,
            server_write_mac_key=mac_key,
            client_write_iv=iv,
            server_write_iv=iv,
            cipher_suite=0x002F,
        )
        encrypted = rl.encrypt_application_data(b"test data")
        decrypted, ct = rl.decrypt_application_data(encrypted)
        self.assertEqual(decrypted, b"test data")
        self.assertEqual(ct, 23)

    def test_decrypt_without_keys_raises(self):
        rl = TLSRecordLayer()
        record = struct.pack("!BBBH", 23, 3, 3, 32) + os.urandom(32)
        with self.assertRaises(TLSKeyError):
            rl.decrypt_application_data(record)

    def test_decrypt_short_record_raises(self):
        with self.assertRaises(ValueError):
            self.rl.decrypt_application_data(b"\x17\x03\x03")

    def test_encrypt_sha256_suite(self):
        rl = TLSRecordLayer()
        rl.set_keys(
            client_write_key=os.urandom(16),
            server_write_key=os.urandom(16),
            client_write_mac_key=os.urandom(32),
            server_write_mac_key=os.urandom(32),
            client_write_iv=os.urandom(16),
            server_write_iv=os.urandom(16),
            cipher_suite=0xC027,  # SHA-256 based
        )
        encrypted = rl.encrypt_application_data(b"hello sha256")
        self.assertGreater(len(encrypted), 5)


class TestTLSRecordLayerInit(unittest.TestCase):
    def test_initial_state(self):
        rl = TLSRecordLayer()
        self.assertEqual(rl.client_seq_num, 0)
        self.assertEqual(rl.server_seq_num, 0)
        self.assertIsNone(rl.client_write_key)


class TestTLSSocket(unittest.TestCase):
    def test_init_without_keys(self):
        class FakeCtx:
            pass
        import socket
        s1, s2 = socket.socketpair()
        try:
            ts = TLSSocket(s1, FakeCtx())
            self.assertIsNotNone(ts.record_layer)
        finally:
            s1.close()
            s2.close()

    def test_settimeout(self):
        import socket
        s1, s2 = socket.socketpair()
        try:
            class FakeCtx:
                pass
            ts = TLSSocket(s1, FakeCtx())
            ts.settimeout(5.0)  # should not raise
        finally:
            s1.close()
            s2.close()

    def test_close(self):
        import socket
        s1, s2 = socket.socketpair()
        class FakeCtx:
            pass
        ts = TLSSocket(s1, FakeCtx())
        ts.close()
        s2.close()

    def test_makefile(self):
        import socket
        s1, s2 = socket.socketpair()
        try:
            class FakeCtx:
                pass
            ts = TLSSocket(s1, FakeCtx())
            f = ts.makefile('rb')
            self.assertIsInstance(f, TLSSocketFile)
        finally:
            s1.close()
            s2.close()


class TestTLSSocketFile(unittest.TestCase):
    def test_close(self):
        class FakeTLS:
            def recv(self, n):
                return b""
        f = TLSSocketFile(FakeTLS())
        f.close()  # should not raise


class TestHelloRequest(unittest.TestCase):
    def test_handshake_type(self):
        hr = HelloRequest()
        self.assertEqual(hr.handshake_type, struct.pack("B", 0))

    def test_message(self):
        hr = HelloRequest()
        msg = hr.message
        self.assertIsInstance(msg, bytes)


class TestServerHelloProperties(unittest.TestCase):
    def test_initial_values_none(self):
        sh = ServerHello()
        self.assertIsNone(sh.version)
        self.assertIsNone(sh.session_id)
        self.assertIsNone(sh.cipher_suite)
        self.assertIsNone(sh.extensions)

    def test_parse_minimal(self):
        """Test ServerHello.parse with minimal data."""
        sh = ServerHello()
        # Build a minimal ServerHello message
        # TLS record header (5 bytes) + handshake header (4 bytes)
        # + version(2) + random(32) + session_id_len(1) + cipher(2) + compression(1)
        version = b"\x03\x03"
        random_bytes = os.urandom(32)
        session_id_len = b"\x00"
        cipher = b"\x00\x2F"
        compression = b"\x00"
        body = version + random_bytes + session_id_len + cipher + compression
        hs_header = struct.pack("B", 2) + struct.pack("!I", len(body))[1:]
        record_header = b"\x16\x03\x03" + struct.pack("!H", len(hs_header) + len(body))
        data = record_header + hs_header + body
        sh.parse(data)
        self.assertEqual(sh.version, b"\x03\x03")
        self.assertEqual(sh.cipher_suite, b"\x00\x2F")


class TestCertificateProperties(unittest.TestCase):
    def test_version(self):
        c = Certificate()
        c.version = b"\x03\x03"
        self.assertEqual(c.version, b"\x03\x03")


class TestCertificateRequestProperties(unittest.TestCase):
    def test_version(self):
        cr = CertificateRequest()
        cr.version = b"\x03\x03"
        self.assertEqual(cr.version, b"\x03\x03")


class TestServerKeyExchangeProperties(unittest.TestCase):
    def test_version(self):
        ske = ServerKeyExchange()
        ske.version = b"\x03\x03"
        self.assertEqual(ske.version, b"\x03\x03")


class TestServerHelloDoneProperties(unittest.TestCase):
    def test_version(self):
        shd = ServerHelloDone()
        shd.version = b"\x03\x03"
        self.assertEqual(shd.version, b"\x03\x03")

    def test_content(self):
        shd = ServerHelloDone()
        shd.version = b"\x03\x03"
        c = shd.content()
        self.assertIsInstance(c, bytes)


if __name__ == "__main__":
    unittest.main()
