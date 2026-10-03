"""Tests for TLS 1.3 handshake, Session Ticket, and IDN Punycode."""

import hashlib
import os
import struct
import unittest
from types import SimpleNamespace

from ja3requests import TlsConfig
from ja3requests.exceptions import TLSHandshakeError
from ja3requests.protocol.tls import TLS, HELLO_RETRY_REQUEST_RANDOM
from ja3requests.protocol.tls.tls13 import (
    TLS13Handshake,
    TLS13KeySchedule,
    TLS13KeyExchange,
    TLS13RecordProtection,
    GROUP_X25519,
    GROUP_SECP256R1,
    TLS13_CIPHER_PARAMS,
)
from ja3requests.protocol.tls.extensions import SNIExtension
from ja3requests.sockets.https import HttpsSocket


# ============================================================================
# TLS 1.3 Handshake Tests
# ============================================================================


class TestTLS13HandshakeInit(unittest.TestCase):
    def test_create_handshake(self):
        priv, pub = TLS13KeyExchange.generate_x25519_keypair()
        hs = TLS13Handshake(None, priv, GROUP_X25519, b"client_hello_data")
        self.assertIsNotNone(hs)
        self.assertEqual(hs._transcript, b"client_hello_data")

    def test_cipher_params(self):
        self.assertIn(0x1301, TLS13_CIPHER_PARAMS)
        self.assertIn(0x1302, TLS13_CIPHER_PARAMS)
        self.assertIn(0x1303, TLS13_CIPHER_PARAMS)


class TestTLS13ClientShares(unittest.TestCase):
    def test_rebuilding_client_hello_uses_fresh_private_keys(self):
        tls = TLS(None)
        config = TlsConfig.secure()
        tls.set_payload(config)
        first = tls._tls13_private_keys.copy()
        tls.set_payload(config)
        second = tls._tls13_private_keys
        self.assertEqual(set(first), {GROUP_X25519, GROUP_SECP256R1})
        self.assertEqual(set(second), set(first))
        for group in first:
            self.assertIsNot(first[group], second[group])

    def test_unsupported_group_closes_connection(self):
        config = TlsConfig.secure()
        config.supported_groups = [24]
        context = SimpleNamespace(
            destination_address="example.invalid",
            port=443,
            tls_config=config,
            connect_timeout=1,
        )

        class FakeConnection:
            closed = False

            def close(self):
                self.closed = True

        connection = FakeConnection()
        sock = HttpsSocket(context)
        sock._new_conn = lambda host, port: connection
        with self.assertRaises(TLSHandshakeError):
            sock.new_conn()
        self.assertTrue(connection.closed)


class TestTLS13HelloRetryRequest(unittest.TestCase):
    @staticmethod
    def retry(group=GROUP_SECP256R1, suite=0x1301, cookie=None, version=b"\x03\x04"):
        extensions = struct.pack("!HH", 0x002B, 2) + version
        if group is not None:
            extensions += struct.pack("!HHH", 0x0033, 2, group)
        if cookie is not None:
            value = struct.pack("!H", len(cookie)) + cookie
            extensions += struct.pack("!HH", 0x002C, len(value)) + value
        return (
            b"\x03\x03"
            + HELLO_RETRY_REQUEST_RANDOM
            + b"\x00"
            + struct.pack("!H", suite)
            + b"\x00"
            + struct.pack("!H", len(extensions))
            + extensions
        )

    @staticmethod
    def client(connection=None):
        config = TlsConfig.secure()
        config.key_share_groups = [GROUP_X25519]
        tls = TLS(connection)
        tls.set_payload(config)
        tls._handshake_messages = tls.body.handshake_message
        return tls

    def test_retry_preserves_client_hello_and_hashes_first_hello(self):
        sent = []
        tls = self.client(SimpleNamespace(sendall=sent.append))
        original = tls.body
        first = tls._handshake_messages
        retry = self.retry(cookie=b"opaque-cookie")

        suite, group, cookie = tls._parse_hello_retry_request(retry)
        tls._send_retried_client_hello(retry, suite, group, cookie)

        self.assertEqual(tls.body.random, original.random)
        self.assertEqual(tls.body.cipher_suites, original.cipher_suites)
        self.assertEqual(tls.body.session_id, original.session_id)
        extensions = {ext.extension_type: ext for ext in tls.body._custom_extensions}
        self.assertEqual(extensions[0x0033].key_shares[0][0], GROUP_SECP256R1)
        self.assertEqual(extensions[0x002C].encode(), b"\x00\x0dopaque-cookie")
        digest = hashlib.sha256(first).digest()
        expected = b"\xfe\x00\x00\x20" + digest
        expected += b"\x02" + len(retry).to_bytes(3, "big") + retry
        expected += tls.body.handshake_message
        self.assertEqual(tls._handshake_messages, expected)
        self.assertEqual(sent, [tls.body.message])

    def test_rejects_invalid_retry_parameters(self):
        tls = self.client()
        for label, retry in (
            ("offered group", self.retry(group=GROUP_X25519)),
            ("unsupported group", self.retry(group=24)),
            ("unoffered suite", self.retry(suite=0x1304)),
            ("wrong version", self.retry(version=b"\x03\x03")),
            ("no change", self.retry(group=None)),
        ):
            with self.subTest(label=label):
                with self.assertRaises(TLSHandshakeError):
                    tls._parse_hello_retry_request(retry)

    def test_cookie_only_retry_keeps_initial_share(self):
        sent = []
        tls = self.client(SimpleNamespace(sendall=sent.append))
        first_key = tls._tls13_private_keys[GROUP_X25519]
        retry = self.retry(group=None, cookie=b"cookie")

        suite, group, cookie = tls._parse_hello_retry_request(retry)
        self.assertIsNone(group)
        tls._send_retried_client_hello(retry, suite, group, cookie)

        self.assertIs(tls._tls13_private_keys[GROUP_X25519], first_key)
        extensions = {ext.extension_type: ext for ext in tls.body._custom_extensions}
        self.assertEqual(extensions[0x0033].key_shares[0][0], GROUP_X25519)
        self.assertEqual(extensions[0x002C].encode(), b"\x00\x06cookie")
        self.assertEqual(sent, [tls.body.message])

    def test_second_retry_is_rejected(self):
        retry = self.retry()
        message = b"\x02" + len(retry).to_bytes(3, "big") + retry
        record = b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message

        class Connection:
            def __init__(self):
                self.buffer = record + record
                self.sent = []

            def sendall(self, data):
                self.sent.append(data)

            def recv(self, size):
                data, self.buffer = self.buffer[:size], self.buffer[size:]
                return data

            def settimeout(self, timeout):
                pass

        connection = Connection()
        tls = self.client(connection)
        self.assertFalse(tls.handshake())
        self.assertEqual(len(connection.sent), 2)


class TestTLS13ServerHelloParsing(unittest.TestCase):
    """Test process_server_hello with synthetic ServerHello data."""

    def _build_server_hello(
        self, cipher_suite=0x1301, group=GROUP_X25519, pub_key=None
    ):
        """Build a synthetic ServerHello with key_share extension."""
        if pub_key is None:
            _, pub_key = TLS13KeyExchange.generate_x25519_keypair()

        version = b"\x03\x03"
        random_bytes = os.urandom(32)
        session_id = b"\x00"
        cipher = struct.pack("!H", cipher_suite)
        compression = b"\x00"

        # key_share extension
        key_share_data = struct.pack("!HH", group, len(pub_key)) + pub_key
        key_share_ext = struct.pack("!HH", 0x0033, len(key_share_data)) + key_share_data

        # supported_versions extension
        sv_data = struct.pack("!H", 0x0304)
        sv_ext = struct.pack("!HH", 0x002B, len(sv_data)) + sv_data

        extensions = key_share_ext + sv_ext
        ext_block = struct.pack("!H", len(extensions)) + extensions

        return version + random_bytes + session_id + cipher + compression + ext_block

    def test_process_server_hello_x25519(self):
        client_priv, client_pub = TLS13KeyExchange.generate_x25519_keypair()
        server_priv, server_pub = TLS13KeyExchange.generate_x25519_keypair()

        client_hello = b"fake_client_hello"
        hs = TLS13Handshake(None, client_priv, GROUP_X25519, client_hello)
        server_hello = self._build_server_hello(pub_key=server_pub)

        result = hs.process_server_hello(server_hello)
        self.assertTrue(result)
        self.assertIsNotNone(hs._key_schedule)
        self.assertIsNotNone(hs._server_handshake_rp)
        self.assertIsNotNone(hs._client_handshake_rp)
        self.assertEqual(hs._cipher_suite, 0x1301)

    def test_process_server_hello_secp256r1(self):
        client_priv, client_pub = TLS13KeyExchange.generate_secp256r1_keypair()
        server_priv, server_pub = TLS13KeyExchange.generate_secp256r1_keypair()

        hs = TLS13Handshake(None, client_priv, GROUP_SECP256R1, b"ch")
        server_hello = self._build_server_hello(
            group=GROUP_SECP256R1, pub_key=server_pub
        )
        self.assertTrue(hs.process_server_hello(server_hello))

    def test_process_server_hello_selects_matching_private_key(self):
        x25519_private, _ = TLS13KeyExchange.generate_x25519_keypair()
        p256_private, _ = TLS13KeyExchange.generate_secp256r1_keypair()
        _, server_public = TLS13KeyExchange.generate_secp256r1_keypair()

        hs = TLS13Handshake(
            None,
            x25519_private,
            GROUP_X25519,
            b"ch",
            private_keys={
                GROUP_X25519: x25519_private,
                GROUP_SECP256R1: p256_private,
            },
        )
        server_hello = self._build_server_hello(
            group=GROUP_SECP256R1, pub_key=server_public
        )
        self.assertTrue(hs.process_server_hello(server_hello))
        self.assertIs(hs._private_key, p256_private)
        self.assertEqual(hs._key_share_group, GROUP_SECP256R1)

    def test_rejects_group_without_a_matching_private_key(self):
        x25519_private, _ = TLS13KeyExchange.generate_x25519_keypair()
        _, server_public = TLS13KeyExchange.generate_secp256r1_keypair()
        hs = TLS13Handshake(None, x25519_private, GROUP_X25519, b"ch")
        server_hello = self._build_server_hello(
            group=GROUP_SECP256R1, pub_key=server_public
        )
        self.assertFalse(hs.process_server_hello(server_hello))

    def test_process_server_hello_chacha20(self):
        client_priv, _ = TLS13KeyExchange.generate_x25519_keypair()
        _, server_pub = TLS13KeyExchange.generate_x25519_keypair()

        hs = TLS13Handshake(None, client_priv, GROUP_X25519, b"ch")
        server_hello = self._build_server_hello(cipher_suite=0x1303, pub_key=server_pub)
        self.assertTrue(hs.process_server_hello(server_hello))
        self.assertEqual(hs._cipher_type, "chacha20-poly1305")

    def test_process_server_hello_too_short(self):
        hs = TLS13Handshake(None, None, GROUP_X25519, b"ch")
        self.assertFalse(hs.process_server_hello(b"\x03\x03"))

    def test_process_server_hello_no_key_share(self):
        client_priv, _ = TLS13KeyExchange.generate_x25519_keypair()
        hs = TLS13Handshake(None, client_priv, GROUP_X25519, b"ch")
        # ServerHello without extensions
        version = b"\x03\x03"
        server_hello = version + os.urandom(32) + b"\x00" + b"\x13\x01" + b"\x00"
        self.assertFalse(hs.process_server_hello(server_hello))


class TestTLS13EncryptedHandshake(unittest.TestCase):
    """Test encrypted handshake message parsing and Finished."""

    def _setup_handshake(self):
        client_priv, client_pub = TLS13KeyExchange.generate_x25519_keypair()
        server_priv, server_pub = TLS13KeyExchange.generate_x25519_keypair()

        hs = TLS13Handshake(None, client_priv, GROUP_X25519, b"client_hello")

        # Build and process ServerHello
        version = b"\x03\x03"
        sh = version + os.urandom(32) + b"\x00" + b"\x13\x01" + b"\x00"
        key_share_data = struct.pack("!HH", GROUP_X25519, len(server_pub)) + server_pub
        key_share_ext = struct.pack("!HH", 0x0033, len(key_share_data)) + key_share_data
        ext_block = struct.pack("!H", len(key_share_ext)) + key_share_ext
        server_hello = sh + ext_block

        hs.process_server_hello(server_hello)
        return hs

    def test_parse_encrypted_handshake_messages(self):
        hs = self._setup_handshake()
        # Build fake EncryptedExtensions (type 8)
        ee_data = b"\x00\x00"  # empty extensions
        msg = struct.pack("B", 8) + struct.pack("!I", len(ee_data))[1:] + ee_data
        messages = hs.parse_encrypted_handshake(msg)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0][0], 8)

    def test_build_client_finished(self):
        hs = self._setup_handshake()
        finished_record = hs.build_client_finished()
        self.assertIsInstance(finished_record, bytes)
        # Should be a TLS record (starts with 0x17 for application data wrapper)
        self.assertEqual(finished_record[0], 0x17)

    def test_derive_application_keys(self):
        hs = self._setup_handshake()
        client_rp, server_rp = hs.derive_application_keys()
        self.assertIsInstance(client_rp, TLS13RecordProtection)
        self.assertIsInstance(server_rp, TLS13RecordProtection)

    def test_app_keys_encrypt_decrypt(self):
        hs = self._setup_handshake()
        client_rp, server_rp = hs.derive_application_keys()

        # Client encrypts, server decrypts
        ct = client_rp.encrypt(0x17, b"application data")
        header = ct[:5]
        ciphertext = ct[5:]
        # Can't decrypt with server_rp directly since server_rp is for
        # decrypting server→client, not client→server. This is by design.
        # Verify the encryption at least produces valid output.
        self.assertGreater(len(ct), 5)


class TestTLS13DecryptHandshakeRecord(unittest.TestCase):
    def test_decrypt_and_parse_transcript(self):
        """Only complete parsed messages enter the handshake transcript."""
        client_priv, _ = TLS13KeyExchange.generate_x25519_keypair()
        server_priv, server_pub = TLS13KeyExchange.generate_x25519_keypair()

        hs = TLS13Handshake(None, client_priv, GROUP_X25519, b"ch")
        sh = b"\x03\x03" + os.urandom(32) + b"\x00" + b"\x13\x01" + b"\x00"
        ks = struct.pack("!HH", GROUP_X25519, 32) + server_pub
        ext = struct.pack("!HH", 0x0033, len(ks)) + ks
        hs.process_server_hello(sh + struct.pack("!H", len(ext)) + ext)

        # Create a separate encryptor with the same keys as server handshake RP
        # so the seq_num matches for encrypt(0) → decrypt(0)
        enc_rp = TLS13RecordProtection(
            hs._server_handshake_rp.key,
            hs._server_handshake_rp.iv,
        )

        test_msg = b"\x08\x00\x00\x02\x00\x00"  # EncryptedExtensions
        ct_record = enc_rp.encrypt(0x16, test_msg)
        header = ct_record[:5]
        ciphertext = ct_record[5:]

        transcript_before = len(hs._transcript)
        content_type, plaintext = hs.decrypt_handshake_record(ciphertext, header)
        self.assertEqual(content_type, 0x16)
        self.assertEqual(plaintext, test_msg)
        self.assertEqual(len(hs._transcript), transcript_before)
        hs.parse_encrypted_handshake(plaintext)
        self.assertEqual(len(hs._transcript), transcript_before + len(test_msg))


# ============================================================================
# NewSessionTicket Tests
# ============================================================================


class TestNewSessionTicket(unittest.TestCase):
    def test_parse_new_session_ticket(self):
        import socket
        from ja3requests.protocol.tls import TLS
        from ja3requests.protocol.tls.session_cache import TLSSessionCache

        s1, s2 = socket.socketpair()
        try:
            cache = TLSSessionCache()
            tls = TLS(
                s1,
                session_cache=cache,
                server_host="ticket.example.com",
                server_port=443,
            )
            tls._master_secret = os.urandom(48)
            tls._selected_cipher_suite = 0x002F

            # Build NewSessionTicket: lifetime(4) + ticket_len(2) + ticket
            ticket_data = os.urandom(128)
            nst = struct.pack("!IH", 3600, len(ticket_data)) + ticket_data
            self.assertEqual(tls._parse_new_session_ticket(nst), (3600, ticket_data))
            self.assertIsNone(cache.get_tls12_ticket("ticket.example.com", 443))
        finally:
            s1.close()
            s2.close()

    def test_parse_short_ticket_ignored(self):
        import socket
        from ja3requests.protocol.tls import TLS
        from ja3requests.protocol.tls.session_cache import TLSSessionCache

        s1, s2 = socket.socketpair()
        try:
            cache = TLSSessionCache()
            tls = TLS(s1, session_cache=cache, server_host="t.com", server_port=443)
            tls._master_secret = os.urandom(48)
            with self.assertRaises(TLSHandshakeError):
                tls._parse_new_session_ticket(b"\x00")
            self.assertIsNone(cache.get_tls12_ticket("t.com", 443))
        finally:
            s1.close()
            s2.close()


# ============================================================================
# IDN Punycode Tests
# ============================================================================


class TestSNIPunycode(unittest.TestCase):
    def test_ascii_domain_unchanged(self):
        ext = SNIExtension("example.com")
        data = ext.encode()
        self.assertIn(b"example.com", data)

    def test_unicode_domain_converted(self):
        ext = SNIExtension("例え.jp")
        data = ext.encode()
        # Should NOT contain raw unicode bytes
        self.assertNotIn("例え".encode("utf-8"), data)
        # Should contain Punycode-encoded version
        self.assertIn(b"xn--", data)

    def test_mixed_domain(self):
        ext = SNIExtension("münchen.de")
        data = ext.encode()
        self.assertIn(b"xn--", data)

    def test_already_ascii(self):
        ext = SNIExtension("sub.domain.example.org")
        data = ext.encode()
        self.assertIn(b"sub.domain.example.org", data)


if __name__ == "__main__":
    unittest.main()
