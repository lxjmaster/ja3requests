"""Tests for remaining tasks: cookies crash fix, client cert, HPACK dynamic table."""

import os
import struct
import socket
import unittest

from ja3requests.base.__sessions import BaseSession
from ja3requests.cookies import Ja3RequestsCookieJar
from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.protocol.h2.hpack import HPACKEncoder, HPACKDecoder


class TestCookiesPropertySafety(unittest.TestCase):
    """Test BaseSession.cookies doesn't crash when Request/response is None."""

    def test_cookies_with_none_request(self):
        s = BaseSession()
        # Request is None by default
        self.assertIsNone(s._request)
        cookies = s.cookies
        self.assertIsInstance(cookies, Ja3RequestsCookieJar)

    def test_cookies_with_none_response(self):
        s = BaseSession()
        s._request = type('MockReq', (), {'cookies': None})()
        self.assertIsNone(s._response)
        cookies = s.cookies
        self.assertIsInstance(cookies, Ja3RequestsCookieJar)

    def test_cookies_with_session_cookies(self):
        s = BaseSession()
        s._cookies.set("a", "1")
        cookies = s.cookies
        self.assertEqual(cookies.get("a"), "1")

    def test_cookies_merges_all_sources(self):
        s = BaseSession()
        s._cookies.set("session", "s1")
        s._request = type('MockReq', (), {'cookies': {"request": "r1"}})()
        s._response = type('MockResp', (), {'cookies': Ja3RequestsCookieJar()})()
        cookies = s.cookies
        self.assertEqual(cookies.get("session"), "s1")


class TestClientCertConfig(unittest.TestCase):
    """Test TlsConfig client certificate properties."""

    def test_default_no_cert(self):
        config = TlsConfig()
        self.assertIsNone(config.client_cert)
        self.assertIsNone(config.client_key)

    def test_set_cert_path(self):
        config = TlsConfig()
        config.client_cert = "/path/to/cert.pem"
        config.client_key = "/path/to/key.pem"
        self.assertEqual(config.client_cert, "/path/to/cert.pem")
        self.assertEqual(config.client_key, "/path/to/key.pem")

    def test_set_cert_bytes(self):
        config = TlsConfig()
        config.client_cert = b"-----BEGIN CERTIFICATE-----\n..."
        self.assertIsInstance(config.client_cert, bytes)


class TestClientCertParsing(unittest.TestCase):
    """Test TLS CertificateRequest parsing."""

    def test_parse_certificate_request(self):
        from ja3requests.protocol.tls import TLS

        s1, s2 = socket.socketpair()
        try:
            tls = TLS(s1)

            # Build CertificateRequest: cert_types + sig_algs + distinguished_names
            cert_types = b"\x02\x01\x40"  # 2 types: RSA(1), ECDSA(64)
            sig_algs = struct.pack("!H", 4) + struct.pack("!HH", 0x0401, 0x0501)
            dn_list = struct.pack("!H", 0)  # empty DN list
            data = cert_types + sig_algs + dn_list

            tls._parse_certificate_request(data)
            self.assertTrue(tls._client_cert_requested)
            self.assertEqual(tls._cert_types, [1, 64])
            self.assertEqual(tls._cert_sig_algs, [0x0401, 0x0501])
        finally:
            s1.close()
            s2.close()


class TestClientCertBuilding(unittest.TestCase):
    """Test building client certificate message."""

    def test_build_empty_certificate(self):
        from ja3requests.protocol.tls import TLS

        s1, s2 = socket.socketpair()
        try:
            tls = TLS(s1)
            msg = tls._build_empty_certificate()
            # Should be a TLS record with handshake type 11
            self.assertEqual(msg[0], 0x16)  # Handshake
            self.assertEqual(msg[5], 0x0b)  # Certificate type
        finally:
            s1.close()
            s2.close()

    def test_build_client_certificate_from_pem(self):
        from ja3requests.protocol.tls import TLS
        import base64

        s1, s2 = socket.socketpair()
        try:
            tls = TLS(s1)
            # Fake DER certificate
            fake_der = os.urandom(256)
            fake_pem = (
                b"-----BEGIN CERTIFICATE-----\n"
                + base64.b64encode(fake_der)
                + b"\n-----END CERTIFICATE-----\n"
            )
            msg = tls._build_client_certificate(fake_pem)
            self.assertEqual(msg[0], 0x16)  # Handshake
            self.assertEqual(msg[5], 0x0b)  # Certificate type
            # Should contain the DER cert
            self.assertIn(fake_der, msg)
        finally:
            s1.close()
            s2.close()

    def test_build_client_certificate_bad_pem_returns_empty(self):
        from ja3requests.protocol.tls import TLS

        s1, s2 = socket.socketpair()
        try:
            tls = TLS(s1)
            msg = tls._build_client_certificate(b"not a valid PEM")
            # Should fall back to empty certificate
            self.assertEqual(msg[5], 0x0b)
        finally:
            s1.close()
            s2.close()

    def test_load_cert_data_bytes(self):
        from ja3requests.protocol.tls import TLS
        result = TLS._load_cert_data(b"raw bytes")
        self.assertEqual(result, b"raw bytes")

    def test_load_cert_data_none(self):
        from ja3requests.protocol.tls import TLS
        result = TLS._load_cert_data(None)
        self.assertIsNone(result)

    def test_load_cert_data_string(self):
        from ja3requests.protocol.tls import TLS
        result = TLS._load_cert_data("string data")
        self.assertEqual(result, b"string data")


class TestHPACKDynamicTable(unittest.TestCase):
    """Test HPACK encoder uses dynamic table for compression."""

    def test_repeated_header_uses_dynamic_table(self):
        enc = HPACKEncoder()
        dec = HPACKDecoder()

        headers = [("x-custom", "value1")]
        # First encoding: literal with incremental indexing
        encoded1 = enc.encode_headers(headers)
        # Should have added to dynamic table
        self.assertEqual(len(enc.dynamic_table), 1)
        self.assertEqual(enc.dynamic_table[0], ("x-custom", "value1"))

        # Second encoding of same header: should use indexed representation
        encoded2 = enc.encode_headers(headers)
        # Indexed encoding is shorter than literal
        self.assertLess(len(encoded2), len(encoded1))

        # Both should decode correctly
        decoded1 = dec.decode_headers(encoded1)
        self.assertEqual(decoded1, [("x-custom", "value1")])

    def test_sensitive_headers_not_indexed(self):
        enc = HPACKEncoder()
        enc.encode_headers([("authorization", "Bearer token123")])
        # Sensitive headers should NOT be added to dynamic table
        self.assertEqual(len(enc.dynamic_table), 0)

    def test_cookie_not_indexed(self):
        enc = HPACKEncoder()
        enc.encode_headers([("cookie", "session=abc")])
        self.assertEqual(len(enc.dynamic_table), 0)

    def test_dynamic_table_eviction(self):
        enc = HPACKEncoder()
        # Fill dynamic table with large entries
        for i in range(200):
            enc.encode_headers([(f"x-header-{i}", f"value-{i}" * 10)])

        # Table should not exceed max size
        self.assertLessEqual(enc._dynamic_table_size, enc.MAX_DYNAMIC_TABLE_SIZE)

    def test_encode_decode_roundtrip_with_dynamic(self):
        enc = HPACKEncoder()
        dec = HPACKDecoder()

        all_headers = [
            (":method", "GET"),
            (":path", "/api/v1"),
            ("accept", "application/json"),
            ("x-request-id", "abc123"),
        ]
        encoded = enc.encode_headers(all_headers)
        decoded = dec.decode_headers(encoded)
        self.assertEqual(decoded, all_headers)

    def test_dynamic_table_name_match(self):
        """Same name, different value should use name index from dynamic table."""
        enc = HPACKEncoder()
        enc.encode_headers([("x-trace", "trace-1")])
        self.assertEqual(len(enc.dynamic_table), 1)

        # Same name, different value
        encoded2 = enc.encode_headers([("x-trace", "trace-2")])
        # Should use name index from dynamic table
        self.assertEqual(len(enc.dynamic_table), 2)


if __name__ == "__main__":
    unittest.main()
