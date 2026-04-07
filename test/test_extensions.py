"""Tests for ja3requests.protocol.tls.extensions module."""

import struct
import unittest

from ja3requests.protocol.tls.extensions import (
    Extension,
    SNIExtension,
    SupportedGroupsExtension,
    SignatureAlgorithmsExtension,
    ALPNExtension,
    ECPointFormatsExtension,
    SessionTicketExtension,
    ExtendedMasterSecretExtension,
    RenegotiationInfoExtension,
    StatusRequestExtension,
)


class TestExtensionBase(unittest.TestCase):
    """Test the Extension ABC."""

    def test_cannot_instantiate_abc(self):
        with self.assertRaises(TypeError):
            Extension()

    def test_to_bytes_includes_type_and_length(self):
        ext = SNIExtension("example.com")
        raw = ext.to_bytes()
        ext_type, ext_len = struct.unpack("!HH", raw[:4])
        self.assertEqual(ext_type, 0x0000)
        self.assertEqual(ext_len, len(raw) - 4)

    def test_repr(self):
        ext = SNIExtension("example.com")
        self.assertIn("SNIExtension", repr(ext))
        self.assertIn("0x0000", repr(ext))


class TestSNIExtension(unittest.TestCase):
    """Test Server Name Indication extension."""

    def test_extension_type(self):
        self.assertEqual(SNIExtension.extension_type, 0x0000)

    def test_encode_structure(self):
        ext = SNIExtension("example.com")
        data = ext.encode()
        # Should have: 2 bytes list length, 1 byte name type, 2 bytes name length, name
        name = b"example.com"
        expected_entry_len = 1 + 2 + len(name)  # type + name_len + name
        list_len = struct.unpack("!H", data[:2])[0]
        self.assertEqual(list_len, expected_entry_len)

        name_type = data[2]
        self.assertEqual(name_type, 0)  # hostname

        name_len = struct.unpack("!H", data[3:5])[0]
        self.assertEqual(name_len, len(name))

        self.assertEqual(data[5:], name)

    def test_to_bytes_roundtrip(self):
        ext = SNIExtension("test.example.com")
        raw = ext.to_bytes()
        # First 2 bytes: type, next 2: length
        self.assertEqual(struct.unpack("!H", raw[:2])[0], 0x0000)


class TestSupportedGroupsExtension(unittest.TestCase):
    """Test Supported Groups extension."""

    def test_extension_type(self):
        self.assertEqual(SupportedGroupsExtension.extension_type, 0x000A)

    def test_encode_single_group(self):
        ext = SupportedGroupsExtension([23])
        data = ext.encode()
        # 2 bytes length + 2 bytes per group
        groups_len = struct.unpack("!H", data[:2])[0]
        self.assertEqual(groups_len, 2)
        group = struct.unpack("!H", data[2:4])[0]
        self.assertEqual(group, 23)

    def test_encode_multiple_groups(self):
        groups = [23, 24, 25, 29]
        ext = SupportedGroupsExtension(groups)
        data = ext.encode()
        groups_len = struct.unpack("!H", data[:2])[0]
        self.assertEqual(groups_len, len(groups) * 2)
        for i, expected in enumerate(groups):
            actual = struct.unpack("!H", data[2 + i * 2:4 + i * 2])[0]
            self.assertEqual(actual, expected)


class TestSignatureAlgorithmsExtension(unittest.TestCase):
    """Test Signature Algorithms extension."""

    def test_extension_type(self):
        self.assertEqual(SignatureAlgorithmsExtension.extension_type, 0x000D)

    def test_encode(self):
        algs = [0x0401, 0x0501, 0x0601]
        ext = SignatureAlgorithmsExtension(algs)
        data = ext.encode()
        algs_len = struct.unpack("!H", data[:2])[0]
        self.assertEqual(algs_len, len(algs) * 2)
        for i, expected in enumerate(algs):
            actual = struct.unpack("!H", data[2 + i * 2:4 + i * 2])[0]
            self.assertEqual(actual, expected)


class TestALPNExtension(unittest.TestCase):
    """Test ALPN extension."""

    def test_extension_type(self):
        self.assertEqual(ALPNExtension.extension_type, 0x0010)

    def test_encode_single_protocol(self):
        ext = ALPNExtension(["http/1.1"])
        data = ext.encode()
        # 2 bytes list length, then: 1 byte proto length + proto
        list_len = struct.unpack("!H", data[:2])[0]
        proto_len = data[2]
        self.assertEqual(proto_len, len("http/1.1"))
        proto = data[3:3 + proto_len].decode()
        self.assertEqual(proto, "http/1.1")
        self.assertEqual(list_len, 1 + proto_len)

    def test_encode_multiple_protocols(self):
        ext = ALPNExtension(["h2", "http/1.1"])
        data = ext.encode()
        list_len = struct.unpack("!H", data[:2])[0]
        # h2: 1 + 2 = 3, http/1.1: 1 + 8 = 9 => total 12
        self.assertEqual(list_len, 12)


class TestECPointFormatsExtension(unittest.TestCase):
    """Test EC Point Formats extension."""

    def test_extension_type(self):
        self.assertEqual(ECPointFormatsExtension.extension_type, 0x000B)

    def test_default_uncompressed(self):
        ext = ECPointFormatsExtension()
        data = ext.encode()
        fmt_count = data[0]
        self.assertEqual(fmt_count, 1)
        self.assertEqual(data[1], 0)  # uncompressed

    def test_custom_formats(self):
        ext = ECPointFormatsExtension([0, 1, 2])
        data = ext.encode()
        self.assertEqual(data[0], 3)


class TestSessionTicketExtension(unittest.TestCase):
    """Test Session Ticket extension."""

    def test_extension_type(self):
        self.assertEqual(SessionTicketExtension.extension_type, 0x0023)

    def test_empty_ticket(self):
        ext = SessionTicketExtension()
        data = ext.encode()
        self.assertEqual(data, b"")

    def test_with_ticket(self):
        ticket = b"\x01\x02\x03\x04"
        ext = SessionTicketExtension(ticket)
        self.assertEqual(ext.encode(), ticket)


class TestExtendedMasterSecretExtension(unittest.TestCase):
    """Test Extended Master Secret extension."""

    def test_extension_type(self):
        self.assertEqual(ExtendedMasterSecretExtension.extension_type, 0x0017)

    def test_empty_body(self):
        ext = ExtendedMasterSecretExtension()
        self.assertEqual(ext.encode(), b"")

    def test_to_bytes_length_zero(self):
        ext = ExtendedMasterSecretExtension()
        raw = ext.to_bytes()
        ext_type, ext_len = struct.unpack("!HH", raw[:4])
        self.assertEqual(ext_type, 0x0017)
        self.assertEqual(ext_len, 0)


class TestRenegotiationInfoExtension(unittest.TestCase):
    """Test Renegotiation Info extension."""

    def test_extension_type(self):
        self.assertEqual(RenegotiationInfoExtension.extension_type, 0xFF01)

    def test_initial_handshake(self):
        ext = RenegotiationInfoExtension()
        data = ext.encode()
        # 1 byte length (0) for empty renegotiated_connection
        self.assertEqual(data, b"\x00")


class TestStatusRequestExtension(unittest.TestCase):
    """Test Status Request (OCSP Stapling) extension."""

    def test_extension_type(self):
        self.assertEqual(StatusRequestExtension.extension_type, 0x0005)

    def test_encode(self):
        ext = StatusRequestExtension()
        data = ext.encode()
        # status_type(1) + responder_id_list_len(0) + request_extensions_len(0)
        self.assertEqual(len(data), 5)
        status_type = data[0]
        self.assertEqual(status_type, 1)  # ocsp


class TestClientHelloWithExtensions(unittest.TestCase):
    """Test that ClientHello correctly builds extensions from Extension objects."""

    def test_custom_extension_in_client_hello(self):
        from ja3requests.protocol.tls.layers.client_hello import ClientHello

        ext = ExtendedMasterSecretExtension()
        hello = ClientHello(
            _extensions=[ext],
        )
        # Extensions should be present in the message
        self.assertIsNotNone(hello.extensions)
        # The extension bytes should contain type 0x0017
        self.assertIn(struct.pack("!H", 0x0017), hello.extensions)

    def test_custom_extension_overrides_auto(self):
        """Custom SNI extension should override auto-generated one."""
        from ja3requests.protocol.tls.layers.client_hello import ClientHello

        custom_sni = SNIExtension("custom.example.com")
        hello = ClientHello(
            server_name="auto.example.com",
            _extensions=[custom_sni],
        )
        # Should contain custom name, not auto
        self.assertIn(b"custom.example.com", hello.extensions)
        self.assertNotIn(b"auto.example.com", hello.extensions)

    def test_mixed_custom_and_auto_extensions(self):
        """Custom extensions and auto-generated ones should coexist."""
        from ja3requests.protocol.tls.layers.client_hello import ClientHello

        ems = ExtendedMasterSecretExtension()
        hello = ClientHello(
            server_name="example.com",
            supported_groups=[23, 24],
            _extensions=[ems],
        )
        ext_data = hello.extensions
        # Should have SNI (auto), SupportedGroups (auto), and EMS (custom)
        self.assertIn(struct.pack("!H", 0x0000), ext_data)  # SNI
        self.assertIn(struct.pack("!H", 0x000A), ext_data)  # SupportedGroups
        self.assertIn(struct.pack("!H", 0x0017), ext_data)  # EMS


class TestTlsConfigWithExtensions(unittest.TestCase):
    """Test TlsConfig extension integration."""

    def test_add_extension_object(self):
        from ja3requests.protocol.tls.config import TlsConfig

        config = TlsConfig()
        ext = ECPointFormatsExtension()
        config.add_extension(ext)
        self.assertIn(ext, config.extensions)

    def test_ja3_string_includes_extension_types(self):
        from ja3requests.protocol.tls.config import TlsConfig

        config = TlsConfig()
        config.server_name = "example.com"
        config.add_extension(ExtendedMasterSecretExtension())
        ja3 = config.get_ja3_string()
        extensions_field = ja3.split(",")[2]
        # Should include EMS type (0x0017 = 23) and SNI type (0x0000 = 0)
        ext_types = extensions_field.split("-")
        self.assertIn("23", ext_types)  # EMS
        self.assertIn("0", ext_types)   # SNI


class TestJA3NoneEdgeCases(unittest.TestCase):
    """Test get_ja3_string with None values that could crash."""

    def test_ja3_with_none_supported_groups(self):
        from ja3requests.protocol.tls.config import TlsConfig

        config = TlsConfig()
        config.supported_groups = None
        # Should not crash
        ja3 = config.get_ja3_string()
        parts = ja3.split(",")
        self.assertEqual(len(parts), 5)
        self.assertEqual(parts[3], "")  # empty elliptic curves

    def test_ja3_with_empty_supported_groups(self):
        from ja3requests.protocol.tls.config import TlsConfig

        config = TlsConfig()
        config.supported_groups = []
        ja3 = config.get_ja3_string()
        parts = ja3.split(",")
        self.assertEqual(parts[3], "")


if __name__ == "__main__":
    unittest.main()
