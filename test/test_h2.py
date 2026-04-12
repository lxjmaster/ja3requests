"""Tests for HTTP/2 implementation (#8)."""

import struct
import unittest

from ja3requests.protocol.h2.frame import (
    H2Frame,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_SETTINGS,
    FRAME_WINDOW_UPDATE,
    FRAME_PING,
    FRAME_GOAWAY,
    FRAME_RST_STREAM,
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    FLAG_ACK,
    CONNECTION_PREFACE,
    build_settings_frame,
    build_window_update_frame,
    build_headers_frame,
    build_data_frame,
    build_goaway_frame,
    build_ping_frame,
    build_rst_stream_frame,
    parse_settings_payload,
    SETTINGS_INITIAL_WINDOW_SIZE,
    SETTINGS_MAX_FRAME_SIZE,
)
from ja3requests.protocol.h2.hpack import (
    HPACKEncoder,
    HPACKDecoder,
    encode_integer,
    decode_integer,
    encode_string,
    STATIC_TABLE,
)
from ja3requests.protocol.h2.connection import H2Connection


# ============================================================================
# Frame Tests
# ============================================================================

class TestH2FrameSerialize(unittest.TestCase):
    """Test frame serialization."""

    def test_empty_frame(self):
        frame = H2Frame(FRAME_SETTINGS, 0, 0, b"")
        data = frame.serialize()
        self.assertEqual(len(data), 9)  # header only
        self.assertEqual(data[:3], b"\x00\x00\x00")  # length = 0
        self.assertEqual(data[3], FRAME_SETTINGS)

    def test_data_frame(self):
        frame = H2Frame(FRAME_DATA, FLAG_END_STREAM, 1, b"hello")
        data = frame.serialize()
        self.assertEqual(len(data), 9 + 5)
        # Length = 5
        length = struct.unpack("!I", b"\x00" + data[:3])[0]
        self.assertEqual(length, 5)
        self.assertEqual(data[3], FRAME_DATA)
        self.assertEqual(data[4], FLAG_END_STREAM)
        stream_id = struct.unpack("!I", data[5:9])[0]
        self.assertEqual(stream_id, 1)
        self.assertEqual(data[9:], b"hello")

    def test_stream_id_clears_reserved_bit(self):
        frame = H2Frame(FRAME_DATA, 0, 0xFFFFFFFF, b"")
        data = frame.serialize()
        stream_id = struct.unpack("!I", data[5:9])[0]
        self.assertEqual(stream_id, 0x7FFFFFFF)


class TestH2FrameParse(unittest.TestCase):
    """Test frame parsing."""

    def test_parse_settings(self):
        frame = build_settings_frame({SETTINGS_INITIAL_WINDOW_SIZE: 65535})
        data = frame.serialize()
        parsed, remaining = H2Frame.parse(data)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.type, FRAME_SETTINGS)
        self.assertEqual(remaining, b"")

    def test_parse_incomplete_header(self):
        frame, remaining = H2Frame.parse(b"\x00\x00")
        self.assertIsNone(frame)
        self.assertEqual(remaining, b"\x00\x00")

    def test_parse_incomplete_payload(self):
        # Header says 10 bytes payload, but only 5 provided
        data = b"\x00\x00\x0a\x00\x00\x00\x00\x00\x00" + b"12345"
        frame, remaining = H2Frame.parse(data)
        self.assertIsNone(frame)

    def test_parse_all_multiple_frames(self):
        f1 = build_settings_frame(ack=True)
        f2 = build_ping_frame()
        data = f1.serialize() + f2.serialize()
        frames, remaining = H2Frame.parse_all(data)
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0].type, FRAME_SETTINGS)
        self.assertEqual(frames[1].type, FRAME_PING)
        self.assertEqual(remaining, b"")

    def test_roundtrip(self):
        original = H2Frame(FRAME_DATA, FLAG_END_STREAM, 3, b"test data")
        data = original.serialize()
        parsed, _ = H2Frame.parse(data)
        self.assertEqual(parsed.type, original.type)
        self.assertEqual(parsed.flags, original.flags)
        self.assertEqual(parsed.stream_id, original.stream_id)
        self.assertEqual(parsed.payload, original.payload)


# ============================================================================
# Frame Builder Tests
# ============================================================================

class TestFrameBuilders(unittest.TestCase):
    """Test frame builder functions."""

    def test_settings_frame(self):
        frame = build_settings_frame({SETTINGS_INITIAL_WINDOW_SIZE: 32768})
        self.assertEqual(frame.type, FRAME_SETTINGS)
        self.assertEqual(frame.stream_id, 0)
        self.assertEqual(frame.length, 6)  # 1 setting = 6 bytes

    def test_settings_ack(self):
        frame = build_settings_frame(ack=True)
        self.assertEqual(frame.flags, FLAG_ACK)
        self.assertEqual(frame.length, 0)

    def test_window_update(self):
        frame = build_window_update_frame(0, 1048576)
        self.assertEqual(frame.type, FRAME_WINDOW_UPDATE)
        increment = struct.unpack("!I", frame.payload)[0]
        self.assertEqual(increment, 1048576)

    def test_headers_frame(self):
        frame = build_headers_frame(1, b"header_block", end_stream=True, end_headers=True)
        self.assertEqual(frame.type, FRAME_HEADERS)
        self.assertEqual(frame.stream_id, 1)
        self.assertEqual(frame.flags, FLAG_END_STREAM | FLAG_END_HEADERS)

    def test_data_frame(self):
        frame = build_data_frame(1, b"body", end_stream=True)
        self.assertEqual(frame.type, FRAME_DATA)
        self.assertEqual(frame.payload, b"body")
        self.assertEqual(frame.flags, FLAG_END_STREAM)

    def test_goaway_frame(self):
        frame = build_goaway_frame(0, error_code=0)
        self.assertEqual(frame.type, FRAME_GOAWAY)
        self.assertEqual(frame.stream_id, 0)

    def test_ping_frame(self):
        frame = build_ping_frame(b"12345678")
        self.assertEqual(frame.type, FRAME_PING)
        self.assertEqual(len(frame.payload), 8)

    def test_rst_stream_frame(self):
        frame = build_rst_stream_frame(3, error_code=2)
        self.assertEqual(frame.type, FRAME_RST_STREAM)
        self.assertEqual(frame.stream_id, 3)


class TestParseSettingsPayload(unittest.TestCase):
    """Test SETTINGS payload parsing."""

    def test_parse_single_setting(self):
        payload = struct.pack("!HI", SETTINGS_MAX_FRAME_SIZE, 32768)
        settings = parse_settings_payload(payload)
        self.assertEqual(settings[SETTINGS_MAX_FRAME_SIZE], 32768)

    def test_parse_multiple_settings(self):
        payload = struct.pack("!HI", 0x01, 4096) + struct.pack("!HI", 0x04, 65535)
        settings = parse_settings_payload(payload)
        self.assertEqual(len(settings), 2)
        self.assertEqual(settings[0x01], 4096)
        self.assertEqual(settings[0x04], 65535)


# ============================================================================
# HPACK Tests
# ============================================================================

class TestHPACKInteger(unittest.TestCase):
    """Test HPACK integer encoding/decoding."""

    def test_encode_small_value(self):
        result = encode_integer(10, 5)
        self.assertEqual(result, bytes([10]))

    def test_encode_max_prefix(self):
        result = encode_integer(31, 5)
        self.assertEqual(len(result), 2)

    def test_encode_large_value(self):
        result = encode_integer(1337, 5)
        self.assertTrue(len(result) > 1)

    def test_roundtrip(self):
        for value in [0, 1, 30, 31, 127, 128, 1337, 65535]:
            encoded = encode_integer(value, 5)
            decoded, _ = decode_integer(encoded, 0, 5)
            self.assertEqual(decoded, value, f"Failed for value {value}")


class TestHPACKString(unittest.TestCase):
    """Test HPACK string encoding."""

    def test_encode_string(self):
        result = encode_string("hello")
        self.assertEqual(result[0], 5)  # length without Huffman
        self.assertEqual(result[1:], b"hello")


class TestHPACKEncoder(unittest.TestCase):
    """Test HPACK header encoding."""

    def test_encode_static_indexed(self):
        enc = HPACKEncoder()
        # :method GET is static index 2
        result = enc.encode_headers([(":method", "GET")])
        self.assertTrue(result[0] & 0x80)  # Indexed header

    def test_encode_static_name_literal_value(self):
        enc = HPACKEncoder()
        result = enc.encode_headers([(":authority", "example.com")])
        self.assertTrue(len(result) > 1)

    def test_encode_new_header(self):
        enc = HPACKEncoder()
        result = enc.encode_headers([("x-custom", "value")])
        self.assertTrue(len(result) > 0)

    def test_encode_multiple_headers(self):
        enc = HPACKEncoder()
        result = enc.encode_headers([
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
            (":authority", "example.com"),
        ])
        self.assertTrue(len(result) > 4)


class TestHPACKDecoder(unittest.TestCase):
    """Test HPACK header decoding."""

    def test_decode_indexed(self):
        dec = HPACKDecoder()
        # Index 2 = :method GET
        data = encode_integer(2, 7, 0x80)
        headers = dec.decode_headers(data)
        self.assertEqual(headers[0], (":method", "GET"))

    def test_encode_decode_roundtrip(self):
        enc = HPACKEncoder()
        dec = HPACKDecoder()
        original = [
            (":method", "GET"),
            (":path", "/"),
            (":scheme", "https"),
        ]
        encoded = enc.encode_headers(original)
        decoded = dec.decode_headers(encoded)
        self.assertEqual(decoded, original)


# ============================================================================
# Connection Tests
# ============================================================================

class TestH2Connection(unittest.TestCase):
    """Test H2Connection management."""

    def test_initiate_sends_preface_and_settings(self):
        sent = []
        def fake_send(data):
            sent.append(data)
        def fake_recv(n):
            return b""

        conn = H2Connection(fake_send, fake_recv)
        conn.initiate()

        # First send: connection preface
        self.assertEqual(sent[0], CONNECTION_PREFACE)
        # Second send: SETTINGS frame
        frame, _ = H2Frame.parse(sent[1])
        self.assertEqual(frame.type, FRAME_SETTINGS)

    def test_initiate_with_window_update(self):
        sent = []
        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn.initiate(window_update_increment=15663105)
        # Should have 3 sends: preface, settings, window_update
        self.assertEqual(len(sent), 3)
        frame, _ = H2Frame.parse(sent[2])
        self.assertEqual(frame.type, FRAME_WINDOW_UPDATE)

    def test_send_request_returns_stream_id(self):
        sent = []
        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        sid = conn.send_request("GET", "example.com", "/")
        self.assertEqual(sid, 1)

    def test_stream_ids_increment(self):
        sent = []
        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        sid1 = conn.send_request("GET", "example.com", "/")
        sid2 = conn.send_request("GET", "example.com", "/page2")
        self.assertEqual(sid1, 1)
        self.assertEqual(sid2, 3)

    def test_send_request_with_body(self):
        sent = []
        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn.send_request("POST", "example.com", "/api", body=b'{"key":"val"}')
        # Should send HEADERS + DATA
        self.assertEqual(len(sent), 2)
        headers_frame, _ = H2Frame.parse(sent[0])
        data_frame, _ = H2Frame.parse(sent[1])
        self.assertEqual(headers_frame.type, FRAME_HEADERS)
        self.assertEqual(data_frame.type, FRAME_DATA)
        self.assertEqual(data_frame.payload, b'{"key":"val"}')

    def test_custom_settings_for_fingerprint(self):
        custom = {0x01: 65536, 0x03: 1000, 0x04: 6291456}
        conn = H2Connection(lambda d: None, lambda n: b"", settings=custom)
        self.assertEqual(conn._local_settings[0x01], 65536)
        self.assertEqual(conn._local_settings[0x03], 1000)


class TestH2Repr(unittest.TestCase):
    """Test repr methods."""

    def test_frame_repr(self):
        frame = H2Frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, b"data")
        r = repr(frame)
        self.assertIn("HEADERS", r)
        self.assertIn("stream=1", r)

    def test_unknown_frame_type(self):
        frame = H2Frame(0xFF, 0, 0, b"")
        r = repr(frame)
        self.assertIn("UNKNOWN", r)


if __name__ == "__main__":
    unittest.main()
