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
    FRAME_PUSH_PROMISE,
    FRAME_PRIORITY,
    FRAME_CONTINUATION,
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    FLAG_ACK,
    FLAG_PADDED,
    FLAG_PRIORITY,
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
    SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_ENABLE_PUSH,
    header_block_fragment,
    data_payload,
)
from ja3requests.protocol.h2.hpack import (
    HPACKEncoder,
    HPACKDecoder,
    encode_integer,
    decode_integer,
    encode_string,
    decode_string,
    STATIC_TABLE,
)
from ja3requests.protocol.h2.connection import H2Connection
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection


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

    def test_parse_all_rejects_oversized_frame_before_payload(self):
        header = H2Frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, b"x" * 16385)
        with self.assertRaisesRegex(ValueError, "maximum frame size"):
            H2Frame.parse_all(header.serialize()[:9], max_payload_size=16384)

    def test_parse_all_accepts_frame_within_custom_maximum(self):
        frame = H2Frame(FRAME_DATA, 0, 1, b"x" * 20000)
        frames, remaining = H2Frame.parse_all(frame.serialize(), max_payload_size=32768)
        self.assertEqual([received.length for received in frames], [20000])
        self.assertEqual(remaining, b"")

    def test_roundtrip(self):
        original = H2Frame(FRAME_DATA, FLAG_END_STREAM, 3, b"test data")
        data = original.serialize()
        parsed, _ = H2Frame.parse(data)
        self.assertEqual(parsed.type, original.type)
        self.assertEqual(parsed.flags, original.flags)
        self.assertEqual(parsed.stream_id, original.stream_id)
        self.assertEqual(parsed.payload, original.payload)

    def test_headers_fragment_skips_priority_and_padding(self):
        frame = H2Frame(
            FRAME_HEADERS,
            FLAG_PRIORITY | FLAG_PADDED | FLAG_END_HEADERS,
            1,
            b"\x02\x00\x00\x00\x03\x0f\x88\x00\x00",
        )
        self.assertEqual(header_block_fragment(frame), b"\x88")

    def test_headers_fragment_rejects_incomplete_metadata(self):
        for flags, payload in (
            (FLAG_PADDED, b""),
            (FLAG_PRIORITY, b"\x00" * 4),
            (FLAG_PADDED | FLAG_PRIORITY, b"\x02" + b"\x00" * 5),
        ):
            with self.subTest(flags=flags, payload=payload):
                with self.assertRaisesRegex(ValueError, "Invalid HTTP/2 HEADERS"):
                    header_block_fragment(H2Frame(FRAME_HEADERS, flags, 1, payload))

    def test_data_payload_excludes_padding(self):
        for flags, payload, expected in (
            (0, b"plain", b"plain"),
            (FLAG_PADDED, b"\x02data\x00\x00", b"data"),
            (FLAG_PADDED, b"\x00data", b"data"),
            (FLAG_PADDED, b"\x00", b""),
        ):
            with self.subTest(flags=flags, payload=payload):
                self.assertEqual(
                    data_payload(H2Frame(FRAME_DATA, flags, 1, payload)), expected
                )

    def test_invalid_data_padding_rejected_even_on_unknown_stream(self):
        for payload in (b"", b"\x02x"):
            for connection_type in (H2Connection, H2MultiplexConnection):
                with self.subTest(payload=payload, connection_type=connection_type):
                    conn = connection_type(lambda data: None, lambda size: b"")
                    conn._recv_buffer = H2Frame(
                        FRAME_DATA, FLAG_PADDED, 9, payload
                    ).serialize()
                    with self.assertRaisesRegex(
                        ValueError, "Invalid HTTP/2 DATA padding"
                    ):
                        conn._read_frames()

    def test_data_on_connection_stream_rejected(self):
        conn = H2Connection(lambda data: None, lambda size: b"")
        conn._recv_buffer = H2Frame(FRAME_DATA, 0, 0, b"x").serialize()
        with self.assertRaisesRegex(ValueError, "DATA requires a stream"):
            conn._read_frames()


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
        frame = build_headers_frame(
            1, b"header_block", end_stream=True, end_headers=True
        )
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

    def test_truncated_integer_is_rejected(self):
        for data in (b"", b"\x1f", b"\x1f\x80"):
            with self.subTest(data=data):
                with self.assertRaisesRegex(ValueError, "Truncated HPACK integer"):
                    decode_integer(data, 0, 5)

    def test_oversized_integer_is_rejected(self):
        for data in (encode_integer(1 << 32, 5), b"\x1f" + b"\x80" * 5 + b"\x00"):
            with self.subTest(data=data):
                with self.assertRaisesRegex(ValueError, "HPACK integer exceeds"):
                    decode_integer(data, 0, 5)


class TestHPACKString(unittest.TestCase):
    """Test HPACK string encoding."""

    def test_encode_string(self):
        result = encode_string("hello")
        self.assertEqual(result[0], 5)  # length without Huffman
        self.assertEqual(result[1:], b"hello")

    def test_truncated_string_is_rejected(self):
        for data in (b"", b"\x05ab", b"\x7f", b"\x7f\x80"):
            with self.subTest(data=data):
                with self.assertRaisesRegex(ValueError, "Truncated HPACK"):
                    decode_string(data, 0)


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
        result = enc.encode_headers(
            [
                (":method", "GET"),
                (":path", "/"),
                (":scheme", "https"),
                (":authority", "example.com"),
            ]
        )
        self.assertTrue(len(result) > 4)

    def test_peer_table_size_change_starts_next_block_with_update(self):
        enc = HPACKEncoder()
        enc.encode_headers([("x-custom", "value")])
        enc.set_table_size(0)
        self.assertEqual(enc.dynamic_table, [])
        block = enc.encode_headers([(':method', 'GET')])
        self.assertEqual(block[:1], b'\x20')
        self.assertNotEqual(enc.encode_headers([(':method', 'GET')])[:1], b'\x20')


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

    def test_size_update_evicts_entries_and_allows_reinsertion(self):
        dec = HPACKDecoder(64)
        insert = b"\x40" + encode_string("x-token") + encode_string("value")
        self.assertEqual(dec.decode_headers(insert), [("x-token", "value")])
        self.assertEqual(
            dec.decode_headers(encode_integer(62, 7, 0x80)), [("x-token", "value")]
        )

        dec.decode_headers(encode_integer(0, 5, 0x20))
        self.assertEqual(dec.dynamic_table, [])
        with self.assertRaisesRegex(ValueError, "Invalid HPACK header index 62"):
            dec.decode_headers(encode_integer(62, 7, 0x80))

        dec.decode_headers(encode_integer(64, 5, 0x20) + insert)
        self.assertEqual(
            dec.decode_headers(encode_integer(62, 7, 0x80)), [("x-token", "value")]
        )

    def test_insertion_evicts_oldest_using_utf8_byte_size(self):
        dec = HPACKDecoder(70)
        first = b"\x40" + encode_string("x") + encode_string("é")
        second = b"\x40" + encode_string("y") + encode_string("z")
        third = b"\x40" + encode_string("q") + encode_string("r")
        dec.decode_headers(first + second)
        self.assertEqual(dec._dynamic_table_size, 69)
        dec.decode_headers(third)
        self.assertEqual(dec.dynamic_table, [("q", "r"), ("y", "z")])
        self.assertEqual(dec._dynamic_table_size, 68)
        with self.assertRaisesRegex(ValueError, "Invalid HPACK header index 64"):
            dec.decode_headers(encode_integer(64, 7, 0x80))

    def test_dynamic_name_lookup_and_oversized_entry(self):
        dec = HPACKDecoder(40)
        first = b"\x40" + encode_string("x-name") + encode_string("a")
        dec.decode_headers(first)
        self.assertEqual(
            dec.decode_headers(encode_integer(62, 6, 0x40) + encode_string("b")),
            [("x-name", "b")],
        )
        dec.decode_headers(
            b"\x40" + encode_string("x-name") + encode_string("long" * 20)
        )
        self.assertEqual(dec.dynamic_table, [])

    def test_rejects_invalid_size_update_and_index(self):
        dec = HPACKDecoder(64)
        with self.assertRaisesRegex(ValueError, "advertised limit"):
            dec.decode_headers(encode_integer(65, 5, 0x20))
        with self.assertRaisesRegex(ValueError, "after header field"):
            dec.decode_headers(b"\x88" + encode_integer(0, 5, 0x20))
        for block in (b"\x80", encode_integer(62, 4) + encode_string("value")):
            with self.subTest(block=block):
                with self.assertRaisesRegex(ValueError, "Invalid HPACK header index"):
                    dec.decode_headers(block)

    def test_larger_advertised_limit_requires_size_update_to_use_it(self):
        dec = HPACKDecoder(8192)
        large_entry = b"\x40" + encode_string("x") + encode_string("v" * 5000)
        dec.decode_headers(large_entry)
        self.assertEqual(dec.dynamic_table, [])
        dec.decode_headers(encode_integer(8192, 5, 0x20) + large_entry)
        self.assertEqual(len(dec.dynamic_table), 1)


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
        self.assertEqual(parse_settings_payload(frame.payload)[SETTINGS_ENABLE_PUSH], 0)

    def test_cannot_advertise_unsupported_push(self):
        for connection_type in (H2Connection, H2MultiplexConnection):
            with self.subTest(connection_type=connection_type):
                with self.assertRaisesRegex(ValueError, "push is not supported"):
                    connection_type(
                        lambda data: None,
                        lambda size: b"",
                        settings={SETTINGS_ENABLE_PUSH: 1},
                    )

    def test_custom_header_table_limit_applies_to_both_connection_paths(self):
        for connection_type in (H2Connection, H2MultiplexConnection):
            with self.subTest(connection_type=connection_type):
                conn = connection_type(
                    lambda data: None,
                    lambda size: b"",
                    settings={SETTINGS_HEADER_TABLE_SIZE: 64},
                )
                with self.assertRaisesRegex(ValueError, "advertised limit"):
                    conn._decoder.decode_headers(encode_integer(65, 5, 0x20))

    def test_push_promise_rejected_on_both_connection_paths(self):
        promise = H2Frame(
            FRAME_PUSH_PROMISE, FLAG_END_HEADERS, 1, b"\x00\x00\x00\x02\x82"
        )
        for connection_type in (H2Connection, H2MultiplexConnection):
            with self.subTest(connection_type=connection_type):
                conn = connection_type(lambda data: None, lambda size: b"")
                conn._recv_buffer = promise.serialize()
                with self.assertRaisesRegex(ConnectionError, "PUSH_PROMISE"):
                    conn._read_frames()

    def test_invalid_control_frame_stream_ids_fail_both_connection_paths(self):
        frames = (
            H2Frame(FRAME_HEADERS, FLAG_END_HEADERS, 0, b"\x88"),
            H2Frame(FRAME_RST_STREAM, 0, 0, b"\x00" * 4),
            H2Frame(FRAME_SETTINGS, 0, 1, b""),
            H2Frame(FRAME_PING, 0, 1, b"\x00" * 8),
            H2Frame(FRAME_GOAWAY, 0, 1, b"\x00" * 8),
        )
        for connection_type in (H2Connection, H2MultiplexConnection):
            for frame in frames:
                with self.subTest(connection_type=connection_type, frame=frame):
                    conn = connection_type(lambda data: None, lambda size: b"")
                    conn._recv_buffer = frame.serialize()
                    with self.assertRaisesRegex(ValueError, "requires"):
                        conn._read_frames()

    def test_invalid_control_frame_lengths_fail_both_connection_paths(self):
        frames = (
            H2Frame(FRAME_RST_STREAM, 0, 1, b"\x00" * 3),
            H2Frame(FRAME_PING, 0, 0, b"\x00" * 7),
            H2Frame(FRAME_SETTINGS, FLAG_ACK, 0, b"\x00"),
        )
        for connection_type in (H2Connection, H2MultiplexConnection):
            for frame in frames:
                with self.subTest(connection_type=connection_type, frame=frame):
                    conn = connection_type(lambda data: None, lambda size: b"")
                    conn._recv_buffer = frame.serialize()
                    with self.assertRaisesRegex(ValueError, "Invalid HTTP/2"):
                        conn._read_frames()

    def test_local_frame_size_limit_applies_to_both_connection_paths(self):
        oversized_header = H2Frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, b"x" * 16385)
        accepted_frame = H2Frame(FRAME_DATA, 0, 1, b"x" * 20000)
        for connection_type in (H2Connection, H2MultiplexConnection):
            with self.subTest(connection_type=connection_type):
                conn = connection_type(lambda data: None, lambda size: b"")
                conn._recv_buffer = oversized_header.serialize()[:9]
                with self.assertRaisesRegex(ValueError, "maximum frame size"):
                    conn._read_frames()

                conn = connection_type(
                    lambda data: None,
                    lambda size: b"",
                    settings={SETTINGS_MAX_FRAME_SIZE: 32768},
                )
                conn._recv_buffer = accepted_frame.serialize()
                self.assertEqual(
                    [frame.length for frame in conn._read_frames()], [20000]
                )

    def test_server_preface_requires_initial_settings_on_both_paths(self):
        invalid_first_frames = (
            H2Frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, b"\x88"),
            build_ping_frame(),
            build_settings_frame(ack=True),
        )
        for connection_type in (H2Connection, H2MultiplexConnection):
            for frame in invalid_first_frames:
                with self.subTest(connection_type=connection_type, frame=frame):
                    conn = connection_type(lambda raw: None, lambda size: b"")
                    conn._preface_sent = True
                    conn._recv_buffer = frame.serialize()
                    with self.assertRaisesRegex(ValueError, "server preface"):
                        conn._read_frames()

    def test_server_preface_accepts_settings_followed_by_response(self):
        settings = build_settings_frame()
        headers = H2Frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, b"\x88")
        for connection_type in (H2Connection, H2MultiplexConnection):
            with self.subTest(connection_type=connection_type):
                conn = connection_type(lambda raw: None, lambda size: b"")
                conn._preface_sent = True
                conn._next_stream_id = 3
                conn._recv_buffer = settings.serialize() + headers.serialize()
                frames = conn._read_frames()
                self.assertEqual(
                    [frame.type for frame in frames], [FRAME_SETTINGS, FRAME_HEADERS]
                )
                self.assertTrue(conn._server_preface_received)

    def test_server_preface_settings_can_be_fragmented(self):
        settings = build_settings_frame({SETTINGS_INITIAL_WINDOW_SIZE: 32768})
        wire = settings.serialize()
        pieces = iter((wire[:5], wire[5:9], wire[9:]))
        conn = H2Connection(lambda raw: None, lambda size: next(pieces))
        conn._preface_sent = True
        self.assertEqual(conn._read_frames(), [])
        self.assertEqual(conn._read_frames(), [])
        self.assertEqual(
            [frame.type for frame in conn._read_frames()], [FRAME_SETTINGS]
        )
        self.assertTrue(conn._server_preface_received)

    def test_frames_on_idle_stream_fail_both_connection_paths(self):
        frames = (
            H2Frame(FRAME_DATA, 0, 3, b"unexpected"),
            H2Frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, b"\x88"),
            build_rst_stream_frame(3, 0),
            build_window_update_frame(3, 1),
            H2Frame(FRAME_HEADERS, FLAG_END_HEADERS, 2, b"\x88"),
        )
        for connection_type in (H2Connection, H2MultiplexConnection):
            for frame in frames:
                with self.subTest(connection_type=connection_type, frame=frame):
                    conn = connection_type(lambda raw: None, lambda size: b"")
                    conn._preface_sent = True
                    conn._server_preface_received = True
                    conn._next_stream_id = 3  # Stream 1 was opened locally.
                    conn._recv_buffer = frame.serialize()
                    with self.assertRaisesRegex(ValueError, "idle stream"):
                        conn._read_frames()

    def test_idle_priority_and_unknown_frame_remain_allowed(self):
        frames = (
            H2Frame(FRAME_PRIORITY, 0, 3, b"\x00" * 5),
            H2Frame(0xFA, 0, 3, b"extension"),
            H2Frame(FRAME_DATA, 0, 1, b"late"),
        )
        for connection_type in (H2Connection, H2MultiplexConnection):
            with self.subTest(connection_type=connection_type):
                conn = connection_type(lambda raw: None, lambda size: b"")
                conn._preface_sent = True
                conn._server_preface_received = True
                conn._next_stream_id = 3
                conn._recv_buffer = b"".join(frame.serialize() for frame in frames)
                self.assertEqual(
                    [frame.serialize() for frame in conn._read_frames()],
                    [frame.serialize() for frame in frames],
                )

    def test_response_data_before_headers_fails_both_connection_paths(self):
        for connection_type in (H2Connection, H2MultiplexConnection):
            with self.subTest(connection_type=connection_type):
                data = H2Frame(FRAME_DATA, FLAG_END_STREAM, 1, b"unexpected")
                if connection_type is H2Connection:
                    conn = connection_type(
                        lambda raw: None, lambda size: data.serialize()
                    )
                    with self.assertRaisesRegex(ValueError, "before response headers"):
                        conn.receive_response(1)
                else:
                    conn = connection_type(lambda raw: None, lambda size: b"")
                    conn._peer_settings_received = True
                    stream_id = conn.send_request("GET", "example.com", "/")
                    with self.assertRaisesRegex(ValueError, "before response headers"):
                        conn._dispatch_frame(data)

    def test_response_requires_one_status_in_both_connection_paths(self):
        encoder = HPACKEncoder()
        blocks = (
            b"",
            encoder.encode_headers([("x-test", "value")]),
            encoder.encode_headers([(':status', '200'), (':status', '404')]),
            encoder.encode_headers([(':status', '20x')]),
            encoder.encode_headers([(':status', '101')]),
        )
        for connection_type in (H2Connection, H2MultiplexConnection):
            for block in blocks:
                with self.subTest(connection_type=connection_type, block=block):
                    frame = H2Frame(
                        FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, block
                    )
                    if connection_type is H2Connection:
                        conn = connection_type(
                            lambda raw: None, lambda size: frame.serialize()
                        )
                        with self.assertRaisesRegex(ValueError, ":status"):
                            conn.receive_response(1)
                    else:
                        conn = connection_type(lambda raw: None, lambda size: b"")
                        conn._peer_settings_received = True
                        conn.send_request("GET", "example.com", "/")
                        with self.assertRaisesRegex(ValueError, ":status"):
                            conn._dispatch_frame(frame)

    def test_interim_response_and_trailers_preserve_final_headers(self):
        encoder = HPACKEncoder()
        frames = (
            H2Frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS,
                1,
                encoder.encode_headers([(':status', '103')]),
            ),
            H2Frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS,
                1,
                encoder.encode_headers([(':status', '200'), ('x-final', 'yes')]),
            ),
            H2Frame(FRAME_DATA, 0, 1, b"body"),
            H2Frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                encoder.encode_headers([('x-trailer', 'done')]),
            ),
        )
        expected = ([(':status', '200'), ('x-final', 'yes')], b"body")
        for connection_type in (H2Connection, H2MultiplexConnection):
            with self.subTest(connection_type=connection_type):
                if connection_type is H2Connection:
                    wire = b"".join(frame.serialize() for frame in frames)
                    conn = connection_type(lambda raw: None, lambda size: wire)
                    self.assertEqual(conn.receive_response(1), expected)
                else:
                    conn = connection_type(lambda raw: None, lambda size: b"")
                    conn._peer_settings_received = True
                    conn.send_request("GET", "example.com", "/")
                    for frame in frames:
                        conn._dispatch_frame(frame)
                    self.assertEqual(conn.receive_response(1), expected)

    def test_interim_response_requires_final_headers(self):
        interim = H2Frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            1,
            HPACKEncoder().encode_headers([(':status', '103')]),
        )
        ended_interim = H2Frame(
            FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, interim.payload
        )
        cases = (
            ((ended_interim,), "interim response ended stream"),
            (
                (interim, H2Frame(FRAME_DATA, FLAG_END_STREAM, 1, b"body")),
                "before response headers",
            ),
        )
        for connection_type in (H2Connection, H2MultiplexConnection):
            for frames, message in cases:
                with self.subTest(connection_type=connection_type, message=message):
                    if connection_type is H2Connection:
                        wire = b"".join(frame.serialize() for frame in frames)
                        conn = connection_type(lambda raw: None, lambda size: wire)
                        with self.assertRaisesRegex(ValueError, message):
                            conn.receive_response(1)
                    else:
                        conn = connection_type(lambda raw: None, lambda size: b"")
                        conn._peer_settings_received = True
                        conn.send_request("GET", "example.com", "/")
                        with self.assertRaisesRegex(ValueError, message):
                            for frame in frames:
                                conn._dispatch_frame(frame)

    def test_response_frames_after_end_stream_fail_both_connection_paths(self):
        ending_headers = H2Frame(
            FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, b"\x88"
        )
        late_frames = (
            H2Frame(FRAME_DATA, 0, 1, b"late"),
            H2Frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                HPACKEncoder().encode_headers([("x-late", "value")]),
            ),
        )
        for connection_type in (H2Connection, H2MultiplexConnection):
            for late_frame in late_frames:
                with self.subTest(connection_type=connection_type, frame=late_frame):
                    if connection_type is H2Connection:
                        wire = ending_headers.serialize() + late_frame.serialize()
                        conn = connection_type(lambda raw: None, lambda size: wire)
                        with self.assertRaisesRegex(ValueError, "after END_STREAM"):
                            conn.receive_response(1)
                    else:
                        conn = connection_type(lambda raw: None, lambda size: b"")
                        conn._peer_settings_received = True
                        conn.send_request("GET", "example.com", "/")
                        conn._dispatch_frame(ending_headers)
                        with self.assertRaisesRegex(ValueError, "after END_STREAM"):
                            conn._dispatch_frame(late_frame)
                        self.assertEqual(conn._streams[1].body, b"")
                        self.assertTrue(conn.failed)
                        with self.assertRaisesRegex(
                            ConnectionError, "after END_STREAM"
                        ):
                            conn.receive_response(1)

    def test_control_frames_after_end_stream_do_not_fail_response(self):
        ending_headers = H2Frame(
            FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, b"\x88"
        )
        control_frames = (
            build_window_update_frame(1, 1),
            build_rst_stream_frame(1, 0),
        )
        expected = ([(':status', '200')], b"")
        for connection_type in (H2Connection, H2MultiplexConnection):
            with self.subTest(connection_type=connection_type):
                if connection_type is H2Connection:
                    wire = ending_headers.serialize() + b"".join(
                        frame.serialize() for frame in control_frames
                    )
                    conn = connection_type(lambda raw: None, lambda size: wire)
                    self.assertEqual(conn.receive_response(1), expected)
                else:
                    conn = connection_type(lambda raw: None, lambda size: b"")
                    conn._peer_settings_received = True
                    conn.send_request("GET", "example.com", "/")
                    conn._dispatch_frame(ending_headers)
                    for frame in control_frames:
                        conn._dispatch_frame(frame)
                    self.assertEqual(conn.receive_response(1), expected)

    def test_server_cannot_enable_push(self):
        for value in (1, 2):
            setting = build_settings_frame({SETTINGS_ENABLE_PUSH: value})
            for connection_type in (H2Connection, H2MultiplexConnection):
                with self.subTest(value=value, connection_type=connection_type):
                    conn = connection_type(lambda data: None, lambda size: b"")
                    with self.assertRaisesRegex(ValueError, "Invalid server"):
                        conn._handle_connection_frame(setting)

    def test_legacy_priority_and_continuation_response(self):
        priority = H2Frame(FRAME_PRIORITY, 0, 5, b"\x00" * 5)
        headers = H2Frame(
            FRAME_HEADERS,
            FLAG_PRIORITY | FLAG_PADDED | FLAG_END_STREAM,
            1,
            b"\x01\x00\x00\x00\x03\x0f\x00",
        )
        continuation = H2Frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, b"\x88")
        wire = priority.serialize() + headers.serialize() + continuation.serialize()
        conn = H2Connection(lambda data: None, lambda size: wire)
        self.assertEqual(conn.receive_response(1), ([(':status', '200')], b""))

    def test_priority_on_connection_stream_rejected(self):
        conn = H2Connection(lambda data: None, lambda size: b"")
        conn._recv_buffer = H2Frame(FRAME_PRIORITY, 0, 0, b"\x00" * 5).serialize()
        with self.assertRaisesRegex(ValueError, "PRIORITY requires a stream"):
            conn._read_frames()

    def test_priority_cannot_interrupt_header_block(self):
        headers = H2Frame(FRAME_HEADERS, 0, 1, b"")
        priority = H2Frame(FRAME_PRIORITY, 0, 3, b"\x00" * 5)
        conn = H2Connection(lambda data: None, lambda size: b"")
        conn._recv_buffer = headers.serialize() + priority.serialize()
        with self.assertRaisesRegex(ValueError, "field block interrupted"):
            conn._read_frames()

    def test_invalid_priority_resets_only_active_stream(self):
        sent = []
        conn = H2MultiplexConnection(sent.append, lambda size: b"")
        conn._peer_settings_received = True
        first = conn.send_request("GET", "example.com", "/first")
        conn._dispatch_frame(H2Frame(FRAME_PRIORITY, 0, first, b"\x00" * 4))
        reset, _ = H2Frame.parse(sent[-1])
        self.assertEqual((reset.type, reset.stream_id), (FRAME_RST_STREAM, first))
        self.assertEqual(reset.payload, b"\x00\x00\x00\x06")
        with self.assertRaisesRegex(ConnectionError, "Invalid HTTP/2 PRIORITY"):
            conn.receive_response(first)
        self.assertFalse(conn.failed)

        second = conn.send_request("GET", "example.com", "/second")
        conn._dispatch_frame(
            H2Frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, second, b"\x88")
        )
        self.assertEqual(conn.receive_response(second), ([(':status', '200')], b""))

    def test_padded_data_uses_full_length_for_flow_control(self):
        sent = []
        conn = H2MultiplexConnection(sent.append, lambda size: b"")
        conn._local_settings[SETTINGS_INITIAL_WINDOW_SIZE] = 8
        conn._connection_receive_target = 8
        conn._connection_receive_window = 8
        conn._peer_settings_received = True
        stream_id = conn.send_request("GET", "example.com", "/")
        conn._dispatch_frame(
            H2Frame(FRAME_HEADERS, FLAG_END_HEADERS, stream_id, b"\x88")
        )
        conn._dispatch_frame(
            H2Frame(FRAME_DATA, FLAG_PADDED, stream_id, b"\x04a" + b"\x00" * 4)
        )
        self.assertEqual(conn._streams[stream_id].body, b"a")
        frames = [H2Frame.parse(raw)[0] for raw in sent]
        updates = [frame for frame in frames if frame.type == FRAME_WINDOW_UPDATE]
        self.assertEqual([frame.stream_id for frame in updates], [0, stream_id])
        self.assertEqual(
            [int.from_bytes(frame.payload, "big") for frame in updates], [6, 6]
        )

    def test_cancelled_fragmented_headers_update_hpack_table(self):
        sent = []
        server_encoder = HPACKEncoder()
        first_block = server_encoder.encode_headers(
            [(":status", "200"), ("x-token", "value")]
        )
        second_block = server_encoder.encode_headers(
            [(":status", "200"), ("x-token", "value")]
        )
        conn = H2MultiplexConnection(sent.append, lambda size: b"")
        conn._peer_settings_received = True
        first = conn.send_request("GET", "example.com", "/first")
        conn._dispatch_frame(H2Frame(FRAME_HEADERS, 0, first, first_block[:3]))
        conn.cancel_stream(first)
        conn._dispatch_frame(
            H2Frame(FRAME_CONTINUATION, FLAG_END_HEADERS, first, first_block[3:])
        )

        second = conn.send_request("GET", "example.com", "/second")
        conn._dispatch_frame(
            H2Frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                second,
                second_block,
            )
        )
        headers, _ = conn.receive_response(second)
        self.assertIn(("x-token", "value"), headers)

    def test_other_stream_headers_update_hpack_table(self):
        server_encoder = HPACKEncoder()
        first_block = server_encoder.encode_headers([("x-token", "value")])
        second_block = server_encoder.encode_headers(
            [(":status", "200"), ("x-token", "value")]
        )
        wire = (
            H2Frame(
                FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, first_block
            ).serialize()
            + H2Frame(
                FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, second_block
            ).serialize()
        )
        conn = H2Connection(lambda data: None, lambda size: wire)
        headers, _ = conn.receive_response(1)
        self.assertIn(("x-token", "value"), headers)

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

    def test_send_body_applies_peer_settings_change(self):
        sent = []
        received = iter(
            [
                build_settings_frame({SETTINGS_INITIAL_WINDOW_SIZE: 2}).serialize(),
                build_settings_frame({SETTINGS_INITIAL_WINDOW_SIZE: 4}).serialize(),
            ]
        )
        conn = H2Connection(sent.append, lambda n: next(received))
        conn.initiate()

        assert conn.send_request("POST", "example.com", "/", body=b"abcd") == 1
        data = [H2Frame.parse(raw)[0] for raw in sent if raw != CONNECTION_PREFACE]
        data = [frame for frame in data if frame.type == FRAME_DATA]
        assert [frame.payload for frame in data] == [b"ab", b"cd"]
        assert not data[0].flags & FLAG_END_STREAM
        assert data[1].flags & FLAG_END_STREAM

    def test_reset_while_sending_body_aborts_stream(self):
        sent = []
        received = iter(
            [
                build_settings_frame({SETTINGS_INITIAL_WINDOW_SIZE: 2}).serialize(),
                build_rst_stream_frame(1, 2).serialize(),
            ]
        )
        conn = H2Connection(sent.append, lambda n: next(received))
        conn.initiate()

        with self.assertRaisesRegex(ConnectionError, "reset by peer"):
            conn.send_request("POST", "example.com", "/", body=b"abcd")
        data = [H2Frame.parse(raw)[0] for raw in sent if raw != CONNECTION_PREFACE]
        data = [frame for frame in data if frame.type == FRAME_DATA]
        assert [frame.payload for frame in data] == [b"ab"]

    def test_early_response_data_releases_receive_window_during_upload(self):
        sent = []
        early = build_headers_frame(1, b"\x88").serialize()
        early += b"".join(
            build_data_frame(1, b"r" * 16000).serialize() for _ in range(3)
        )
        early += build_window_update_frame(1, 1).serialize()
        received = iter(
            [
                build_settings_frame({SETTINGS_INITIAL_WINDOW_SIZE: 1}).serialize(),
                early,
                build_data_frame(1, b"end", end_stream=True).serialize(),
            ]
        )
        conn = H2Connection(sent.append, lambda n: next(received))
        conn.initiate()

        conn.send_request("POST", "example.com", "/", body=b"ab")
        frames = [H2Frame.parse(raw)[0] for raw in sent if raw != CONNECTION_PREFACE]
        updates = [
            frame.stream_id for frame in frames if frame.type == FRAME_WINDOW_UPDATE
        ]
        assert updates == [0, 1]
        assert [frame.payload for frame in frames if frame.type == FRAME_DATA] == [
            b"a",
            b"b",
        ]
        _, body = conn.receive_response(1)
        assert body == b"r" * 48000 + b"end"

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
