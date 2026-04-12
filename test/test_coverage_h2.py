"""Coverage improvement tests for H2 and HPACK decoder."""

import struct
import unittest

from ja3requests.protocol.h2.hpack import (
    HPACKEncoder,
    HPACKDecoder,
    encode_integer,
    decode_integer,
    encode_string,
    decode_string,
    STATIC_TABLE,
)
from ja3requests.protocol.h2.frame import (
    H2Frame,
    FRAME_SETTINGS,
    FRAME_HEADERS,
    FRAME_DATA,
    FRAME_WINDOW_UPDATE,
    FRAME_PING,
    FRAME_GOAWAY,
    FRAME_RST_STREAM,
    FLAG_ACK,
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    parse_settings_payload,
    build_settings_frame,
    build_ping_frame,
    build_goaway_frame,
    build_window_update_frame,
    build_headers_frame,
    build_data_frame,
)
from ja3requests.protocol.h2.connection import H2Connection


class TestHPACKDecoderLiteral(unittest.TestCase):
    """Test HPACK decoder with literal headers."""

    def test_decode_literal_without_indexing(self):
        enc = HPACKEncoder()
        dec = HPACKDecoder()
        headers = [("x-custom-header", "custom-value")]
        encoded = enc.encode_headers(headers)
        decoded = dec.decode_headers(encoded)
        self.assertEqual(decoded, headers)

    def test_decode_literal_with_indexed_name(self):
        enc = HPACKEncoder()
        dec = HPACKDecoder()
        # :authority has static index 1, value is literal
        headers = [(":authority", "my.host.com")]
        encoded = enc.encode_headers(headers)
        decoded = dec.decode_headers(encoded)
        self.assertEqual(decoded, headers)

    def test_decode_multiple_mixed(self):
        enc = HPACKEncoder()
        dec = HPACKDecoder()
        headers = [
            (":method", "POST"),     # indexed
            (":path", "/api/v1"),    # name indexed, value literal
            ("content-type", "application/json"),  # name indexed, value literal
            ("x-request-id", "abc123"),  # fully literal
        ]
        encoded = enc.encode_headers(headers)
        decoded = dec.decode_headers(encoded)
        self.assertEqual(decoded, headers)

    def test_decode_incremental_indexing(self):
        """Test literal with incremental indexing (0x40 prefix)."""
        dec = HPACKDecoder()
        # Build literal with incremental indexing manually:
        # 0x40 | index=1 (:authority), then string value
        data = encode_integer(1, 6, 0x40)
        data += encode_string("indexed-host.com")
        headers = dec.decode_headers(data)
        self.assertEqual(headers[0], (":authority", "indexed-host.com"))
        # Should be added to dynamic table
        self.assertEqual(len(dec.dynamic_table), 1)

    def test_decode_dynamic_table_size_update(self):
        """Test dynamic table size update (0x20 prefix)."""
        dec = HPACKDecoder()
        # Size update: 0x20 | value
        data = encode_integer(4096, 5, 0x20)
        headers = dec.decode_headers(data)
        self.assertEqual(headers, [])


class TestDecodeString(unittest.TestCase):
    def test_decode_plain_string(self):
        data = encode_string("hello")
        result, offset = decode_string(data, 0)
        self.assertEqual(result, b"hello")
        self.assertEqual(offset, len(data))


class TestH2ConnectionReceive(unittest.TestCase):
    """Test H2Connection frame handling."""

    def test_handle_settings_ack(self):
        """SETTINGS ACK should be handled silently."""
        sent = []
        ack_frame = build_settings_frame(ack=True).serialize()

        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn._recv_buffer = ack_frame
        frames = conn._read_frames()
        for f in frames:
            if f.stream_id == 0:
                conn._handle_connection_frame(f)
        # No crash, no response needed for ACK

    def test_handle_peer_settings(self):
        """Peer SETTINGS should trigger ACK."""
        sent = []
        settings_frame = build_settings_frame({0x04: 32768}).serialize()

        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn._recv_buffer = settings_frame
        frames = conn._read_frames()
        for f in frames:
            conn._handle_connection_frame(f)
        # Should have sent SETTINGS ACK
        self.assertTrue(len(sent) > 0)
        ack, _ = H2Frame.parse(sent[-1])
        self.assertEqual(ack.type, FRAME_SETTINGS)
        self.assertEqual(ack.flags, FLAG_ACK)

    def test_handle_ping(self):
        """PING should trigger PING ACK."""
        sent = []
        ping = build_ping_frame(b"testping").serialize()

        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn._recv_buffer = ping
        frames = conn._read_frames()
        for f in frames:
            conn._handle_connection_frame(f)
        # Should respond with PING ACK
        ack, _ = H2Frame.parse(sent[-1])
        self.assertEqual(ack.type, FRAME_PING)
        self.assertTrue(ack.flags & FLAG_ACK)

    def test_handle_ping_ack_ignored(self):
        """PING ACK should not trigger another response."""
        sent = []
        ping_ack = build_ping_frame(b"testping", ack=True).serialize()

        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn._recv_buffer = ping_ack
        frames = conn._read_frames()
        for f in frames:
            conn._handle_connection_frame(f)
        # Should NOT send anything in response to PING ACK
        self.assertEqual(len(sent), 0)

    def test_handle_goaway(self):
        """GOAWAY should be handled gracefully."""
        sent = []
        goaway = build_goaway_frame(0, error_code=0).serialize()

        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn._recv_buffer = goaway
        frames = conn._read_frames()
        for f in frames:
            conn._handle_connection_frame(f)
        # No crash

    def test_handle_window_update(self):
        """WINDOW_UPDATE should be handled gracefully."""
        sent = []
        wu = build_window_update_frame(0, 65535).serialize()

        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn._recv_buffer = wu
        frames = conn._read_frames()
        for f in frames:
            conn._handle_connection_frame(f)

    def test_close(self):
        """close() should send GOAWAY."""
        sent = []
        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn.close()
        self.assertTrue(len(sent) > 0)
        frame, _ = H2Frame.parse(sent[-1])
        self.assertEqual(frame.type, FRAME_GOAWAY)

    def test_close_on_broken_connection(self):
        """close() should not raise on broken connection."""
        def broken_send(d):
            raise OSError("broken pipe")
        conn = H2Connection(broken_send, lambda n: b"")
        conn.close()  # Should not raise


class TestH2ConnectionRequest(unittest.TestCase):
    """Test H2Connection request building."""

    def test_request_skips_connection_headers(self):
        """Connection-specific headers should be stripped."""
        sent = []
        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn.send_request(
            "GET", "example.com", "/",
            headers=[
                ("Host", "example.com"),      # Should be skipped
                ("Connection", "keep-alive"),  # Should be skipped
                ("Accept", "text/html"),       # Should be kept
            ]
        )
        # Parse the HEADERS frame and decode
        frame, _ = H2Frame.parse(sent[0])
        dec = HPACKDecoder()
        headers = dec.decode_headers(frame.payload)
        header_names = [h[0] for h in headers]
        self.assertNotIn("host", header_names)
        self.assertNotIn("connection", header_names)
        self.assertIn("accept", header_names)

    def test_get_request_has_end_stream(self):
        """GET without body should have END_STREAM on HEADERS."""
        sent = []
        conn = H2Connection(lambda d: sent.append(d), lambda n: b"")
        conn.send_request("GET", "example.com", "/")
        frame, _ = H2Frame.parse(sent[0])
        self.assertTrue(frame.flags & FLAG_END_STREAM)


if __name__ == "__main__":
    unittest.main()
