"""
ja3requests.protocol.h2.frame
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HTTP/2 frame parser and serializer (RFC 7540 Section 4).

Frame format:
    +-----------------------------------------------+
    |                 Length (24)                    |
    +---------------+---------------+---------------+
    |   Type (8)    |   Flags (8)   |
    +-+-------------+---------------+-------------------------------+
    |R|                 Stream Identifier (31)                      |
    +=+=============================================================+
    |                   Frame Payload (0...)                      ...
    +---------------------------------------------------------------+
"""

import struct


# Frame types (RFC 7540 Section 6)
FRAME_DATA = 0x00
FRAME_HEADERS = 0x01
FRAME_PRIORITY = 0x02
FRAME_RST_STREAM = 0x03
FRAME_SETTINGS = 0x04
FRAME_PUSH_PROMISE = 0x05
FRAME_PING = 0x06
FRAME_GOAWAY = 0x07
FRAME_WINDOW_UPDATE = 0x08
FRAME_CONTINUATION = 0x09

# Frame flag constants
FLAG_END_STREAM = 0x01
FLAG_END_HEADERS = 0x04
FLAG_PADDED = 0x08
FLAG_PRIORITY = 0x20
FLAG_ACK = 0x01  # For SETTINGS and PING

FRAME_TYPE_NAMES = {
    FRAME_DATA: "DATA",
    FRAME_HEADERS: "HEADERS",
    FRAME_PRIORITY: "PRIORITY",
    FRAME_RST_STREAM: "RST_STREAM",
    FRAME_SETTINGS: "SETTINGS",
    FRAME_PUSH_PROMISE: "PUSH_PROMISE",
    FRAME_PING: "PING",
    FRAME_GOAWAY: "GOAWAY",
    FRAME_WINDOW_UPDATE: "WINDOW_UPDATE",
    FRAME_CONTINUATION: "CONTINUATION",
}

# Settings identifiers (RFC 7540 Section 6.5.2)
SETTINGS_HEADER_TABLE_SIZE = 0x01
SETTINGS_ENABLE_PUSH = 0x02
SETTINGS_MAX_CONCURRENT_STREAMS = 0x03
SETTINGS_INITIAL_WINDOW_SIZE = 0x04
SETTINGS_MAX_FRAME_SIZE = 0x05
SETTINGS_MAX_HEADER_LIST_SIZE = 0x06

# HTTP/2 connection preface
CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Default settings
DEFAULT_SETTINGS = {
    SETTINGS_HEADER_TABLE_SIZE: 4096,
    SETTINGS_ENABLE_PUSH: 1,
    SETTINGS_MAX_CONCURRENT_STREAMS: 100,
    SETTINGS_INITIAL_WINDOW_SIZE: 65535,
    SETTINGS_MAX_FRAME_SIZE: 16384,
    SETTINGS_MAX_HEADER_LIST_SIZE: 16384,
}


class H2Frame:
    """Represents an HTTP/2 frame."""

    HEADER_SIZE = 9  # 3 (length) + 1 (type) + 1 (flags) + 4 (stream_id)

    def __init__(self, frame_type=0, flags=0, stream_id=0, payload=b""):
        self.type = frame_type
        self.flags = flags
        self.stream_id = stream_id & 0x7FFFFFFF  # Clear reserved bit
        self.payload = payload

    @property
    def length(self):
        return len(self.payload)

    @property
    def type_name(self):
        return FRAME_TYPE_NAMES.get(self.type, f"UNKNOWN(0x{self.type:02X})")

    def serialize(self):
        """Serialize frame to bytes for sending."""
        header = struct.pack("!I", self.length)[1:]  # 24-bit length (3 bytes)
        header += struct.pack("!BB", self.type, self.flags)
        header += struct.pack("!I", self.stream_id)
        return header + self.payload

    @staticmethod
    def parse(data):
        """
        Parse a single frame from bytes.
        Returns (H2Frame, remaining_bytes) or (None, data) if incomplete.
        """
        if len(data) < H2Frame.HEADER_SIZE:
            return None, data

        length = struct.unpack("!I", b"\x00" + data[:3])[0]
        frame_type = data[3]
        flags = data[4]
        stream_id = struct.unpack("!I", data[5:9])[0] & 0x7FFFFFFF

        total_size = H2Frame.HEADER_SIZE + length
        if len(data) < total_size:
            return None, data

        payload = data[H2Frame.HEADER_SIZE:total_size]
        remaining = data[total_size:]

        frame = H2Frame(frame_type, flags, stream_id, payload)
        return frame, remaining

    @staticmethod
    def parse_all(data):
        """Parse all complete frames from data, return (frames, remaining)."""
        frames = []
        while len(data) >= H2Frame.HEADER_SIZE:
            frame, data = H2Frame.parse(data)
            if frame is None:
                break
            frames.append(frame)
        return frames, data

    def __repr__(self):
        return (
            f"<H2Frame {self.type_name} stream={self.stream_id} "
            f"flags=0x{self.flags:02X} length={self.length}>"
        )


# ============================================================================
# Frame Builders
# ============================================================================

def build_settings_frame(settings=None, ack=False):
    """
    Build a SETTINGS frame.

    :param settings: Dict of {setting_id: value}
    :param ack: If True, build a SETTINGS ACK frame (empty payload)
    :return: H2Frame
    """
    if ack:
        return H2Frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")

    payload = b""
    for setting_id, value in (settings or {}).items():
        payload += struct.pack("!HI", setting_id, value)

    return H2Frame(FRAME_SETTINGS, 0, 0, payload)


def build_window_update_frame(stream_id, increment):
    """
    Build a WINDOW_UPDATE frame.

    :param stream_id: Stream ID (0 for connection-level)
    :param increment: Window size increment
    :return: H2Frame
    """
    payload = struct.pack("!I", increment & 0x7FFFFFFF)
    return H2Frame(FRAME_WINDOW_UPDATE, 0, stream_id, payload)


def build_headers_frame(stream_id, header_block, end_stream=False, end_headers=True):
    """
    Build a HEADERS frame.

    :param stream_id: Stream ID
    :param header_block: HPACK-encoded header block
    :param end_stream: Set END_STREAM flag
    :param end_headers: Set END_HEADERS flag
    :return: H2Frame
    """
    flags = 0
    if end_stream:
        flags |= FLAG_END_STREAM
    if end_headers:
        flags |= FLAG_END_HEADERS
    return H2Frame(FRAME_HEADERS, flags, stream_id, header_block)


def build_data_frame(stream_id, data, end_stream=False):
    """
    Build a DATA frame.

    :param stream_id: Stream ID
    :param data: Payload bytes
    :param end_stream: Set END_STREAM flag
    :return: H2Frame
    """
    flags = FLAG_END_STREAM if end_stream else 0
    return H2Frame(FRAME_DATA, flags, stream_id, data)


def build_goaway_frame(last_stream_id, error_code=0, debug_data=b""):
    """Build a GOAWAY frame."""
    payload = struct.pack("!II", last_stream_id & 0x7FFFFFFF, error_code)
    payload += debug_data
    return H2Frame(FRAME_GOAWAY, 0, 0, payload)


def build_ping_frame(opaque_data=b"\x00" * 8, ack=False):
    """Build a PING frame."""
    flags = FLAG_ACK if ack else 0
    return H2Frame(FRAME_PING, flags, 0, opaque_data[:8].ljust(8, b"\x00"))


def build_rst_stream_frame(stream_id, error_code=0):
    """Build a RST_STREAM frame."""
    payload = struct.pack("!I", error_code)
    return H2Frame(FRAME_RST_STREAM, 0, stream_id, payload)


# ============================================================================
# Settings Parser
# ============================================================================

def parse_settings_payload(payload):
    """Parse SETTINGS frame payload into dict."""
    settings = {}
    offset = 0
    while offset + 6 <= len(payload):
        setting_id, value = struct.unpack("!HI", payload[offset:offset + 6])
        settings[setting_id] = value
        offset += 6
    return settings
