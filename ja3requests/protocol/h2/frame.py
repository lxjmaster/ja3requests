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

from __future__ import annotations

import struct
from typing import Dict, List, Mapping, Optional, Sequence, Tuple, Union


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
    SETTINGS_ENABLE_PUSH: 0,
    SETTINGS_MAX_CONCURRENT_STREAMS: 100,
    SETTINGS_INITIAL_WINDOW_SIZE: 65535,
    SETTINGS_MAX_FRAME_SIZE: 16384,
    SETTINGS_MAX_HEADER_LIST_SIZE: 16384,
}

H2Settings = Union[Mapping[int, int], Sequence[Tuple[int, int]]]
H2Priority = Tuple[int, int, int, bool]
DEFAULT_PSEUDO_HEADER_ORDER = (":method", ":authority", ":scheme", ":path")


def _integer(value: int, minimum: int, maximum: int, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ValueError(f"Invalid HTTP/2 {label}: {value!r}")


def normalize_settings(settings: Optional[H2Settings]) -> Tuple[Tuple[int, int], ...]:
    """Validate and snapshot exact wire pairs; repeated IDs retain wire order."""
    if settings is None:
        settings = DEFAULT_SETTINGS
    if isinstance(settings, Mapping):
        pairs = tuple(settings.items())
    elif isinstance(settings, Sequence) and not isinstance(settings, (str, bytes)):
        pairs = tuple(settings)
    else:
        raise ValueError("HTTP/2 settings must be a mapping or ordered pairs")
    if len(pairs) * 6 > 16384:
        raise ValueError("HTTP/2 initial SETTINGS exceeds the default frame size")
    for pair in pairs:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ValueError("HTTP/2 settings must contain (identifier, value) pairs")
        setting_id, value = pair
        _integer(setting_id, 0, 65535, "setting identifier")
        _integer(value, 0, 0xFFFFFFFF, "setting value")
        if setting_id == SETTINGS_ENABLE_PUSH and value != 0:
            raise ValueError(
                "HTTP/2 server push is not supported; ENABLE_PUSH must be 0"
            )
        if setting_id == SETTINGS_INITIAL_WINDOW_SIZE and value > 0x7FFFFFFF:
            raise ValueError("Invalid HTTP/2 initial stream window")
        if setting_id == SETTINGS_MAX_FRAME_SIZE and not 16384 <= value <= 16777215:
            raise ValueError("Invalid HTTP/2 maximum frame size")
    return tuple((identifier, value) for identifier, value in pairs)


def validate_initial_window(increment: Optional[int]) -> None:
    """Zero/None omit the frame; positive increments cannot overflow 65535."""
    if increment is not None:
        _integer(
            increment, 0, 0x7FFFFFFF - 65535, "initial connection window increment"
        )


def normalize_pseudo_header_order(order: Optional[Sequence[str]]) -> Tuple[str, ...]:
    if order is None:
        return DEFAULT_PSEUDO_HEADER_ORDER
    if (
        not isinstance(order, Sequence)
        or isinstance(order, (str, bytes))
        or len(order) != 4
        or any(not isinstance(name, str) for name in order)
        or set(order) != set(DEFAULT_PSEUDO_HEADER_ORDER)
    ):
        raise ValueError(
            "HTTP/2 pseudo-header order must contain each request pseudo-header once"
        )
    return tuple(order)


def normalize_priority_frames(
    frames: Optional[Sequence[H2Priority]],
) -> Tuple[H2Priority, ...]:
    if frames is None:
        return ()
    if not isinstance(frames, Sequence) or isinstance(frames, (str, bytes)):
        raise ValueError("HTTP/2 priority frames must be an ordered sequence")
    result = []
    for priority in frames:
        if not isinstance(priority, (tuple, list)) or len(priority) != 4:
            raise ValueError(
                "HTTP/2 priority must be (stream_id, dependency, weight, exclusive)"
            )
        stream_id, dependency, weight, exclusive = priority
        _integer(stream_id, 1, 0x7FFFFFFF, "priority stream identifier")
        _integer(dependency, 0, 0x7FFFFFFF, "priority dependency")
        _integer(weight, 1, 256, "priority weight")
        if dependency == stream_id or not isinstance(exclusive, bool):
            raise ValueError("Invalid HTTP/2 priority dependency or exclusive flag")
        result.append((stream_id, dependency, weight, exclusive))
    return tuple(result)


class H2Frame:
    """Represents an HTTP/2 frame."""

    HEADER_SIZE = 9  # 3 (length) + 1 (type) + 1 (flags) + 4 (stream_id)

    def __init__(
        self,
        frame_type: int = 0,
        flags: int = 0,
        stream_id: int = 0,
        payload: bytes = b"",
    ) -> None:
        self.type = frame_type
        self.flags = flags
        self.stream_id = stream_id & 0x7FFFFFFF  # Clear reserved bit
        self.payload = payload

    @property
    def length(self) -> int:
        return len(self.payload)

    @property
    def type_name(self) -> str:
        return FRAME_TYPE_NAMES.get(self.type, f"UNKNOWN(0x{self.type:02X})")

    def serialize(self) -> bytes:
        """Serialize frame to bytes for sending."""
        header = struct.pack("!I", self.length)[1:]  # 24-bit length (3 bytes)
        header += struct.pack("!BB", self.type, self.flags)
        header += struct.pack("!I", self.stream_id)
        return header + self.payload

    @staticmethod
    def parse(data: bytes) -> Tuple[Optional[H2Frame], bytes]:
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

        payload = data[H2Frame.HEADER_SIZE : total_size]
        remaining = data[total_size:]

        frame = H2Frame(frame_type, flags, stream_id, payload)
        return frame, remaining

    @staticmethod
    def parse_all(
        data: bytes, max_payload_size: Optional[int] = None
    ) -> Tuple[List[H2Frame], bytes]:
        """Parse all complete frames from data, return (frames, remaining)."""
        frames: List[H2Frame] = []
        while len(data) >= H2Frame.HEADER_SIZE:
            if (
                max_payload_size is not None
                and int.from_bytes(data[:3], "big") > max_payload_size
            ):
                raise ValueError("HTTP/2 frame exceeds local maximum frame size")
            frame, data = H2Frame.parse(data)
            if frame is None:
                break
            frames.append(frame)
        return frames, data

    def __repr__(self) -> str:
        return (
            f"<H2Frame {self.type_name} stream={self.stream_id} "
            f"flags=0x{self.flags:02X} length={self.length}>"
        )


# ============================================================================
# Frame Builders
# ============================================================================


def build_settings_frame(
    settings: Optional[H2Settings] = None, ack: bool = False
) -> H2Frame:
    """
    Build a SETTINGS frame.

    :param settings: Mapping or ordered (setting_id, value) pairs; None is empty
    :param ack: If True, build a SETTINGS ACK frame (empty payload)
    :return: H2Frame
    """
    if ack:
        return H2Frame(FRAME_SETTINGS, FLAG_ACK, 0, b"")

    payload = b""
    for setting_id, value in normalize_settings({} if settings is None else settings):
        payload += struct.pack("!HI", setting_id, value)

    return H2Frame(FRAME_SETTINGS, 0, 0, payload)


def build_window_update_frame(stream_id: int, increment: int) -> H2Frame:
    """
    Build a WINDOW_UPDATE frame.

    :param stream_id: Stream ID (0 for connection-level)
    :param increment: Window size increment
    :return: H2Frame
    """
    _integer(stream_id, 0, 0x7FFFFFFF, "window stream identifier")
    _integer(increment, 1, 0x7FFFFFFF, "window increment")
    payload = struct.pack("!I", increment)
    return H2Frame(FRAME_WINDOW_UPDATE, 0, stream_id, payload)


def build_priority_frame(
    stream_id: int, dependency: int, weight: int, exclusive: bool = False
) -> H2Frame:
    """Encode a legacy PRIORITY signal without opening a request stream."""
    normalize_priority_frames([(stream_id, dependency, weight, exclusive)])
    payload = struct.pack(
        "!IB", dependency | (0x80000000 if exclusive else 0), weight - 1
    )
    return H2Frame(FRAME_PRIORITY, 0, stream_id, payload)


def build_headers_frame(
    stream_id: int,
    header_block: bytes,
    end_stream: bool = False,
    end_headers: bool = True,
) -> H2Frame:
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


def build_data_frame(stream_id: int, data: bytes, end_stream: bool = False) -> H2Frame:
    """
    Build a DATA frame.

    :param stream_id: Stream ID
    :param data: Payload bytes
    :param end_stream: Set END_STREAM flag
    :return: H2Frame
    """
    flags = FLAG_END_STREAM if end_stream else 0
    return H2Frame(FRAME_DATA, flags, stream_id, data)


def build_goaway_frame(
    last_stream_id: int, error_code: int = 0, debug_data: bytes = b""
) -> H2Frame:
    """Build a GOAWAY frame."""
    payload = struct.pack("!II", last_stream_id & 0x7FFFFFFF, error_code)
    payload += debug_data
    return H2Frame(FRAME_GOAWAY, 0, 0, payload)


def build_ping_frame(opaque_data: bytes = b"\x00" * 8, ack: bool = False) -> H2Frame:
    """Build a PING frame."""
    flags = FLAG_ACK if ack else 0
    return H2Frame(FRAME_PING, flags, 0, opaque_data[:8].ljust(8, b"\x00"))


def build_rst_stream_frame(stream_id: int, error_code: int = 0) -> H2Frame:
    """Build a RST_STREAM frame."""
    payload = struct.pack("!I", error_code)
    return H2Frame(FRAME_RST_STREAM, 0, stream_id, payload)


# ============================================================================
# Settings Parser
# ============================================================================


def parse_settings_pairs(payload: bytes) -> List[Tuple[int, int]]:
    """Parse every SETTINGS entry in wire order, including repeated IDs."""
    if len(payload) % 6:
        raise ValueError("Invalid HTTP/2 SETTINGS frame")
    return list(struct.iter_unpack("!HI", payload))


def parse_settings_payload(payload: bytes) -> Dict[int, int]:
    """Return final SETTINGS values; protocol application uses ordered pairs."""
    return dict(parse_settings_pairs(payload))


def header_block_fragment(frame: H2Frame) -> bytes:
    """Return a HEADERS field block without optional priority or padding fields."""
    payload = frame.payload
    offset = 0
    padding = 0
    if frame.flags & FLAG_PADDED:
        if not payload:
            raise ValueError("Invalid HTTP/2 HEADERS padding")
        padding = payload[0]
        offset = 1
    if frame.flags & FLAG_PRIORITY:
        if len(payload) - offset < 5:
            raise ValueError("Invalid HTTP/2 HEADERS priority fields")
        offset += 5
    if padding > len(payload) - offset:
        raise ValueError("Invalid HTTP/2 HEADERS padding")
    return payload[offset : len(payload) - padding if padding else len(payload)]


def data_payload(frame: H2Frame) -> bytes:
    """Return DATA content without the optional Pad Length and padding bytes."""
    if not frame.flags & FLAG_PADDED:
        return frame.payload
    if not frame.payload:
        raise ValueError("Invalid HTTP/2 DATA padding")
    padding = frame.payload[0]
    if padding > frame.length - 1:
        raise ValueError("Invalid HTTP/2 DATA padding")
    return frame.payload[1 : frame.length - padding if padding else frame.length]
