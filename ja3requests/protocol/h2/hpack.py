"""
ja3requests.protocol.h2.hpack
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Simplified HPACK header compression (RFC 7541).
Supports static table lookups and literal header encoding.
"""

import struct


# HPACK Static Table (RFC 7541 Appendix A) — first 61 entries
STATIC_TABLE = [
    None,  # index 0 is unused
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
]

# Build reverse lookup for static table
_STATIC_NAME_INDEX = {}
_STATIC_PAIR_INDEX = {}
for _i, _entry in enumerate(STATIC_TABLE):
    if _entry is None:
        continue
    _name, _value = _entry
    if _name not in _STATIC_NAME_INDEX:
        _STATIC_NAME_INDEX[_name] = _i
    if (_name, _value) and _value:
        _STATIC_PAIR_INDEX[(_name, _value)] = _i


def encode_integer(value, prefix_bits, first_byte=0):
    """
    Encode an integer using HPACK integer encoding (RFC 7541 Section 5.1).

    :param value: Integer to encode
    :param prefix_bits: Number of prefix bits (1-8)
    :param first_byte: The first byte with prefix bits already set
    :return: Encoded bytes
    """
    max_prefix = (1 << prefix_bits) - 1

    if value < max_prefix:
        return bytes([first_byte | value])

    result = bytes([first_byte | max_prefix])
    value -= max_prefix
    while value >= 128:
        result += bytes([(value & 0x7F) | 0x80])
        value >>= 7
    result += bytes([value])
    return result


def decode_integer(data, offset, prefix_bits):
    """
    Decode an HPACK-encoded integer (RFC 7541 Section 5.1).

    :return: (value, new_offset)
    """
    if offset >= len(data):
        raise ValueError("Truncated HPACK integer")
    max_prefix = (1 << prefix_bits) - 1
    value = data[offset] & max_prefix
    offset += 1

    if value < max_prefix:
        return value, offset

    m = 0
    while offset < len(data):
        if m >= 35:
            raise ValueError("HPACK integer exceeds 32-bit limit")
        b = data[offset]
        offset += 1
        value += (b & 0x7F) << m
        if value > 0xFFFFFFFF:
            raise ValueError("HPACK integer exceeds 32-bit limit")
        m += 7
        if b & 0x80 == 0:
            return value, offset

    raise ValueError("Truncated HPACK integer")


def encode_string(s):
    """
    Encode a string using HPACK string literal (without Huffman).

    :param s: String or bytes to encode
    :return: Encoded bytes
    """
    if isinstance(s, str):
        s = s.encode("utf-8")
    # No Huffman encoding (H=0)
    return encode_integer(len(s), 7, 0) + s


def decode_string(data, offset):
    """
    Decode an HPACK string literal (with Huffman support).

    :return: (string_bytes, new_offset)
    """
    if offset >= len(data):
        raise ValueError("Truncated HPACK string")
    huffman = data[offset] & 0x80
    length, offset = decode_integer(data, offset, 7)
    if length > len(data) - offset:
        raise ValueError("Truncated HPACK string")
    string_bytes = data[offset : offset + length]
    offset += length

    if huffman:
        from ja3requests.protocol.h2.huffman import (
            huffman_decode,
        )  # pylint: disable=import-outside-toplevel

        string_bytes = huffman_decode(string_bytes)

    return string_bytes, offset


class HPACKEncoder:
    """
    HPACK encoder with static and dynamic table support.
    Uses incremental indexing for repeated headers to improve compression.
    """

    MAX_DYNAMIC_TABLE_SIZE = 4096

    def __init__(self):
        self.dynamic_table = []  # List of (name, value) tuples, newest first
        self._dynamic_table_size = 0
        self._max_dynamic_table_size = self.MAX_DYNAMIC_TABLE_SIZE
        self._pending_table_size_min = None
        self._pending_table_size_final = None

    def set_table_size(self, size):
        """Apply a peer limit and announce it at the next header block."""
        size = min(size, self.MAX_DYNAMIC_TABLE_SIZE)
        if size == self._max_dynamic_table_size:
            return
        self._max_dynamic_table_size = size
        self._pending_table_size_final = size
        self._pending_table_size_min = (
            size
            if self._pending_table_size_min is None
            else min(self._pending_table_size_min, size)
        )
        while self._dynamic_table_size > size and self.dynamic_table:
            name, value = self.dynamic_table.pop()
            self._dynamic_table_size -= len(name) + len(value) + 32

    def encode_headers(self, headers):
        """
        Encode a list of (name, value) header tuples.

        :param headers: List of (name, value) tuples
        :return: Encoded header block bytes
        """
        result = b""
        if self._pending_table_size_final is not None:
            result += encode_integer(self._pending_table_size_min, 5, 0x20)
            if self._pending_table_size_final != self._pending_table_size_min:
                result += encode_integer(self._pending_table_size_final, 5, 0x20)
            self._pending_table_size_min = None
            self._pending_table_size_final = None
        for name, value in headers:
            result += self._encode_header(name, value)
        return result

    def _find_in_dynamic_table(self, name, value):
        """Search dynamic table for exact match or name match.
        Returns (exact_index, name_index) where index is 1-based from static table end.
        """
        name_match = None
        for i, (n, v) in enumerate(self.dynamic_table):
            idx = len(STATIC_TABLE) + i
            if n == name and v == value:
                return idx, idx  # exact match
            if n == name and name_match is None:
                name_match = idx
        return None, name_match

    def _add_to_dynamic_table(self, name, value):
        """Add a header to the dynamic table."""
        entry_size = len(name) + len(value) + 32  # per RFC 7541 Section 4.1
        # Evict entries if table would exceed max size
        while (
            self._dynamic_table_size + entry_size > self._max_dynamic_table_size
            and self.dynamic_table
        ):
            evicted = self.dynamic_table.pop()
            self._dynamic_table_size -= len(evicted[0]) + len(evicted[1]) + 32

        if entry_size <= self._max_dynamic_table_size:
            self.dynamic_table.insert(0, (name, value))
            self._dynamic_table_size += entry_size

    def _encode_header(self, name, value):
        """Encode a single header field."""
        name_lower = name.lower() if isinstance(name, str) else name.decode().lower()

        # Check static table for exact match → indexed
        pair_key = (name_lower, value)
        if pair_key in _STATIC_PAIR_INDEX:
            idx = _STATIC_PAIR_INDEX[pair_key]
            return encode_integer(idx, 7, 0x80)

        # Check dynamic table for exact match → indexed
        exact_idx, name_idx = self._find_in_dynamic_table(name_lower, value)
        if exact_idx is not None:
            return encode_integer(exact_idx, 7, 0x80)

        # Sensitive headers: literal without indexing (never indexed)
        if name_lower in (
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
        ):
            if name_lower in _STATIC_NAME_INDEX:
                idx = _STATIC_NAME_INDEX[name_lower]
                result = encode_integer(idx, 4, 0x10)  # Never indexed
            else:
                result = b"\x10"
                result += encode_string(name_lower)
            result += encode_string(value)
            return result

        # Non-sensitive headers: literal with incremental indexing → adds to dynamic table
        if name_lower in _STATIC_NAME_INDEX:
            idx = _STATIC_NAME_INDEX[name_lower]
            result = encode_integer(idx, 6, 0x40)
            result += encode_string(value)
        elif name_idx is not None:
            result = encode_integer(name_idx, 6, 0x40)
            result += encode_string(value)
        else:
            result = b"\x40"  # 0100 0000, new name
            result += encode_string(name_lower)
            result += encode_string(value)

        self._add_to_dynamic_table(name_lower, value)
        return result


class HPACKDecoder:
    """
    HPACK decoder with a bounded dynamic table.
    """

    def __init__(self, max_table_size=4096):
        self.dynamic_table = []
        self._dynamic_table_size = 0
        self._max_table_size = max_table_size
        self._table_size = min(max_table_size, 4096)

    def _lookup(self, index):
        if 1 <= index < len(STATIC_TABLE):
            return STATIC_TABLE[index]
        dynamic_index = index - len(STATIC_TABLE)
        if 0 <= dynamic_index < len(self.dynamic_table):
            return self.dynamic_table[dynamic_index]
        raise ValueError(f"Invalid HPACK header index {index}")

    def _evict_to_fit(self, incoming_size=0):
        while (
            self.dynamic_table
            and self._dynamic_table_size + incoming_size > self._table_size
        ):
            name, value = self.dynamic_table.pop()
            self._dynamic_table_size -= (
                len(name.encode("utf-8")) + len(value.encode("utf-8")) + 32
            )

    def _add_to_dynamic_table(self, name, value):
        entry_size = len(name.encode("utf-8")) + len(value.encode("utf-8")) + 32
        self._evict_to_fit(entry_size)
        if entry_size <= self._table_size:
            self.dynamic_table.insert(0, (name, value))
            self._dynamic_table_size += entry_size

    def decode_headers(self, data):
        """
        Decode an HPACK-encoded header block.

        :param data: HPACK-encoded bytes
        :return: List of (name, value) tuples
        """
        headers = []
        offset = 0
        saw_header = False

        while offset < len(data):
            byte = data[offset]

            if byte & 0x80:
                # Indexed header field (Section 6.1)
                index, offset = decode_integer(data, offset, 7)
                headers.append(self._lookup(index))
                saw_header = True

            elif byte & 0x40:
                # Literal with incremental indexing (Section 6.2.1)
                index, offset = decode_integer(data, offset, 6)
                if index == 0:
                    name, offset = decode_string(data, offset)
                    name = name.decode("utf-8") if isinstance(name, bytes) else name
                else:
                    name = self._lookup(index)[0]
                value, offset = decode_string(data, offset)
                value = value.decode("utf-8") if isinstance(value, bytes) else value
                headers.append((name, value))
                self._add_to_dynamic_table(name, value)
                saw_header = True

            elif byte & 0x20:
                # Dynamic table size update (Section 6.3)
                if saw_header:
                    raise ValueError("HPACK table size update after header field")
                size, offset = decode_integer(data, offset, 5)
                if size > self._max_table_size:
                    raise ValueError("HPACK table size update exceeds advertised limit")
                self._table_size = size
                self._evict_to_fit()

            else:
                # Literal without indexing (Section 6.2.2) or never indexed (6.2.3)
                prefix = 4 if (byte & 0xF0) == 0x00 else 4
                index, offset = decode_integer(data, offset, prefix)
                if index == 0:
                    name, offset = decode_string(data, offset)
                    name = name.decode("utf-8") if isinstance(name, bytes) else name
                else:
                    name = self._lookup(index)[0]
                value, offset = decode_string(data, offset)
                value = value.decode("utf-8") if isinstance(value, bytes) else value
                headers.append((name, value))
                saw_header = True

        return headers
