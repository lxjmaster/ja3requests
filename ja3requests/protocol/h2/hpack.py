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
    max_prefix = (1 << prefix_bits) - 1
    value = data[offset] & max_prefix
    offset += 1

    if value < max_prefix:
        return value, offset

    m = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        value += (b & 0x7F) << m
        m += 7
        if b & 0x80 == 0:
            break

    return value, offset


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
    Decode an HPACK string literal.

    :return: (string_bytes, new_offset)
    """
    huffman = data[offset] & 0x80
    length, offset = decode_integer(data, offset, 7)
    string_bytes = data[offset:offset + length]
    offset += length

    if huffman:
        # Huffman decoding not implemented — return raw bytes
        pass

    return string_bytes, offset


class HPACKEncoder:
    """
    Simplified HPACK encoder.
    Uses static table + literal headers without indexing.
    """

    def __init__(self):
        self.dynamic_table = []

    def encode_headers(self, headers):
        """
        Encode a list of (name, value) header tuples.

        :param headers: List of (name, value) tuples
        :return: Encoded header block bytes
        """
        result = b""
        for name, value in headers:
            result += self._encode_header(name, value)
        return result

    def _encode_header(self, name, value):
        """Encode a single header field."""
        name_lower = name.lower() if isinstance(name, str) else name.decode().lower()

        # Check static table for exact match
        pair_key = (name_lower, value)
        if pair_key in _STATIC_PAIR_INDEX:
            idx = _STATIC_PAIR_INDEX[pair_key]
            return encode_integer(idx, 7, 0x80)

        # Check static table for name match → literal with name index
        if name_lower in _STATIC_NAME_INDEX:
            idx = _STATIC_NAME_INDEX[name_lower]
            # Literal without indexing (0000xxxx)
            result = encode_integer(idx, 4, 0x00)
            result += encode_string(value)
            return result

        # Literal without indexing, new name
        result = b"\x00"  # 0000 0000
        result += encode_string(name_lower)
        result += encode_string(value)
        return result


class HPACKDecoder:
    """
    Simplified HPACK decoder.
    Handles indexed headers and literal headers from static table.
    """

    def __init__(self):
        self.dynamic_table = []

    def decode_headers(self, data):
        """
        Decode an HPACK-encoded header block.

        :param data: HPACK-encoded bytes
        :return: List of (name, value) tuples
        """
        headers = []
        offset = 0

        while offset < len(data):
            byte = data[offset]

            if byte & 0x80:
                # Indexed header field (Section 6.1)
                index, offset = decode_integer(data, offset, 7)
                if 1 <= index < len(STATIC_TABLE):
                    name, value = STATIC_TABLE[index]
                    headers.append((name, value))
                elif index - len(STATIC_TABLE) < len(self.dynamic_table):
                    headers.append(self.dynamic_table[index - len(STATIC_TABLE)])
                else:
                    offset += 1  # skip invalid

            elif byte & 0x40:
                # Literal with incremental indexing (Section 6.2.1)
                index, offset = decode_integer(data, offset, 6)
                if index > 0 and index < len(STATIC_TABLE):
                    name = STATIC_TABLE[index][0]
                else:
                    name, offset = decode_string(data, offset)
                    name = name.decode("utf-8") if isinstance(name, bytes) else name
                value, offset = decode_string(data, offset)
                value = value.decode("utf-8") if isinstance(value, bytes) else value
                headers.append((name, value))
                self.dynamic_table.insert(0, (name, value))

            elif byte & 0x20:
                # Dynamic table size update (Section 6.3)
                _, offset = decode_integer(data, offset, 5)

            else:
                # Literal without indexing (Section 6.2.2) or never indexed (6.2.3)
                prefix = 4 if (byte & 0xF0) == 0x00 else 4
                index, offset = decode_integer(data, offset, prefix)
                if index > 0 and index < len(STATIC_TABLE):
                    name = STATIC_TABLE[index][0]
                else:
                    name, offset = decode_string(data, offset)
                    name = name.decode("utf-8") if isinstance(name, bytes) else name
                value, offset = decode_string(data, offset)
                value = value.decode("utf-8") if isinstance(value, bytes) else value
                headers.append((name, value))

        return headers
