"""
ja3requests.protocol.h2.hpack
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Simplified HPACK header compression (RFC 7541).
Supports static table lookups and literal header encoding.
"""

from __future__ import annotations

import struct
from typing import Dict, Iterable, List, Optional, Tuple, Union, cast


_HeaderField = Union[str, bytes]


# HPACK Static Table (RFC 7541 Appendix A) — first 61 entries
STATIC_TABLE: List[Optional[Tuple[str, str]]] = [
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
_STATIC_NAME_INDEX: Dict[str, int] = {}
_STATIC_PAIR_INDEX: Dict[Tuple[str, str], int] = {}
for _i, _entry in enumerate(STATIC_TABLE):
    if _entry is None:
        continue
    _name, _value = _entry
    if _name not in _STATIC_NAME_INDEX:
        _STATIC_NAME_INDEX[_name] = _i
    if (_name, _value) and _value:
        _STATIC_PAIR_INDEX[(_name, _value)] = _i


def encode_integer(value: int, prefix_bits: int, first_byte: int = 0) -> bytes:
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


def decode_integer(data: bytes, offset: int, prefix_bits: int) -> Tuple[int, int]:
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


def encode_string(s: _HeaderField) -> bytes:
    """
    Encode a string using HPACK string literal (without Huffman).

    :param s: String or bytes to encode
    :return: Encoded bytes
    """
    if isinstance(s, str):
        s = s.encode("utf-8")
    # No Huffman encoding (H=0)
    return encode_integer(len(s), 7, 0) + s


class HeaderLimitError(ValueError):
    """The peer exceeded the local compressed or decoded header budget."""


def decode_string(
    data: bytes, offset: int, max_size: Optional[int] = None
) -> Tuple[bytes, int]:
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
    if max_size is not None and (max_size < 0 or (not huffman and length > max_size)):
        raise HeaderLimitError("HTTP/2 decoded header list limit exceeded")
    string_bytes = data[offset : offset + length]
    offset += length

    if huffman:
        from ja3requests.protocol.h2.huffman import (
            HuffmanLimitError,
            huffman_decode,
        )  # pylint: disable=import-outside-toplevel

        try:
            string_bytes = huffman_decode(string_bytes, max_size=max_size)
        except HuffmanLimitError as error:
            raise HeaderLimitError(
                "HTTP/2 decoded header list limit exceeded"
            ) from error

    return string_bytes, offset


def _hpack_entry_size(name: _HeaderField, value: _HeaderField) -> int:
    """Count uncompressed octets plus the RFC 7541 table-entry overhead."""
    name_bytes = name.encode("utf-8") if isinstance(name, str) else name
    value_bytes = value.encode("utf-8") if isinstance(value, str) else value
    return len(name_bytes) + len(value_bytes) + 32


def validate_header_fields(
    headers: Iterable[Tuple[_HeaderField, _HeaderField]],
) -> None:
    """Validate text fields without changing connection-wide HPACK state."""
    for name, value in headers:
        for field in (name, value):
            try:
                if isinstance(field, bytes):
                    field.decode("utf-8")
                else:
                    field.encode("utf-8")
            except UnicodeError as error:
                raise ValueError("HPACK header fields must be valid UTF-8") from error


class HPACKEncoder:
    """
    HPACK encoder with static and dynamic table support.
    Uses incremental indexing for repeated headers to improve compression.
    """

    MAX_DYNAMIC_TABLE_SIZE = 4096

    def __init__(self) -> None:
        # Names are normalized to str; values retain their input representation.
        self.dynamic_table: List[Tuple[str, _HeaderField]] = []  # Newest first
        self._dynamic_table_size = 0
        self._max_dynamic_table_size = self.MAX_DYNAMIC_TABLE_SIZE
        self._pending_table_size_min: Optional[int] = None
        self._pending_table_size_final: Optional[int] = None

    def set_table_size(self, size: int) -> None:
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
            self._dynamic_table_size -= _hpack_entry_size(name, value)

    def encode_headers(
        self, headers: Iterable[Tuple[_HeaderField, _HeaderField]]
    ) -> bytes:
        """
        Encode UTF-8 (name, value) header tuples.

        Byte fields must contain valid UTF-8; their representation is retained
        in the encoder table. Unlike this text-header API, encode_string accepts
        arbitrary octets. Validate the entire block before changing table state.

        :param headers: List of (name, value) tuples
        :return: Encoded header block bytes
        :raises ValueError: A field cannot be represented as UTF-8 text.
        """
        headers = list(headers)
        validate_header_fields(headers)
        result = b""
        if self._pending_table_size_final is not None:
            # set_table_size always initializes both pending sizes together.
            result += encode_integer(cast(int, self._pending_table_size_min), 5, 0x20)
            if self._pending_table_size_final != self._pending_table_size_min:
                result += encode_integer(self._pending_table_size_final, 5, 0x20)
            self._pending_table_size_min = None
            self._pending_table_size_final = None
        for name, value in headers:
            result += self._encode_header(name, value)
        return result

    def _find_in_dynamic_table(
        self, name: str, value: _HeaderField
    ) -> Tuple[Optional[int], Optional[int]]:
        """Search dynamic table for exact match or name match.
        Returns (exact_index, name_index) where index is 1-based from static table end.
        """
        name_match: Optional[int] = None
        for i, (n, v) in enumerate(self.dynamic_table):
            idx = len(STATIC_TABLE) + i
            if n == name and v == value:
                return idx, idx  # exact match
            if n == name and name_match is None:
                name_match = idx
        return None, name_match

    def _add_to_dynamic_table(self, name: str, value: _HeaderField) -> None:
        """Add a header to the dynamic table."""
        entry_size = _hpack_entry_size(name, value)
        # Evict entries if table would exceed max size
        while (
            self._dynamic_table_size + entry_size > self._max_dynamic_table_size
            and self.dynamic_table
        ):
            evicted = self.dynamic_table.pop()
            self._dynamic_table_size -= _hpack_entry_size(*evicted)

        if entry_size <= self._max_dynamic_table_size:
            self.dynamic_table.insert(0, (name, value))
            self._dynamic_table_size += entry_size

    def _encode_header(self, name: _HeaderField, value: _HeaderField) -> bytes:
        """Encode a single header field."""
        name_lower = name.lower() if isinstance(name, str) else name.decode().lower()

        # Check static table for exact match → indexed
        pair_key = (name_lower, value)
        if pair_key in _STATIC_PAIR_INDEX:
            # Membership in the static index proves this is a string pair.
            idx = _STATIC_PAIR_INDEX[cast(Tuple[str, str], pair_key)]
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

    def __init__(
        self, max_table_size: int = 4096, max_header_list_size: Optional[int] = None
    ) -> None:
        self.dynamic_table: List[Tuple[str, str]] = []
        self._dynamic_table_size = 0
        self._max_table_size = max_table_size
        self._table_size = min(max_table_size, 4096)
        self._max_header_list_size = max_header_list_size

    def _lookup(self, index: int) -> Tuple[str, str]:
        if 1 <= index < len(STATIC_TABLE):
            # Only index zero is the None sentinel in the static table.
            return cast(Tuple[str, str], STATIC_TABLE[index])
        dynamic_index = index - len(STATIC_TABLE)
        if 0 <= dynamic_index < len(self.dynamic_table):
            return self.dynamic_table[dynamic_index]
        raise ValueError(f"Invalid HPACK header index {index}")

    def _evict_to_fit(self, incoming_size: int = 0) -> None:
        while (
            self.dynamic_table
            and self._dynamic_table_size + incoming_size > self._table_size
        ):
            name, value = self.dynamic_table.pop()
            self._dynamic_table_size -= (
                len(name.encode("utf-8")) + len(value.encode("utf-8")) + 32
            )

    def _add_to_dynamic_table(self, name: str, value: str) -> None:
        entry_size = len(name.encode("utf-8")) + len(value.encode("utf-8")) + 32
        self._evict_to_fit(entry_size)
        if entry_size <= self._table_size:
            self.dynamic_table.insert(0, (name, value))
            self._dynamic_table_size += entry_size

    def decode_headers(self, data: bytes) -> List[Tuple[str, str]]:
        """
        Decode an HPACK-encoded header block.

        :param data: HPACK-encoded bytes
        :return: List of (name, value) tuples
        """
        headers: List[Tuple[str, str]] = []
        offset = 0
        saw_header = False
        header_size = 0

        while offset < len(data):
            byte = data[offset]

            if byte & 0x80:
                # Indexed header field (Section 6.1)
                index, offset = decode_integer(data, offset, 7)
                name, value = self._lookup(index)
                field_size = len(name.encode("utf-8")) + len(value.encode("utf-8")) + 32

            elif byte & 0x20 and not byte & 0x40:
                # Dynamic table size update (Section 6.3)
                if saw_header:
                    raise ValueError("HPACK table size update after header field")
                size, offset = decode_integer(data, offset, 5)
                if size > self._max_table_size:
                    raise ValueError("HPACK table size update exceeds advertised limit")
                self._table_size = size
                self._evict_to_fit()
                continue

            else:
                # Budget literals before allocating either raw or Huffman output.
                remaining = (
                    None
                    if self._max_header_list_size is None
                    else self._max_header_list_size - header_size - 32
                )
                if remaining is not None and remaining < 0:
                    raise HeaderLimitError("HTTP/2 decoded header list limit exceeded")
                prefix = 6 if byte & 0x40 else 4
                index, offset = decode_integer(data, offset, prefix)
                if index == 0:
                    raw_name, offset = decode_string(data, offset, max_size=remaining)
                    name_size = len(raw_name)
                    name = raw_name.decode("utf-8")
                else:
                    name = self._lookup(index)[0]
                    name_size = len(name.encode("utf-8"))
                if remaining is not None:
                    remaining -= name_size
                raw_value, offset = decode_string(data, offset, max_size=remaining)
                value = raw_value.decode("utf-8")
                field_size = name_size + len(raw_value) + 32

            header_size += field_size
            if (
                self._max_header_list_size is not None
                and header_size > self._max_header_list_size
            ):
                raise HeaderLimitError("HTTP/2 decoded header list limit exceeded")
            headers.append((name, value))
            if not byte & 0x80 and byte & 0x40:
                self._add_to_dynamic_table(name, value)
            saw_header = True

        return headers
