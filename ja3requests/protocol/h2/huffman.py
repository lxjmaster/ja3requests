"""
ja3requests.protocol.h2.huffman
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HPACK Huffman coding table and codec (RFC 7541 Appendix B).
"""

# Huffman code table: (code, bit_length) indexed by byte value 0-255 + EOS
# From RFC 7541 Appendix B
HUFFMAN_TABLE = [
    (0x1FF8, 13),
    (0x7FFFD8, 23),
    (0xFFFFFE2, 28),
    (0xFFFFFE3, 28),
    (0xFFFFFE4, 28),
    (0xFFFFFE5, 28),
    (0xFFFFFE6, 28),
    (0xFFFFFE7, 28),
    (0xFFFFFE8, 28),
    (0xFFFFEA, 24),
    (0x3FFFFFFC, 30),
    (0xFFFFFE9, 28),
    (0xFFFFFEA, 28),
    (0x3FFFFFFD, 30),
    (0xFFFFFEB, 28),
    (0xFFFFFEC, 28),
    (0xFFFFFED, 28),
    (0xFFFFFEE, 28),
    (0xFFFFFEF, 28),
    (0xFFFFFF0, 28),
    (0xFFFFFF1, 28),
    (0xFFFFFF2, 28),
    (0x3FFFFFFE, 30),
    (0xFFFFFF3, 28),
    (0xFFFFFF4, 28),
    (0xFFFFFF5, 28),
    (0xFFFFFF6, 28),
    (0xFFFFFF7, 28),
    (0xFFFFFF8, 28),
    (0xFFFFFF9, 28),
    (0xFFFFFFA, 28),
    (0xFFFFFFB, 28),
    (0x14, 6),
    (0x3F8, 10),
    (0x3F9, 10),
    (0xFFA, 12),
    (0x1FF9, 13),
    (0x15, 6),
    (0xF8, 8),
    (0x7FA, 11),
    (0x3FA, 10),
    (0x3FB, 10),
    (0xF9, 8),
    (0x7FB, 11),
    (0xFA, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1A, 6),
    (0x1B, 6),
    (0x1C, 6),
    (0x1D, 6),
    (0x1E, 6),
    (0x1F, 6),
    (0x5C, 7),
    (0xFB, 8),
    (0x7FFC, 15),
    (0x20, 6),
    (0xFFB, 12),
    (0x3FC, 10),
    (0x1FFA, 13),
    (0x21, 6),
    (0x5D, 7),
    (0x5E, 7),
    (0x5F, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6A, 7),
    (0x6B, 7),
    (0x6C, 7),
    (0x6D, 7),
    (0x6E, 7),
    (0x6F, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xFC, 8),
    (0x73, 7),
    (0xFD, 8),
    (0x1FFB, 13),
    (0x7FFF0, 19),
    (0x1FFC, 13),
    (0x3FFC, 14),
    (0x22, 6),
    (0x7FFD, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2A, 6),
    (0x7, 5),
    (0x2B, 6),
    (0x76, 7),
    (0x2C, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2D, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7A, 7),
    (0x7B, 7),
    (0x7FFE, 15),
    (0x7FC, 11),
    (0x3FFD, 14),
    (0x1FFD, 13),
    (0xFFFFFFC, 28),
    (0xFFFE6, 20),
    (0x3FFFD2, 22),
    (0xFFFE7, 20),
    (0xFFFE8, 20),
    (0x3FFFD3, 22),
    (0x3FFFD4, 22),
    (0x3FFFD5, 22),
    (0x7FFFD9, 23),
    (0x3FFFD6, 22),
    (0x7FFFDA, 23),
    (0x7FFFDB, 23),
    (0x7FFFDC, 23),
    (0x7FFFDD, 23),
    (0x7FFFDE, 23),
    (0xFFFFEB, 24),
    (0x7FFFDF, 23),
    (0xFFFFEC, 24),
    (0xFFFFED, 24),
    (0x3FFFD7, 22),
    (0x7FFFE0, 23),
    (0xFFFFEE, 24),
    (0x7FFFE1, 23),
    (0x7FFFE2, 23),
    (0x7FFFE3, 23),
    (0x7FFFE4, 23),
    (0x1FFFDC, 21),
    (0x3FFFD8, 22),
    (0x7FFFE5, 23),
    (0x3FFFD9, 22),
    (0x7FFFE6, 23),
    (0x7FFFE7, 23),
    (0xFFFFEF, 24),
    (0x3FFFDA, 22),
    (0x1FFFDD, 21),
    (0xFFFE9, 20),
    (0x3FFFDB, 22),
    (0x3FFFDC, 22),
    (0x7FFFE8, 23),
    (0x7FFFE9, 23),
    (0x1FFFDE, 21),
    (0x7FFFEA, 23),
    (0x3FFFDD, 22),
    (0x3FFFDE, 22),
    (0xFFFFF0, 24),
    (0x1FFFDF, 21),
    (0x3FFFDF, 22),
    (0x7FFFEB, 23),
    (0x7FFFEC, 23),
    (0x1FFFE0, 21),
    (0x1FFFE1, 21),
    (0x3FFFE0, 22),
    (0x1FFFE2, 21),
    (0x7FFFED, 23),
    (0x3FFFE1, 22),
    (0x7FFFEE, 23),
    (0x7FFFEF, 23),
    (0xFFFEA, 20),
    (0x3FFFE2, 22),
    (0x3FFFE3, 22),
    (0x3FFFE4, 22),
    (0x7FFFF0, 23),
    (0x3FFFE5, 22),
    (0x3FFFE6, 22),
    (0x7FFFF1, 23),
    (0x3FFFFE0, 26),
    (0x3FFFFE1, 26),
    (0xFFFEB, 20),
    (0x7FFF1, 19),
    (0x3FFFE7, 22),
    (0x7FFFF2, 23),
    (0x3FFFE8, 22),
    (0x1FFFFEC, 25),
    (0x3FFFFE2, 26),
    (0x3FFFFE3, 26),
    (0x3FFFFE4, 26),
    (0x7FFFFDE, 27),
    (0x7FFFFDF, 27),
    (0x3FFFFE5, 26),
    (0xFFFFF1, 24),
    (0x1FFFFED, 25),
    (0x7FFF2, 19),
    (0x1FFFE3, 21),
    (0x3FFFFE6, 26),
    (0x7FFFFE0, 27),
    (0x7FFFFE1, 27),
    (0x3FFFFE7, 26),
    (0x7FFFFE2, 27),
    (0xFFFFF2, 24),
    (0x1FFFE4, 21),
    (0x1FFFE5, 21),
    (0x3FFFFE8, 26),
    (0x3FFFFE9, 26),
    (0xFFFFFFD, 28),
    (0x7FFFFE3, 27),
    (0x7FFFFE4, 27),
    (0x7FFFFE5, 27),
    (0xFFFEC, 20),
    (0xFFFFF3, 24),
    (0xFFFED, 20),
    (0x1FFFE6, 21),
    (0x3FFFE9, 22),
    (0x1FFFE7, 21),
    (0x1FFFE8, 21),
    (0x7FFFF3, 23),
    (0x3FFFEA, 22),
    (0x3FFFEB, 22),
    (0x1FFFFEE, 25),
    (0x1FFFFEF, 25),
    (0xFFFFF4, 24),
    (0xFFFFF5, 24),
    (0x3FFFFEA, 26),
    (0x7FFFF4, 23),
    (0x3FFFFEB, 26),
    (0x7FFFFE6, 27),
    (0x3FFFFEC, 26),
    (0x3FFFFED, 26),
    (0x7FFFFE7, 27),
    (0x7FFFFE8, 27),
    (0x7FFFFE9, 27),
    (0x7FFFFEA, 27),
    (0x7FFFFEB, 27),
    (0xFFFFFFE, 28),
    (0x7FFFFEC, 27),
    (0x7FFFFED, 27),
    (0x7FFFFEE, 27),
    (0x7FFFFEF, 27),
    (0x7FFFFF0, 27),
    (0x3FFFFEE, 26),
    (0x3FFFFFFF, 30),  # EOS
]

# Build decode tree
_DECODE_TREE = {}


def _build_decode_tree():
    """Build a binary trie for Huffman decoding."""
    for byte_val, (code, bit_len) in enumerate(HUFFMAN_TABLE[:256]):
        node = _DECODE_TREE
        for i in range(bit_len - 1, -1, -1):
            bit = (code >> i) & 1
            if bit not in node:
                node[bit] = {}
            node = node[bit]
        node['value'] = byte_val


_build_decode_tree()


def huffman_encode(data):
    """
    Encode bytes using HPACK Huffman coding.

    :param data: bytes or str to encode
    :return: Huffman-encoded bytes
    """
    if isinstance(data, str):
        data = data.encode('utf-8')

    bits = 0
    bits_left = 0
    result = bytearray()

    for byte in data:
        code, bit_len = HUFFMAN_TABLE[byte]
        bits = (bits << bit_len) | code
        bits_left += bit_len

        while bits_left >= 8:
            bits_left -= 8
            result.append((bits >> bits_left) & 0xFF)

    # Pad with EOS prefix (all 1s)
    if bits_left > 0:
        bits = (bits << (8 - bits_left)) | ((1 << (8 - bits_left)) - 1)
        result.append(bits & 0xFF)

    return bytes(result)


def huffman_decode(data):
    """
    Decode Huffman-encoded bytes.

    :param data: Huffman-encoded bytes
    :return: Decoded bytes
    """
    result = bytearray()
    node = _DECODE_TREE
    padding = 0
    padding_bits = 0

    for byte in data:
        for i in range(7, -1, -1):
            bit = (byte >> i) & 1
            node = node.get(bit)
            if node is None:
                raise ValueError("Invalid HPACK Huffman code")
            padding = (padding << 1) | bit
            padding_bits += 1
            if 'value' in node:
                result.append(node['value'])
                node = _DECODE_TREE
                padding = 0
                padding_bits = 0

    if padding_bits > 7 or padding != (1 << padding_bits) - 1:
        raise ValueError("Invalid HPACK Huffman padding")

    return bytes(result)
