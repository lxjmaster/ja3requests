"""Inspect an encoded ClientHello without regenerating keys or protocol state."""

from __future__ import annotations

import struct
from typing import TYPE_CHECKING, Iterable, List, Tuple

if TYPE_CHECKING:
    from typing_extensions import TypedDict

    class _ClientHelloInfo(TypedDict):
        record_version: int
        version: int
        session_id_length: int
        ciphers: List[int]
        compression: List[int]
        extensions: List[int]
        groups: List[int]
        point_formats: List[int]
        key_shares: List[Tuple[int, int]]
        ja3: str


def inspect_client_hello(record: bytes) -> _ClientHelloInfo:
    """Return wire fields and JA3 from one complete ClientHello TLS record.

    Hostnames, tickets and public keys are deliberately omitted from this summary.
    ``TLS.sent_client_hellos`` supplies the actual records, including retry messages.
    """
    if len(record) < 9 or record[0] != 22 or record[5] != 1:
        raise ValueError("Expected a ClientHello record")
    if (
        int.from_bytes(record[3:5], 'big') != len(record) - 5
        or int.from_bytes(record[6:9], 'big') != len(record) - 9
    ):
        raise ValueError("Invalid ClientHello length")
    data = memoryview(record)[9:]
    pos = 0

    def take(size: int) -> bytes:
        nonlocal pos
        if pos + size > len(data):
            raise ValueError("Truncated ClientHello")
        value = bytes(data[pos : pos + size])
        pos += size
        return value

    def vector(width: int) -> bytes:
        return take(int.from_bytes(take(width), 'big'))

    def words(value: bytes) -> List[int]:
        if len(value) % 2:
            raise ValueError("Invalid uint16 vector")
        return [x[0] for x in struct.iter_unpack('!H', value)]

    version = int.from_bytes(take(2), 'big')
    take(32)
    session_id_length = len(vector(1))
    ciphers = words(vector(2))
    compression = list(vector(1))
    extensions: List[int]
    groups: List[int]
    points: List[int]
    shares: List[Tuple[int, int]]
    extensions, groups, points, shares = [], [], [], []
    if pos < len(data):
        size = int.from_bytes(take(2), 'big')
        if pos + size != len(data):
            raise ValueError("Invalid extensions length")
        while pos < len(data):
            kind = int.from_bytes(take(2), 'big')
            payload = vector(2)
            if kind in extensions:
                raise ValueError("Duplicate extension")
            extensions.append(kind)
            if kind in (10, 51):
                if (
                    len(payload) < 2
                    or int.from_bytes(payload[:2], 'big') != len(payload) - 2
                ):
                    raise ValueError("Invalid extension vector")
                if kind == 10:
                    groups = words(payload[2:])
                else:
                    offset = 2
                    while offset < len(payload):
                        if offset + 4 > len(payload):
                            raise ValueError("Truncated key share")
                        group, length = struct.unpack(
                            '!HH', payload[offset : offset + 4]
                        )
                        offset += 4 + length
                        if offset > len(payload):
                            raise ValueError("Truncated key share")
                        shares.append((group, length))
            elif kind == 11:
                if not payload or payload[0] != len(payload) - 1:
                    raise ValueError("Invalid point formats")
                points = list(payload[1:])

    def without_grease(values: Iterable[int]) -> List[int]:
        return [v for v in values if not (v >> 8 == v & 255 and v & 0x0F0F == 0x0A0A)]

    ja3 = ','.join(
        '-'.join(map(str, without_grease(values)))
        for values in ([version], ciphers, extensions, groups, points)
    )
    return dict(
        record_version=int.from_bytes(record[1:3], 'big'),
        version=version,
        session_id_length=session_id_length,
        ciphers=ciphers,
        compression=compression,
        extensions=extensions,
        groups=groups,
        point_formats=points,
        key_shares=shares,
        ja3=ja3,
    )
