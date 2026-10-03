"""Independent test-side decoder: consumes bytes, never project TLS objects."""

import struct


def decode(record):
    assert record[0] == 22
    assert len(record) == 5 + int.from_bytes(record[3:5], 'big')
    body = record[5:]
    assert body[0] == 1 and len(body) == 4 + int.from_bytes(body[1:4], 'big')
    body = body[4:]
    pos = 34
    sid_len = body[pos]
    sid = body[pos + 1 : pos + 1 + sid_len]
    pos += 1 + sid_len
    size = int.from_bytes(body[pos : pos + 2], 'big')
    suites = [v[0] for v in struct.iter_unpack('!H', body[pos + 2 : pos + 2 + size])]
    pos += 2 + size
    size = body[pos]
    compression = list(body[pos + 1 : pos + 1 + size])
    pos += 1 + size
    extensions = []
    if pos < len(body):
        size = int.from_bytes(body[pos : pos + 2], 'big')
        pos += 2
        assert pos + size == len(body)
        while pos < len(body):
            kind, size = struct.unpack('!HH', body[pos : pos + 4])
            pos += 4
            payload = body[pos : pos + size]
            assert len(payload) == size
            extensions.append((kind, payload))
            pos += size
    return dict(
        record_version=record[1:3].hex(),
        version=int.from_bytes(body[:2], 'big'),
        random=body[2:34],
        session_id=sid,
        ciphers=suites,
        compression=compression,
        extensions=extensions,
    )


def grease(value):
    return value >> 8 == value & 255 and value & 0x0F0F == 0x0A0A


def profile(record):
    """Normalize ephemeral bytes only, retaining order and encoded share sizes."""
    hello = decode(record)
    ext = dict(hello['extensions'])
    groups = [v[0] for v in struct.iter_unpack('!H', ext.get(10, b'\0\0')[2:])]
    points = list(ext.get(11, b'\0')[1:])
    shares = []
    data = ext.get(51, b'\0\0')[2:]
    while data:
        kind, size = struct.unpack('!HH', data[:4])
        shares.append([kind, size])
        data = data[4 + size :]
    kinds = [k for k, _ in hello['extensions']]
    ja3 = ','.join(
        '-'.join(str(x) for x in values if not grease(x))
        for values in ([hello['version']], hello['ciphers'], kinds, groups, points)
    )
    return dict(
        record_version=hello['record_version'],
        version=hello['version'],
        session_id_length=len(hello['session_id']),
        compression=hello['compression'],
        ciphers=['GREASE' if grease(x) else x for x in hello['ciphers']],
        extension_types=['GREASE' if grease(x) else x for x in kinds],
        groups=['GREASE' if grease(x) else x for x in groups],
        point_formats=points,
        key_shares=shares,
        ja3=ja3,
    )
