"""Offline browser evidence; capture dependencies never enter runtime tests."""

import hashlib
import json
from pathlib import Path
import struct

from ja3requests import TlsConfig
from ja3requests.protocol.tls import TLS
from test.wire_client_hello import decode, grease, profile, reassemble
from ja3requests.protocol.h2.hpack import HPACKDecoder


def test_chrome154_capture_calibration():
    capture = json.loads(
        (Path(__file__).parent / 'fixtures/chrome154_macos_hello.json').read_text()
    )
    record = bytes.fromhex(capture['record_hex'])
    assert hashlib.sha256(record).hexdigest() == capture['sha256']
    assert capture['browser'] == 'Google Chrome 154.0.8037.95'
    actual = decode(record)
    config = TlsConfig.from_browser('chrome', 154)
    tls = TLS(None, server_host='localhost')
    tls.set_payload(config)
    subset = decode(tls.body.message)
    actual_types = [k for k, _ in actual['extensions'] if not grease(k)]
    subset_types = [k for k, _ in subset['extensions']]
    assert subset_types == [k for k in actual_types if k in subset_types]
    assert set(actual_types) - set(subset_types) == {65037, 51764, 18, 27, 17613}
    assert [
        x for x in actual['ciphers'] if not grease(x) and x not in (52393, 52392)
    ] == [x for x in subset['ciphers'] if not grease(x)]
    assert len(actual['session_id']) == len(subset['session_id']) == 32
    assert actual['compression'] == subset['compression'] == [0]
    aext, sext = dict(actual['extensions']), dict(subset['extensions'])
    for kind in (0, 5, 11, 16, 23, 35, 45, 65281):
        assert aext[kind] == sext[kind]
    assert profile(record)['groups'] == ['GREASE', 4588, 29, 23, 24]
    assert profile(tls.body.message)['groups'] == [29, 23, 24]
    assert profile(tls.body.message)['key_shares'] == [[29, 32]]
    # Deliberately different, not a fake success based on matching five fields.
    assert profile(record)['ja3'] != profile(tls.body.message)['ja3']


def test_existing_implicit_browser_selection_stays_pinned():
    a = TlsConfig.from_browser('chrome')
    b = TlsConfig.from_browser('chrome', 124)
    assert a.get_ja3_string('localhost') == b.get_ja3_string('localhost')


def test_preset_extensions_are_not_shared():
    a = TlsConfig.from_browser('chrome', 154)
    b = TlsConfig.from_browser('chrome', 154)
    a.extensions[2].formats.append(1)
    assert b.extensions[2].formats == [0]


def test_chrome155_received_bytes_and_connection_table_reuse():
    fixture = json.loads(
        (Path(__file__).parent / 'fixtures/chrome155_macos_tls_h2.json').read_text()
    )
    assert fixture['manifest']['browser'] == 'Google Chrome 155.0.8059.39'
    assert len(fixture['cases']) == 5
    for case in fixture['cases']:
        for name in ('tls_client', 'tls_server', 'h2_client', 'h2_server'):
            raw = bytes.fromhex(case[name + '_hex'])
            assert hashlib.sha256(raw).hexdigest() == case[name + '_sha256']
        hellos = reassemble(bytes.fromhex(case['tls_client_hex']))
        assert len(hellos) == 1
        assert hellos[0]['handshake_hex'] == case['hellos'][0]['handshake_hex']
        assert hellos[0]['record_versions'] == case['hellos'][0]['record_versions']
        wire = bytes.fromhex(case['h2_client_hex'])
        assert wire[:24] == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        offset = 24
        blocks = []
        while offset < len(wire):
            size = int.from_bytes(wire[offset : offset + 3], 'big')
            kind, flags, stream = struct.unpack('!BBI', wire[offset + 3 : offset + 9])
            payload = wire[offset + 9 : offset + 9 + size]
            assert len(payload) == size
            offset += 9 + size
            if kind == 1:
                # These reviewed samples contain complete, unpadded HEADERS.
                assert flags & 4 and not flags & 8
                priority = None
                if flags & 32:
                    dependency, weight = struct.unpack('!IB', payload[:5])
                    priority = [
                        dependency & 0x7FFFFFFF,
                        weight + 1,
                        bool(dependency >> 31),
                    ]
                    payload = payload[5:]
                blocks.append((stream, flags, priority, payload))
        assert offset == len(wire) and len(blocks) == 2
        decoder = HPACKDecoder(max_header_list_size=65536)
        for (stream, flags, priority, block), expected in zip(blocks, case['requests']):
            assert stream == expected['stream'] and flags == expected['flags']
            assert priority == expected['priority']
            assert block.hex() == expected['block_hex']
            assert len(decoder.dynamic_table) == expected['dynamic_entries_before']
            headers = decoder.decode_headers(block)
            assert [
                [name.encode().hex(), value.encode().hex()] for name, value in headers
            ] == expected['headers']
            assert len(decoder.dynamic_table) == expected['dynamic_entries_after']
