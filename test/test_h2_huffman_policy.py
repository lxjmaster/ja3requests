"""Independent fixed vectors and retained browser bytes for outbound HPACK."""

import copy
import json
from pathlib import Path

import pytest

from ja3requests import TlsConfig
from ja3requests.protocol.h2.connection import H2Connection
from ja3requests.protocol.h2.hpack import HPACKDecoder, HPACKEncoder, encode_string
from ja3requests.sockets.https import HttpsSocket


def test_rfc7541_c4_request_vectors_and_dynamic_reuse():
    # RFC 7541 C.4.1/C.4.2, with Huffman strings and reused authority.
    headers = [
        (':method', 'GET'),
        (':scheme', 'http'),
        (':path', '/'),
        (':authority', 'www.example.com'),
    ]
    encoder = HPACKEncoder(huffman=True)
    first = encoder.encode_headers(headers)
    second = encoder.encode_headers(headers + [('cache-control', 'no-cache')])
    assert first.hex() == '828684418cf1e3c2e5f23a6ba0ab90f4ff'
    assert second.hex() == '828684be5886a8eb10649cbf'
    decoder = HPACKDecoder()
    assert decoder.decode_headers(first) == headers
    assert decoder.decode_headers(second) == headers + [('cache-control', 'no-cache')]


@pytest.mark.parametrize('value', [b'', b'a', b'?0', b'\x00\xff', 'é'])
def test_no_benefit_keeps_raw_string_bytes(value):
    assert encode_string(value, huffman=True) == encode_string(value)


def test_opt_in_string_vector_and_arbitrary_octets():
    assert encode_string('www.example.com') == b'\x0fwww.example.com'
    assert (
        encode_string('www.example.com', huffman=True).hex()
        == '8cf1e3c2e5f23a6ba0ab90f4ff'
    )
    assert (
        encode_string(b'www.example.com', huffman=True).hex()
        == '8cf1e3c2e5f23a6ba0ab90f4ff'
    )
    from ja3requests.protocol.h2.hpack import decode_string

    raw = bytes(range(256)) * 16
    block = encode_string(raw, huffman=True)
    decoded, offset = decode_string(block, 0)
    assert decoded == raw and offset == len(block)


def test_resize_sensitive_fields_and_invalid_utf8_before_mutation():
    encoder = HPACKEncoder(huffman=True)
    decoder = HPACKDecoder()
    headers = [
        ('authorization', 'www.example.com'),
        ('cookie', 'www.example.com'),
        ('x-vector', 'www.example.com'),
    ]
    block = encoder.encode_headers(headers)
    assert decoder.decode_headers(block) == headers
    assert [name for name, _ in encoder.dynamic_table] == ['x-vector']
    encoder.set_table_size(0)
    encoder.set_table_size(128)
    before = copy.deepcopy(encoder.__dict__)
    with pytest.raises(ValueError, match='UTF-8'):
        encoder.encode_headers([('x-valid', 'www.example.com'), ('x-bad', b'\xff')])
    assert encoder.__dict__ == before
    assert decoder.decode_headers(encoder.encode_headers(headers)) == headers
    assert decoder.decode_headers(encoder.encode_headers(headers)) == headers
    assert [name for name, _ in encoder.dynamic_table] == ['x-vector']


@pytest.mark.parametrize('value', [None, 0, 1, 'yes', [], object()])
def test_invalid_policy_rejected_before_config_or_connection_changes(value):
    config = TlsConfig()
    old_key = HttpsSocket._tls_policy_key(config, 'localhost')
    with pytest.raises(ValueError, match='bool'):
        config.h2_huffman = value
    assert HttpsSocket._tls_policy_key(config, 'localhost') == old_key
    with pytest.raises(ValueError, match='bool'):
        HPACKEncoder(huffman=value)
    with pytest.raises(ValueError, match='bool'):
        encode_string('www.example.com', huffman=value)
    writes = []
    with pytest.raises(ValueError, match='bool'):
        H2Connection(writes.append, None, huffman=value)
    assert not writes


def test_policy_identity_and_snapshot_preserve_historical_defaults():
    a = TlsConfig.from_browser('chrome', 154)
    b = copy.deepcopy(a)
    assert a.h2_huffman is b.h2_huffman is False
    old = HttpsSocket._tls_policy_key(a, 'localhost')
    b.h2_huffman = True
    assert old != HttpsSocket._tls_policy_key(b, 'localhost')
    assert a.h2_huffman is False
    assert a.get_ja3_string('localhost') == b.get_ja3_string('localhost')
    b._h2_huffman = 'invalid'
    with pytest.raises(ValueError, match='bool'):
        HttpsSocket._tls_policy_key(b, 'localhost')


def test_first_browser_request_matches_exact_received_hpack_bytes():
    fixture = json.loads(
        (Path(__file__).parent / 'fixtures/chrome155_macos_tls_h2.json').read_text()
    )
    for case in fixture['cases'][:3]:
        request = case['requests'][0]
        headers = [
            (bytes.fromhex(k).decode(), bytes.fromhex(v).decode())
            for k, v in request['headers']
        ]
        assert (
            HPACKEncoder(huffman=True).encode_headers(headers).hex()
            == request['block_hex']
        )
        assert HPACKEncoder().encode_headers(headers).hex() != request['block_hex']
