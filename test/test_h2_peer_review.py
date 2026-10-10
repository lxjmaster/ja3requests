"""Independent response-field and repeated peer SETTINGS regressions."""

import asyncio
import struct

import pytest

from ja3requests.protocol.h2.connection import H2Connection
from ja3requests.protocol.h2.frame import H2Frame
from ja3requests.protocol.h2.hpack import HPACKDecoder
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection
from ja3requests.protocol.h2.async_connection import H2ProtocolError
from test.mock_servers.local import h2_frame
from test.test_async_h2 import connected, request


def literal(name, value, indexed=False):
    """Encode small raw literals without production normalization/validation."""
    name, value = name.encode('utf-8'), value.encode('utf-8')
    assert len(name) < 127 and len(value) < 127
    return bytes([64 if indexed else 0, len(name)]) + name + bytes([len(value)]) + value


INVALID_FIELDS = [
    ('', 'value'),
    ('X-Test', 'value'),
    ('x bad', 'value'),
    ('x\x00bad', 'value'),
    ('x\tbad', 'value'),
    ('x\x7fbad', 'value'),
    ('xé', 'value'),
    ('x:bad', 'value'),
    ('x(bad)', 'value'),
    ('x-test', 'a\r\nSet-Cookie: injected=yes; Path=/'),
    ('x-test', 'a\x00b'),
    ('x-test', 'a\rb'),
    ('x-test', 'a\nb'),
    ('x-test', ' leading'),
    ('x-test', 'trailing '),
    ('x-test', '\tleading'),
    ('x-test', 'trailing\t'),
    ('connection', 'close'),
    ('proxy-connection', 'keep-alive'),
    ('keep-alive', 'timeout=1'),
    ('transfer-encoding', 'chunked'),
    ('upgrade', 'h2c'),
    ('te', 'trailers'),
    (':method', 'GET'),
]


def response_blocks(field, phase):
    block = literal(*field) + literal('x-shared', 'saved', indexed=True)
    if phase == 'final':
        return [h2_frame(1, 5, 1, b'\x88' + block)]
    if phase == 'interim':
        return [h2_frame(1, 4, 1, literal(':status', '103') + block)]
    return [
        h2_frame(1, 4, 1, b'\x88'),
        h2_frame(0, 0, 1, b'discard'),
        h2_frame(1, 5, 1, block),
    ]


@pytest.mark.parametrize('field', INVALID_FIELDS)
@pytest.mark.parametrize('phase', ['final', 'interim', 'trailers'])
@pytest.mark.parametrize('entry', ['serial', 'multiplex', 'async'])
def test_malformed_fields_reset_only_stream_and_preserve_hpack(field, phase, entry):
    frames = response_blocks(field, phase)
    good = h2_frame(1, 5, 3, b'\x88\xbe')  # Most recent dynamic entry.
    if entry == 'async':

        async def run():
            async with connected() as (conn, wire):
                first, second = await request(conn), await request(conn)
                wire.feed(b''.join(frames) + good)
                with pytest.raises(H2ProtocolError):
                    await conn.receive_headers(first, timeout=1)
                assert await conn.receive_headers(second, timeout=1) == [
                    (':status', '200'),
                    ('x-shared', 'saved'),
                ]
                assert await conn.read_stream(second, 1, timeout=1) == b''
                await wire.flush()
                assert [frame.payload for frame in wire.frames(3, first)] == [
                    b'\x00\x00\x00\x01'
                ]
                assert not conn.failed and conn._buffered_bytes == 0

        asyncio.run(run())
        return
    sent = []
    incoming = [b''.join(frames) + good]
    connection_type = H2Connection if entry == 'serial' else H2MultiplexConnection
    conn = connection_type(sent.append, lambda _size: incoming.pop(0))
    conn._peer_settings_received = True
    first = conn.send_request('GET', 'example.test', '/')
    second = conn.send_request('GET', 'example.test', '/')
    if entry == 'multiplex':
        for frame in conn._feed_frames(incoming.pop(0)):
            conn._dispatch_frame(frame)
    with pytest.raises((ValueError, ConnectionError)):
        conn.receive_response(first)
    assert conn.receive_response(second) == (
        [(':status', '200'), ('x-shared', 'saved')],
        b'',
    )
    resets = [raw for raw in sent if raw[3] == 3]
    assert resets == [h2_frame(3, 0, first, b'\x00\x00\x00\x01')]
    assert conn._failed is None
    if entry == 'multiplex':
        assert conn._buffered_bytes == 0


@pytest.mark.parametrize(
    'block',
    [
        literal('x-test', 'ok') + b'\x88',
        b'\x88\x88',
        b'\x88' + literal(':authority', 'example.test'),
    ],
)
def test_pseudo_fields_are_ordered_unique_and_response_only(block):
    sent = []
    conn = H2MultiplexConnection(sent.append, None)
    conn._peer_settings_received = True
    stream = conn.send_request('GET', 'example.test', '/')
    conn._dispatch_frame(H2Frame(1, 5, stream, block))
    with pytest.raises(ConnectionError):
        conn.receive_response(stream)
    assert sent[-1] == h2_frame(3, 0, stream, b'\x00\x00\x00\x01')
    assert conn._failed is None


@pytest.mark.parametrize('connection_type', [H2Connection, H2MultiplexConnection])
@pytest.mark.parametrize(
    'sizes,prefix',
    [
        ([0, 4096], b'\x20\x3f\xe1\x1f'),
        ([128, 64, 512], b'\x3f\x21\x3f\xe1\x03'),
        ([0, 0, 4096], b'\x20\x3f\xe1\x1f'),
    ],
)
def test_duplicate_peer_table_sizes_announce_minimum_then_final(
    connection_type, sizes, prefix
):
    sent = []
    conn = connection_type(sent.append, None)
    conn._peer_settings_received = True
    decoder = HPACKDecoder()
    fields = [('x-custom', 'value')]
    conn.send_request('GET', 'example.test', '/', headers=fields)
    first = decoder.decode_headers(sent[-1][9:])
    conn._handle_connection_frame(
        H2Frame(4, 0, 0, b''.join(struct.pack('!HI', 1, size) for size in sizes))
    )
    assert sent[-1] == h2_frame(4, 1, 0)
    conn.send_request('GET', 'example.test', '/', headers=fields)
    block = sent[-1][9:]
    assert block.startswith(prefix)
    assert decoder.decode_headers(block) == first
    conn.send_request('GET', 'example.test', '/', headers=fields)
    assert decoder.decode_headers(sent[-1][9:]) == first


@pytest.mark.parametrize('connection_type', [H2Connection, H2MultiplexConnection])
@pytest.mark.parametrize(
    'pairs', [[(2, 1), (2, 0)], [(4, 2147483648), (4, 65535)], [(5, 0), (5, 16384)]]
)
def test_invalid_intermediate_setting_cannot_be_hidden(connection_type, pairs):
    sent = []
    conn = connection_type(sent.append, None)
    payload = b''.join(struct.pack('!HI', key, value) for key, value in pairs)
    with pytest.raises(ValueError):
        conn._handle_connection_frame(H2Frame(4, 0, 0, payload))
    assert not sent
    assert conn._failed is not None
    with pytest.raises((ValueError, ConnectionError)):
        conn.send_request('GET', 'example.test', '/')


@pytest.mark.parametrize('connection_type', [H2Connection, H2MultiplexConnection])
def test_intermediate_window_overflow_cannot_be_hidden(connection_type):
    sent = []
    conn = connection_type(sent.append, None)
    conn._peer_settings_received = True
    stream = conn.send_request('GET', 'example.test', '/')
    if connection_type is H2Connection:
        conn._active_send_stream = stream
        conn._stream_send_window = 2147483647
    else:
        conn._streams[stream].send_window = 2147483647
    sent.clear()
    with pytest.raises(ValueError, match='overflow'):
        conn._handle_connection_frame(
            H2Frame(4, 0, 0, struct.pack('!HIHI', 4, 65536, 4, 65535))
        )
    assert not sent
    assert conn._failed is not None


def test_ordered_settings_parser_keeps_compatibility_and_rejects_truncation():
    from ja3requests.protocol.h2.frame import (
        parse_settings_pairs,
        parse_settings_payload,
    )

    pairs = [(1, 0), (65535, 23), (1, 4096)]
    payload = b''.join(struct.pack('!HI', *pair) for pair in pairs)
    assert parse_settings_pairs(payload) == pairs
    assert parse_settings_payload(payload) == {1: 4096, 65535: 23}
    for malformed in [b'x', payload + b'x']:
        with pytest.raises(ValueError):
            parse_settings_pairs(malformed)


def test_extension_free_client_hello_has_no_offered_alpn():
    from ja3requests import TlsConfig
    from ja3requests.protocol.tls import TLS
    from ja3requests.protocol.tls.layers.client_hello import ClientHello

    hello = ClientHello(use_grease=False)
    encoded = hello.message
    assert hello.offered_alpn_protocols == ()
    assert hello.message == encoded
    tls = TLS(None)
    tls.set_payload(TlsConfig.legacy())
    assert tls.body.offered_alpn_protocols == ()


@pytest.mark.parametrize('connection_type', [H2Connection, H2MultiplexConnection])
def test_valid_repeated_fields_empty_values_and_internal_whitespace(connection_type):
    fields = [
        ('x-empty', ''),
        ('x-test', 'a b\tc'),
        ('set-cookie', 'one=yes'),
        ('set-cookie', 'two=yes'),
    ]
    block = b'\x88' + b''.join(literal(*field) for field in fields)
    conn = connection_type(lambda _raw: None, lambda _size: h2_frame(1, 5, 1, block))
    if connection_type is H2MultiplexConnection:
        conn._peer_settings_received = True
        conn.send_request('GET', 'example.test', '/')
        conn._dispatch_frame(H2Frame(1, 5, 1, block))
    assert conn.receive_response(1) == ([(':status', '200')] + fields, b'')


def test_malformed_async_response_stops_blocked_upload_and_leaves_other_stream_alive():
    from ja3requests._upload import UploadSource
    from test.test_async_h2_upload import upload

    async def run():
        waiting, stopped = asyncio.Event(), asyncio.Event()

        async def chunks():
            try:
                yield b'prefix'
                waiting.set()
                await asyncio.Event().wait()
            finally:
                stopped.set()

        async with connected() as (conn, wire):
            first = await upload(conn, UploadSource(chunks()), timeout=1)
            await asyncio.wait_for(waiting.wait(), 1)
            other = await request(conn)
            wire.feed(
                h2_frame(1, 5, first, b'\x88' + literal('x-probe', 'a\r\nb')),
                h2_frame(1, 5, other, b'\x88'),
            )
            with pytest.raises(H2ProtocolError):
                await conn.receive_headers(first, timeout=1)
            await asyncio.wait_for(stopped.wait(), 1)
            assert await conn.receive_headers(other, timeout=1) == [(':status', '200')]
            assert not conn._producers and not conn.failed
            await wire.flush()
            assert [frame.payload for frame in wire.frames(3, first)] == [
                b'\x00\x00\x00\x01'
            ]

    asyncio.run(run())
