"""Fixed wire vectors and pre-commit validation for request H2 controls."""

import asyncio
import copy
import io
import struct

import pytest

from ja3requests import Session, TlsConfig
from ja3requests._upload import UploadSource
from ja3requests.protocol.h2.async_connection import AsyncH2Connection
from ja3requests.protocol.h2.connection import H2Connection
from ja3requests.protocol.h2.frame import (
    build_headers_frame,
    normalize_headers_priority,
)
from ja3requests.protocol.h2.hpack import HPACKEncoder, HPACKDecoder
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection
from ja3requests.requests.request import Request
from ja3requests.sockets.https import HttpsSocket


@pytest.mark.parametrize(
    'priority,payload',
    [
        (None, b''),
        ((256, True), b'\x80\x00\x00\x00\xff'),
        ((183, True), b'\x80\x00\x00\x00\xb6'),
        ((1, False), b'\x00' * 5),
    ],
)
def test_headers_priority_exact_wire(priority, payload):
    frame = build_headers_frame(1, b'\x82', end_stream=True, priority=priority)
    assert frame.flags == (5 if priority is None else 37)
    assert frame.payload == payload + b'\x82'


@pytest.mark.parametrize('length', [0, 16379, 16380, 16384, 32763, 32764])
def test_headers_priority_reserves_first_frame_octets_only(length):
    connection = H2Connection(lambda _: None, None)
    block = b'x' * length
    frames = list(connection._header_frames(1, block, True, (183, True)))
    assert frames[0].type == 1 and frames[0].flags & 33 == 33
    assert frames[0].payload[:5] == b'\x80\x00\x00\x00\xb6'
    assert all(frame.type == 9 and frame.flags & 33 == 0 for frame in frames[1:])
    assert all(len(frame.payload) <= 16384 for frame in frames)
    assert all(not frame.flags & 4 for frame in frames[:-1])
    assert frames[-1].flags & 4
    assert (
        frames[0].payload[5:] + b''.join(frame.payload for frame in frames[1:]) == block
    )


@pytest.mark.parametrize(
    'value',
    [
        False,
        1,
        [],
        (1,),
        (1, True, 0),
        (True, True),
        (0, True),
        (257, False),
        (1, 0),
        ('1', False),
    ],
)
@pytest.mark.parametrize('engine', ['serial', 'multiplex', 'async'])
def test_bad_priority_leaves_stream_and_hpack_state_unchanged(value, engine):
    writes = []
    if engine == 'async':

        async def send(data):
            writes.append(data)

        async def receive(_):
            return b''

        connection = AsyncH2Connection(send, receive)
    else:
        cls = H2Connection if engine == 'serial' else H2MultiplexConnection
        connection = cls(writes.append, lambda _: b'')
    before = copy.deepcopy(connection._encoder.__dict__)
    with pytest.raises(ValueError):
        if engine == 'async':
            asyncio.run(
                connection.send_request('GET', 'localhost', '/', headers_priority=value)
            )
        else:
            connection.send_request('GET', 'localhost', '/', headers_priority=value)
    assert not writes and connection._next_stream_id == 1
    assert connection._encoder.__dict__ == before


def test_priority_validation_precedes_multipart_file_reads():
    class Unread(io.BytesIO):
        def read(self, size=-1):
            raise AssertionError('Invalid metadata read the source')

    with Session(use_pooling=False) as session, pytest.raises(ValueError):
        session.post(
            'http://127.0.0.1:1/',
            files={'file': Unread(b'body')},
            h2_headers_priority=(0, True),
        )


@pytest.mark.parametrize('engine', ['multiplex', 'async'])
def test_invalid_upload_priority_precedes_source_preparation(engine):
    class Unprepared(io.BytesIO):
        def tell(self):
            raise AssertionError('Invalid metadata prepared the source')

    source = UploadSource(Unprepared(b'body'))

    async def send(_):
        pass

    async def receive(_):
        return b''

    with pytest.raises(ValueError):
        if engine == 'async':
            connection = AsyncH2Connection(send, receive)
            asyncio.run(
                connection.begin_upload(
                    'POST', 'localhost', '/', body=source, headers_priority=(0, True)
                )
            )
        else:
            connection = H2MultiplexConnection(lambda _: None, lambda _: b'')
            connection.begin_upload(
                'POST', 'localhost', '/', body=source, headers_priority=(0, True)
            )
    assert not source._prepared and not source.consumed


@pytest.mark.parametrize('huffman', [False, True])
def test_excluded_literals_sensitive_fields_and_table_resize(huffman):
    encoder = HPACKEncoder(
        huffman=huffman, indexing_exclusions=[':path', 'x-choice', 'cookie']
    )
    decoder = HPACKDecoder()
    headers = [
        (':path', '/pixel.png'),
        ('x-choice', 'www.example.com'),
        ('cookie', 'secret'),
    ]
    first = encoder.encode_headers(headers)
    assert first[0] == 4  # literal without insertion, static name index 4
    assert decoder.decode_headers(first) == headers
    assert encoder.dynamic_table == decoder.dynamic_table == []
    assert encoder.encode_headers([(':path', '/')]) == b'\x84'
    assert encoder.encode_headers([('cookie', 'secret')])[0] == 0x1F
    encoder.set_table_size(0)
    encoder.set_table_size(128)
    assert decoder.decode_headers(
        encoder.encode_headers(headers + [('x-reuse', 'one')])
    ) == headers + [('x-reuse', 'one')]
    assert [name for name, _ in decoder.dynamic_table] == ['x-reuse']
    assert decoder.decode_headers(
        encoder.encode_headers(headers + [('x-reuse', 'one')])
    ) == headers + [('x-reuse', 'one')]
    encoder.set_table_size(0)
    assert decoder.decode_headers(encoder.encode_headers(headers)) == headers
    assert not decoder.dynamic_table


def test_exact_dynamic_reference_and_indexed_name_remain_usable():
    encoder = HPACKEncoder(indexing_exclusions=['x-choice'])
    encoder._add_to_dynamic_table('x-choice', 'one')
    assert encoder.encode_headers([('x-choice', 'one')]) == b'\xbe'
    assert encoder.encode_headers([('x-choice', 'two')]) == b'\x0f\x2f\x03two'
    assert encoder.dynamic_table == [('x-choice', 'one')]


@pytest.mark.parametrize(
    'value',
    [
        None,
        ':path',
        b':path',
        42,
        {},
        {'x'},
        [''],
        [1],
        [':'],
        ['x:y'],
        ['bad name'],
        ['x\r'],
        ['K'],
    ],
)
def test_invalid_exclusions_do_not_change_config_or_policy(value):
    config = TlsConfig()
    original = HttpsSocket._tls_policy_key(config, 'localhost')
    with pytest.raises(ValueError):
        config.h2_indexing_exclusions = value
    assert config.h2_indexing_exclusions == ()
    assert HttpsSocket._tls_policy_key(config, 'localhost') == original
    with pytest.raises(ValueError):
        HPACKEncoder(indexing_exclusions=value)


def test_policy_copies_caller_inputs_and_priority_stays_request_scoped():
    names = [':path', 'X-Choice', ':path']
    config = TlsConfig()
    original = HttpsSocket._tls_policy_key(config, 'localhost')
    config.h2_indexing_exclusions = names
    names.clear()
    assert config.h2_indexing_exclusions == (':path', 'x-choice')
    assert original != HttpsSocket._tls_policy_key(config, 'localhost')
    cloned = copy.deepcopy(config)
    cloned.h2_indexing_exclusions = ['X-Choice', ':PATH']
    assert HttpsSocket._tls_policy_key(
        config, 'localhost'
    ) == HttpsSocket._tls_policy_key(cloned, 'localhost')
    priority = [256, True]
    request = Request(
        'GET', 'https://localhost/', tls_config=config, h2_headers_priority=priority
    ).request()
    priority[0] = 183
    key = HttpsSocket._tls_policy_key(request.tls_config, 'localhost')
    request.h2_headers_priority = (183, True)
    assert HttpsSocket._tls_policy_key(request.tls_config, 'localhost') == key
    assert normalize_headers_priority(None) is None


def test_default_exclusions_keep_existing_bytes():
    headers = [(':method', 'GET'), (':path', '/pixel.png'), ('x-choice', 'one')]
    a, b = HPACKEncoder(), HPACKEncoder(indexing_exclusions=[])
    for _ in range(3):
        assert a.encode_headers(headers) == b.encode_headers(headers)
