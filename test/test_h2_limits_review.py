"""GOAWAY classification and bounded active/discarded response headers."""

import asyncio
import socket
import struct
from unittest.mock import patch

import pytest

from ja3requests import AsyncSession, HTTPRetry
from ja3requests.async_pool import AsyncConnectionPool, _Entry
from ja3requests.async_transport import open_transport
from ja3requests.pool import PooledH2Connection
from ja3requests.protocol.h2.async_connection import AsyncH2Connection, H2ProtocolError
from ja3requests.protocol.h2.connection import H2Connection, H2GoAwayError
from ja3requests.protocol.h2.frame import H2Frame
from ja3requests.protocol.h2.hpack import (
    HeaderLimitError,
    HPACKDecoder,
    HPACKEncoder,
    encode_integer,
    encode_string,
)
from ja3requests.protocol.h2.huffman import (
    HuffmanLimitError,
    huffman_decode,
    huffman_encode,
)
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    recv_with_ragged_eof,
)
from test.test_async_h2 import PREFACE, Wire, connected, headers, request


def _fragments(stream, block, *, end=True):
    for offset in range(0, len(block), 16384):
        last = offset + 16384 >= len(block)
        yield h2_frame(
            1 if offset == 0 else 9,
            (1 if end and offset == 0 else 0) | (4 if last else 0),
            stream,
            block[offset : offset + 16384],
        )


async def _until(predicate):
    while not predicate():
        await asyncio.sleep(0)


@pytest.mark.parametrize('huffman', [False, True])
@pytest.mark.parametrize('value', ['literal', 'é' * 8])
def test_decoded_header_budget_counts_octets_and_stops_before_literal_insertion(
    huffman, value
):
    raw = value.encode('utf-8')
    encoded = huffman_encode(raw) if huffman else raw
    block = b'\x40' + encode_string('x-value')
    block += encode_integer(len(encoded), 7, 0x80 if huffman else 0) + encoded
    size = len(b'x-value') + len(raw) + 32
    decoder = HPACKDecoder(max_header_list_size=size)
    assert decoder.decode_headers(block) == [('x-value', value)]
    assert decoder.decode_headers(b'\xbe') == [('x-value', value)]
    too_small = HPACKDecoder(max_header_list_size=size - 1)
    with pytest.raises(HeaderLimitError, match='decoded header list'):
        too_small.decode_headers(block)
    assert not too_small.dynamic_table


def test_indexed_header_expansion_stops_during_list_decode(monkeypatch):
    decoder = HPACKDecoder(max_header_list_size=3 * 2000)
    value = 'x' * (2000 - len('x-repeat') - 32)
    decoder.decode_headers(HPACKEncoder().encode_headers([('x-repeat', value)]))
    lookups = []
    lookup = decoder._lookup

    def count(index):
        lookups.append(index)
        return lookup(index)

    monkeypatch.setattr(decoder, '_lookup', count)
    with pytest.raises(HeaderLimitError):
        decoder.decode_headers(b'\xbe' * 1024)
    assert len(lookups) == 4


def test_huffman_output_limit_fails_before_decoding_invalid_tail():
    encoded = huffman_encode(b'00000000')
    assert huffman_decode(encoded, max_size=8) == b'00000000'
    with pytest.raises(HuffmanLimitError):
        huffman_decode(encoded + b'\xff' * 4, max_size=7)
    assert huffman_decode(b'', max_size=0) == b''


@pytest.mark.parametrize('limit', [0, 41, 42, 65536])
def test_configured_header_list_limit_is_used_without_changing_settings(limit):
    conn = H2Connection(lambda _data: None, lambda _size: b'', settings={6: limit})
    assert conn._local_settings[6] == limit
    assert conn._header_block_limit == max(65536, 4 * limit)
    if limit < 42:
        with pytest.raises(HeaderLimitError):
            conn._decode_headers(b'\x88')
    else:
        assert conn._decode_headers(b'\x88') == [(':status', '200')]
    default = H2Connection(lambda _data: None, lambda _size: b'')
    assert default._local_settings[6] == 16384
    assert default._header_block_limit == 65536


@pytest.mark.parametrize('connection_type', [H2Connection, H2MultiplexConnection])
@pytest.mark.parametrize('settings', [{6: 96}, {}, [], {2: 0}])
@pytest.mark.parametrize('discarded', [False, True])
@pytest.mark.parametrize('kind', ['compressed', 'literal', 'indexed', 'trailers'])
def test_sync_active_and_discarded_header_limits_fail_connection(
    connection_type, settings, discarded, kind
):
    incoming = []
    conn = connection_type(
        lambda _data: None, lambda _size: incoming.pop(0), settings=settings
    )
    conn._peer_settings_received = True
    stream = conn.send_request('GET', 'example.test', '/')
    active = stream
    if discarded:
        if isinstance(conn, H2MultiplexConnection):
            conn.cancel_stream(stream)
        active = conn.send_request('GET', 'example.test', '/active')
    if kind == 'compressed':
        block = b'\x20' * (conn._header_block_limit + 1)
    elif kind == 'literal':
        block = HPACKEncoder().encode_headers(
            [(':status', '200'), ('x-large', 'x' * conn._local_settings[6])]
        )
    elif kind == 'indexed':
        block = b'\x88' + b'\x8f' * (conn._local_settings[6] + 1)
    else:
        incoming.append(headers(stream))
        block = HPACKEncoder().encode_headers(
            [('x-trailer', 'x' * conn._local_settings[6])]
        )
    incoming.extend(_fragments(stream, block))
    with pytest.raises(HeaderLimitError):
        if connection_type is H2Connection:
            conn.receive_response(active)
        else:
            while incoming:
                for frame in conn._feed_frames(incoming.pop(0)):
                    conn._dispatch_frame(frame)
    assert isinstance(conn._failed, HeaderLimitError)
    assert not conn._ignored_header_block and not conn._pending_frames
    if isinstance(conn, H2MultiplexConnection):
        assert all(not state.header_block for state in conn._streams.values())
        with pytest.raises(ConnectionError):
            conn.send_request('GET', 'example.test', '/')
    else:
        with pytest.raises(HeaderLimitError):
            conn.send_request('GET', 'example.test', '/')


@pytest.mark.parametrize(
    'connection_type', [H2Connection, H2MultiplexConnection, AsyncH2Connection]
)
@pytest.mark.parametrize('settings', [None, {}, [], {2: 0}, {6: 32768}])
def test_decoded_budget_is_local_when_not_advertised(connection_type, settings):
    conn = connection_type(lambda _data: None, lambda _size: b'', settings=settings)
    limit = 32768 if settings == {6: 32768} else 16384
    block = HPACKEncoder().encode_headers(
        [(':status', '200'), ('x', 'a' * (limit - 42 - 33))]
    )
    assert conn._decode_headers(block) == [
        (':status', '200'),
        ('x', 'a' * (limit - 42 - 33)),
    ]
    # The budget resets for each block; an exact boundary does not poison state.
    assert conn._decode_headers(b'\x88') == [(':status', '200')]
    oversized = HPACKEncoder().encode_headers(
        [(':status', '200'), ('x', 'a' * (limit - 42 - 32))]
    )
    with pytest.raises(HeaderLimitError, match='decoded header list'):
        conn._decode_headers(oversized)


@pytest.mark.parametrize('settings', [{}, [], {2: 0}])
@pytest.mark.parametrize('cancelled', [False, True])
def test_async_omitted_budget_stops_indexed_expansion_and_fails_streams(
    settings, cancelled
):
    async def run():
        wire = Wire()
        conn = AsyncH2Connection(wire.send, wire.recv, settings=settings)
        try:
            await conn.initiate()
            wire.feed(h2_frame(4, 0, 0))
            await wire.flush()
            first, second = await request(conn), await request(conn)
            if cancelled:
                await conn.cancel_stream(first)
            # 4 KB on the wire would otherwise expand to over 3 MB of fields.
            block = b'\x88\x40\x01x\x7f\xe9\x06' + b'a' * 1000 + b'\xbe' * 3000
            wire.feed(h2_frame(1, 5, first, block))
            with pytest.raises(H2ProtocolError, match='decoded header list'):
                await conn.receive_headers(second if cancelled else first, timeout=1)
            assert conn.failed
            assert not conn._ignored_header_block
            assert all(not state.header_block for state in conn._streams.values())
            with pytest.raises(H2ProtocolError):
                await request(conn)
        finally:
            await conn.aclose()
            assert conn._reader_task.done() and conn._writer_task.done()

    asyncio.run(run())


@pytest.mark.parametrize('cancelled', [False, True])
def test_compressed_header_limit_is_checked_before_append_without_end_headers(
    cancelled,
):
    async def run():
        async with connected() as (conn, wire):
            stream = await request(conn)
            wire.feed(h2_frame(1, 0, stream, b'\x20' * 16384))
            await asyncio.wait_for(_until(lambda: conn._streams[stream].header_open), 1)
            if cancelled:
                await conn.cancel_stream(stream)
            for _ in range(3):
                wire.feed(h2_frame(9, 0, stream, b'\x20' * 16384))
            await asyncio.wait_for(_until(lambda: conn._header_block_bytes == 65536), 1)
            retained = (
                conn._ignored_header_block
                if cancelled
                else conn._streams[stream].header_block
            )
            assert len(retained) == conn._header_block_limit
            wire.feed(h2_frame(9, 0, stream, b'\x20'))
            await asyncio.wait_for(_until(lambda: conn.failed), 1)
            assert isinstance(conn._failed, H2ProtocolError)
            assert not conn._ignored_header_block
            assert all(not state.header_block for state in conn._streams.values())
            with pytest.raises(H2ProtocolError):
                await request(conn)

    asyncio.run(run())


def test_compressed_limit_exact_boundary_and_cancelled_hpack_state_are_preserved():
    async def run():
        async with connected() as (conn, wire):
            first = await request(conn)
            block = b'\x20' * (conn._header_block_limit - 1) + b'\x88'
            wire.feed(*_fragments(first, block))
            assert await conn.receive_headers(first, timeout=1) == [(':status', '200')]
        wire = Wire()
        conn = AsyncH2Connection(wire.send, wire.recv, settings={6: 87})
        try:
            await conn.initiate()
            wire.feed(h2_frame(4, 0, 0))
            await wire.flush()
            first, second = await request(conn), await request(conn)
            block = b'\x88\x40\x08x-shared\x05saved'
            wire.feed(h2_frame(1, 0, first, block[:7]))
            await asyncio.wait_for(_until(lambda: conn._streams[first].header_open), 1)
            await conn.cancel_stream(first)
            wire.feed(
                h2_frame(9, 4, first, block[7:]), headers(second, True, b'\x88\xbe')
            )
            assert await conn.receive_headers(second, timeout=1) == [
                (':status', '200'),
                ('x-shared', 'saved'),
            ]
            assert not conn.failed
        finally:
            await conn.aclose()
            assert conn._reader_task.done() and conn._writer_task.done()

    asyncio.run(run())


class _GoAwayTransport:
    negotiated_protocol = 'h2'

    def __init__(self, code, last_id, attempt, observed):
        self.wire = Wire()
        self.closed = False
        self.code, self.last_id, self.attempt = code, last_id, attempt
        self.observed = observed

    async def write(self, data):
        await self.wire.send(data)
        if data == PREFACE:
            self.wire.feed(h2_frame(4, 0, 0))
        elif data[3] == 1:
            stream = int.from_bytes(data[5:9], 'big')
            self.observed.append((self.attempt, stream))
            if self.attempt == 1:
                self.wire.feed(
                    h2_frame(7, 0, 0, struct.pack('!II', self.last_id, self.code))
                )
                if self.code:
                    self.wire.feed(b'')
            if self.attempt > 1 or (self.code == 0 and self.last_id >= stream):
                self.wire.feed(headers(stream, True))

    async def read(self, size):
        return await self.wire.recv(size)

    def close(self):
        self.closed = True
        self.wire.feed(b'')

    async def aclose(self):
        self.close()


@pytest.mark.parametrize('code', [0, 1, 2, 9])
@pytest.mark.parametrize('last_id', [0, 1])
def test_goaway_error_prevents_retry_even_when_current_stream_is_accepted(
    code, last_id
):
    async def run():
        transports, observed = [], []

        async def connect(*args, **kwargs):
            transport = _GoAwayTransport(code, last_id, len(transports) + 1, observed)
            transports.append(transport)
            return transport

        with patch('ja3requests.async_sessions.open_transport', connect):
            async with AsyncSession(
                retry=HTTPRetry(total=1, backoff_factor=0)
            ) as session:
                if code:
                    with pytest.raises(H2ProtocolError) as error:
                        await session.get('https://example.test/', timeout=1)
                    assert error.value.error_code == code
                    assert error.value.last_stream_id == last_id
                    assert isinstance(error.value.__cause__, H2GoAwayError)
                    assert len(observed) == 1
                else:
                    response = await session.get('https://example.test/', timeout=1)
                    assert response.status_code == 200
                    assert len(observed) == (2 if last_id == 0 else 1)
        assert all(transport.closed for transport in transports)

    asyncio.run(run())


def _read_frame(conn):
    header = read_exact(conn, 9)
    length = int.from_bytes(header[:3], 'big')
    return (
        header[3],
        header[4],
        int.from_bytes(header[5:9], 'big'),
        read_exact(conn, length),
    )


@pytest.mark.parametrize('api', ['sync', 'async'])
def test_cancelled_idle_connection_closes_socket_after_header_limit(api):
    observed = []

    def peer(sock):
        assert read_exact(sock, 24) == PREFACE
        sock.sendall(h2_frame(4, 0, 0))
        while True:
            kind, _, stream, _ = _read_frame(sock)
            if kind == 1:
                break
        sock.sendall(h2_frame(1, 0, stream, b'\x20' * 16384))
        while True:
            kind, _, reset_stream, _ = _read_frame(sock)
            if kind == 3:
                assert reset_stream == stream
                break
        for _ in range(3):
            sock.sendall(h2_frame(9, 0, stream, b'\x20' * 16384))
        sock.sendall(h2_frame(9, 0, stream, b'\x20'))
        observed.append(recv_with_ragged_eof(sock, 1))

    with LocalServer(peer) as server:
        if api == 'sync':
            sock = socket.create_connection(('127.0.0.1', server.port), timeout=2)
            conn = H2MultiplexConnection(sock.sendall, sock.recv)
            pooled = PooledH2Connection(sock, 'http')
            conn.set_pooled_connection(pooled)
            try:
                conn.initiate()
                stream = conn.send_request('GET', 'example.test', '/', timeout=1)
                with conn._condition:
                    assert conn._condition.wait_for(
                        lambda: conn._streams[stream].header_open, 1
                    )
                conn.cancel_stream(stream)
                conn._reader.join(2)
                assert not conn._reader.is_alive() and conn.failed
                assert pooled.conn is None
            finally:
                sock.close()
                conn._reader.join(2)
        else:

            async def run():
                pool = AsyncConnectionPool(max_pool_size=1)
                key = ('127.0.0.1', server.port, 'http', None, None)
                state = {}

                async def factory():
                    transport = await open_transport(
                        '127.0.0.1', server.port, timeout=1
                    )
                    conn = AsyncH2Connection(transport.write, transport.read)
                    state.update(conn=conn, transport=transport)
                    try:
                        await conn.initiate()
                        await conn._wait_for(lambda: conn.capacity_available, 1)
                        return _Entry(key, transport, conn)
                    except BaseException:
                        transport.close()
                        await conn.aclose()
                        await transport.aclose()
                        raise

                try:
                    lease = await pool._acquire(key, factory)
                    conn = state['conn']
                    stream = await request(conn)
                    await asyncio.wait_for(
                        _until(lambda: conn._streams[stream].header_open), 1
                    )
                    await conn.cancel_stream(stream)
                    await lease.release(False)
                    assert not state['transport'].closed and lease.entry.leases == 0
                    await asyncio.wait_for(_until(lambda: state['transport'].closed), 2)
                    assert not pool._entries
                    assert isinstance(conn._failed, H2ProtocolError)
                finally:
                    await pool.aclose()
                assert not pool._cleanup
                assert conn._reader_task.done() and conn._writer_task.done()
                assert conn._close_task.done()

            asyncio.run(run())
    assert observed == [b'']
