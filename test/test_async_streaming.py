"""Event-controlled network evidence for native asynchronous response reading."""

import asyncio
import zlib

import brotli
import pytest

from ja3requests.async_response import AsyncResponse
from ja3requests.async_sessions import AsyncSession
from ja3requests.async_transport import open_transport
from ja3requests import TlsConfig
from ja3requests.exceptions import StreamConsumedError, Timeout
from test.integration.conftest import trusted_certificates
from test.mock_servers.local import LocalServer, tls12_context, tls13_context
from test.test_network_streaming import compressed_gate, framed_gate


class SocketTransport:
    """Observe closure while exercising the project's actual native transport."""

    def __init__(self, transport):
        self.transport = transport
        self.closes = 0

    @classmethod
    async def connect(cls, port):
        return cls(await open_transport('127.0.0.1', port))

    async def read(self, size):
        return await self.transport.read(size)

    async def request(self):
        await self.transport.write(b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')

    async def aclose(self):
        if not self.transport.closed:
            self.closes += 1
            await self.transport.aclose()


async def with_peer(handler, client):
    tasks, errors = set(), []

    async def serve(reader, writer):
        task = asyncio.current_task()
        tasks.add(task)
        try:
            await handler(reader, writer)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            errors.append(error)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(serve, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    try:
        await client(port)
    finally:
        server.close()
        await server.wait_closed()
        if tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*tasks), 2)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
    if errors:
        raise errors[0]


def framing_parts(framing):
    first, tail = b'alpha', b'omega'
    if framing == 'length':
        return b'Content-Length: 10\r\n', first, tail, first + tail
    if framing == 'chunked':
        return (
            b'Transfer-Encoding: chunked\r\n',
            b'5\r\nalpha\r\n',
            b'5\r\nomega\r\n0\r\nX-Finished: yes\r\n\r\n',
            first + tail,
        )
    if framing == 'close':
        return b'Connection: close\r\n', first, tail, first + tail
    first, tail = first * 40, tail * 40
    if framing == 'br':
        compressor = brotli.Compressor()
        prefix = compressor.process(first) + compressor.flush()
        suffix = compressor.process(tail) + compressor.finish()
    else:
        compressor = zlib.compressobj(
            wbits={'gzip': 31, 'deflate': 15, 'raw-deflate': -15}[framing]
        )
        prefix = compressor.compress(first) + compressor.flush(zlib.Z_SYNC_FLUSH)
        suffix = compressor.compress(tail) + compressor.flush(zlib.Z_FINISH)
    encoding = 'deflate' if framing == 'raw-deflate' else framing
    headers = (
        'Content-Length: %d\r\nContent-Encoding: %s\r\n'
        % (len(prefix) + len(suffix), encoding)
    ).encode()
    return headers, prefix, suffix, first + tail


@pytest.mark.parametrize(
    'framing', ['length', 'chunked', 'close', 'gzip', 'deflate', 'raw-deflate', 'br']
)
def test_headers_and_decoded_prefix_arrive_before_the_peer_sends_its_tail(framing):
    async def scenario():
        allow_first, allow_tail, tail_sent = (
            asyncio.Event(),
            asyncio.Event(),
            asyncio.Event(),
        )
        heartbeat = asyncio.Event()
        headers, prefix, suffix, expected = framing_parts(framing)
        released = []

        async def peer(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n')
            await writer.drain()
            await allow_first.wait()
            writer.write(prefix)
            await writer.drain()
            await allow_tail.wait()
            writer.write(suffix)
            await writer.drain()
            tail_sent.set()

        async def client(port):
            transport = await SocketTransport.connect(port)

            async def release(reusable):
                released.append(reusable)
                await transport.aclose()

            response = None
            try:
                await transport.request()
                response = await asyncio.wait_for(
                    AsyncResponse.from_http1(
                        transport,
                        method='GET',
                        url='http://127.0.0.1:%d' % port,
                        release=release,
                        timeout=1,
                    ),
                    1,
                )
                assert response.status_code == 200
                assert not allow_first.is_set()
                iterator = response.aiter_content(17)
                read = asyncio.ensure_future(iterator.__anext__())
                asyncio.get_running_loop().call_soon(heartbeat.set)
                await asyncio.wait_for(heartbeat.wait(), 1)
                assert not read.done()
                allow_first.set()
                first = await asyncio.wait_for(read, 1)
                assert first and expected.startswith(first)
                assert not tail_sent.is_set()
                allow_tail.set()
                result = bytearray(first)
                async for chunk in iterator:
                    assert 0 < len(chunk) <= 17
                    result.extend(chunk)
                assert bytes(result) == expected
                assert response._body is None
                assert released == [framing != 'close']
            finally:
                allow_first.set()
                allow_tail.set()
                if response is not None:
                    await response.aclose()
                await transport.aclose()

        await with_peer(peer, client)

    asyncio.run(scenario())


def test_trailers_finish_before_reuse_and_old_response_close_cannot_close_new_lease():
    async def scenario():
        requests, released = [], []
        allow_second = asyncio.Event()

        async def peer(reader, writer):
            requests.append(await reader.readuntil(b'\r\n\r\n'))
            writer.write(
                b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
                b'3\r\none\r\n0\r\nX-Trailer: value\r\n\r\n'
            )
            await writer.drain()
            requests.append(await reader.readuntil(b'\r\n\r\n'))
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n')
            await writer.drain()
            await allow_second.wait()
            writer.write(b'two')
            await writer.drain()

        async def client(port):
            transport = await SocketTransport.connect(port)

            async def release(reusable):
                released.append(reusable)
                if not reusable:
                    await transport.aclose()

            try:
                await transport.request()
                first = await AsyncResponse.from_http1(
                    transport,
                    method='GET',
                    url='http://localhost',
                    release=release,
                    timeout=1,
                )
                assert await first.read() == b'one'
                assert released == [True]
                await transport.request()
                second = await AsyncResponse.from_http1(
                    transport,
                    method='GET',
                    url='http://localhost',
                    release=release,
                    timeout=1,
                )
                await first.aclose()
                assert transport.closes == 0
                assert released == [True]
                allow_second.set()
                assert await second.read() == b'two'
                assert released == [True, True]
                await second.aclose()
            finally:
                allow_second.set()
                await transport.aclose()

        await with_peer(peer, client)
        assert len(requests) == 2

    asyncio.run(scenario())


@pytest.mark.parametrize('phase', ['headers', 'body', 'early-close'])
def test_cancellation_and_early_close_disconnect_without_waiting_for_peer_eof(phase):
    async def scenario():
        waiting, disconnected = asyncio.Event(), asyncio.Event()
        released = []

        async def peer(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            if phase != 'headers':
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhead')
                await writer.drain()
            waiting.set()
            assert await reader.read() == b''
            disconnected.set()

        async def client(port):
            transport = await SocketTransport.connect(port)

            async def release(reusable):
                released.append(reusable)
                await transport.aclose()

            async def open_response():
                return await AsyncResponse.from_http1(
                    transport,
                    method='GET',
                    url='http://localhost',
                    release=release,
                    timeout=None,
                )

            response = None
            try:
                await transport.request()
                if phase == 'headers':
                    task = asyncio.ensure_future(open_response())
                else:
                    response = await asyncio.wait_for(open_response(), 1)
                    iterator = response.aiter_content(4)
                    assert await iterator.__anext__() == b'head'
                    if phase == 'early-close':
                        await response.aclose()
                        await iterator.aclose()
                        with pytest.raises(StreamConsumedError):
                            await response.read()
                    else:
                        task = asyncio.ensure_future(iterator.__anext__())
                await asyncio.wait_for(waiting.wait(), 1)
                if phase != 'early-close':
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await asyncio.wait_for(task, 1)
                await asyncio.wait_for(disconnected.wait(), 1)
                assert released == [False]
                if response is not None:
                    await response.aclose()
                    assert released == [False]
            finally:
                await transport.aclose()

        await with_peer(peer, client)

    asyncio.run(scenario())


def test_network_read_timeout_maps_to_library_timeout_and_closes_the_connection():
    async def scenario():
        disconnected = asyncio.Event()

        async def peer(reader, writer):
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n')
            await writer.drain()
            assert await reader.read() == b''
            disconnected.set()

        async def client(port):
            transport = await SocketTransport.connect(port)
            try:
                await transport.request()
                response = await AsyncResponse.from_http1(
                    transport, method='GET', url='http://localhost', timeout=0.01
                )
                with pytest.raises(Timeout, match='Response read'):
                    await response.read()
                await asyncio.wait_for(disconnected.wait(), 1)
                assert transport.transport.closed
                assert response.closed
            finally:
                await transport.aclose()

        await with_peer(peer, client)

    asyncio.run(scenario())


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('framing', ['length', 'chunked', 'gzip'])
def test_async_session_streams_authenticated_tls_prefix_before_tail(
    trusted_certificates, monkeypatch, version, framing
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    config = TlsConfig.secure()
    config.alpn_protocols = ['http/1.1']
    certificate = trusted_certificates.leaves['valid']
    if version == 12:
        config.cipher_suites = [0x1301, 0xC02F]
        context = tls12_context(*certificate, cipher='ECDHE-RSA-AES128-GCM-SHA256')
    else:
        config.cipher_suites = [0x1301]
        context = tls13_context(*certificate)
    gate, expected = (
        compressed_gate('gzip')
        if framing == 'gzip'
        else (framed_gate(framing), b'alphaomega')
    )

    async def scenario(port):
        hooks = []
        try:
            async with AsyncSession(
                tls_config=config, hooks={'after_request': [hooks.append]}
            ) as session:
                async with await session.get(
                    'https://127.0.0.1:%d/stream' % port, stream=True, timeout=(3, 1)
                ) as response:
                    assert response.status_code == 200
                    assert hooks == [response]
                    assert not gate.allow_first.is_set()
                    gate.allow_first.set()
                    iterator = response.aiter_content(17)
                    first = await asyncio.wait_for(iterator.__anext__(), 1)
                    assert first and expected.startswith(first)
                    assert not gate.tail_sent.is_set()
                    gate.allow_tail.set()
                    rest = bytearray(first)
                    async for chunk in iterator:
                        rest.extend(chunk)
                    assert bytes(rest) == expected
                    assert response._body is None
        finally:
            gate.release()

    with LocalServer(gate.serve, context) as server:
        asyncio.run(scenario(server.port))


def test_async_session_early_close_discards_then_reconnects():
    async def scenario():
        connections = []
        first_closed = asyncio.Event()

        async def peer(reader, writer):
            connections.append(await reader.readuntil(b'\r\n\r\n'))
            if len(connections) == 1:
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhead')
                await writer.drain()
                assert await reader.read() == b''
                first_closed.set()
            else:
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
                await writer.drain()

        async def client(port):
            async with AsyncSession() as session:
                response = await session.get(
                    'http://127.0.0.1:%d/first' % port, stream=True, timeout=1
                )
                iterator = response.aiter_content(4)
                assert await iterator.__anext__() == b'head'
                await response.aclose()
                await iterator.aclose()
                await asyncio.wait_for(first_closed.wait(), 1)
                second = await session.get(
                    'http://127.0.0.1:%d/second' % port, timeout=1
                )
                assert second.content == b'ok'
                await response.aclose()
                assert second.content == b'ok'

        await with_peer(peer, client)
        assert len(connections) == 2

    asyncio.run(scenario())
