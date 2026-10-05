"""Async response contracts, strict decoding and exactly-once release."""

import asyncio
import contextvars
import gzip
import tracemalloc
import zlib
from types import SimpleNamespace

import brotli
import pytest

from ja3requests.async_response import AsyncResponse
from ja3requests.exceptions import (
    ConnectionException,
    ContentDecodingError,
    HTTPError,
    InvalidResponseHeaders,
    InvalidStatusLine,
    StreamConsumedError,
    Timeout,
)


class MemoryTransport:
    def __init__(self, wire, fragment=65536):
        self.wire = bytearray(wire)
        self.fragment = fragment
        self.reads = 0
        self.closes = 0

    async def read(self, size):
        self.reads += 1
        size = min(size, self.fragment)
        data = bytes(self.wire[:size])
        del self.wire[:size]
        return data

    async def aclose(self):
        self.closes += 1


def wire(body=b'body', headers=b'', status=b'200 OK'):
    return (
        b'HTTP/1.1 '
        + status
        + b'\r\n'
        + b'Content-Length: %d\r\n' % len(body)
        + headers
        + b'\r\n'
        + body
    )


async def make_response(payload, fragment=65536, **kwargs):
    transport = MemoryTransport(payload, fragment)
    released = []

    async def release(reusable):
        released.append(reusable)

    response = await AsyncResponse.from_http1(
        transport,
        method=kwargs.pop('method', 'GET'),
        url='https://example.test/path',
        release=kwargs.pop('release', release),
        **kwargs
    )
    return response, transport, released


async def collect(iterator):
    return [item async for item in iterator]


def test_cached_body_metadata_cookies_and_error_do_not_hide_io():
    async def scenario():
        request = SimpleNamespace(url='https://example.test/path', headers={})
        response, transport, released = await make_response(
            wire(
                b'{"answer":42}',
                b'Set-Cookie: a=one; Path=/\r\n'
                b'set-cookie: b=two; Path=/\r\n'
                b'Content-Type: application/json; charset="utf-8"\r\n',
                b'503 Busy',
            ),
            request=request,
        )
        reads = transport.reads
        with pytest.raises(RuntimeError, match='await response.read'):
            _ = response.content
        with pytest.raises(HTTPError) as raised:
            response.raise_for_status()
        assert raised.value.response is response
        assert raised.value.request is request
        assert transport.reads == reads
        assert response.cookies.get_dict() == {'a': 'one', 'b': 'two'}
        assert not any(name.lower() == 'set-cookie' for name in response.headers)
        assert len(response.raw_headers) == 4
        assert await response.json() == {'answer': 42}
        assert await response.text() == '{"answer":42}'
        assert response.content == b'{"answer":42}'
        assert b''.join(await collect(response.aiter_content(3))) == response.content
        await response.aclose()
        await response.aclose()
        assert released == [True]
        assert response.closed

    asyncio.run(scenario())


def test_encoding_override_and_redirect_metadata():
    async def scenario():
        response, _, released = await make_response(
            wire(b'caf\xe9', b'Location: /next\r\n', b'302 Found')
        )
        response.encoding = 'latin-1'
        assert await response.text() == 'caf\xe9'
        assert response.location == '/next'
        assert response.is_redirected
        assert released == [True]

    asyncio.run(scenario())


@pytest.mark.parametrize('chunk_size', [1, 31, 65536])
@pytest.mark.parametrize('encoding', ['gzip', 'deflate', 'raw-deflate', 'br'])
def test_fragmented_decoding_and_one_uncached_consumer(encoding, chunk_size):
    body = b'alpha\r\nbeta\nomega' * 100
    if encoding == 'gzip':
        compressed = gzip.compress(body[:17]) + gzip.compress(body[17:])
    elif encoding == 'br':
        compressed = brotli.compress(body)
    elif encoding == 'deflate':
        compressed = zlib.compress(body)
    else:
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(body) + compressor.flush()

    async def scenario():
        name = 'deflate' if encoding == 'raw-deflate' else encoding
        response, _, released = await make_response(
            wire(compressed, ('Content-Encoding: %s\r\n' % name).encode()), fragment=3
        )
        iterator = response.aiter_content(chunk_size)
        first = await iterator.__anext__()
        assert first and len(first) <= chunk_size
        with pytest.raises(StreamConsumedError):
            await response.read()
        with pytest.raises(StreamConsumedError):
            await response.aiter_content().__anext__()
        assert first + b''.join(await collect(iterator)) == body
        assert response._body is None
        with pytest.raises(StreamConsumedError):
            _ = response.content
        await response.aclose()
        assert released == [True]

    asyncio.run(scenario())


@pytest.mark.parametrize('chunk_size', [1, 127])
def test_raw_deflate_can_share_a_zlib_header(chunk_size):
    compressed = b'\x78\x9c\x00\x63\xff' + b'x' * 156 + b'\x01\x00\x00\xff\xff'

    async def scenario():
        response, _, released = await make_response(
            wire(compressed, b'Content-Encoding: deflate\r\n'), fragment=3
        )
        assert b''.join(await collect(response.aiter_content(chunk_size))) == b'x' * 156
        assert released == [True]

    asyncio.run(scenario())


@pytest.mark.parametrize('encoding', ['gzip', 'deflate', 'br'])
@pytest.mark.parametrize('eager', [False, True])
def test_truncated_decoder_never_releases_a_reusable_connection(encoding, eager):
    compressed = {
        'gzip': gzip.compress(b'payload'),
        'deflate': zlib.compress(b'payload'),
        'br': brotli.compress(b'payload'),
    }[encoding][:-1]

    async def scenario():
        response, _, released = await make_response(
            wire(compressed, ('Content-Encoding: %s\r\n' % encoding).encode())
        )
        with pytest.raises(ContentDecodingError):
            if eager:
                await response.read()
            else:
                await collect(response.aiter_content(2))
        assert released == [False]
        assert response._body is None
        await response.aclose()
        assert released == [False]

    asyncio.run(scenario())


def test_brotli_expansion_streams_without_a_body_sized_python_allocation():
    size = 4 * 1024 * 1024
    payload = wire(brotli.compress(b'x' * size), b'Content-Encoding: br\r\n')

    async def scenario():
        response, _, released = await make_response(payload)
        count = 0
        tracemalloc.start()
        try:
            async for chunk in response.aiter_content(4096):
                assert chunk == b'x' * len(chunk)
                count += len(chunk)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert count == size
        assert peak < 1024 * 1024
        assert response._body is None
        assert released == [True]

    asyncio.run(scenario())


@pytest.mark.parametrize('chunk_size', [True, 0, -1, 1.5, None])
def test_invalid_chunk_sizes_do_not_claim_or_close_a_body(chunk_size):
    async def scenario():
        response, _, released = await make_response(wire())
        with pytest.raises(ValueError):
            await response.aiter_content(chunk_size).__anext__()
        assert await response.read() == b'body'
        assert released == [True]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    'body, delimiter, expected',
    [
        (b'one\r\ntwo\n\nlast', None, [b'one', b'two', b'', b'last']),
        (b'one<>two<>last', b'<>', [b'one', b'two', b'last']),
    ],
)
def test_lines_preserve_split_delimiters(body, delimiter, expected):
    async def scenario():
        response, _, released = await make_response(wire(body), fragment=1)
        assert await collect(response.aiter_lines(1, delimiter)) == expected
        assert released == [True]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    'payload, error',
    [
        (b'', ConnectionError),
        (b'HTTP/1.1 20', InvalidStatusLine),
        (b'HTTP/1.1 200 OK\r\nContent-Len', InvalidResponseHeaders),
        (b'HTTP/1.1 100 Continue\r\n\r\n', InvalidStatusLine),
        (b'INVALID 200 OK\r\n\r\n', InvalidStatusLine),
        (b'HTTP/1.1 200 OK\r\nMissingColon\r\n\r\n', InvalidResponseHeaders),
        (b'HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n', InvalidResponseHeaders),
        (
            b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n',
            InvalidResponseHeaders,
        ),
        (b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\na', ConnectionException),
        (
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nz\r\n',
            ConnectionException,
        ),
        (
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\naZZ',
            ConnectionException,
        ),
    ],
)
def test_malformed_headers_or_body_discard_once(payload, error):
    async def scenario():
        transport = MemoryTransport(payload, fragment=1)
        released = []

        async def release(reusable):
            released.append(reusable)

        with pytest.raises(error):
            response = await AsyncResponse.from_http1(
                transport, method='GET', url='http://example.test', release=release
            )
            await response.read()
        assert released == [False]

    asyncio.run(scenario())


def test_informational_headers_and_trailers_are_consumed_before_reuse():
    async def scenario():
        response, _, released = await make_response(
            b'HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n'
            b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
            b'3;ext=value\r\none\r\n3\r\ntwo\r\n0\r\nX-Trailer: yes\r\n\r\n',
            fragment=1,
        )
        assert response.status_code == 200
        assert 'Link' not in response.headers
        assert await response.read() == b'onetwo'
        assert released == [True]

    asyncio.run(scenario())


@pytest.mark.parametrize('method,status', [('HEAD', 200), ('GET', 204), ('GET', 304)])
def test_no_body_responses_do_not_wait_for_advertised_length(method, status):
    async def scenario():
        response, _, released = await make_response(
            ('HTTP/1.1 %d OK\r\nContent-Length: 99\r\n\r\n' % status).encode(),
            method=method,
        )
        assert await response.read() == b''
        assert released == [True]

    asyncio.run(scenario())


class WaitingTransport(MemoryTransport):
    def __init__(self, wire_bytes):
        super().__init__(wire_bytes)
        self.waiting = asyncio.Event()
        self.resume = asyncio.Event()
        self.wait_cancelled = 0

    async def read(self, size):
        if self.wire:
            return await super().read(size)
        self.waiting.set()
        try:
            await self.resume.wait()
        except asyncio.CancelledError:
            self.wait_cancelled += 1
            raise
        return b''


@pytest.mark.parametrize('phase', ['headers', 'body'])
def test_read_deadline_is_library_timeout_and_external_cancel_stays_cancelled(phase):
    async def scenario(timeout, cancel):
        initial = (
            b''
            if phase == 'headers'
            else b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n'
        )
        transport = WaitingTransport(initial)
        released = []

        async def release(reusable):
            released.append(reusable)

        async def request_body():
            response = await AsyncResponse.from_http1(
                transport,
                method='GET',
                url='http://example.test',
                release=release,
                timeout=timeout,
            )
            await response.read()

        task = asyncio.ensure_future(request_body())
        await asyncio.wait_for(transport.waiting.wait(), 1)
        if cancel:
            task.cancel()
        with pytest.raises(asyncio.CancelledError if cancel else Timeout):
            await asyncio.wait_for(task, 1)
        assert transport.wait_cancelled == 1
        assert released == [False]

    asyncio.run(scenario(0.01, False))
    asyncio.run(scenario(None, True))


def test_close_wakes_a_pending_read_and_releases_once():
    async def scenario():
        transport = WaitingTransport(b'HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n')
        released = []

        async def release(reusable):
            released.append(reusable)

        response = await AsyncResponse.from_http1(
            transport, method='GET', url='http://example.test', release=release
        )
        task = asyncio.ensure_future(response.read())
        await asyncio.wait_for(transport.waiting.wait(), 1)
        await asyncio.wait_for(response.aclose(), 1)
        with pytest.raises(asyncio.CancelledError):
            await task
        await response.aclose()
        assert released == [False]
        assert transport.wait_cancelled == 1

    asyncio.run(scenario())


def test_repeated_cancellation_of_close_finishes_one_cleanup():
    async def scenario():
        entered, complete = asyncio.Event(), asyncio.Event()
        released = []

        async def release(reusable):
            entered.set()
            await complete.wait()
            released.append(reusable)

        response, _, _ = await make_response(wire(), release=release)
        closing = asyncio.ensure_future(response.aclose())
        await asyncio.wait_for(entered.wait(), 1)
        closing.cancel()
        await asyncio.sleep(0)
        closing.cancel()
        complete.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(closing, 1)
        await response.aclose()
        assert released == [False]
        assert response._cleanup_task.done()

    asyncio.run(scenario())


def test_cleanup_cannot_replace_a_decoder_failure_or_inherit_request_context():
    async def scenario():
        context = contextvars.ContextVar('async_response_test', default='empty')
        observed = []

        async def release(_reusable):
            observed.append(context.get())
            raise OSError('release failure')

        token = context.set('request-private-state')
        try:
            response, _, _ = await make_response(
                wire(b'broken', b'Content-Encoding: gzip\r\n'), release=release
            )
            with pytest.raises(ContentDecodingError):
                await response.read()
            assert response.closed
            assert observed == ['empty']
        finally:
            context.reset(token)

    asyncio.run(scenario())


def test_cancelled_read_remains_cancelled_when_release_fails():
    async def scenario():
        transport = WaitingTransport(b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n')

        async def release(_reusable):
            raise OSError('release failure')

        response = await AsyncResponse.from_http1(
            transport, method='GET', url='http://example.test', release=release
        )
        task = asyncio.ensure_future(response.read())
        await asyncio.wait_for(transport.waiting.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert response.closed

    asyncio.run(scenario())


def test_response_rejects_a_different_loop_before_transport_access():
    first_loop = asyncio.new_event_loop()
    second_loop = asyncio.new_event_loop()
    try:
        response, transport, released = first_loop.run_until_complete(
            make_response(wire())
        )
        reads = transport.reads
        with pytest.raises(RuntimeError, match='different event loop'):
            second_loop.run_until_complete(response.read())
        assert transport.reads == reads
        assert not released
        first_loop.run_until_complete(response.aclose())
        assert released == [False]
    finally:
        first_loop.close()
        second_loop.close()


def test_unowned_bytes_after_http1_framing_prevent_reuse():
    async def scenario():
        response, _, released = await make_response(wire(b'ok') + b'unowned')
        assert await response.read() == b'ok'
        assert released == [False]

    asyncio.run(scenario())


class FakeH2:
    def __init__(self):
        self.bodies = {1: bytearray(b'first'), 3: bytearray(b'other')}
        self.reads = []
        self.cancelled = []

    async def read_stream(self, stream_id, size, timeout=None):
        self.reads.append(stream_id)
        body = self.bodies[stream_id]
        data = bytes(body[:size])
        del body[:size]
        if not data:
            del self.bodies[stream_id]  # A second EOF read would be an error.
        return data

    async def cancel_stream(self, stream_id):
        self.cancelled.append(stream_id)
        self.bodies.pop(stream_id, None)


def test_h2_early_close_targets_one_stream_and_cached_read_never_repeats_eof():
    async def scenario():
        h2 = FakeH2()
        released = []

        async def release(reusable):
            released.append(reusable)

        first = await AsyncResponse.from_http2(
            h2,
            1,
            [(':status', '200'), ('content-length', '5')],
            method='GET',
            url='https://example.test',
            release=release,
        )
        other = await AsyncResponse.from_http2(
            h2,
            3,
            [(':status', '200'), ('content-length', '5'), ('set-cookie', 'a=b')],
            method='GET',
            url='https://example.test',
            release=release,
        )
        iterator = first.aiter_content(2)
        assert await iterator.__anext__() == b'fi'
        await first.aclose()
        await iterator.aclose()
        assert h2.cancelled == [1]
        assert await other.read() == b'other'
        reads = len(h2.reads)
        assert await other.read() == b'other'
        assert other.cookies.get('a') == 'b'
        await other.aclose()
        assert len(h2.reads) == reads
        assert h2.cancelled == [1]
        assert released == [False, True]

    asyncio.run(scenario())


@pytest.mark.parametrize('length', ['4', '6'])
def test_h2_length_mismatch_discards_only_the_owned_stream(length):
    async def scenario():
        h2 = FakeH2()
        released = []

        async def release(reusable):
            released.append(reusable)

        response = await AsyncResponse.from_http2(
            h2,
            1,
            [(':status', '200'), ('content-length', length)],
            method='GET',
            url='https://example.test',
            release=release,
        )
        with pytest.raises(ConnectionException):
            await response.read()
        assert h2.cancelled == [1]
        assert h2.bodies[3] == b'other'
        assert released == [False]

    asyncio.run(scenario())
