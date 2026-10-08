"""Independent HTTP/1 peers exercise incremental upload and exchange ownership."""

import asyncio
import contextvars
import gzip
import io
import threading
import tracemalloc

import pytest

from ja3requests import AsyncConnectionPool, AsyncSession, HTTPRetry, TlsConfig
from ja3requests.async_transport import AsyncTransport
from ja3requests.exceptions import InvalidData, StreamConsumedError, Timeout
from test.integration.conftest import trusted_certificates
from test.mock_servers.local import (
    LocalServer,
    read_exact,
    read_headers,
    recv_with_ragged_eof,
    serve_socks,
    tls12_context,
    tls13_context,
)


async def read_body(reader, headers):
    if headers.get('transfer-encoding') != 'chunked':
        return await reader.readexactly(int(headers.get('content-length', '0')))
    result = bytearray()
    while True:
        line = await reader.readuntil(b'\r\n')
        size = int(line[:-2], 16)
        if not size:
            assert await reader.readexactly(2) == b'\r\n'
            return bytes(result)
        result.extend(await reader.readexactly(size))
        assert await reader.readexactly(2) == b'\r\n'


async def reply(writer, status=200, body=b'ok', headers=b''):
    writer.write(
        ('HTTP/1.1 %d Test\r\nContent-Length: %d\r\n' % (status, len(body))).encode()
        + headers
        + b'\r\n'
        + body
    )
    await writer.drain()


class UploadPeer:
    def __init__(self, route):
        self.route = route
        self.tasks = set()
        self.writers = set()
        self.errors = []
        self.requests = []
        self.connections = 0

    async def __aenter__(self):
        self.server = await asyncio.start_server(self.serve, '127.0.0.1', 0)
        self.url = 'http://127.0.0.1:%d' % self.server.sockets[0].getsockname()[1]
        return self

    async def serve(self, reader, writer):
        self.tasks.add(asyncio.current_task())
        self.writers.add(writer)
        self.connections += 1
        try:
            while True:
                wire = await reader.readuntil(b'\r\n\r\n')
                first, *lines = wire.decode('latin1').split('\r\n')
                method, path, _ = first.split(' ')
                headers = dict(
                    (name.lower(), value.strip())
                    for name, value in (line.split(':', 1) for line in lines if line)
                )
                self.requests.append((method, path, headers))
                if await self.route(reader, writer, method, path, headers) is False:
                    break
        except (asyncio.CancelledError, ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as error:
            self.errors.append(error)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
            self.writers.discard(writer)
            self.tasks.discard(asyncio.current_task())

    async def __aexit__(self, exc_type, *_args):
        self.server.close()
        await self.server.wait_closed()
        for writer in tuple(self.writers):
            writer.close()
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
        if exc_type is None:
            assert self.errors == []


@pytest.mark.parametrize('delay_phase', ['source', 'write', 'both'])
def test_upload_progress_can_exceed_response_read_budget(monkeypatch, delay_phase):
    async def scenario():
        received = []
        original = AsyncTransport.write

        async def slow_write(transport, data):
            if delay_phase in ('write', 'both') and data.startswith(b'1\r\nx'):
                await asyncio.sleep(0.07)
            await original(transport, data)

        async def chunks():
            for _ in range(4):
                if delay_phase in ('source', 'both'):
                    await asyncio.sleep(0.07)
                yield b'x'

        async def route(reader, writer, _method, _path, headers):
            received.append(await read_body(reader, headers))
            await reply(writer)

        monkeypatch.setattr(AsyncTransport, 'write', slow_write)
        async with UploadPeer(route) as peer, AsyncSession() as session:
            response = await session.post(peer.url, data=chunks(), timeout=(1, 0.12))
            assert await response.read() == b'ok'
            assert received == [b'xxxx']
            assert session.pool._entries[0].leases == 0

    asyncio.run(scenario())


@pytest.mark.parametrize('phase', ['headers', 'body'])
def test_upload_completion_restores_response_stall_timeout(phase):
    async def scenario():
        uploaded = asyncio.Event()

        async def route(reader, writer, _method, _path, headers):
            assert await read_body(reader, headers) == b'body'
            uploaded.set()
            if phase == 'body':
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na')
                await writer.drain()
            await reader.read()
            return False

        async with UploadPeer(route) as peer, AsyncSession() as session:
            with pytest.raises(Timeout, match='Response read timed out') as caught:
                await asyncio.wait_for(
                    session.post(peer.url, data=iter((b'body',)), timeout=(1, 0.08)),
                    2,
                )
            assert caught.value.phase == 'read' and uploaded.is_set()
            assert caught.value.response.url == peer.url
            assert caught.value.request is caught.value.response.request
            assert not session.pool._entries

    asyncio.run(scenario())


@pytest.mark.parametrize('timeout', [None, 1])
def test_async_generator_preserves_request_context_and_scope_across_pulls(timeout):
    async def scenario():
        context = contextvars.ContextVar('upload_request')
        caller = context.set('caller')
        observed = []

        async def chunks():
            assert context.get() == 'caller'
            token = context.set('source-scope')
            try:
                yield b'first'
                await asyncio.sleep(0)
                assert context.get() == 'source-scope'
                yield b''
                assert context.get() == 'source-scope'
                yield b'second'
            finally:
                context.reset(token)
                observed.append(context.get())

        async def route(reader, writer, _method, _path, headers):
            assert await read_body(reader, headers) == b'firstsecond'
            await reply(writer)

        try:
            async with UploadPeer(route) as peer, AsyncSession() as session:
                await session.post(peer.url, data=chunks(), timeout=timeout)
            assert observed == ['caller'] and context.get() == 'caller'
        finally:
            context.reset(caller)

    asyncio.run(scenario())


def test_cancelled_async_generator_unwinds_in_its_original_context():
    async def scenario():
        context = contextvars.ContextVar('upload_scope', default='caller')
        blocked = asyncio.Event()
        unwound = []

        async def chunks():
            token = context.set('source')
            try:
                yield b'prefix'
                blocked.set()
                await asyncio.Event().wait()
            finally:
                context.reset(token)
                unwound.append(context.get())

        async def route(reader, _writer, *_args):
            await reader.read()
            return False

        async with UploadPeer(route) as peer, AsyncSession() as session:
            task = asyncio.create_task(session.post(peer.url, data=chunks(), timeout=1))
            await asyncio.wait_for(blocked.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert unwound == ['caller'] and context.get() == 'caller'
            assert not session.pool._entries

    asyncio.run(scenario())


@pytest.mark.parametrize('cancel_from', ['source', 'future'])
@pytest.mark.parametrize('retry', [False, True])
def test_source_cancellation_propagates_without_network_retry(cancel_from, retry):
    async def scenario():
        received = asyncio.Event()
        pulls = []

        async def chunks():
            pulls.append(True)
            await received.wait()
            if cancel_from == 'source':
                raise asyncio.CancelledError()
            future = asyncio.get_running_loop().create_future()
            future.cancel()
            await future
            yield b'unreachable'

        async def route(reader, _writer, *_args):
            received.set()
            await reader.read()
            return False

        policy = HTTPRetry(total=2, backoff_factor=0) if retry else None
        async with UploadPeer(route) as peer, AsyncSession(retry=policy) as session:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(
                    session.put(peer.url, data=chunks(), timeout=0.2), 1
                )
            assert pulls == [True] and len(peer.requests) == peer.connections == 1
            assert not session.pool._entries and not session._requests

    asyncio.run(scenario())


def test_rejected_request_leaves_unstarted_native_generator_available():
    async def scenario():
        finished = []

        async def chunks():
            try:
                yield b'body'
            finally:
                finished.append(True)

        source = chunks()
        async with AsyncSession() as session:
            with pytest.raises(InvalidData):
                await session.put(
                    'http://127.0.0.1:1/',
                    data=source,
                    headers={'Transfer-Encoding': 'chunked'},
                )
            assert not session.pool._entries and not finished
            assert await source.__anext__() == b'body'
            await source.aclose()
            assert finished == [True]

    asyncio.run(scenario())


@pytest.mark.parametrize('finish', ['early-response', 'cancel', 'timeout'])
def test_generator_suspended_after_yield_finishes_in_producer_context(
    monkeypatch, finish
):
    async def scenario():
        context = contextvars.ContextVar('suspended_upload_scope', default='caller')
        writing = asyncio.Event()
        finished = []
        original = AsyncTransport.write

        async def chunks():
            producer = asyncio.current_task()
            token = context.set('source')
            try:
                yield b'prefix'
                pytest.fail('A stopped upload must not resume body production')
            finally:
                assert asyncio.current_task() is producer
                context.reset(token)
                finished.append(context.get())

        async def paused(transport, data):
            if not data.startswith(b'PUT '):
                writing.set()
                await asyncio.Event().wait()
            await original(transport, data)

        async def route(reader, writer, *_args):
            await writing.wait()
            if finish == 'early-response':
                await reply(writer, 413, b'early')
            await reader.read()
            return False

        monkeypatch.setattr(AsyncTransport, 'write', paused)
        source = chunks()
        async with UploadPeer(route) as peer, AsyncSession() as session:
            task = asyncio.create_task(
                session.put(
                    peer.url,
                    data=source,
                    timeout=0.05 if finish == 'timeout' else 1,
                )
            )
            try:
                await asyncio.wait_for(writing.wait(), 1)
                if finish == 'cancel':
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await asyncio.wait_for(task, 1)
                elif finish == 'timeout':
                    with pytest.raises(Timeout) as caught:
                        await asyncio.wait_for(task, 1)
                    assert caught.value.phase == 'write'
                else:
                    response = await asyncio.wait_for(task, 1)
                    assert response.status_code == 413
                    assert await response.read() == b'early'
                assert finished == ['caller'] and context.get() == 'caller'
                assert source.ag_frame is None and not session.pool._entries
                await source.aclose()
            finally:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.parametrize('cleanup_error', [False, True])
def test_real_early_response_finalizes_suspended_large_async_chunk(cleanup_error):
    async def scenario():
        context = contextvars.ContextVar('large_upload_scope', default='caller')
        started = asyncio.Event()
        finished = []

        async def chunks():
            producer = asyncio.current_task()
            token = context.set('source')
            try:
                started.set()
                yield b'x' * (8 * 1024 * 1024)
                pytest.fail('An early response must stop the unfinished source')
            finally:
                assert asyncio.current_task() is producer
                context.reset(token)
                finished.append(context.get())
                if cleanup_error:
                    raise RuntimeError('source finalizer failed after cleanup')

        async def route(reader, writer, *_args):
            await started.wait()
            await reply(writer, 413, b'early')
            await reader.read()
            return False

        source = chunks()
        async with UploadPeer(route) as peer, AsyncSession() as session:
            response = await asyncio.wait_for(
                session.put(peer.url, data=source, timeout=1), 2
            )
            assert response.status_code == 413 and await response.read() == b'early'
            assert finished == ['caller'] and context.get() == 'caller'
            assert source.ag_frame is None and not session.pool._entries
            await source.aclose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    'finish', ['request-cancel', 'response-close', 'session-close']
)
def test_repeated_cancellation_joins_generator_finalizer(monkeypatch, finish):
    async def scenario():
        context = contextvars.ContextVar('finalizing_upload_scope', default='caller')
        writing = asyncio.Event()
        finalizing = asyncio.Event()
        release = asyncio.Event()
        finished = []
        original = AsyncTransport.write

        async def chunks():
            producer = asyncio.current_task()
            token = context.set('source')
            try:
                yield b'prefix'
            finally:
                finalizing.set()
                await release.wait()
                assert asyncio.current_task() is producer
                context.reset(token)
                finished.append(context.get())

        async def paused(transport, data):
            if not data.startswith(b'PUT '):
                writing.set()
                await asyncio.Event().wait()
            await original(transport, data)

        async def route(reader, writer, *_args):
            await writing.wait()
            if finish != 'request-cancel':
                await reply(writer, 413, b'early')
            await reader.read()
            return False

        monkeypatch.setattr(AsyncTransport, 'write', paused)
        source = chunks()
        async with UploadPeer(route) as peer, AsyncSession() as session:
            request = asyncio.create_task(
                session.put(peer.url, data=source, stream=True, timeout=1)
            )
            closing = repeated = None
            try:
                await asyncio.wait_for(writing.wait(), 1)
                if finish == 'request-cancel':
                    closing = request
                    request.cancel()
                else:
                    response = await asyncio.wait_for(request, 1)
                    closing = asyncio.create_task(
                        response.aclose()
                        if finish == 'response-close'
                        else session.aclose()
                    )
                await asyncio.wait_for(finalizing.wait(), 1)
                closing.cancel()
                await asyncio.sleep(0)
                closing.cancel()
                repeated = asyncio.create_task(session.aclose())
                await asyncio.sleep(0)
                if finish == 'session-close':
                    # A cancelled Session.aclose caller may leave its shielded
                    # owner running; a later close still joins that same owner.
                    assert not session._close_task.done()
                else:
                    assert not closing.done()
                assert not repeated.done() and not finished
                release.set()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(closing, 1)
                await asyncio.wait_for(repeated, 1)
                assert finished == ['caller'] and context.get() == 'caller'
                assert source.ag_frame is None and not session.pool._entries
                await source.aclose()
            finally:
                release.set()
                if not request.done():
                    request.cancel()
                await asyncio.gather(
                    *(
                        task
                        for task in (request, closing, repeated)
                        if task is not None
                    ),
                    return_exceptions=True,
                )

    asyncio.run(scenario())


def test_source_catching_deadline_cancellation_keeps_the_upload_timeout():
    async def scenario():
        async def chunks():
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                yield b'late'

        async def route(reader, _writer, *_args):
            await reader.read()
            return False

        async with UploadPeer(route) as peer, AsyncSession() as session:
            with pytest.raises(Timeout, match='upload source read') as caught:
                await session.post(peer.url, data=chunks(), timeout=0.05)
            assert caught.value.phase == 'write'
            assert not session.pool._entries

    asyncio.run(scenario())


@pytest.mark.parametrize('multipart', [False, True])
def test_wrapped_binary_file_streams_its_output_instead_of_underlying_size(
    tmp_path, multipart
):
    payload = b'upload payload\n' * 1024
    path = tmp_path / 'payload.gz'
    path.write_bytes(gzip.compress(payload))

    async def scenario():
        async def route(reader, writer, _method, _path, headers):
            assert headers.get('transfer-encoding') == 'chunked'
            assert 'content-length' not in headers
            body = await read_body(reader, headers)
            if multipart:
                from test.test_async_multipart import parts

                assert parts(headers['content-type'], body) == [
                    ('file', 'payload.gz', payload)
                ]
            else:
                assert body == payload
            await reply(writer)

        async with UploadPeer(route) as peer, AsyncSession() as session:
            with gzip.open(path, 'rb') as source:
                options = {'files': {'file': source}} if multipart else {'data': source}
                await session.post(peer.url, timeout=1, **options)
                assert not source.closed

    asyncio.run(scenario())


@pytest.mark.parametrize('kind', ['file', 'iterator', 'async'])
@pytest.mark.parametrize('declared', [False, True])
def test_real_peer_receives_exact_fixed_or_chunked_upload(kind, declared):
    async def scenario():
        bodies = []

        async def route(reader, writer, _method, _path, headers):
            bodies.append(await read_body(reader, headers))
            await reply(writer)

        async def chunks():
            yield b'abc'
            yield b''
            yield b'def'

        source = (
            io.BytesIO(b'prefixabcdef')
            if kind == 'file'
            else (iter((b'abc', b'', b'def')) if kind == 'iterator' else chunks())
        )
        if kind == 'file':
            source.seek(6)
        async with UploadPeer(route) as peer, AsyncSession() as session:
            response = await session.put(
                peer.url,
                data=source,
                headers={'Content-Length': '6'} if declared else {},
                timeout=2,
            )
            assert await response.read() == b'ok'
            assert bodies == [b'abcdef']
            headers = peer.requests[0][2]
            assert 'content-type' not in headers
            known = declared or kind == 'file'
            assert headers.get('content-length') == ('6' if known else None)
            assert headers.get('transfer-encoding') == (None if known else 'chunked')
        if kind == 'file':
            assert not source.closed and source.tell() == 12

    asyncio.run(scenario())


@pytest.mark.parametrize(
    'headers',
    [
        {'Content-Length': '1', 'content-length': '1'},
        {'Content-Length': '-1'},
        {'Content-Length': '1,1'},
        {'Content-Length': ' 1'},
        {'Transfer-Encoding': 'chunked'},
        {'Content-Length': '1', 'Transfer-Encoding': 'chunked'},
    ],
)
def test_streaming_framing_rejected_before_source_pull_or_network(headers):
    async def scenario():
        pulled = []

        def chunks():
            pulled.append(True)
            yield b'x'

        async with AsyncSession() as session:
            with pytest.raises(InvalidData):
                await session.put('http://127.0.0.1:1/', data=chunks(), headers=headers)
        assert pulled == []

    asyncio.run(scenario())


@pytest.mark.parametrize(
    'chunks,length', [([b'ab'], 3), ([b'abcd'], 3), (['bad'], None)]
)
def test_source_errors_are_not_network_retried(chunks, length):
    async def scenario():
        async def route(reader, writer, _method, _path, headers):
            await read_body(reader, headers)
            await reply(writer)

        async with UploadPeer(route) as peer, AsyncSession(
            retry=HTTPRetry(total=2)
        ) as session:
            with pytest.raises(InvalidData):
                await session.put(
                    peer.url,
                    data=iter(chunks),
                    timeout=1,
                    headers={} if length is None else {'Content-Length': str(length)},
                )
            assert peer.connections == 1
            assert not session.pool._entries

    asyncio.run(scenario())


def test_source_prefix_arrives_before_eof_and_backpressure_stops_pulls(monkeypatch):
    async def scenario():
        prefix = asyncio.Event()
        release = asyncio.Event()
        write_started = asyncio.Event()
        pulls = []
        original = AsyncTransport.write

        async def chunks():
            pulls.append(1)
            yield b'x' * 65536
            pulls.append(2)
            yield b'last'

        async def paused(transport, data):
            await original(transport, data)
            if not data.startswith(b'PUT '):
                write_started.set()
                await release.wait()

        monkeypatch.setattr(AsyncTransport, 'write', paused)

        async def route(reader, writer, _method, _path, _headers):
            assert await reader.readuntil(b'\r\n') == b'10000\r\n'
            assert await reader.readexactly(65538) == b'x' * 65536 + b'\r\n'
            prefix.set()
            assert await reader.readuntil(b'\r\n') == b'4\r\n'
            assert await reader.readexactly(6) == b'last\r\n'
            assert await reader.readexactly(5) == b'0\r\n\r\n'
            await reply(writer)

        async with UploadPeer(route) as peer, AsyncSession() as session:
            task = asyncio.create_task(session.put(peer.url, data=chunks(), timeout=2))
            try:
                await asyncio.wait_for(prefix.wait(), 1)
                await asyncio.wait_for(write_started.wait(), 1)
                assert pulls == [1] and not task.done()
                release.set()
                assert await (await asyncio.wait_for(task, 2)).read() == b'ok'
            finally:
                release.set()

    asyncio.run(scenario())


@pytest.mark.parametrize('status', [307, 308, 503])
@pytest.mark.parametrize('replayable', [False, True])
def test_body_preserving_redirect_and_retry_replay_rules(status, replayable):
    async def scenario():
        bodies = []
        hooks = []

        async def route(reader, writer, _method, _path, headers):
            bodies.append(await read_body(reader, headers))
            if len(bodies) == 1:
                await reply(writer, status, headers=b'Location: /again\r\n')
            else:
                await reply(writer)

        source = io.BytesIO(b'offsetpayload') if replayable else iter((b'payload',))
        if replayable:
            source.seek(6)
        retry = HTTPRetry(total=1, status_forcelist=[503]) if status == 503 else None
        async with UploadPeer(route) as peer, AsyncSession(retry=retry) as session:

            async def before(request):
                hooks.append(request.url)

            operation = session.put(
                peer.url,
                data=source,
                timeout=2,
                hooks={'before_request': [before]},
            )
            if replayable:
                response = await operation
                assert await response.read() == b'ok'
                assert bodies == [b'payload', b'payload']
                assert len(hooks) == (1 if status == 503 else 2)
                assert not source.closed
            else:
                with pytest.raises(StreamConsumedError) as caught:
                    await operation
                assert caught.value.response.status_code == status
                assert bodies == [b'payload']

    asyncio.run(scenario())


def test_before_hook_replaces_buffered_body_with_one_stream_source():
    async def scenario():
        seen = []
        source = io.BytesIO(b'new-body')

        def before(request):
            request.body = source

        async def route(reader, writer, _method, _path, headers):
            seen.append((headers, await read_body(reader, headers)))
            await reply(writer)

        async with UploadPeer(route) as peer, AsyncSession() as session:
            await session.put(peer.url, data=b'old', hooks={'before_request': [before]})
        assert seen[0][0]['content-length'] == '8'
        assert seen[0][1] == b'new-body'
        assert not source.closed

    asyncio.run(scenario())


@pytest.mark.parametrize('initial', ['file', 'one-shot'])
def test_redirect_hook_selects_new_body_before_replay_check(initial):
    async def scenario():
        bodies = []
        headers_seen = []
        source = io.BytesIO(b'first') if initial == 'file' else iter((b'first',))

        def before(request):
            if request.url.endswith('/again'):
                request.body = io.BytesIO(b'longer-body')

        async def route(reader, writer, _method, path, headers):
            headers_seen.append(headers)
            bodies.append(await read_body(reader, headers))
            if path == '/':
                await reply(writer, 307, headers=b'Location: /again\r\n')
            else:
                await reply(writer)

        async with UploadPeer(route) as peer, AsyncSession() as session:
            await session.put(
                peer.url, data=source, hooks={'before_request': [before]}, timeout=2
            )
        assert bodies == [b'first', b'longer-body']
        assert headers_seen[-1]['content-length'] == '11'

    asyncio.run(scenario())


@pytest.mark.parametrize('stream', [False, True])
def test_early_response_is_readable_while_writer_is_blocked(monkeypatch, stream):
    async def scenario():
        writing = asyncio.Event()
        release_write = asyncio.Event()
        cancelled_write = asyncio.Event()
        original = AsyncTransport.write

        async def paused(transport, data):
            if not data.startswith(b'PUT '):
                writing.set()
                try:
                    await release_write.wait()
                except asyncio.CancelledError:
                    cancelled_write.set()
                    raise
            await original(transport, data)

        monkeypatch.setattr(AsyncTransport, 'write', paused)

        async def route(_reader, writer, *_args):
            await writing.wait()
            await reply(writer, 413, b'early')
            await _reader.read()
            return False

        async with UploadPeer(route) as peer, AsyncSession() as session:
            response = await asyncio.wait_for(
                session.put(
                    peer.url,
                    data=iter((b'x' * 65536,)),
                    stream=stream,
                    timeout=2,
                ),
                1,
            )
            if stream:
                assert not cancelled_write.is_set()
                assert not response._released
            assert response.status_code == 413
            assert await asyncio.wait_for(response.read(), 1) == b'early'
            assert cancelled_write.is_set()
            assert not session.pool._entries

    asyncio.run(scenario())


@pytest.mark.parametrize('failure', ['error', 'timeout'])
def test_late_write_failure_surfaces_through_streaming_response(monkeypatch, failure):
    async def scenario():
        writing = asyncio.Event()
        fail_write = asyncio.Event()
        original = AsyncTransport.write

        async def paused(transport, data):
            if not data.startswith(b'PUT '):
                writing.set()
                await fail_write.wait()
                raise OSError('late upload write failure')
            await original(transport, data)

        monkeypatch.setattr(AsyncTransport, 'write', paused)

        async def route(reader, writer, *_args):
            await writing.wait()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab')
            await writer.drain()
            await reader.read()
            return False

        async with UploadPeer(route) as peer, AsyncSession() as session:
            response = await session.put(
                peer.url,
                data=iter((b'data',)),
                stream=True,
                timeout=0.1 if failure == 'timeout' else 2,
            )
            if failure == 'error':
                fail_write.set()
            expected = Timeout if failure == 'timeout' else OSError
            with pytest.raises(expected):
                await response.read()
            assert not session.pool._entries

    asyncio.run(scenario())


@pytest.mark.parametrize('action', ['cancel', 'close', 'timeout'])
def test_blocking_borrowed_source_is_joined_after_network_stop(action):
    async def scenario():
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        peer_closed = asyncio.Event()
        release = threading.Event()

        class Blocking:
            closed = False

            def __iter__(self):
                return self

            def __next__(self):
                loop.call_soon_threadsafe(entered.set)
                assert release.wait(4)
                return b'data'

            def close(self):
                self.closed = True

        async def route(reader, _writer, *_args):
            await reader.read()
            peer_closed.set()
            return False

        source = Blocking()
        pool = AsyncConnectionPool()
        async with UploadPeer(route) as peer:
            session = AsyncSession(pool=pool)
            task = asyncio.create_task(
                session.put(
                    peer.url,
                    data=source,
                    timeout=0.1 if action == 'timeout' else 2,
                )
            )
            closer = None
            try:
                await asyncio.wait_for(entered.wait(), 1)
                if action == 'cancel':
                    task.cancel()
                elif action == 'close':
                    closer = asyncio.create_task(session.aclose())
                await asyncio.wait_for(peer_closed.wait(), 1)
                assert not task.done() and not source.closed
                if action == 'cancel':
                    for _ in range(3):
                        task.cancel()
                        await asyncio.sleep(0)
                        assert not task.done()
                release.set()
                with pytest.raises(
                    Timeout if action == 'timeout' else asyncio.CancelledError
                ):
                    await asyncio.wait_for(task, 2)
                if closer is not None:
                    await closer
                assert not pool._closed and not pool._entries
            finally:
                release.set()
                await session.aclose()
                await pool.aclose()
            assert not source.closed and not session._requests

    asyncio.run(scenario())


def test_complete_chunked_upload_returns_connection_to_pool():
    async def scenario():
        bodies = []

        async def route(reader, writer, _method, _path, headers):
            bodies.append(await read_body(reader, headers))
            await reply(writer)

        async with UploadPeer(route) as peer, AsyncSession() as session:
            for _ in range(2):
                await session.put(peer.url, data=iter((b'one', b'two')), timeout=2)
            assert peer.connections == 1
            assert bodies == [b'onetwo', b'onetwo']

    asyncio.run(scenario())


@pytest.mark.parametrize('finish', ['read', 'close', 'session-close'])
@pytest.mark.parametrize('empty', [False, True])
def test_early_final_stops_async_source_without_closing_borrowed_object(finish, empty):
    async def scenario():
        started = asyncio.Event()
        cancelled = asyncio.Event()

        class Source:
            close_count = 0

            def __aiter__(self):
                return self

            async def __anext__(self):
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()

            async def aclose(self):
                self.close_count += 1

        async def route(reader, writer, *_args):
            await started.wait()
            await reply(writer, 413, b'' if empty else b'early')
            await reader.read()
            return False

        source = Source()
        before = set(asyncio.all_tasks())
        async with UploadPeer(route) as peer, AsyncSession() as session:
            response = await asyncio.wait_for(
                session.put(peer.url, data=source, stream=True, timeout=2), 1
            )
            if finish == 'read':
                assert await response.read() == (b'' if empty else b'early')
            elif finish == 'close':
                await response.aclose()
            else:
                await session.aclose()
            assert cancelled.is_set() and source.close_count == 0
            assert not session.pool._entries
        await asyncio.sleep(0)
        assert set(asyncio.all_tasks()) == before

    asyncio.run(scenario())


@pytest.mark.parametrize('known', [False, True])
@pytest.mark.parametrize(
    'route',
    [
        'http',
        'socks4a',
        'socks5h',
        'tls12',
        'tls13',
        'tls13-http',
        'tls13-socks5h',
    ],
)
def test_tls_and_proxy_routes_send_prefix_before_source_finishes(
    trusted_certificates, monkeypatch, known, route
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    config = TlsConfig.secure()
    config.alpn_protocols = ['http/1.1']
    certificate = trusted_certificates.leaves['valid']
    context = None
    if route == 'tls12':
        config.cipher_suites = [0x1301, 0xC02F]
        context = tls12_context(*certificate, cipher='ECDHE-RSA-AES128-GCM-SHA256')
    elif route.startswith('tls13'):
        config.cipher_suites = [0x1301]
        context = tls13_context(*certificate)
    proxy_scheme = route.rsplit('-', 1)[-1] if '-' in route else route
    proxy_scheme = None if proxy_scheme.startswith('tls') else proxy_scheme
    prefix = b'x' * 65536
    tail = b'last'
    seen = []
    observed = {}

    def readline(conn):
        result = b''
        while not result.endswith(b'\r\n'):
            result += read_exact(conn, 1)
        return result

    def http_peer(conn):
        headers = read_headers(conn).lower()
        if known:
            assert b'content-length: 65540\r\n' in headers
        else:
            assert b'transfer-encoding: chunked\r\n' in headers
            assert readline(conn) == b'10000\r\n'
        assert read_exact(conn, len(prefix)) == prefix
        if not known:
            assert read_exact(conn, 2) == b'\r\n'
        seen.append('prefix')
        loop.call_soon_threadsafe(prefix_seen.set)
        if not known:
            assert readline(conn) == b'4\r\n'
        assert read_exact(conn, len(tail)) == tail
        if not known:
            assert read_exact(conn, 7) == b'\r\n0\r\n\r\n'
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
        while recv_with_ragged_eof(conn, 1024):
            pass

    def tunnel(conn):
        if context is None:
            http_peer(conn)
        else:
            with context.wrap_socket(conn, server_side=True) as secured:
                http_peer(secured)

    def proxy_peer(conn):
        if proxy_scheme == 'http':
            assert read_headers(conn).startswith(b'CONNECT ')
            conn.sendall(b'HTTP/1.1 200 Established\r\n\r\n')
            tunnel(conn)
        else:
            serve_socks(
                conn,
                observed,
                version=4 if proxy_scheme == 'socks4a' else 5,
                tunnel_handler=tunnel,
            )

    async def scenario(port):
        nonlocal loop, prefix_seen
        loop = asyncio.get_running_loop()
        prefix_seen = asyncio.Event()
        finish = asyncio.Event()

        async def chunks():
            yield prefix
            await finish.wait()
            yield tail

        async with AsyncSession(tls_config=config) as session:
            scheme = 'https' if context is not None else 'http'
            host = 'localhost:443' if proxy_scheme else '127.0.0.1:%d' % port
            task = asyncio.create_task(
                session.put(
                    '%s://%s/upload' % (scheme, host),
                    data=chunks(),
                    timeout=(3, 2),
                    headers={'Content-Length': '65540'} if known else {},
                    proxies=(
                        {scheme: '%s://127.0.0.1:%d' % (proxy_scheme, port)}
                        if proxy_scheme
                        else None
                    ),
                )
            )
            try:
                await asyncio.wait_for(prefix_seen.wait(), 3)
                assert not task.done() and seen == ['prefix']
                finish.set()
                assert await (await task).read() == b'ok'
            finally:
                finish.set()

    loop = prefix_seen = None
    with LocalServer(
        proxy_peer if proxy_scheme else http_peer, None if proxy_scheme else context
    ) as server:
        asyncio.run(scenario(server.port))


def test_generated_upload_memory_is_bounded_as_total_size_grows():
    async def scenario():
        totals = []

        async def route(reader, writer, _method, _path, headers):
            assert headers['transfer-encoding'] == 'chunked'
            total = 0
            while True:
                size = int((await reader.readuntil(b'\r\n'))[:-2], 16)
                if not size:
                    assert await reader.readexactly(2) == b'\r\n'
                    break
                assert size <= 65536
                total += len(await reader.readexactly(size))
                assert await reader.readexactly(2) == b'\r\n'
            totals.append(total)
            await reply(writer)

        peaks = []
        async with UploadPeer(route) as peer, AsyncSession() as session:
            for count in (16, 128):

                async def chunks():
                    for _ in range(count):
                        yield b'x' * 65536

                tracemalloc.start()
                try:
                    await session.put(peer.url, data=chunks(), timeout=2)
                    peaks.append(tracemalloc.get_traced_memory()[1])
                finally:
                    tracemalloc.stop()
        assert totals == [1024 * 1024, 8 * 1024 * 1024]
        assert peaks[1] < peaks[0] + 512 * 1024

    asyncio.run(scenario())


def test_transferred_upload_response_owns_source_when_original_request_is_cancelled():
    async def scenario():
        loop = asyncio.get_running_loop()
        source_started = asyncio.Event()
        hook_started = asyncio.Event()
        allow_body = asyncio.Event()
        allow_source = threading.Event()
        captured = []

        class BlockingFile:
            closed = False

            def seekable(self):
                return False

            def read(self, _size):
                loop.call_soon_threadsafe(source_started.set)
                assert allow_source.wait(5)
                return b'data'

            def close(self):
                self.closed = True

        async def slow(reader, writer, *_args):
            await source_started.wait()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n')
            await writer.drain()
            await allow_body.wait()
            writer.write(b'tail')
            await writer.drain()
            await reader.read()
            return False

        async def ready(_reader, writer, *_args):
            await reply(writer, body=b'')

        async def after(response):
            captured.append(response)
            hook_started.set()
            await asyncio.Event().wait()

        source = BlockingFile()
        async with UploadPeer(slow) as slow_peer, UploadPeer(ready) as ready_peer:
            donor, recipient = AsyncSession(), AsyncSession()
            task = asyncio.create_task(
                donor.post(
                    slow_peer.url,
                    data=source,
                    stream=True,
                    timeout=3,
                    hooks={'after_request': [after]},
                )
            )
            try:
                await asyncio.wait_for(hook_started.wait(), 1)
                response = captured[0]
                adapter = response.request.body
                adopted = await recipient.get(
                    ready_peer.url,
                    stream=True,
                    hooks={'after_request': [lambda _response: response]},
                )
                assert adopted is response
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 1)
                await asyncio.wait_for(donor.aclose(), 1)
                assert not adapter._closed and not source.closed
                assert not response.closed and not response._transport.closed
                allow_source.set()
                allow_body.set()
                assert await asyncio.wait_for(response.read(), 2) == b'tail'
                assert adapter._closed and not source.closed
                assert not donor.pool._entries
            finally:
                allow_source.set()
                allow_body.set()
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await donor.aclose()
                await recipient.aclose()

    asyncio.run(scenario())


def test_transferred_h2_upload_keeps_producing_after_original_request_cancellation(
    trusted_certificates, monkeypatch
):
    from test.integration.test_h2_streaming_network import (
        await_transport_close,
        receive_frame,
        start_h2,
        trusted_h2_peer,
    )
    from test.mock_servers.local import h2_frame

    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    received = []

    def peer(conn):
        start_h2(conn)
        while True:
            kind, flags, stream, _data = receive_frame(conn)
            if kind == 1:
                assert flags == 4
                break
        conn.sendall(h2_frame(1, 4, stream, b'\x88'))
        body = bytearray()
        while True:
            kind, flags, target, data = receive_frame(conn)
            assert kind != 3, 'Transferring the response cancelled its upload'
            if kind == 0:
                assert target == stream
                body.extend(data)
                if flags & 1:
                    break
        received.append(bytes(body))
        conn.sendall(h2_frame(0, 1, stream, b'tail'))
        await_transport_close(conn)

    async def scenario(port):
        allow_source = asyncio.Event()
        hook_started = asyncio.Event()
        captured = []

        async def source():
            await allow_source.wait()
            yield b'data-after-transfer'

        async def ready(_reader, writer, *_args):
            await reply(writer, body=b'')

        async def after(response):
            captured.append(response)
            hook_started.set()
            await asyncio.Event().wait()

        async with UploadPeer(ready) as ready_peer:
            donor = AsyncSession(tls_config=config)
            recipient = AsyncSession()
            task = asyncio.create_task(
                donor.post(
                    'https://127.0.0.1:%d/' % port,
                    data=source(),
                    stream=True,
                    timeout=3,
                    hooks={'after_request': [after]},
                )
            )
            try:
                await asyncio.wait_for(hook_started.wait(), 2)
                response = captured[0]
                adapter = response.request.body
                producer = next(iter(donor.pool._entries[0].h2._producers.values()))
                await recipient.get(
                    ready_peer.url,
                    stream=True,
                    hooks={'after_request': [lambda _response: response]},
                )
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 1)
                await asyncio.wait_for(donor.aclose(), 1)
                assert not adapter._closed and not producer.done()
                allow_source.set()
                assert await response.read() == b'tail'
                assert adapter._closed and producer.done()
                assert not donor.pool._entries
            finally:
                allow_source.set()
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                await donor.aclose()
                await recipient.aclose()

    with LocalServer(peer, context) as server:
        asyncio.run(scenario(server.port))
    assert received == [b'data-after-transfer']
