"""Real loopback policy/lifetime tests driven on the client's event loop."""

import asyncio
import json
from dataclasses import replace

import pytest

from ja3requests.async_pool import AsyncConnectionPool
from ja3requests.async_sessions import AsyncSession
from ja3requests.exceptions import (
    InvalidResponseHeaders,
    InvalidStatusLine,
    MaxRetriedException,
    Timeout,
)
from ja3requests.retry import HTTPRetry


class Peer:
    def __init__(self, route):
        self.route = route
        self.requests = []
        self.connections = 0
        self.tasks = set()
        self.writers = set()
        self.errors = []
        self.received = None

    async def __aenter__(self):
        self.received = asyncio.Event()
        self.server = await asyncio.start_server(self.serve, '127.0.0.1', 0)
        self.url = 'http://127.0.0.1:%d' % self.server.sockets[0].getsockname()[1]
        return self

    async def serve(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        self.connections += 1
        try:
            while True:
                try:
                    wire = await reader.readuntil(b'\r\n\r\n')
                except asyncio.IncompleteReadError:
                    break
                first, *lines = wire.decode('latin1').split('\r\n')
                method, path, _ = first.split(' ')
                headers = dict(line.split(': ', 1) for line in lines if line)
                body = await reader.readexactly(int(headers.get('Content-Length', 0)))
                request = (method, path, headers, body)
                self.requests.append(request)
                self.received.set()
                status, response_headers, response_body = await self.route(*request)
                response_headers = dict(response_headers)
                response_headers.setdefault('Content-Length', str(len(response_body)))
                writer.write(('HTTP/1.1 %d Test\r\n' % status).encode())
                writer.write(
                    ''.join(
                        '%s: %s\r\n' % item for item in response_headers.items()
                    ).encode('latin1')
                )
                writer.write(b'\r\n')
                if method != 'HEAD':
                    writer.write(response_body)
                await writer.drain()
                if response_headers.get('Connection', '').lower() == 'close':
                    break
        except (asyncio.CancelledError, ConnectionError):
            pass
        except Exception as error:
            self.errors.append(error)
        finally:
            writer.close()
            await writer.wait_closed()
            self.writers.discard(writer)
            self.tasks.discard(task)

    async def __aexit__(self, exc_type, *_):
        self.server.close()
        for writer in tuple(self.writers):
            writer.close()
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*tuple(self.tasks), return_exceptions=True)
        await self.server.wait_closed()
        if exc_type is None:
            assert not self.errors


async def ok(*_):
    return 200, {}, b'ok'


def test_http_reuse_and_binary_or_json_request_serialization():
    async def run():
        async with Peer(ok) as peer:
            async with AsyncSession() as session:
                assert (
                    await (
                        await session.get(peer.url, params={'q': 'a b'}, timeout=1)
                    ).text()
                    == 'ok'
                )
                response = await session.post(peer.url, json={}, timeout=1)
                assert response.content == b'ok'
                await session.patch(peer.url, data=b'\xff\x00', timeout=1)
                assert peer.connections == 1
                assert peer.requests[0][1] == '/?q=a+b'
                assert json.loads(peer.requests[1][3]) == {}
                assert peer.requests[2][3] == b'\xff\x00'
            assert not session.pool._entries
            with pytest.raises(RuntimeError, match='closed'):
                await session.get(peer.url)

    asyncio.run(run())


def test_retry_hooks_and_cookies_have_one_final_boundary():
    async def run():
        calls = []

        async def route(*_):
            return (
                (503, {'Set-Cookie': 'retry=seen; Path=/'}, b'bad')
                if len(peer.requests) == 1
                else (200, {}, b'ok')
            )

        async def before(request):
            calls.append(('before', request.url))
            assert not hasattr(request, 'send')
            return replace(request, headers=dict(request.headers, X_Test='yes'))

        async def after(response):
            calls.append(('after', response.status_code))

        async with Peer(route) as peer:
            async with AsyncSession(
                retry=HTTPRetry(total=1, backoff_factor=0),
                hooks={'before_request': [before], 'after_request': [after]},
            ) as session:
                result = await session.get(peer.url, timeout=1)
                assert result.content == b'ok'
                assert session.cookies.get('retry') == 'seen'
                assert len(peer.requests) == 2 and len(calls) == 2
                assert peer.requests[1][2]['X_Test'] == 'yes'

    asyncio.run(run())


@pytest.mark.parametrize('method', ['GET', 'POST'])
def test_empty_response_eof_obeys_retry_method_policy(method):
    async def run():
        async def route(*_):
            if len(peer.requests) == 1:
                raise ConnectionError('Close before sending any response bytes')
            return 200, {}, b'ok'

        async with Peer(route) as peer:
            async with AsyncSession(
                retry=HTTPRetry(total=1, backoff_factor=0)
            ) as session:
                if method == 'GET':
                    response = await session.request(method, peer.url, timeout=1)
                    assert response.content == b'ok'
                    assert len(peer.requests) == peer.connections == 2
                else:
                    with pytest.raises(ConnectionError, match='before HTTP response'):
                        await session.request(method, peer.url, timeout=1)
                    assert len(peer.requests) == peer.connections == 1
                    assert not session.pool._entries

    asyncio.run(run())


@pytest.mark.parametrize(
    'prefix, error',
    [
        (b'HTTP/1.1 20', InvalidStatusLine),
        (b'HTTP/1.1 200 OK\r\nContent-Len', InvalidResponseHeaders),
        (b'HTTP/1.1 100 Continue\r\n\r\n', InvalidStatusLine),
    ],
)
def test_partial_response_eof_is_not_retried(prefix, error):
    async def run():
        async def route(*_):
            if len(peer.requests) == 1:
                writer = next(iter(peer.writers))
                writer.write(prefix)
                await writer.drain()
                raise ConnectionError('Close after an incomplete response')
            return 200, {}, b'ok'

        async with Peer(route) as peer:
            async with AsyncSession(
                retry=HTTPRetry(total=1, backoff_factor=0)
            ) as session:
                with pytest.raises(error):
                    await session.get(peer.url, timeout=1)
                assert len(peer.requests) == peer.connections == 1
                assert not session.pool._entries

    asyncio.run(run())


@pytest.mark.parametrize('raise_on_status', [True, False])
def test_exhaustion_runs_hooks_and_retains_closed_final_response(raise_on_status):
    async def run():
        async def route(*_):
            return 503, {}, b'bad'

        observed = []
        async with Peer(route) as peer:
            async with AsyncSession(
                retry=HTTPRetry(total=0, raise_on_status=raise_on_status)
            ) as session:
                if raise_on_status:
                    with pytest.raises(MaxRetriedException) as raised:
                        await session.get(
                            peer.url,
                            stream=True,
                            timeout=1,
                            hooks={'after_request': [observed.append]},
                        )
                    assert raised.value.response is observed[0]
                    assert observed[0].closed
                else:
                    result = await session.get(
                        peer.url, timeout=1, hooks={'after_request': [observed.append]}
                    )
                    assert result is observed[0] and result.content == b'bad'
                assert len(peer.requests) == 1

    asyncio.run(run())


@pytest.mark.parametrize('event', ['before_request', 'after_request'])
def test_hook_oserror_does_not_trigger_retries(event):
    async def run():
        def fail(_):
            raise OSError('hook failed')

        async with Peer(ok) as peer:
            async with AsyncSession(
                retry=HTTPRetry(total=3, backoff_factor=0)
            ) as session:
                with pytest.raises(OSError, match='hook failed'):
                    await session.get(
                        peer.url, timeout=1, stream=True, hooks={event: [fail]}
                    )
                assert len(peer.requests) == (event == 'after_request')
                assert not session.pool._entries

    asyncio.run(run())


@pytest.mark.parametrize(
    'status,method,expected',
    [
        (301, 'POST', 'GET'),
        (302, 'POST', 'GET'),
        (303, 'PUT', 'GET'),
        (307, 'POST', 'POST'),
        (308, 'PATCH', 'PATCH'),
        (302, 'PUT', 'PUT'),
        (303, 'HEAD', 'HEAD'),
    ],
)
def test_redirect_method_and_body_rules(status, method, expected):
    async def run():
        async def route(_method, path, *_):
            if path == '/one':
                return (
                    status,
                    {'Location': 'two', 'Set-Cookie': 'step=one; Path=/'},
                    b'',
                )
            return 200, {}, b'ok'

        async with Peer(route) as peer:
            async with AsyncSession() as session:
                response = await session.request(
                    method,
                    peer.url + '/one',
                    data=b'payload',
                    allow_redirects=True,
                    timeout=1,
                )
                assert response.status_code == 200
                assert peer.requests[1][0:2] == (expected, '/two')
                assert peer.requests[1][3] == (b'' if expected == 'GET' else b'payload')
                assert 'step=one' in peer.requests[1][2]['Cookie']

    asyncio.run(run())


@pytest.mark.parametrize('cookie_source', ['headers', 'hook'])
def test_same_origin_redirect_preserves_explicit_cookie(cookie_source):
    async def run():
        async def route(_method, path, headers, _body):
            if path == '/one':
                return 302, {'Location': '/two', 'Set-Cookie': 'sid=new; Path=/'}, b''
            return (200 if headers.get('Cookie') == 'sid=manual' else 401), {}, b'ok'

        def before(request):
            if cookie_source == 'hook' and request.url.endswith('/one'):
                request.headers['Cookie'] = 'sid=manual'

        async with Peer(route) as peer:
            async with AsyncSession(hooks={'before_request': [before]}) as session:
                session.cookies.set('sid', 'old', domain='127.0.0.1', path='/')
                response = await session.get(
                    peer.url + '/one',
                    headers=(
                        {'cOOkie': 'sid=manual'} if cookie_source == 'headers' else None
                    ),
                    timeout=1,
                )
                assert response.status_code == 200
                assert [r[2]['Cookie'] for r in peer.requests] == ['sid=manual'] * 2
                assert session.cookies.get('sid') == 'new'

    asyncio.run(run())


def test_same_origin_redirect_refreshes_cookie_jar_header():
    async def run():
        async def route(_method, path, *_):
            if path == '/one':
                return 302, {'Location': '/two', 'Set-Cookie': 'sid=new; Path=/'}, b''
            return 200, {}, b'ok'

        async with Peer(route) as peer:
            async with AsyncSession() as session:
                session.cookies.set('sid', 'old', domain='127.0.0.1', path='/')
                await session.get(peer.url + '/one', timeout=1)
                assert [r[2]['Cookie'] for r in peer.requests] == ['sid=old', 'sid=new']

    asyncio.run(run())


def test_cross_origin_redirect_strips_credentials_and_does_not_restore_them():
    async def run():
        async with Peer(ok) as target:

            async def route(*_):
                return 307, {'Location': target.url}, b''

            async with Peer(route) as source:
                async with AsyncSession() as session:
                    await session.post(
                        source.url,
                        data=b'x',
                        auth=('user', 'secret'),
                        headers={
                            'Cookie': 'manual=secret',
                            'Proxy-Authorization': 'secret',
                        },
                        cookies={'temporary': 'secret'},
                        timeout=1,
                    )
                    headers = target.requests[0][2]
                    assert not (
                        {'Authorization', 'Proxy-Authorization', 'Cookie'}
                        & headers.keys()
                    )
                    assert headers['Host'].endswith(target.url.rsplit(':', 1)[1])

    asyncio.run(run())


def test_borrowed_pool_survives_session_close_and_owns_remaining_response():
    async def run():
        async with Peer(ok) as peer:
            async with AsyncConnectionPool(max_pool_size=1) as pool:
                one, two = AsyncSession(pool=pool), AsyncSession(pool=pool)
                await one.get(peer.url, timeout=1)
                response = await two.get(peer.url, stream=True, timeout=1)
                await one.aclose()
                assert not pool._closed
                assert await response.read() == b'ok'
                await two.get(peer.url, timeout=1)
                assert peer.connections == 1
                await two.aclose()

    asyncio.run(run())


@pytest.mark.parametrize('phase', ['headers', 'hook', 'backoff'])
def test_external_cancellation_cleans_lease_without_hidden_followup(phase):
    async def run():
        entered = asyncio.Event()

        async def route(*_):
            if phase == 'headers':
                entered.set()
                await asyncio.Event().wait()
            return (
                (503, {'Retry-After': '60'}, b'bad')
                if phase == 'backoff'
                else (200, {}, b'ok')
            )

        async def after(_):
            entered.set()
            await asyncio.Event().wait()

        async with Peer(route) as peer:
            async with AsyncSession(
                retry=HTTPRetry(total=3, backoff_factor=0)
            ) as session:
                if phase == 'backoff':
                    original = session._backoff

                    async def signal_backoff(*args):
                        entered.set()
                        await original(*args)

                    session._backoff = signal_backoff
                task = asyncio.create_task(
                    session.get(
                        peer.url,
                        stream=True,
                        timeout=None,
                        hooks={'after_request': [after]} if phase == 'hook' else None,
                    )
                )
                await asyncio.wait_for(entered.wait(), 1)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                assert len(peer.requests) == 1
                assert not session.pool._entries
                assert not session.pool._creating and not session.pool._waiters

    asyncio.run(run())


def test_session_shutdown_cancels_owned_requests_but_not_application_task():
    async def run():
        async def route(*_):
            await asyncio.Event().wait()

        async with Peer(route) as peer:
            session = AsyncSession()
            task = asyncio.create_task(session.get(peer.url))
            await asyncio.wait_for(peer.received.wait(), 1)
            await asyncio.wait_for(session.aclose(), 1)
            with pytest.raises(asyncio.CancelledError):
                await task
            assert not asyncio.current_task().cancelled()
            assert not session.pool._entries

    asyncio.run(run())


def test_phase_timeout_is_library_timeout_and_external_timeout_stays_external():
    async def run():
        async def route(*_):
            await asyncio.Event().wait()

        async with Peer(route) as peer:
            async with AsyncSession() as session:
                with pytest.raises(Timeout):
                    await session.get(peer.url, timeout=(1, 0.02))
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(session.get(peer.url, timeout=None), 0.02)
                assert not session.pool._entries

    asyncio.run(run())


@pytest.mark.parametrize(
    'timeout', [-1, True, float('inf'), float('nan'), (1,), (1, 2, 3), (None, -1), '3']
)
def test_invalid_budgets_fail_before_connect(timeout):
    async def run():
        async with AsyncSession() as session:
            with pytest.raises(ValueError):
                await session.get('http://127.0.0.1:1', timeout=timeout)
            assert not session.pool._creating and not session.pool._entries

    asyncio.run(run())


def test_session_cross_loop_and_invalid_pool_combination():
    with pytest.raises(ValueError):
        AsyncSession(pool=AsyncConnectionPool(), use_pooling=False)
    session = AsyncSession()
    asyncio.run(session.aclose())
    with pytest.raises(RuntimeError, match='event loops'):
        asyncio.run(session.aclose())
