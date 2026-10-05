"""Independent integration review regressions for async ownership boundaries."""

import asyncio
import gc
import weakref

import pytest

from ja3requests.async_pool import AsyncConnectionPool, _Entry
from ja3requests.async_sessions import AsyncSession
from ja3requests.exceptions import ConnectionException, Timeout
from ja3requests.protocol.exceptions import ProxyError
from ja3requests.retry import HTTPRetry
from test.test_async_session import Peer, ok
from test.test_async_pool import KEY, Transport


class GatedPeer(Peer):
    """Send headers immediately, but keep body bytes off the wire until released."""

    def __init__(self):
        super().__init__(None)
        self.allow_body = asyncio.Event()

    async def serve(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.writers.add(writer)
        self.connections += 1
        try:
            while True:
                await reader.readuntil(b'\r\n\r\n')
                writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n')
                await writer.drain()
                await self.allow_body.wait()
                writer.write(b'tail')
                await writer.drain()
        except (asyncio.CancelledError, ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
            self.writers.discard(writer)
            self.tasks.discard(task)


@pytest.mark.parametrize('pooled', [True, False])
@pytest.mark.parametrize('finish', ['read', 'recipient_close', 'pool_close'])
def test_transferred_private_response_survives_original_session_close(pooled, finish):
    async def scenario():
        async with GatedPeer() as slow, Peer(ok) as ready:
            donor = AsyncSession(use_pooling=pooled)
            middle, recipient = AsyncSession(), AsyncSession()
            try:
                response = await donor.get(slow.url, stream=True, timeout=1)
                transport = response._transport
                own = await donor.get(ready.url, stream=True, timeout=1)
                for session in (middle, recipient):
                    result = await session.get(
                        ready.url,
                        stream=True,
                        timeout=1,
                        hooks={'after_request': [lambda _: response]},
                    )
                    assert result is response
                await middle.aclose()
                await asyncio.wait_for(donor.aclose(), 1)
                assert own.closed
                assert donor.pool._closed
                assert not response.closed and not transport.closed
                assert not response._buffer

                if finish == 'read':
                    slow.allow_body.set()
                    assert await response.read() == b'tail'
                elif finish == 'recipient_close':
                    await asyncio.wait_for(recipient.aclose(), 1)
                else:
                    # Explicit pool shutdown still overrides transferred leases.
                    await asyncio.wait_for(donor.pool.aclose(), 1)
                    with pytest.raises(ConnectionException):
                        await response.read()
                assert transport.closed
                assert not donor.pool._entries
                await response.aclose()
            finally:
                await recipient.aclose()
                await middle.aclose()
                await donor.aclose()

    asyncio.run(scenario())


def test_consumed_transfer_does_not_pin_later_reused_connection():
    async def scenario():
        async with GatedPeer() as slow, Peer(ok) as ready:
            async with AsyncSession() as donor, AsyncSession() as recipient:
                response = await donor.get(slow.url, stream=True, timeout=1)
                transport = response._transport
                await recipient.get(
                    ready.url,
                    stream=True,
                    timeout=1,
                    hooks={'after_request': [lambda _: response]},
                )
                slow.allow_body.set()
                assert await response.read() == b'tail'
                await recipient.aclose()
                assert not transport.closed
                assert (await donor.get(slow.url, timeout=1)).content == b'tail'
                assert slow.connections == 1
                await donor.aclose()
                assert transport.closed and not donor.pool._entries

    asyncio.run(scenario())


def test_response_transferred_back_is_closed_by_original_session():
    async def scenario():
        async with GatedPeer() as slow, Peer(ok) as ready:
            async with AsyncSession() as donor, AsyncSession() as recipient:
                response = await donor.get(slow.url, stream=True, timeout=1)
                transport = response._transport
                for session in (recipient, donor):
                    await session.get(
                        ready.url,
                        stream=True,
                        timeout=1,
                        hooks={'after_request': [lambda _: response]},
                    )
                await recipient.aclose()
                assert not response.closed and not transport.closed
                await donor.aclose()
                assert response.closed and transport.closed
                assert not donor.pool._entries

    asyncio.run(scenario())


def test_response_moved_after_shutdown_snapshot_is_not_closed_by_old_owner():
    async def scenario():
        async with GatedPeer() as peer:
            async with AsyncSession() as donor, AsyncSession() as recipient:
                response = await donor.get(peer.url, stream=True, timeout=1)
                transport = response._transport

                async def transfer():
                    # Let shutdown take its response snapshot, then move the
                    # response before those scheduled close coroutines run.
                    await asyncio.sleep(0)
                    recipient._adopt_response(response)
                    assert not response.closed

                closing = asyncio.create_task(donor.aclose())
                moving = asyncio.create_task(transfer())
                await asyncio.wait_for(asyncio.gather(closing, moving), 1)
                assert not response.closed and not transport.closed
                peer.allow_body.set()
                assert await response.read() == b'tail'
                assert transport.closed and not donor.pool._entries

    asyncio.run(scenario())


@pytest.mark.parametrize('borrowed_pool', [False, True])
@pytest.mark.parametrize(
    'finish', ['request_cancel', 'session_close', 'hook_error', 'replacement']
)
def test_inflight_request_cleanup_preserves_transferred_response(borrowed_pool, finish):
    async def scenario():
        async with GatedPeer() as slow, Peer(ok) as ready:
            shared = AsyncConnectionPool() if borrowed_pool else None
            donor, recipient = AsyncSession(pool=shared), AsyncSession(pool=shared)
            pools = {donor.pool, recipient.pool}
            captured = asyncio.get_running_loop().create_future()
            finish_hook = asyncio.Event()
            hook_finished = asyncio.Event()
            request = None
            fallback = None

            async def hold_response(response):
                try:
                    captured.set_result(response)
                    await finish_hook.wait()
                    if finish == 'hook_error':
                        raise OSError('donor hook failed after transfer')
                    return fallback
                finally:
                    hook_finished.set()

            try:
                if finish == 'replacement':
                    fallback = await donor.get(ready.url, stream=True, timeout=1)
                request = asyncio.create_task(
                    donor.get(
                        slow.url,
                        stream=True,
                        timeout=1,
                        hooks={'after_request': [hold_response]},
                    )
                )
                response = await asyncio.wait_for(captured, 1)
                transport = response._transport
                moved = await recipient.get(
                    ready.url,
                    stream=True,
                    timeout=1,
                    hooks={'after_request': [lambda _: response]},
                )
                assert moved is response
                assert not response._buffer and not response.closed

                if finish in ('request_cancel', 'session_close'):
                    if finish == 'request_cancel':
                        request.cancel()
                    else:
                        await asyncio.wait_for(donor.aclose(), 1)
                    with pytest.raises(asyncio.CancelledError):
                        await asyncio.wait_for(request, 1)
                else:
                    finish_hook.set()
                    if finish == 'hook_error':
                        with pytest.raises(OSError, match='donor hook failed'):
                            await asyncio.wait_for(request, 1)
                    else:
                        assert await asyncio.wait_for(request, 1) is fallback
                        assert await fallback.read() == b'ok'
                await asyncio.wait_for(hook_finished.wait(), 1)
                await asyncio.wait_for(donor.aclose(), 1)
                assert not response.closed and not transport.closed
                assert not response._buffer

                slow.allow_body.set()
                assert await asyncio.wait_for(response.read(), 1) == b'tail'
                assert response.closed and not recipient._responses
                await asyncio.wait_for(recipient.aclose(), 1)
            finally:
                finish_hook.set()
                if request is not None:
                    request.cancel()
                    await asyncio.gather(request, return_exceptions=True)
                await donor.aclose()
                await recipient.aclose()
                await asyncio.gather(*(pool.aclose() for pool in pools))

            assert transport.closed
            assert not donor._requests and not recipient._requests
            assert not donor._responses and not recipient._responses
            assert not donor._hook_tasks and not recipient._hook_tasks
            for pool in pools:
                assert not pool._entries and not pool._creating
                assert not pool._waiters and not pool._cleanup
        assert not slow.tasks and not ready.tasks
        assert not slow.writers and not ready.writers

    asyncio.run(scenario())


def test_session_close_releases_dropped_stream_in_borrowed_pool():
    async def scenario():
        async with Peer(ok) as peer:
            async with AsyncConnectionPool(max_pool_size=1) as pool:
                first = AsyncSession(pool=pool)
                second = AsyncSession(pool=pool)
                try:
                    response = await first.get(peer.url, stream=True, timeout=1)
                    assert pool._entries[0].leases == 1
                    del response
                    # The public owner must still be able to release its lease
                    # if the caller no longer keeps a response reference.
                    await asyncio.sleep(0)
                    gc.collect()
                    await first.aclose()
                    try:
                        fresh = await second.get(peer.url, timeout=(0.1, 1))
                    except Timeout:
                        pytest.fail(
                            'Closing the first session leaked its borrowed lease'
                        )
                    assert fresh.content == b'ok'
                    assert not pool._closed
                finally:
                    await first.aclose()
                    await second.aclose()

    asyncio.run(scenario())


def test_hook_replacement_transfers_response_out_of_previous_session():
    async def scenario():
        async with Peer(ok) as peer:
            async with AsyncConnectionPool(max_pool_size=2) as pool:
                donor = AsyncSession(pool=pool)
                recipient = AsyncSession(pool=pool)
                try:
                    replacement = await donor.get(peer.url, stream=True, timeout=1)
                    response = await recipient.get(
                        peer.url,
                        stream=True,
                        timeout=1,
                        hooks={'after_request': [lambda _response: replacement]},
                    )
                    assert response is replacement
                    await donor.aclose()
                    assert (
                        not response.closed
                    ), 'Previous session retained replacement ownership'
                    assert await response.read() == b'ok'
                finally:
                    await recipient.aclose()
                    await donor.aclose()

    asyncio.run(scenario())


def test_hook_replacement_honors_eager_body_contract():
    async def scenario():
        async with Peer(ok) as peer:
            async with AsyncSession() as session:
                replacement = await session.get(peer.url, stream=True, timeout=1)
                response = await session.get(
                    peer.url,
                    timeout=1,
                    hooks={'after_request': [lambda _response: replacement]},
                )
                assert response is replacement
                assert response.content == b'ok'

    asyncio.run(scenario())


def test_session_close_does_not_wait_for_hook_that_joins_same_close():
    async def scenario():
        entered = asyncio.Event()
        joined_close = asyncio.Event()
        session = AsyncSession()

        async def after(_response):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                joined_close.set()
                # Reentrant cleanup is a normal hook finally-block operation.
                await session.aclose()

        async with Peer(ok) as peer:
            request = asyncio.create_task(
                session.get(
                    peer.url,
                    stream=True,
                    hooks={'after_request': [after]},
                    timeout=1,
                )
            )
            await asyncio.wait_for(entered.wait(), 1)
            closing = asyncio.create_task(session.aclose())
            await asyncio.wait_for(joined_close.wait(), 1)
            completed, _pending = await asyncio.wait((closing,), timeout=0.1)
            deadlocked = not completed
            if deadlocked:
                # Break the reproduced cycle so a failing regression leaves no
                # task/socket behind and never relies on asyncio.run teardown.
                for task in tuple(session._requests):
                    task.cancel()
            await asyncio.wait_for(
                asyncio.gather(request, closing, return_exceptions=True), 1
            )
            assert (
                not deadlocked
            ), 'Close task awaited the hook which awaited that same close task'
            assert not session.pool._entries

    asyncio.run(scenario())


def test_proxy_protocol_rejection_is_not_a_transient_connect_retry():
    async def scenario():
        async def rejected(*_args):
            return 407, {}, b'denied'

        async with Peer(rejected) as proxy:
            async with AsyncSession(
                retry=HTTPRetry(total=2, backoff_factor=0)
            ) as session:
                with pytest.raises(ProxyError):
                    await session.get(
                        'https://origin.test/', proxies={'https': proxy.url}, timeout=1
                    )
            assert (
                len(proxy.requests) == 1
            ), 'An authentication/protocol rejection was retried'
            assert proxy.requests[0][0] == 'CONNECT'

    asyncio.run(scenario())


def test_creator_cancellation_racing_completed_candidate_retires_result():
    async def scenario():
        transport = Transport()
        loop = asyncio.get_running_loop()
        creator = None

        async def create():
            # Run cancellation before _acquire's task-result continuation.
            loop.call_soon(creator.cancel)
            return _Entry(KEY, transport)

        pool = AsyncConnectionPool(max_pool_size=1)
        creator = asyncio.create_task(pool._acquire(KEY, create))
        with pytest.raises(asyncio.CancelledError):
            await creator
        await pool.aclose()
        assert not pool._creating and not pool._entries and not pool._cleanup
        assert transport.closed and transport.close_count == 1

    asyncio.run(scenario())


def test_creator_repeated_cancellation_releases_reservation_for_other_waiter():
    async def scenario():
        entered = asyncio.Event()
        cleaning = asyncio.Event()
        transports = []

        async def create():
            transport = Transport()
            transports.append(transport)
            if len(transports) == 1:
                entered.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    # Same ordering as native setup cleanup: synchronous socket
                    # close precedes any awaited H2/background-task join.
                    transport.close()
                    cleaning.set()
                    await asyncio.Event().wait()
            return _Entry(KEY, transport)

        async with AsyncConnectionPool(max_pool_size=1) as pool:
            creator = asyncio.create_task(pool._acquire(KEY, create))
            await entered.wait()
            waiter = asyncio.create_task(pool._acquire(KEY, create))
            await asyncio.sleep(0)
            creator.cancel()
            await asyncio.wait_for(cleaning.wait(), 1)
            creator.cancel()
            with pytest.raises(asyncio.CancelledError):
                await creator
            lease = await asyncio.wait_for(waiter, 1)
            assert len(transports) == 2 and transports[0].closed
            assert not pool._creating and not pool._waiters
            await lease.release(True)
        assert all(transport.closed for transport in transports)

    asyncio.run(scenario())


def test_repeated_cancel_of_close_waiters_keeps_pool_cleanup_owned():
    async def scenario():
        started = asyncio.Event()
        finish = asyncio.Event()

        class GatedTransport(Transport):
            async def aclose(self):
                self.close_count += 1
                self.close()
                started.set()
                await finish.wait()

        transport = GatedTransport()
        pool = AsyncConnectionPool(max_pool_size=1)

        async def create():
            return _Entry(KEY, transport)

        await pool._acquire(KEY, create)
        first = asyncio.create_task(pool.aclose())
        await started.wait()
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        second = asyncio.create_task(pool.aclose())
        await asyncio.sleep(0)
        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second
        assert not pool._close_task.done()
        finish.set()
        await asyncio.wait_for(pool.aclose(), 1)
        assert transport.closed and transport.close_count == 1
        assert not pool._cleanup and not pool._entries

    asyncio.run(scenario())


def test_shutdown_does_not_depend_on_hook_suppressing_cancellation():
    async def scenario():
        entered = asyncio.Event()
        cancelled = asyncio.Event()
        gate = asyncio.Event()
        finished = asyncio.Event()
        hooks = []
        session = AsyncSession()

        async def after(_response):
            hooks.append(asyncio.current_task())
            entered.set()
            try:
                try:
                    await gate.wait()
                except asyncio.CancelledError:
                    cancelled.set()
                    await gate.wait()
            finally:
                finished.set()

        async with Peer(ok) as peer:

            async def application():
                try:
                    await session.get(
                        peer.url, stream=True, hooks={'after_request': [after]}
                    )
                except asyncio.CancelledError:
                    pass
                return 'application continued'

            request = asyncio.create_task(application())
            await asyncio.wait_for(entered.wait(), 1)
            closing = asyncio.create_task(session.aclose())
            await asyncio.wait_for(cancelled.wait(), 1)
            completed, _pending = await asyncio.wait((closing,), timeout=0.1)
            depended_on_user_hook = not completed
            # The test, as the hook owner, then allows its outstanding cleanup.
            gate.set()
            await asyncio.wait_for(finished.wait(), 1)
            result = await asyncio.wait_for(request, 1)
            await asyncio.wait_for(closing, 1)
            await asyncio.gather(*hooks, return_exceptions=True)
            assert (
                not depended_on_user_hook
            ), 'Session shutdown awaited user hook cooperation'
            assert result == 'application continued'
            assert not request.cancelled() and not session.pool._entries
            assert all(task.done() for task in hooks)

    asyncio.run(scenario())


def test_shutdown_does_not_cancel_preexisting_task_returned_by_hook():
    async def scenario():
        entered = asyncio.Event()
        gate = asyncio.Event()
        session = AsyncSession()

        async def application_work():
            await gate.wait()
            return None

        external_task = asyncio.create_task(application_work())

        def after(_response):
            entered.set()
            # Awaitable results are supported, but this task existed before the
            # callback and is application-owned, not an internal hook task.
            return external_task

        async with Peer(ok) as peer:
            request = asyncio.create_task(
                session.get(
                    peer.url,
                    stream=True,
                    hooks={'after_request': [after]},
                )
            )
            await asyncio.wait_for(entered.wait(), 1)
            await asyncio.wait_for(session.aclose(), 1)
            was_cancelled = external_task.cancelled()
            gate.set()
            await asyncio.gather(request, external_task, return_exceptions=True)
            assert (
                not was_cancelled
            ), 'Shutdown cancelled a task supplied by application hook'
            assert not session.pool._entries

    asyncio.run(scenario())


@pytest.mark.parametrize('stream', [False, True])
def test_completed_cached_response_can_be_collected_while_session_remains_open(stream):
    async def scenario():
        async with Peer(ok) as peer:
            async with AsyncSession() as session:
                response = await session.get(peer.url, stream=stream, timeout=1)
                if stream:
                    assert await response.read() == b'ok'
                else:
                    assert response.content == b'ok'
                observed = weakref.ref(response)
                del response
                # Release completed task results too; the live session must
                # not keep all past eager bodies through its ownership set.
                await asyncio.sleep(0)
                gc.collect()
                assert (
                    observed() is None
                ), 'Session retained a fully released cached body'
                assert (await session.get(peer.url, timeout=1)).content == b'ok'
                assert peer.connections == 1

    asyncio.run(scenario())
