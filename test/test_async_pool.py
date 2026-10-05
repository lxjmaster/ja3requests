"""Cancellation and ownership evidence for asynchronous connection admission."""

import asyncio

import pytest

from ja3requests.async_pool import AsyncConnectionPool, _Entry


KEY = ('localhost', 80, 'http', None, None)


class Transport:
    def __init__(self):
        self.closed = False
        self.close_count = 0

    def close(self):
        self.closed = True

    async def aclose(self):
        self.close()
        self.close_count += 1


class H2:
    def __init__(self):
        self.failed = False
        self._goaway_received = False
        self._peer_settings_received = True
        self._peer_settings = {3: 2}
        self.capacity_available = True
        self.callback = None
        self.closed = False

    def set_state_callback(self, callback):
        self.callback = callback

    async def aclose(self):
        self.closed = True


@pytest.mark.parametrize('field', ['max_connections_per_host', 'max_pool_size'])
@pytest.mark.parametrize('value', [0, -1, True, 1.5])
def test_pool_rejects_invalid_capacity(field, value):
    with pytest.raises(ValueError):
        AsyncConnectionPool(**{field: value})


@pytest.mark.parametrize('value', [-1, float('nan'), float('inf')])
def test_pool_rejects_invalid_idle_timeout(value):
    with pytest.raises(ValueError):
        AsyncConnectionPool(idle_timeout=value)


def test_completed_old_lease_cannot_release_or_close_new_owner():
    async def run():
        async with AsyncConnectionPool(max_pool_size=1) as pool:
            transport = Transport()

            async def create():
                return _Entry(KEY, transport)

            first = await pool._acquire(KEY, create)
            await first.release(True)
            second = await pool._acquire(KEY, create)
            await first.release(False)
            assert second.entry.leases == 1
            assert not transport.closed
            await second.release(False)
            assert transport.closed and not pool._entries
        assert transport.close_count == 1

    asyncio.run(run())


def test_cancelling_waiter_does_not_cancel_creator_or_leak_slot():
    async def run():
        gate = asyncio.Event()
        entered = asyncio.Event()
        created = []
        async with AsyncConnectionPool(max_pool_size=1) as pool:

            async def create():
                transport = Transport()
                created.append(transport)
                entered.set()
                await gate.wait()
                return _Entry(KEY, transport)

            first = asyncio.create_task(pool._acquire(KEY, create))
            await asyncio.wait_for(entered.wait(), 1)
            second = asyncio.create_task(pool._acquire(KEY, create))
            await asyncio.sleep(0)
            second.cancel()
            with pytest.raises(asyncio.CancelledError):
                await second
            assert not pool._waiters and not first.done()
            gate.set()
            lease = await first
            assert len(created) == 1 and lease.entry.leases == 1
            await lease.release(True)
        assert created[0].closed

    asyncio.run(run())


def test_cancelling_creator_releases_reservation_for_waiter():
    async def run():
        entered = asyncio.Event()
        transports = []
        async with AsyncConnectionPool(max_pool_size=1) as pool:

            async def create():
                transport = Transport()
                transports.append(transport)
                if len(transports) == 1:
                    entered.set()
                    try:
                        await asyncio.Event().wait()
                    finally:
                        transport.close()
                return _Entry(KEY, transport)

            creator = asyncio.create_task(pool._acquire(KEY, create))
            await asyncio.wait_for(entered.wait(), 1)
            waiter = asyncio.create_task(pool._acquire(KEY, create))
            await asyncio.sleep(0)
            creator.cancel()
            with pytest.raises(asyncio.CancelledError):
                await creator
            lease = await asyncio.wait_for(waiter, 1)
            assert len(transports) == 2 and transports[0].closed
            assert not pool._creating and not pool._waiters
            await lease.release(True)

    asyncio.run(run())


def test_pool_close_wakes_admission_and_is_terminal():
    async def run():
        pool = AsyncConnectionPool(max_pool_size=1)
        transport = Transport()

        async def create():
            return _Entry(KEY, transport)

        lease = await pool._acquire(KEY, create)
        waiter = asyncio.create_task(pool._acquire(KEY, create))
        await asyncio.sleep(0)
        await pool.aclose()
        with pytest.raises(RuntimeError, match='closed'):
            await waiter
        await lease.release(True)
        await pool.aclose()
        assert transport.closed and not pool._entries
        with pytest.raises(RuntimeError, match='closed'):
            await pool._acquire(KEY, create)

    asyncio.run(run())


def test_pool_binds_only_at_use_and_rejects_cross_loop_use():
    pool = AsyncConnectionPool()
    assert pool._loop is None
    asyncio.run(pool.aclose())
    with pytest.raises(RuntimeError, match='event loops'):
        asyncio.run(pool.aclose())


def test_h2_peer_capacity_and_release_do_not_close_other_streams():
    async def run():
        transport, h2 = Transport(), H2()
        async with AsyncConnectionPool(max_pool_size=1) as pool:

            async def create():
                return _Entry(KEY, transport, h2)

            one = await pool._acquire(KEY, create)
            two = await pool._acquire(KEY, create)
            waiter = asyncio.create_task(pool._acquire(KEY, create))
            await asyncio.sleep(0)
            assert not waiter.done() and one.entry is two.entry
            await one.release(False)
            three = await asyncio.wait_for(waiter, 1)
            assert not transport.closed and three.entry.leases == 2
            h2._goaway_received = True
            await two.release(True)
            assert not transport.closed
            await three.release(True)
            assert transport.closed and h2.closed

    asyncio.run(run())


def test_idle_route_eviction_and_unpooled_h2_shutdown():
    async def run():
        transports = []
        async with AsyncConnectionPool(max_pool_size=1) as pool:

            async def create():
                transport = Transport()
                transports.append(transport)
                return _Entry(KEY, transport)

            first = await pool._acquire(KEY, create)
            await first.release(True)
            other = ('localhost', 81, 'http', None, None)
            h2 = H2()

            async def create_other():
                return _Entry(other, Transport(), h2, reusable=False)

            second = await pool._acquire(other, create_other)
            assert transports[0].closed
            await second.release(True)
            assert h2.closed and second.entry.transport.closed

    asyncio.run(run())
