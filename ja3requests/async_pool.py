"""Loop-bound connection admission and response leases for native async I/O."""

from __future__ import annotations

import asyncio
import math
from typing import Any, Awaitable, Callable, List, Optional, Set, Tuple

from ja3requests._async_utils import owner_task


class _Entry:
    def __init__(
        self,
        key: Tuple[Any, ...],
        transport: Any,
        h2: Any = None,
        reusable: bool = True,
    ):
        self.key = key
        self.transport = transport
        self.h2 = h2
        self.leases = 0
        self.transferred_leases = 0
        self.last_used = asyncio.get_running_loop().time()
        self.retired = False
        self.reusable = reusable

    @property
    def healthy(self) -> bool:
        return (
            not self.retired
            and not self.transport.closed
            and not (
                self.h2 is not None and (self.h2.failed or self.h2._goaway_received)
            )
        )

    async def aclose(self) -> None:
        self.retired = True
        self.transport.close()
        if self.h2 is not None:
            await self.h2.aclose()
        await self.transport.aclose()


class _Lease:
    def __init__(self, pool: AsyncConnectionPool, entry: _Entry):
        self.pool = pool
        self.entry = entry
        self.released = False
        self.generation = pool._generation
        self._transferred = False

    def transfer(self) -> None:
        """Keep this lease alive when its original private session closes."""
        if (
            not self.released
            and not self._transferred
            and not self.entry.retired
            and self.generation is self.pool._generation
        ):
            self._transferred = True
            self.entry.transferred_leases += 1

    async def release(self, reusable: bool) -> None:
        if self.released:
            return
        self.released = True
        await self.pool._release(self, reusable)


class AsyncConnectionPool:
    """A terminal, loop-bound pool; explicit pools are borrowed by sessions.

    Construction performs no I/O and binds no loop. Capacity includes pending
    connections. HTTP/1 leases are exclusive; H2 leases share a healthy transport.
    """

    def __init__(
        self,
        max_connections_per_host: int = 10,
        idle_timeout: float = 60.0,
        max_pool_size: int = 100,
    ) -> None:
        for value in (max_connections_per_host, max_pool_size):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError('pool capacities must be positive integers')
        if not math.isfinite(idle_timeout) or idle_timeout < 0:
            raise ValueError('idle_timeout must be finite and non-negative')
        self._max_per_host = max_connections_per_host
        self._max_pool_size = max_pool_size
        self._idle_timeout = idle_timeout
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._entries: List[_Entry] = []
        self._creating: dict = {}
        self._waiters: Set[asyncio.Future] = set()
        self._cleanup: Set[asyncio.Task] = set()
        self._closed = False
        self._generation = object()
        self._close_task: Optional[asyncio.Task] = None
        self._session_close_task: Optional[asyncio.Task] = None

    def _bind(self) -> None:
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise RuntimeError('AsyncConnectionPool cannot be used across event loops')

    def _wake(self) -> None:
        for waiter in tuple(self._waiters):
            if not waiter.done():
                waiter.set_result(None)

    def _retire(self, entry: _Entry) -> asyncio.Task:
        if entry in self._entries:
            self._entries.remove(entry)
        entry.retired = True
        entry.transport.close()
        task = owner_task(entry.aclose())
        self._cleanup.add(task)
        task.add_done_callback(self._cleanup_done)
        self._wake()
        return task

    def _cleanup_done(self, task: asyncio.Task) -> None:
        self._cleanup.discard(task)
        if not task.cancelled():
            task.exception()  # Observe background close failures.

    def _h2_state_changed(self, entry: _Entry) -> None:
        # A cancelled stream can receive more header fragments after its lease
        # is gone. Retire a now-failed idle transport without another borrower.
        if entry in self._entries and not entry.leases and not entry.healthy:
            self._retire(entry)
        else:
            self._wake()

    async def _acquire(
        self,
        key: Tuple[Any, ...],
        factory: Callable[[], Awaitable[_Entry]],
        *,
        share_h2: bool = True,
    ) -> _Lease:
        self._bind()
        while True:
            if self._closed:
                raise RuntimeError('AsyncConnectionPool is closed')
            now = self._loop.time()
            for entry in tuple(self._entries):
                if not entry.leases and (
                    not entry.healthy or now - entry.last_used >= self._idle_timeout
                ):
                    self._retire(entry)
            for entry in self._entries:
                if entry.key != key or not entry.healthy:
                    continue
                if entry.h2 is None:
                    available = not entry.leases
                else:
                    available = (
                        share_h2
                        and entry.h2.capacity_available
                        and entry.leases < entry.h2._peer_settings[3]
                    )
                if available:
                    entry.leases += 1
                    return _Lease(self, entry)

            # Serialize the first handshake for a policy/route identity so H2
            # callers can share it as soon as peer SETTINGS grants capacity.
            same_pending = any(item == key for item in self._creating.values())
            awaiting_settings = any(
                entry.key == key
                and entry.healthy
                and entry.h2 is not None
                and not entry.h2._peer_settings_received
                for entry in self._entries
            )
            host_count = sum(entry.key[:3] == key[:3] for entry in self._entries)
            host_count += sum(item[:3] == key[:3] for item in self._creating.values())
            if (
                not same_pending
                and not awaiting_settings
                and host_count < self._max_per_host
                and len(self._entries) + len(self._creating) < self._max_pool_size
            ):
                task = owner_task(factory())
                self._creating[task] = key
                entry = None
                try:
                    entry = await task
                    if self._closed:
                        await asyncio.shield(self._retire(entry))
                        raise RuntimeError('AsyncConnectionPool closed during connect')
                    self._entries.append(entry)
                    entry.leases = 1
                    if entry.h2 is not None:
                        entry.h2.set_state_callback(
                            lambda: self._h2_state_changed(entry)
                        )
                    return _Lease(self, entry)
                except BaseException:
                    # A result can race cancellation of the awaiting creator.
                    if entry is None and task.done() and not task.cancelled():
                        if task.exception() is None:
                            self._retire(task.result())
                    raise
                finally:
                    self._creating.pop(task, None)
                    self._wake()

            # Evict a different idle route if it alone occupies global capacity.
            idle = next(
                (e for e in self._entries if not e.leases and e.key != key), None
            )
            if idle is not None:
                self._retire(idle)
                continue
            waiter = self._loop.create_future()
            self._waiters.add(waiter)
            try:
                await waiter
            finally:
                self._waiters.discard(waiter)

    async def _release(self, lease: _Lease, reusable: bool) -> None:
        self._bind()
        entry = lease.entry
        if lease.generation is not self._generation or entry.retired:
            return
        entry.leases = max(0, entry.leases - 1)
        if lease._transferred:
            entry.transferred_leases -= 1
        entry.last_used = self._loop.time()
        if not entry.reusable or (entry.h2 is None and not reusable):
            await asyncio.shield(self._retire(entry))
        elif (self._closed or not entry.healthy) and not entry.leases:
            await asyncio.shield(self._retire(entry))
        self._wake()

    async def _close_from_session(self) -> None:
        """Stop admission, retaining only connections with transferred leases.

        The session has already released its own requests and responses. Any
        retained connection closes when its final recipient releases it; public
        aclose() can still force all such connections closed at any time.
        """
        self._bind()
        if self._close_task is not None:
            await asyncio.shield(self._close_task)
            return
        if self._session_close_task is None:
            self._closed = True
            for task in tuple(self._creating):
                task.cancel()
            for entry in tuple(self._entries):
                if not entry.transferred_leases:
                    self._retire(entry)
            self._wake()
            self._session_close_task = owner_task(self._finish_close())
        await asyncio.shield(self._session_close_task)

    async def aclose(self) -> None:
        """Close owned transports, wake borrowers and join internal tasks."""
        self._bind()
        if self._close_task is None:
            self._closed = True
            self._generation = object()
            for task in tuple(self._creating):
                task.cancel()
            for entry in tuple(self._entries):
                self._retire(entry)
            self._wake()
            self._close_task = owner_task(self._finish_close())
        await asyncio.shield(self._close_task)

    async def _finish_close(self) -> None:
        await asyncio.gather(*tuple(self._creating), return_exceptions=True)
        while self._cleanup:
            pending = tuple(self._cleanup)
            await asyncio.gather(*pending, return_exceptions=True)
            # gather may finish synchronously for already completed tasks;
            # their scheduled callbacks need not have run yet.
            self._cleanup.difference_update(pending)

    async def __aenter__(self) -> AsyncConnectionPool:
        self._bind()
        if self._closed:
            raise RuntimeError('AsyncConnectionPool is closed')
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()
