"""Explicit async measurements; excluded from the unchanged default bench suite."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import AsyncExitStack, ExitStack
import gc
import math
import statistics
import threading
import time
import tracemalloc

import pytest

from ja3requests.async_sessions import AsyncSession
from bench.peers import TLSLoopbackPeer
from bench.test_protocol_performance import (
    assert_peer,
    client_session,
    consume,
    server_context,
    tls_config,
)


class LoopHeartbeat:
    """Measure periodic callback lateness without a busy polling task."""

    def __init__(self, loop, interval=0.001):
        self.loop = loop
        self.interval = interval
        self.intervals = []
        self.last = time.perf_counter()
        self.handle = loop.call_later(interval, self._tick)

    def _tick(self):
        now = time.perf_counter()
        self.intervals.append(now - self.last)
        self.last = now
        self.handle = self.loop.call_later(self.interval, self._tick)

    def finish(self):
        self.handle.cancel()
        tail = time.perf_counter() - self.last
        ordered = sorted(self.intervals)
        return {
            "requested_interval_seconds": self.interval,
            "observed_intervals_seconds": self.intervals,
            "observations": len(ordered),
            "median_interval_seconds": statistics.median(ordered) if ordered else None,
            "p95_interval_seconds": (
                ordered[math.ceil(len(ordered) * 0.95) - 1] if ordered else None
            ),
            "max_callback_lateness_seconds": max(
                0.0, max(self.intervals + [tail]) - self.interval
            ),
            "unfinished_tail_interval_seconds": tail,
        }


async def consume_async(session, peer, timeout):
    started = time.perf_counter()
    response = await session.get(
        peer.url,
        stream=True,
        timeout=timeout,
        allow_redirects=False,
        headers={"Accept-Encoding": "identity"},
    )
    returned = time.perf_counter()
    stream_id = response._stream_id
    total = 0
    first = None
    try:
        assert response.status_code == 200
        assert response.protocol_version == (
            "HTTP/2" if peer.protocol == "h2" else "HTTP/1.1"
        )
        async for chunk in response.aiter_content(16384):
            if not chunk:
                continue
            if first is None:
                first = time.perf_counter()
            assert chunk.count(b"x") == len(chunk)
            total += len(chunk)
        assert total == peer.body_bytes and first is not None
    finally:
        await response.aclose()
    completed = time.perf_counter()
    return {
        "request_started_at": started,
        "request_returned_at": returned,
        "first_chunk_at": first,
        "response_complete_at": completed,
        "request_return_seconds": returned - started,
        "first_chunk_seconds": first - started,
        "complete_seconds": completed - started,
        "received_bytes": total,
        "payload_verified": True,
        "h2_stream_id": stream_id,
    }


async def run_sample(
    client, version, protocol, peer, certificates, options, workers, memory
):
    loop = asyncio.get_running_loop()
    sessions_count = workers if protocol == "http/1.1" else 1
    async with AsyncExitStack() as async_stack:
        with ExitStack() as sync_stack:
            if client == "native_async":
                sessions = [
                    await async_stack.enter_async_context(
                        AsyncSession(tls_config=tls_config(version, protocol))
                    )
                    for _ in range(sessions_count)
                ]
                executor = None
            else:
                sessions = [
                    client_session(sync_stack, client, certificates, version, protocol)
                    for _ in range(sessions_count)
                ]
                executor = sync_stack.enter_context(
                    ThreadPoolExecutor(max_workers=workers)
                )
                # Thread creation is excluded alongside socket/TLS warmup.
                barrier = threading.Barrier(workers)
                await asyncio.gather(
                    *(
                        loop.run_in_executor(executor, barrier.wait, options["timeout"])
                        for _ in range(workers)
                    )
                )

            async def one(session):
                if client == "native_async":
                    return await consume_async(session, peer, options["timeout"])
                return await loop.run_in_executor(
                    executor, consume, session, peer, options["timeout"]
                )

            for session in sessions:
                await one(session)

            ready = asyncio.Event()

            async def worker(index):
                session = sessions[index] if protocol == "http/1.1" else sessions[0]
                await ready.wait()
                rows = []
                for _ in range(options["requests"] // workers):
                    row = await one(session)
                    row["worker_index"] = index
                    rows.append(row)
                return rows

            gc.collect()
            if memory:
                tracemalloc.start()
            heartbeat = LoopHeartbeat(loop) if client == "native_async" else None
            started = time.perf_counter()
            try:
                tasks = [asyncio.create_task(worker(index)) for index in range(workers)]
                ready.set()
                groups = await asyncio.gather(*tasks)
                elapsed = time.perf_counter() - started
                pulse = heartbeat.finish() if heartbeat is not None else None
                peak = tracemalloc.get_traced_memory()[1] if memory else None
            finally:
                if heartbeat is not None:
                    heartbeat.handle.cancel()
                if memory:
                    tracemalloc.stop()
            return [row for group in groups for row in group], elapsed, peak, pulse


CASES = [
    (client, version, protocol, mode)
    for client in ("native_async", "ja3requests", "requests")
    for version in ("TLSv1.2", "TLSv1.3")
    for protocol in ("http/1.1", "h2")
    for mode in ("sequential", "concurrent")
    if client == "native_async" or protocol == "http/1.1"
]


def pair_streaming_evidence(rows, peer, protocol, workers):
    """Pair by H2 stream or serially warmed H1 worker connection, never globally."""
    if protocol == "h2":
        lookup = {row["stream_id"]: row for row in peer.records}
        paired = [(row, lookup[row["h2_stream_id"]]) for row in rows]
    else:
        paired = []
        for worker in range(workers):
            server_rows = [
                row for row in peer.records if row["connection_id"] == worker + 1
            ][1:]
            client_rows = [row for row in rows if row["worker_index"] == worker]
            assert len(client_rows) == len(server_rows)
            paired.extend(zip(client_rows, server_rows))
    for client_row, server_row in paired:
        client_row["connection_id"] = server_row["connection_id"]
        client_row["server_last_send_started"] = server_row["last_send_started"]
        client_row["first_chunk_before_last_send"] = (
            client_row["first_chunk_at"] < server_row["last_send_started"]
        )
        assert (
            client_row["request_started_at"]
            <= client_row["request_returned_at"]
            <= client_row["first_chunk_at"]
            <= client_row["response_complete_at"]
        )
        if peer.body_bytes >= 1048576:
            assert client_row["first_chunk_before_last_send"]


@pytest.mark.parametrize(
    "client,version,protocol,mode",
    CASES,
    ids=["-".join(case).replace("/", "") for case in CASES],
)
def test_async_transport(
    trusted_certificates,
    monkeypatch,
    perf_options,
    record_measurement,
    client,
    version,
    protocol,
    mode,
):
    options = perf_options
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    workers = options["concurrency"] if mode == "concurrent" else 1
    sessions_count = workers if protocol == "http/1.1" else 1
    for sample in range(options["repeat"] + 1):
        memory = sample == options["repeat"]
        context = server_context(trusted_certificates, version, protocol)
        with TLSLoopbackPeer(
            context,
            protocol,
            options["body_bytes"],
            options["requests"] + sessions_count,
            options["timeout"],
            cohort=workers,
        ) as peer:
            rows, elapsed, peak, heartbeat = asyncio.run(
                run_sample(
                    client,
                    version,
                    protocol,
                    peer,
                    trusted_certificates,
                    options,
                    workers,
                    memory,
                )
            )
            assert_peer(peer, version, protocol, sessions_count)
            assert all(not row["session_reused"] for row in peer.connections)
            if protocol == "h2":
                assert (
                    max(row["max_pending_h2_streams"] for row in peer.connections)
                    >= workers
                )
            pair_streaming_evidence(rows, peer, protocol, workers)
            record_measurement(
                {
                    "kind": (
                        "async_transport_memory" if memory else "async_transport_timing"
                    ),
                    "client": client,
                    "version": version,
                    "protocol": protocol,
                    "mode": mode,
                    "workers": workers,
                    "sample": sample + 1,
                    "warmup_requests_excluded": sessions_count,
                    "body_bytes": options["body_bytes"],
                    "requests": options["requests"],
                    "elapsed_seconds": elapsed,
                    "requests_per_second": (
                        None if memory else options["requests"] / elapsed
                    ),
                    "python_peak_bytes": peak,
                    "loop_heartbeat": heartbeat,
                    "request_samples": rows,
                    "server_connections": peer.connections,
                    "server_responses": peer.records,
                    "path_verified": True,
                    "payload_verified": all(row["payload_verified"] for row in rows),
                }
            )
