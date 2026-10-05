#!/usr/bin/env python3
"""Reproducible HTTP/1.1 loopback measurements through the public Session API."""

import argparse
import datetime
import gc
import hashlib
import json
import math
import platform
import socket
import statistics
import subprocess
import sys
import threading
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))

import brotli  # noqa: E402
import cryptography  # noqa: E402
import ja3requests  # noqa: E402
from ja3requests.__version__ import __version__  # noqa: E402
from ja3requests.pool import ConnectionPool  # noqa: E402


class LoopbackPeer:
    """Independent, bounded peer with per-request send times and connection IDs."""

    def __init__(self, size, chunk_size, gap, timeout, requests):
        self.size = size
        self.chunk = b"x" * min(size, chunk_size)
        self.gap = gap
        self.timeout = timeout
        self.expected_requests = requests
        self.records = []
        self.errors = []
        self.connections = 0
        self._sockets = []
        self._workers = []
        self._condition = threading.Condition()
        self._stop = threading.Event()
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(0.1)
        self.url = "http://127.0.0.1:{}/payload".format(self._listener.getsockname()[1])
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def _error(self, error):
        if not self._stop.is_set():
            with self._condition:
                self.errors.append(repr(error))
                self._condition.notify_all()

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError as error:
                self._error(error)
                return
            conn.settimeout(self.timeout)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self._condition:
                self.connections += 1
                connection_id = self.connections
                self._sockets.append(conn)
                if connection_id > self.expected_requests:
                    self.errors.append("More connections than requested samples")
                    conn.close()
                    self._condition.notify_all()
                    return
                worker = threading.Thread(
                    target=self._serve, args=(conn, connection_id), daemon=True
                )
                self._workers.append(worker)
            worker.start()

    def _serve(self, conn, connection_id):
        try:
            with conn, conn.makefile("rb") as reader:
                while not self._stop.is_set():
                    first_line = reader.readline(65537)
                    if not first_line:
                        return
                    if first_line != b"GET /payload HTTP/1.1\r\n":
                        raise ValueError(
                            "Unexpected request line: {!r}".format(first_line)
                        )
                    header_size = len(first_line)
                    while True:
                        line = reader.readline(65537)
                        header_size += len(line)
                        if not line or header_size > 65536:
                            raise ValueError("Incomplete or oversized request headers")
                        if line == b"\r\n":
                            break
                    conn.sendall(
                        (
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n"
                            "Content-Type: application/octet-stream\r\n"
                            "Connection: keep-alive\r\n\r\n"
                        )
                        .format(self.size)
                        .encode("ascii")
                    )
                    remaining = self.size
                    record = {"connection_id": connection_id, "body_bytes": self.size}
                    while remaining:
                        count = min(remaining, len(self.chunk))
                        if remaining == self.size:
                            record["first_send_started"] = time.perf_counter()
                        if remaining == count:
                            record["last_send_started"] = time.perf_counter()
                        conn.sendall(memoryview(self.chunk)[:count])
                        remaining -= count
                        if not remaining:
                            record["last_send_completed"] = time.perf_counter()
                        elif self.gap and self._stop.wait(self.gap):
                            return
                    with self._condition:
                        self.records.append(record)
                        self._condition.notify_all()
        except Exception as error:
            self._error(error)

    def wait_for_records(self):
        deadline = time.monotonic() + self.timeout
        with self._condition:
            while len(self.records) < self.expected_requests and not self.errors:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "Loopback peer did not finish the expected responses"
                    )
                self._condition.wait(remaining)
            if self.errors:
                raise RuntimeError("Loopback peer failed: {}".format(self.errors))
            return list(self.records)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self._stop.set()
        self._listener.close()
        # Stop accepting before taking the final socket/worker inventory.
        self._thread.join(self.timeout + 0.2)
        for conn in self._sockets:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        deadline = time.monotonic() + self.timeout + 0.2
        for worker in self._workers:
            worker.join(max(0, deadline - time.monotonic()))
        if exc_type is None:
            if self._thread.is_alive() or any(w.is_alive() for w in self._workers):
                raise RuntimeError("Loopback peer thread did not terminate")
            if self.errors:
                raise RuntimeError("Loopback peer failed: {}".format(self.errors))


def source_identity():
    files = {}
    digest = hashlib.sha256()
    for path in sorted((ROOT / "ja3requests").rglob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        checksum = hashlib.sha256(path.read_bytes()).hexdigest()
        files[relative] = checksum
        digest.update((relative + "\0" + checksum + "\n").encode("utf-8"))
    return {"sha256": digest.hexdigest(), "module_count": len(files), "files": files}


def git_identity():
    def git(*args):
        return subprocess.check_output(
            ["git"] + list(args),
            cwd=str(ROOT),
            stderr=subprocess.DEVNULL,
            timeout=5,
            universal_newlines=True,
        ).strip()

    try:
        status = git("status", "--porcelain", "--untracked-files=normal")
        return {
            "head_sha": git("rev-parse", "HEAD"),
            "working_tree_dirty_including_untracked": bool(status),
            "tracked_changes_present": any(
                not line.startswith("??") for line in status.splitlines()
            ),
        }
    except (OSError, subprocess.SubprocessError) as error:
        return {"unavailable": type(error).__name__}


def latency_memory_sample(size, args, sample):
    pool = ConnectionPool(max_connections_per_host=1, max_pool_size=1)
    with LoopbackPeer(
        size, args.chunk_kib * 1024, args.gap_ms / 1000, args.timeout, 1
    ) as peer, ja3requests.Session(pool=pool) as session:
        gc.collect()
        response = None
        tracemalloc.start()
        started = time.perf_counter()
        try:
            response = session.get(
                peer.url, stream=True, timeout=args.timeout, allow_redirects=False
            )
            returned = time.perf_counter()
            if response.status_code != 200:
                raise RuntimeError("Unexpected response status")
            received = 0
            first_chunk = None
            for chunk in response.iter_content(chunk_size=args.chunk_kib * 1024):
                if first_chunk is None:
                    first_chunk = time.perf_counter()
                if chunk.count(b"x") != len(chunk):
                    raise RuntimeError("Response content differs from the peer payload")
                received += len(chunk)
            finished = time.perf_counter()
            _, peak = tracemalloc.get_traced_memory()
            if received != size or first_chunk is None:
                raise RuntimeError("Response body length differs from the peer payload")
        finally:
            tracemalloc.stop()
            if response is not None:
                response.close()
        record = peer.wait_for_records()[0]
        return {
            "sample": sample,
            "body_bytes": size,
            "received_bytes": received,
            "payload_verified": True,
            "request_return_seconds": returned - started,
            "first_chunk_seconds": first_chunk - started,
            "complete_seconds": finished - started,
            "python_peak_bytes": peak,
            "server_first_send_seconds": record["first_send_started"] - started,
            "server_last_send_started_seconds": record["last_send_started"] - started,
            "server_last_send_completed_seconds": record["last_send_completed"]
            - started,
            "first_chunk_before_final_send": first_chunk < record["last_send_started"],
            "first_chunk_after_final_send_completed": first_chunk
            >= record["last_send_completed"],
            "accepted_connections": peer.connections,
        }


def throughput_sample(args, sample):
    pool = ConnectionPool(max_connections_per_host=1, max_pool_size=1)
    with LoopbackPeer(
        args.throughput_bytes, args.chunk_kib * 1024, 0, args.timeout, args.requests
    ) as peer, ja3requests.Session(pool=pool) as session:
        started = time.perf_counter()
        for _ in range(args.requests):
            response = session.get(
                peer.url, timeout=args.timeout, allow_redirects=False
            )
            try:
                if (
                    response.status_code != 200
                    or len(response.content) != args.throughput_bytes
                    or response.content.count(b"x") != args.throughput_bytes
                ):
                    raise RuntimeError("Unexpected throughput response")
            finally:
                response.close()
        elapsed = time.perf_counter() - started
        records = peer.wait_for_records()
        counts = {}
        for record in records:
            key = str(record["connection_id"])
            counts[key] = counts.get(key, 0) + 1
        return {
            "sample": sample,
            "requests": args.requests,
            "body_bytes_per_response": args.throughput_bytes,
            "payload_verified": True,
            "elapsed_seconds": elapsed,
            "requests_per_second": args.requests / elapsed,
            "accepted_connections": peer.connections,
            "requests_per_connection": counts,
            "single_connection_reused": peer.connections == 1 and args.requests > 1,
        }


def positive_int(value):
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return result


def finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise argparse.ArgumentTypeError("must be finite")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes-mib", type=positive_int, nargs="+", default=[1, 8])
    parser.add_argument("--repeat", type=positive_int, default=3)
    parser.add_argument("--chunk-kib", type=positive_int, default=64)
    parser.add_argument("--gap-ms", type=finite_float, default=2.0)
    parser.add_argument("--requests", type=positive_int, default=30)
    parser.add_argument("--throughput-bytes", type=positive_int, default=1024)
    parser.add_argument("--timeout", type=finite_float, default=5.0)
    parser.add_argument(
        "--output", type=Path, help="Create a new JSON file; never overwrite one"
    )
    args = parser.parse_args()
    if args.timeout <= 0 or args.gap_ms < 0 or args.gap_ms / 1000 >= args.timeout:
        parser.error("timeout must be positive and 0 <= gap-ms < timeout * 1000")
    if args.output is not None and args.output.exists():
        parser.error("output already exists; select a new result path")
    parameters = {key: value for key, value in vars(args).items() if key != "output"}
    source_before = source_identity()
    report = {
        "schema_version": 1,
        "benchmark": "http1-loopback-v1",
        "started_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "parameters": parameters,
        "environment": {
            "python": sys.version,
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "dependencies": {
                "ja3requests": __version__,
                "cryptography": cryptography.__version__,
                "brotli": brotli.__version__,
            },
            "package_path": ja3requests.__file__,
        },
        "git_before": git_identity(),
        "source_before": source_before,
        "benchmark_script_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "latency_and_memory": [],
        "sequential_throughput": [],
        "measurement_notes": [
            "HTTP/1.1 cleartext on 127.0.0.1 only; no HTTPS, HTTP/2 or external services.",
            "First-chunk time starts before Session.get, not before iterator advancement.",
            "Latency samples use stream=True and consume iter_content without accumulating chunks.",
            "tracemalloc measures Python allocations, includes the server thread, and is not RSS.",
            "The server allocates one fixed chunk before tracing and sends memoryview slices in a loop.",
            "Both paths verify payload length and every byte; latency consumption never joins chunks.",
            "Throughput includes initial connect, complete body consumption, payload verification and response.close; no warmup.",
            "Each sample owns a fresh pool/server; connection reuse is counted at server accept.",
            "Timing and memory are descriptive measurements, not performance pass/fail thresholds.",
        ],
    }
    for size_mib in args.sizes_mib:
        for sample in range(1, args.repeat + 1):
            report["latency_and_memory"].append(
                latency_memory_sample(size_mib * 1024 * 1024, args, sample)
            )
    for sample in range(1, args.repeat + 1):
        report["sequential_throughput"].append(throughput_sample(args, sample))
    report["summary"] = {
        "sizes": [
            {
                "body_bytes": size * 1024 * 1024,
                "median_first_chunk_seconds": statistics.median(
                    row["first_chunk_seconds"]
                    for row in report["latency_and_memory"]
                    if row["body_bytes"] == size * 1024 * 1024
                ),
                "median_python_peak_bytes": statistics.median(
                    row["python_peak_bytes"]
                    for row in report["latency_and_memory"]
                    if row["body_bytes"] == size * 1024 * 1024
                ),
            }
            for size in args.sizes_mib
        ],
        "median_requests_per_second": statistics.median(
            row["requests_per_second"] for row in report["sequential_throughput"]
        ),
    }
    source_after = source_identity()
    report["source_after_sha256"] = source_after["sha256"]
    report["source_stable_during_run"] = source_before == source_after
    report["git_after"] = git_identity()
    report["finished_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        sys.stdout.write(output)
    else:
        with args.output.open("x", encoding="utf-8") as destination:
            destination.write(output)
        print(
            "Created {} (source stable: {})".format(
                args.output, report["source_stable_during_run"]
            )
        )


if __name__ == "__main__":
    main()
