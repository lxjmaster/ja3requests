"""Bounded independent TLS peers with observable connections and H2 flow control."""

import socket
import struct
import threading
import time

from test.mock_servers.local import h2_frame, read_exact


class TLSLoopbackPeer:
    """An OpenSSL server; no project TLS or HPACK codec is used by this peer."""

    def __init__(
        self,
        context,
        protocol,
        body_bytes,
        requests,
        timeout,
        cohort=1,
        close_after_response=False,
    ):
        self.context = context
        self.protocol = protocol
        self.body_bytes = body_bytes
        self.expected_requests = requests
        self.timeout = timeout
        self.cohort = cohort
        self.close_after_response = close_after_response
        self.chunk = b"x" * min(body_bytes, 16384)
        self.records = []
        self.connections = []
        self.errors = []
        self._stop = threading.Event()
        self._condition = threading.Condition()
        self._workers = []
        self._sockets = []
        self._ssl_objects = []
        self._listener = socket.socket()
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(32)
        self._listener.settimeout(0.1)
        self.port = self._listener.getsockname()[1]
        self.url = "https://127.0.0.1:{}/payload".format(self.port)
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def _fail(self, error):
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
                self._fail(error)
                return
            conn.settimeout(self.timeout)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self._condition:
                connection_id = len(self._workers) + 1
                self._sockets.append(conn)
                worker = threading.Thread(
                    target=self._serve, args=(conn, connection_id), daemon=True
                )
                self._workers.append(worker)
            worker.start()

    def _serve(self, raw, connection_id):
        try:
            started = time.perf_counter()
            conn = self.context.wrap_socket(raw, server_side=True)
            with self._condition:
                self._sockets.append(conn)
                self._ssl_objects.append(conn._sslobj)
                evidence = {
                    "connection_id": connection_id,
                    "tls_version": conn.version(),
                    "cipher": conn.cipher()[0],
                    "alpn": conn.selected_alpn_protocol(),
                    "session_reused": conn.session_reused,
                    "server_handshake_seconds": time.perf_counter() - started,
                    "requests": 0,
                    "max_pending_h2_streams": 0,
                }
                self.connections.append(evidence)
            assert evidence["alpn"] == self.protocol
            with conn:
                if self.protocol == "h2":
                    self._http2(conn, evidence)
                else:
                    self._http1(conn, evidence)
        except Exception as error:
            self._fail(error)

    def _complete(self, evidence, record):
        record["connection_id"] = evidence["connection_id"]
        record["last_send_completed"] = time.perf_counter()
        with self._condition:
            evidence["requests"] += 1
            self.records.append(record)
            self._condition.notify_all()

    def _http1(self, conn, evidence):
        with conn.makefile("rb") as reader:
            while not self._stop.is_set():
                line = reader.readline(65537)
                if not line:
                    return
                assert line == b"GET /payload HTTP/1.1\r\n"
                length = len(line)
                while True:
                    line = reader.readline(65537)
                    length += len(line)
                    if not line or length > 65536:
                        raise ValueError("Incomplete or oversized HTTP/1.1 headers")
                    if line == b"\r\n":
                        break
                conn.sendall(
                    (
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n"
                        "Content-Type: application/octet-stream\r\n"
                        "Connection: keep-alive\r\n\r\n"
                    )
                    .format(self.body_bytes)
                    .encode()
                )
                record = {"first_send_started": time.perf_counter()}
                remaining = self.body_bytes
                while remaining:
                    count = min(remaining, len(self.chunk))
                    if count == remaining:
                        record["last_send_started"] = time.perf_counter()
                    conn.sendall(memoryview(self.chunk)[:count])
                    remaining -= count
                self._complete(evidence, record)
                if self.close_after_response:
                    # Match the existing Session ID fixture: retain SSL objects
                    # without reading an unclean client EOF into OpenSSL's cache.
                    return

    def _http2(self, conn, evidence):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        window = 65535
        initial_window = 65535
        frame_size = 16384
        waiting = {}
        active = {}
        received = 0
        while not self._stop.is_set():
            try:
                header = read_exact(conn, 9)
            except EOFError:
                return
            size = int.from_bytes(header[:3], "big")
            if size > 1024 * 1024:
                raise ValueError("Oversized benchmark request frame")
            kind, flags, stream = struct.unpack("!BBI", header[3:])
            payload = read_exact(conn, size)
            if kind == 4 and not flags & 1:
                for setting, value in struct.iter_unpack("!HI", payload):
                    if setting == 4:
                        delta = value - initial_window
                        for state in list(waiting.values()) + list(active.values()):
                            state["window"] += delta
                        initial_window = value
                    elif setting == 5:
                        frame_size = value
                conn.sendall(h2_frame(4, 1, 0))
            elif kind == 8:
                increment = int.from_bytes(payload, "big") & 0x7FFFFFFF
                if stream == 0:
                    window += increment
                elif stream in active:
                    active[stream]["window"] += increment
                elif stream in waiting:
                    waiting[stream]["window"] += increment
            elif kind == 1:
                assert (
                    flags & 4 and flags & 1
                ), "benchmark requests must be complete bodyless HEADERS"
                received += 1
                waiting[stream] = {
                    "remaining": self.body_bytes,
                    "window": initial_window,
                }
                evidence["max_pending_h2_streams"] = max(
                    evidence["max_pending_h2_streams"], len(waiting) + len(active)
                )
            elif kind == 3:
                raise RuntimeError("Client reset a benchmark response stream")
            elif kind == 7:
                return
            # First request is a warmup. Subsequent cohorts prove overlapping streams.
            progressed = True
            while progressed:
                progressed = False
                required = 1 if evidence["requests"] == 0 else self.cohort
                if (
                    not active
                    and waiting
                    and (len(waiting) >= required or received >= self.expected_requests)
                ):
                    active, waiting = waiting, {}
                    for active_id, state in active.items():
                        conn.sendall(h2_frame(1, 4, active_id, b"\x88"))
                        state["record"] = {
                            "stream_id": active_id,
                            "first_send_started": time.perf_counter(),
                        }
                for active_id in list(active):
                    state = active[active_id]
                    count = min(
                        state["remaining"],
                        state["window"],
                        window,
                        frame_size,
                        len(self.chunk),
                    )
                    if count <= 0:
                        continue
                    final = count == state["remaining"]
                    if final:
                        state["record"]["last_send_started"] = time.perf_counter()
                    conn.sendall(h2_frame(0, int(final), active_id, self.chunk[:count]))
                    state["remaining"] -= count
                    state["window"] -= count
                    window -= count
                    progressed = True
                    if final:
                        self._complete(evidence, state["record"])
                        del active[active_id]

    def wait_for_records(self):
        deadline = time.monotonic() + self.timeout
        with self._condition:
            while len(self.records) < self.expected_requests and not self.errors:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        "Benchmark peer did not finish expected requests"
                    )
                self._condition.wait(remaining)
            if self.errors:
                raise RuntimeError("Benchmark peer failed: {}".format(self.errors))
            assert len(self.records) == self.expected_requests
        return list(self.records)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self._stop.set()
        self._listener.close()
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
        self._ssl_objects.clear()
        if exc_type is None:
            assert not self._thread.is_alive()
            assert not any(worker.is_alive() for worker in self._workers)
            assert not self.errors, self.errors
