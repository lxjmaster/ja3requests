"""Bounded, prefix-gated peers for isolated-client memory acceptance.

This development helper lives in the controller process, never in the measured
client. HTTP/2 retains the existing independent peer's frame/flow-control loop.
"""

import math
import ssl
import threading
import time
import zlib

import brotli

from bench.peers import TLSLoopbackPeer
from test.mock_servers.local import read_headers


class _TruncatedResponse(Exception):
    """Stop the independent peer after the deliberately incomplete prefix."""


class _DataSocket:
    """Observe whole DATA frames emitted by TLSLoopbackPeer, without rewriting them."""

    def __init__(self, connection, peer):
        self.connection = connection
        self.peer = peer
        self.stream_id = None

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def sendall(self, data):
        if len(data) >= 9 and data[3] == 0:
            size = int.from_bytes(data[:3], 'big')
            if len(data) != size + 9:
                raise ValueError('Expected one complete independent-peer DATA frame')
            self.stream_id = int.from_bytes(data[5:9], 'big') & 0x7FFFFFFF
            self.peer._last_send_started = time.perf_counter()
            if self.peer._first_send_started is None:
                self.peer._first_send_started = self.peer._last_send_started
            self.connection.sendall(data)
            self.peer._encoded_bytes += size
            self.peer._decoded_bytes += size
            self.peer._max_source_chunk = max(self.peer._max_source_chunk, size)
            if not self.peer._gate_reached and (
                self.peer._decoded_bytes >= self.peer.prefix_bytes
            ):
                self.peer._wait_for_tail()
                if self.peer.truncate:
                    raise _TruncatedResponse()
            return
        self.connection.sendall(data)


class MemoryPeer(TLSLoopbackPeer):
    """One response, generated from fixed blocks and gated before its tail.

    The controller must call ``release_tail`` only after the measured client has
    reported its first yielded application chunk. ``prefix_sent`` is diagnostic;
    it does not authorize release. Body size must exceed the prefix, and callers
    must request application chunks no larger than the decodable prefix.
    """

    def __init__(
        self,
        context,
        protocol,
        body_bytes,
        timeout,
        *,
        encoding='identity',
        chunked=False,
        truncate=False,
        prefix_bytes=32768,
    ):
        if context is not None and not isinstance(context, ssl.SSLContext):
            raise ValueError('context must be an SSLContext or None')
        if protocol not in ('http/1.1', 'h2'):
            raise ValueError('Only HTTP/1.1 and TLS HTTP/2 are supported')
        if not isinstance(prefix_bytes, int) or isinstance(prefix_bytes, bool):
            raise ValueError('prefix_bytes must be an integer')
        if not 0 < prefix_bytes <= 32768:
            raise ValueError('prefix_bytes must be between 1 and 32768')
        if (
            not isinstance(body_bytes, int)
            or isinstance(body_bytes, bool)
            or body_bytes <= prefix_bytes
        ):
            raise ValueError('body_bytes must be an integer larger than the prefix')
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (float, int))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise ValueError('timeout must be finite and positive')
        if encoding not in ('identity', 'gzip', 'deflate', 'br'):
            raise ValueError('Unsupported response encoding')
        if not isinstance(chunked, bool) or not isinstance(truncate, bool):
            raise ValueError('chunked and truncate must be booleans')
        if protocol == 'h2' and (
            context is None or encoding != 'identity' or chunked or prefix_bytes % 16384
        ):
            raise ValueError(
                'H2 requires TLS, identity encoding and a frame-sized prefix'
            )
        super().__init__(
            context, protocol, body_bytes, 1, timeout, close_after_response=True
        )
        if context is None:
            self.url = 'http://127.0.0.1:{}/payload'.format(self.port)
        self.encoding = encoding
        self.chunked = chunked or encoding != 'identity'
        self.truncate = truncate
        self.prefix_bytes = prefix_bytes
        self.prefix_sent = threading.Event()
        self._allow_tail = threading.Event()
        self._release_requested = False
        self._gate_reached = False
        self._gate_prefix_bytes = 0
        self._decoded_bytes = 0
        self._encoded_bytes = 0
        self._max_source_chunk = 0
        self._first_send_started = None
        self._last_send_started = None

    def release_tail(self):
        """Acknowledge a real application yield in the separate client process."""
        self._release_requested = True
        self._allow_tail.set()

    def _wait_for_tail(self):
        self._gate_reached = True
        self._gate_prefix_bytes = self._decoded_bytes
        self.prefix_sent.set()
        if not self._allow_tail.wait(self.timeout):
            raise TimeoutError('Client did not yield a prefix before the tail deadline')
        if self._stop.is_set():
            raise ConnectionAbortedError('Memory peer stopped while its tail was gated')

    def _serve(self, raw, connection_id):
        if connection_id != 1:
            raw.close()
            self._fail(ValueError('Memory acceptance expects exactly one connection'))
            return
        if self.context is not None:
            return super()._serve(raw, connection_id)
        evidence = {
            'connection_id': connection_id,
            'tls_version': None,
            'cipher': None,
            'alpn': None,
            'session_reused': False,
            'server_handshake_seconds': 0.0,
            'requests': 0,
            'max_pending_h2_streams': 0,
        }
        with self._condition:
            self.connections.append(evidence)
        try:
            with raw:
                self._http1(raw, evidence)
        except Exception as error:
            self._fail(error)

    def _send_encoded(self, conn, data):
        if not data:
            return
        self._last_send_started = time.perf_counter()
        if self.chunked and self.encoding != 'identity':
            conn.sendall(('%x\r\n' % len(data)).encode('ascii'))
        conn.sendall(data)
        if self.chunked and self.encoding != 'identity':
            conn.sendall(b'\r\n')
        self._encoded_bytes += len(data)

    def _http1(self, conn, evidence):
        request = read_headers(conn)
        if not request.startswith(b'GET /payload HTTP/1.1\r\n'):
            raise ValueError('Expected a bodyless GET /payload request')
        framing = (
            'Transfer-Encoding: chunked\r\n'
            if self.chunked
            else 'Content-Length: %d\r\n' % self.body_bytes
        )
        coding = (
            ''
            if self.encoding == 'identity'
            else 'Content-Encoding: %s\r\n' % self.encoding
        )
        conn.sendall(
            (
                'HTTP/1.1 200 OK\r\n'
                + framing
                + coding
                + 'Content-Type: application/octet-stream\r\n'
                + 'Connection: close\r\n\r\n'
            ).encode('ascii')
        )
        compressor = None
        if self.encoding == 'br':
            compressor = brotli.Compressor(quality=1)
        elif self.encoding != 'identity':
            compressor = zlib.compressobj(wbits=31 if self.encoding == 'gzip' else 15)
        if self.chunked and self.encoding == 'identity':
            # One logical large chunk is deliberately delivered in bounded writes.
            conn.sendall(('%x\r\n' % self.body_bytes).encode('ascii'))
        self._first_send_started = time.perf_counter()
        while self._decoded_bytes < self.body_bytes:
            remaining = self.body_bytes - self._decoded_bytes
            if not self._gate_reached:
                remaining = min(remaining, self.prefix_bytes - self._decoded_bytes)
            count = min(len(self.chunk), remaining)
            data = memoryview(self.chunk)[:count]
            self._decoded_bytes += count
            self._max_source_chunk = max(self._max_source_chunk, count)
            encoded = (
                data
                if compressor is None
                else (
                    compressor.process(data)
                    if self.encoding == 'br'
                    else compressor.compress(data)
                )
            )
            self._send_encoded(conn, encoded)
            if not self._gate_reached and self._decoded_bytes == self.prefix_bytes:
                if compressor is not None:
                    self._send_encoded(
                        conn,
                        (
                            compressor.flush()
                            if self.encoding == 'br'
                            else compressor.flush(zlib.Z_SYNC_FLUSH)
                        ),
                    )
                self._wait_for_tail()
                if self.truncate:
                    self._complete(evidence, {})
                    return
        if compressor is not None:
            self._send_encoded(
                conn,
                (
                    compressor.finish()
                    if self.encoding == 'br'
                    else compressor.flush(zlib.Z_FINISH)
                ),
            )
        if self.chunked:
            conn.sendall(
                b'\r\n0\r\n\r\n' if self.encoding == 'identity' else b'0\r\n\r\n'
            )
        self._complete(evidence, {})

    def _http2(self, conn, evidence):
        observed = _DataSocket(conn, self)
        try:
            super()._http2(observed, evidence)
        except _TruncatedResponse:
            self._complete(evidence, {'stream_id': observed.stream_id})

    def _complete(self, evidence, record):
        record.update(
            body_bytes=self.body_bytes,
            decoded_body_bytes=self.body_bytes,
            decoded_bytes_sent=self._decoded_bytes,
            encoded_body_bytes=self._encoded_bytes,
            encoding=self.encoding,
            framing=(
                'h2-data'
                if self.protocol == 'h2'
                else ('chunked' if self.chunked else 'content-length')
            ),
            prefix_bytes=self.prefix_bytes,
            gate_prefix_bytes_sent=self._gate_prefix_bytes,
            gate_reached=self._gate_reached,
            tail_release_requested=self._release_requested,
            tail_released_before_complete=self._release_requested
            and self._gate_reached,
            truncated=self.truncate,
            max_source_chunk_bytes=self._max_source_chunk,
            first_send_started=self._first_send_started,
            last_send_started=self._last_send_started,
        )
        super()._complete(evidence, record)

    def __exit__(self, exc_type, exc, traceback):
        # Cleanup wakes a blocked worker but is not a successful prefix release.
        self._stop.set()
        self._allow_tail.set()
        return super().__exit__(exc_type, exc, traceback)
