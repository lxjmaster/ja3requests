"""Concurrent HTTP/2 streams over one TLS transport."""

import threading
import time

from ja3requests.protocol.h2.frame import (
    build_data_frame,
    build_rst_stream_frame,
)
from ja3requests.protocol.h2.stream_state import H2StreamError, H2StreamState, _Stream
from ja3requests.protocol.h2.connection import H2GoAwayError
from ja3requests.protocol.h2.hpack import HeaderLimitError


class H2MultiplexConnection(H2StreamState):
    """Serialize framing and demultiplex responses in one reader thread."""

    def __init__(self, send_func, recv_func, settings=None):
        super().__init__(send_func, recv_func, settings=settings)
        self._condition = threading.Condition(threading.RLock())
        self._reader = None
        self._transport_send = send_func
        self._send = self._send_checked

    def _send_checked(self, data):
        try:
            self._transport_send(data)
        except Exception as error:  # pylint: disable=broad-exception-caught
            with self._condition:
                if self._failed is None:
                    self._failed = error
                self._condition.notify_all()
            raise

    @property
    def failed(self):
        return self._failed is not None

    def set_pooled_connection(self, pooled):
        with self._condition:
            self._pooled_connection = pooled
            pooled.set_max_concurrent_streams(self._peer_settings[3])
            if self._goaway_received:
                pooled.mark_goaway()

    def initiate(self, window_update_increment=None):
        super().initiate(window_update_increment)
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        try:
            while True:
                frames = self._read_frames()
                with self._condition:
                    for frame in frames:
                        self._dispatch_frame(frame)
                    self._condition.notify_all()
        except Exception as error:  # pylint: disable=broad-exception-caught
            with self._condition:
                if self._failed is None:
                    self._failed = error
                self._condition.notify_all()
            if (
                isinstance(error, (HeaderLimitError, H2GoAwayError))
                and self._pooled_connection is not None
            ):
                self._pooled_connection.close()

    def _wait_for(self, predicate, timeout):
        deadline = time.monotonic() + (15.0 if timeout is None else timeout)
        with self._condition:
            while not predicate():
                if self._failed is not None:
                    raise ConnectionError("HTTP/2 connection failed") from self._failed
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("HTTP/2 stream timed out")
                self._condition.wait(remaining)

    def send_request(
        self,
        method,
        authority,
        path,
        headers=None,
        body=None,
        scheme="https",
        timeout=None,
    ):
        if body is not None and not isinstance(body, bytes):
            raise TypeError("HTTP/2 request body must be bytes")
        deadline = time.monotonic() + (15.0 if timeout is None else timeout)
        with self._condition:
            while (
                not self._peer_settings_received
                or len(self._streams) >= self._peer_settings[3]
            ) and not self._goaway_received:
                if self._failed is not None:
                    raise ConnectionError("HTTP/2 connection failed") from self._failed
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("HTTP/2 stream timed out")
                self._condition.wait(remaining)
            if self._failed is not None:
                raise ConnectionError("HTTP/2 connection failed") from self._failed
            if self._goaway_received:
                raise ConnectionError("HTTP/2 connection received GOAWAY")
            stream_id = self._next_stream_id
            self._next_stream_id += 2
            stream = _Stream(self._peer_settings[4], self._local_settings[4])
            self._streams[stream_id] = stream
            h2_headers = [
                (":method", method),
                (":authority", authority),
                (":scheme", scheme),
                (":path", path),
            ]
            for name, value in headers or ():
                name = name.lower()
                if name in ("host", "connection", "transfer-encoding", "upgrade"):
                    continue
                h2_headers.append(
                    (name, value if isinstance(value, (str, bytes)) else str(value))
                )
            try:
                block = self._encoder.encode_headers(h2_headers)
                for frame in self._header_frames(stream_id, block, end_stream=not body):
                    self._send(frame.serialize())
                stream.send_done = not body
            except Exception:
                self._streams.pop(stream_id, None)
                self._condition.notify_all()
                raise

        try:
            offset = 0
            while body and offset < len(body):
                with self._condition:
                    error = stream.error
                    if error is not None:
                        raise error
                    if stream.send_done:
                        break
                    size = min(
                        len(body) - offset,
                        self._peer_settings[5],
                        self._connection_send_window,
                        stream.send_window,
                    )
                    if size > 0:
                        end = offset + size
                        self._send(
                            build_data_frame(
                                stream_id, body[offset:end], end_stream=end == len(body)
                            ).serialize()
                        )
                        self._connection_send_window -= size
                        stream.send_window -= size
                        offset = end
                        stream.send_done = end == len(body)
                if size <= 0:
                    self._wait_for(
                        lambda: stream.error
                        or stream.send_done
                        or (
                            self._connection_send_window > 0 and stream.send_window > 0
                        ),
                        timeout,
                    )
            return stream_id
        except Exception:
            self.cancel_stream(stream_id)
            raise

    def receive_headers(self, stream_id, timeout=None):
        """Wait for final response headers without waiting for its DATA or EOF."""
        try:
            with self._condition:
                stream = self._response_stream(stream_id)
                self._wait_for(
                    lambda: stream.headers is not None or stream.error, timeout
                )
                self._check_response_error(stream)
                return stream.headers
        except Exception:
            self.cancel_stream(stream_id)
            raise

    def read_stream(self, stream_id, size, timeout=None):
        """Return up to size available bytes; release stream state on empty EOF.

        The caller owns the stream until EOF or cancel_stream(). Reading zero
        bytes does not consume or finish the stream. After EOF the caller must
        cache that state instead of reading the removed stream again.
        """
        if not isinstance(size, int) or size < 0:
            raise ValueError("HTTP/2 read size must be a non-negative integer")
        if size == 0:
            return b""
        try:
            with self._condition:
                stream = self._response_stream(stream_id)
                self._wait_for(
                    lambda: stream.body or stream.done or stream.error, timeout
                )
                self._check_response_error(stream)
                if not stream.body:
                    self._streams.pop(stream_id, None)
                    self._condition.notify_all()
                    return b""
                data = bytes(memoryview(stream.body)[:size])
                del stream.body[: len(data)]
                self._buffered_bytes -= len(data)
                self._replenish_connection_window()
                self._replenish_stream_window(stream_id, stream)
                self._condition.notify_all()
                return data
        except Exception:
            self.cancel_stream(stream_id)
            raise

    def receive_response(self, stream_id, timeout=None):
        """Compatibility collector over incremental reads, with one deadline."""
        deadline = time.monotonic() + (15.0 if timeout is None else timeout)
        chunks = []
        try:
            headers = self.receive_headers(
                stream_id, timeout=max(0, deadline - time.monotonic())
            )
            while True:
                chunk = self.read_stream(
                    stream_id, 65536, timeout=max(0, deadline - time.monotonic())
                )
                if not chunk:
                    return headers, b"".join(chunks)
                chunks.append(chunk)
        finally:
            self.cancel_stream(stream_id)

    def cancel_stream(self, stream_id):
        with self._condition:
            stream = self._streams.pop(stream_id, None)
            if stream is not None and stream.header_open:
                self._ignored_header_block = stream.header_block
            if (
                stream is not None
                and not (stream.done and stream.send_done)
                and stream.error is None
                and self._failed is None
            ):
                try:
                    self._send(build_rst_stream_frame(stream_id, 8).serialize())
                except OSError:
                    pass
            if stream is not None:
                if not (stream.done and stream.send_done) and stream.error is None:
                    stream.error = H2StreamError(
                        f"HTTP/2 stream {stream_id} was cancelled"
                    )
                self._discard_body(stream)
            self._condition.notify_all()
