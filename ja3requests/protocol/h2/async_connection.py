"""Native asyncio HTTP/2 scheduling over the project's byte/TLS transport."""

from __future__ import annotations

import asyncio
import contextvars
import math
from collections import OrderedDict, deque
from typing import Awaitable, Callable, List, Optional, Sequence, Tuple

from ja3requests.exceptions import RequestException, Timeout
from ja3requests.protocol.h2.connection import H2Connection, H2GoAwayError
from ja3requests.protocol.h2.frame import (
    FRAME_PRIORITY,
    FRAME_RST_STREAM,
    build_data_frame,
    build_rst_stream_frame,
)
from ja3requests.protocol.h2.stream_state import H2StreamError, H2StreamState, _Stream


class H2ProtocolError(RequestException):
    """Invalid HTTP/2 state is not an automatically retryable transport error."""


class _AsyncStream(_Stream):
    def __init__(self, send_window, receive_window):
        super().__init__(send_window, receive_window)
        self.request_committed = False
        self.send_progress = 0


class _RequestWrite:
    def __init__(self, stream_id, stream, headers, body):
        self.stream_id = stream_id
        self.stream = stream
        self.headers = headers
        self.body = body
        self.headers_sent = False
        self.offset = 0


class AsyncH2Connection(H2StreamState):
    """One reader/writer pair with shared codecs and stream-scoped cancellation.

    Transport callbacks must be native async operations. The transport owner
    closes its socket; aclose() terminates this instance's tasks and streams.
    """

    CONTROL_BUFFER_LIMIT = 65536

    def __init__(
        self,
        send_func: Callable[[bytes], Awaitable[None]],
        recv_func: Callable[[int], Awaitable[bytes]],
        settings=None,
    ) -> None:
        super().__init__(self._queue_control, settings=settings)
        self._send_func = send_func
        self._recv_func = recv_func
        self._loop = None
        self._changed = None
        self._writer_wake = None
        self._reader_task = None
        self._writer_task = None
        self._close_task = None
        self._state_callback = None
        self._closed = False
        self._control = deque()
        self._control_bytes = 0
        self._initializing = False
        self._initial_remaining = 0
        self._outbound = OrderedDict()

    @property
    def failed(self) -> bool:
        return self._failed is not None

    @property
    def capacity_available(self) -> bool:
        # _streams includes reserved requests not yet committed to the writer.
        return (
            self._peer_settings_received
            and not self._closed
            and not self.failed
            and not self._goaway_received
            and len(self._streams) < self._peer_settings[3]
        )

    def set_state_callback(self, callback: Optional[Callable[[], None]]) -> None:
        """Install a synchronous pool wakeup, without transferring ownership."""
        self._state_callback = callback

    def _bind_loop(self):
        loop = asyncio.get_running_loop()
        if self._loop is not None and self._loop is not loop:
            raise RuntimeError("HTTP/2 connection belongs to another event loop")
        if self._loop is None:
            self._loop = loop
            self._changed = asyncio.Event()
            self._writer_wake = asyncio.Event()

    def _spawn(self, coroutine):
        # A pooled connection must not retain its first request's ContextVars.
        return contextvars.Context().run(self._loop.create_task, coroutine)

    def _notify(self):
        if self._changed is not None:
            self._changed.set()
            self._changed = asyncio.Event()
            self._writer_wake.set()
        if self._state_callback is not None:
            self._state_callback()

    def _check_connection(self):
        if self._failed is not None:
            if isinstance(self._failed, RequestException):
                raise self._failed
            raise ConnectionError("HTTP/2 connection failed") from self._failed
        if self._closed:
            raise ConnectionError("HTTP/2 connection is closed")

    def _check_response_error(self, stream):
        if stream.error is not None:
            if isinstance(self._failed, RequestException):
                raise self._failed
            raise stream.error
        if self._failed is not None and not stream.done:
            self._check_connection()

    def _fail(self, error):
        if self._failed is None:
            self._failed = error
        current = asyncio.current_task()
        for task in (self._reader_task, self._writer_task):
            if task is not None and task is not current and not task.done():
                task.cancel()
        self._notify()

    def _queue_control(self, data):
        self._check_connection()
        if self._control_bytes + len(data) > self.CONTROL_BUFFER_LIMIT:
            raise H2ProtocolError("HTTP/2 control output buffer exceeded")
        self._control.append((data, self._initializing))
        self._control_bytes += len(data)
        if self._initializing:
            self._initial_remaining += 1
        if self._writer_wake is not None:
            self._writer_wake.set()

    @staticmethod
    def _timeout_error(phase):
        error = Timeout("Async request timed out during " + phase)
        error.phase = phase
        return error

    async def _wait_for(self, predicate, timeout, phase="HTTP/2 stream"):
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout < 0
        ):
            raise ValueError("HTTP/2 timeout must be non-negative, finite, or None")
        deadline = None if timeout is None else self._loop.time() + timeout
        while not predicate():
            self._check_connection()
            changed = self._changed
            if deadline is None:
                await changed.wait()
                continue
            remaining = deadline - self._loop.time()
            if remaining <= 0:
                raise self._timeout_error(phase)
            try:
                await asyncio.wait_for(changed.wait(), remaining)
            except asyncio.TimeoutError as error:
                raise self._timeout_error(phase) from error

    async def initiate(self, window_update_increment=None) -> None:
        self._bind_loop()
        self._check_connection()
        if self._reader_task is not None:
            raise RuntimeError("HTTP/2 connection is already initiated")
        try:
            self._initializing = True
            H2Connection.initiate(self, window_update_increment)
            self._initializing = False
            self._writer_task = self._spawn(self._write_loop())
            self._reader_task = self._spawn(self._read_loop())
            await self._wait_for(lambda: self._initial_remaining == 0, None)
            self._check_connection()
        except BaseException:
            self._initializing = False
            await self.aclose()
            raise

    async def _read_loop(self):
        try:
            while not self._closed:
                data = await self._recv_func(65536)
                if not data and not self._recv_buffer:
                    raise ConnectionError("HTTP/2 connection closed before END_STREAM")
                try:
                    for frame in self._feed_frames(data):
                        self._dispatch_frame(frame)
                except Exception as error:  # pylint: disable=broad-exception-caught
                    failure = H2ProtocolError(str(error))
                    if isinstance(error, H2GoAwayError):
                        failure.error_code = error.error_code
                        failure.last_stream_id = error.last_stream_id
                    failure.__cause__ = error
                    # Shared state can record a failure before raising it.
                    self._failed = failure
                    raise failure
                self._notify()
        except asyncio.CancelledError:
            raise
        except Exception as error:  # pylint: disable=broad-exception-caught
            self._fail(error)

    def _dispatch_frame(self, frame):
        super()._dispatch_frame(frame)
        stream = self._streams.get(frame.stream_id)
        if stream is not None and stream.error is not None:
            if frame.type == FRAME_PRIORITY or (
                frame.type == FRAME_RST_STREAM
                and int.from_bytes(frame.payload, "big") != 7
            ):
                stream.error = H2ProtocolError(str(stream.error))

    def _next_request_write(self):
        for stream_id, request in list(self._outbound.items()):
            if request.stream.error is not None or request.stream.send_done:
                self._outbound.pop(stream_id, None)
                continue
            if not request.headers_sent or (
                self._connection_send_window > 0 and request.stream.send_window > 0
            ):
                self._outbound.move_to_end(stream_id)
                return request
        return None

    async def _write_loop(self):
        try:
            while not self._closed:
                if self._control:
                    data, initial = self._control.popleft()
                    await self._send_func(data)
                    self._control_bytes -= len(data)
                    if initial:
                        self._initial_remaining -= 1
                    self._notify()
                    continue
                request = self._next_request_write()
                if request is not None:
                    await self._write_request_piece(request)
                    self._notify()
                    continue
                self._writer_wake.clear()
                await self._writer_wake.wait()
        except asyncio.CancelledError:
            raise
        except Exception as error:  # pylint: disable=broad-exception-caught
            self._fail(error)

    async def _write_request_piece(self, request):
        stream = request.stream
        stream_id = request.stream_id
        if not request.headers_sent:
            # Encoding commits connection-wide HPACK state. The connection
            # writer survives caller cancellation until this whole block is sent.
            block = self._encoder.encode_headers(request.headers)
            stream.request_committed = True
            for frame in self._header_frames(
                stream_id, block, end_stream=not request.body
            ):
                await self._send_func(frame.serialize())
                stream.send_progress += 1
                self._notify()
            request.headers_sent = True
            if not request.body:
                stream.send_done = True
                self._outbound.pop(stream_id, None)
            return
        size = min(
            len(request.body) - request.offset,
            self._peer_settings[5],
            self._connection_send_window,
            stream.send_window,
        )
        end = request.offset + size
        frame = build_data_frame(
            stream_id,
            request.body[request.offset : end],
            end_stream=end == len(request.body),
        )
        self._connection_send_window -= size
        stream.send_window -= size
        request.offset = end
        await self._send_func(frame.serialize())
        stream.send_progress += 1
        if end == len(request.body):
            stream.send_done = True
            self._outbound.pop(stream_id, None)

    async def send_request(
        self,
        method: str,
        authority: str,
        path: str,
        headers: Optional[Sequence[Tuple[str, str]]] = None,
        body: Optional[bytes] = None,
        scheme: str = "https",
        timeout: Optional[float] = None,
    ) -> int:
        self._bind_loop()
        if self._reader_task is None:
            raise RuntimeError("HTTP/2 connection has not been initiated")
        if body is not None and not isinstance(body, bytes):
            raise TypeError("HTTP/2 request body must be bytes")
        await self._wait_for(
            lambda: self.capacity_available or self._goaway_received,
            timeout,
            "HTTP/2 admission",
        )
        self._check_connection()
        if self._goaway_received:
            raise ConnectionError("HTTP/2 connection received GOAWAY")
        stream_id = self._next_stream_id
        self._next_stream_id += 2
        stream = _AsyncStream(self._peer_settings[4], self._local_settings[4])
        self._streams[stream_id] = stream
        try:
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
            self._outbound[stream_id] = _RequestWrite(
                stream_id, stream, h2_headers, body or b""
            )
            self._notify()
            while not stream.send_done:
                progress = stream.send_progress
                await self._wait_for(
                    lambda: stream.send_done
                    or stream.error is not None
                    or stream.send_progress != progress,
                    timeout,
                    "HTTP/2 write",
                )
                self._check_response_error(stream)
            self._check_response_error(stream)
            return stream_id
        except BaseException:
            self._cancel_stream_now(stream_id)
            raise

    async def receive_headers(
        self, stream_id: int, timeout: Optional[float] = None
    ) -> List[Tuple[str, str]]:
        self._bind_loop()
        try:
            stream = self._response_stream(stream_id)
            await self._wait_for(
                lambda: stream.headers is not None or stream.error is not None,
                timeout,
                "HTTP/2 headers",
            )
            self._check_response_error(stream)
            return stream.headers
        except BaseException:
            self._cancel_stream_now(stream_id)
            raise

    async def read_stream(
        self, stream_id: int, size: int, timeout: Optional[float] = None
    ) -> bytes:
        self._bind_loop()
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("HTTP/2 read size must be a non-negative integer")
        if size == 0:
            return b""
        try:
            stream = self._response_stream(stream_id)
            await self._wait_for(
                lambda: stream.body or stream.done or stream.error is not None,
                timeout,
                "HTTP/2 body",
            )
            self._check_response_error(stream)
            if not stream.body:
                self._streams.pop(stream_id, None)
                self._notify()
                return b""
            data = bytes(memoryview(stream.body)[:size])
            del stream.body[: len(data)]
            self._buffered_bytes -= len(data)
            self._replenish_connection_window()
            self._replenish_stream_window(stream_id, stream)
            self._notify()
            return data
        except BaseException:
            self._cancel_stream_now(stream_id)
            raise

    def _cancel_stream_now(self, stream_id):
        stream = self._streams.pop(stream_id, None)
        self._outbound.pop(stream_id, None)
        if stream is None:
            return
        if stream.header_open:
            self._ignored_header_block = stream.header_block
        send_reset = (
            stream.request_committed
            and not (stream.done and stream.send_done)
            and stream.error is None
            and not self.failed
            and not self._closed
        )
        if stream.error is None and not (stream.done and stream.send_done):
            stream.error = H2StreamError("HTTP/2 stream %s was cancelled" % stream_id)
        try:
            if send_reset:
                self._send(build_rst_stream_frame(stream_id, 8).serialize())
        except Exception as error:  # pylint: disable=broad-exception-caught
            self._fail(error)
        try:
            self._discard_body(stream)
        except Exception as error:  # pylint: disable=broad-exception-caught
            self._fail(error)
        self._notify()

    async def cancel_stream(self, stream_id: int) -> None:
        self._bind_loop()
        self._cancel_stream_now(stream_id)

    async def _join_tasks(self):
        tasks = [
            task for task in (self._reader_task, self._writer_task) if task is not None
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._control.clear()
        self._control_bytes = 0

    async def aclose(self) -> None:
        self._bind_loop()
        if self._close_task is None:
            self._closed = True
            self._fail(ConnectionError("HTTP/2 connection is closed"))
            for stream_id in list(self._streams):
                self._cancel_stream_now(stream_id)
            self._close_task = self._spawn(self._join_tasks())
        await asyncio.shield(self._close_task)
