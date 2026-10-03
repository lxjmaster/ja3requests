"""Concurrent HTTP/2 streams over one TLS transport."""

import threading
import time

from ja3requests.protocol.h2.connection import H2Connection
from ja3requests.protocol.h2.frame import (
    FRAME_CONTINUATION,
    FRAME_DATA,
    FRAME_GOAWAY,
    FRAME_HEADERS,
    FRAME_PING,
    FRAME_PRIORITY,
    FRAME_RST_STREAM,
    FRAME_SETTINGS,
    FRAME_WINDOW_UPDATE,
    FLAG_ACK,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    build_data_frame,
    build_headers_frame,
    build_ping_frame,
    build_rst_stream_frame,
    build_settings_frame,
    build_window_update_frame,
    data_payload,
    header_block_fragment,
    parse_settings_payload,
    SETTINGS_ENABLE_PUSH,
)


class H2StreamError(ConnectionError):
    """A single stream failed while the underlying connection may remain usable."""


class _Stream:
    def __init__(self, send_window, receive_window):
        self.send_window = send_window
        self.receive_window = receive_window
        self.headers = None
        self.header_block = b""
        self.header_open = False
        self.header_end_stream = False
        self.body = bytearray()
        self.done = False
        self.error = None


class H2MultiplexConnection(H2Connection):
    """Serialize framing and demultiplex responses in one reader thread."""

    def __init__(self, send_func, recv_func, settings=None):
        super().__init__(send_func, recv_func, settings=settings)
        self._condition = threading.Condition(threading.RLock())
        self._streams = {}
        self._failed = None
        self._pooled_connection = None
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
                self._send(
                    build_headers_frame(
                        stream_id, block, end_stream=not body
                    ).serialize()
                )
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
                if size <= 0:
                    self._wait_for(
                        lambda: stream.error
                        or (
                            self._connection_send_window > 0 and stream.send_window > 0
                        ),
                        timeout,
                    )
            return stream_id
        except Exception:
            self.cancel_stream(stream_id)
            raise

    def receive_response(self, stream_id, timeout=None):
        with self._condition:
            stream = self._streams[stream_id]
        try:
            self._wait_for(lambda: stream.done or stream.error, timeout)
            if stream.error:
                raise stream.error
            return stream.headers, bytes(stream.body)
        except Exception:
            self.cancel_stream(stream_id)
            raise
        finally:
            with self._condition:
                self._streams.pop(stream_id, None)
                self._condition.notify_all()

    def cancel_stream(self, stream_id):
        with self._condition:
            stream = self._streams.pop(stream_id, None)
            if stream is not None and stream.header_open:
                self._ignored_header_block = stream.header_block
            if (
                stream is not None
                and not stream.done
                and stream.error is None
                and self._failed is None
            ):
                try:
                    self._send(build_rst_stream_frame(stream_id, 8).serialize())
                except OSError:
                    pass
            self._condition.notify_all()

    def _dispatch_frame(self, frame):
        if frame.stream_id == 0:
            self._handle_connection_frame(frame)
            return
        if frame.type == FRAME_PRIORITY:
            if not self._handle_priority_frame(frame):
                stream = self._streams.get(frame.stream_id)
                if stream is not None:
                    stream.error = H2StreamError(
                        f"Invalid HTTP/2 PRIORITY on stream {frame.stream_id}"
                    )
            return
        stream = self._streams.get(frame.stream_id)
        if stream is None:
            if frame.type == FRAME_DATA:
                self._account_connection_data(frame.length)
            elif frame.type in (FRAME_HEADERS, FRAME_CONTINUATION):
                self._discard_header_fragment(frame)
            return
        if stream.done:
            if frame.type in (FRAME_DATA, FRAME_HEADERS, FRAME_CONTINUATION):
                error = ValueError("HTTP/2 response frame after END_STREAM")
                stream.error = H2StreamError(str(error))
                self._failed = error
                raise error
            return
        if frame.type == FRAME_WINDOW_UPDATE:
            stream.send_window += self._window_increment(frame)
            if stream.send_window > 0x7FFFFFFF:
                raise ValueError("HTTP/2 stream send window overflow")
        elif frame.type in (FRAME_HEADERS, FRAME_CONTINUATION):
            if frame.type == FRAME_HEADERS:
                if stream.header_open:
                    raise ValueError("HTTP/2 HEADERS before CONTINUATION")
                stream.header_open = True
                stream.header_end_stream = bool(frame.flags & FLAG_END_STREAM)
            elif not stream.header_open:
                raise ValueError("HTTP/2 CONTINUATION without HEADERS")
            stream.header_block += (
                header_block_fragment(frame)
                if frame.type == FRAME_HEADERS
                else frame.payload
            )
            if frame.flags & FLAG_END_HEADERS:
                decoded = self._decoder.decode_headers(stream.header_block)
                if stream.headers is None:
                    status = self._response_status(decoded)
                    if status < 200:
                        if stream.header_end_stream:
                            raise ValueError("HTTP/2 interim response ended stream")
                    else:
                        stream.headers = decoded
                elif not stream.header_end_stream or any(
                    name.startswith(":") for name, _ in decoded
                ):
                    raise ValueError("Invalid HTTP/2 response trailers")
                stream.header_block = b""
                stream.header_open = False
                if stream.header_end_stream:
                    stream.done = True
        elif frame.type == FRAME_DATA:
            if stream.header_open:
                raise ValueError("HTTP/2 DATA before complete response headers")
            if stream.headers is None:
                raise ValueError("HTTP/2 DATA before response headers")
            self._account_connection_data(frame.length)
            stream.receive_window -= frame.length
            if stream.receive_window < 0:
                raise ValueError("HTTP/2 stream receive window exceeded")
            stream.body.extend(data_payload(frame))
            target = self._local_settings[4]
            if (
                not frame.flags & FLAG_END_STREAM
                and stream.receive_window < target // 2
            ):
                increment = target - stream.receive_window
                self._send(
                    build_window_update_frame(frame.stream_id, increment).serialize()
                )
                stream.receive_window += increment
            if frame.flags & FLAG_END_STREAM:
                stream.done = True
        elif frame.type == FRAME_RST_STREAM:
            stream.error = H2StreamError(
                f"HTTP/2 stream {frame.stream_id} reset by peer"
            )

    def _handle_connection_frame(self, frame):
        if frame.type == FRAME_SETTINGS:
            if frame.flags & FLAG_ACK:
                if frame.length:
                    raise ValueError("Invalid HTTP/2 SETTINGS ACK")
                return
            if frame.length % 6:
                raise ValueError("Invalid HTTP/2 SETTINGS frame")
            settings = parse_settings_payload(frame.payload)
            if settings.get(SETTINGS_ENABLE_PUSH, 0) != 0:
                raise ValueError("Invalid server HTTP/2 ENABLE_PUSH setting")
            if 4 in settings and settings[4] > 0x7FFFFFFF:
                raise ValueError("Invalid HTTP/2 initial stream window")
            if 5 in settings and not 16384 <= settings[5] <= 16777215:
                raise ValueError("Invalid HTTP/2 maximum frame size")
            if 4 in settings:
                delta = settings[4] - self._peer_settings[4]
                for stream in self._streams.values():
                    stream.send_window += delta
                    if stream.send_window > 0x7FFFFFFF:
                        raise ValueError("HTTP/2 stream send window overflow")
            self._peer_settings.update(settings)
            self._peer_settings_received = True
            if 1 in settings:
                self._encoder.set_table_size(settings[1])
            if 3 in settings and self._pooled_connection is not None:
                self._pooled_connection.set_max_concurrent_streams(settings[3])
            self._send(build_settings_frame(ack=True).serialize())
        elif frame.type == FRAME_WINDOW_UPDATE:
            self._connection_send_window += self._window_increment(frame)
            if self._connection_send_window > 0x7FFFFFFF:
                raise ValueError("HTTP/2 connection send window overflow")
        elif frame.type == FRAME_PING and not frame.flags & FLAG_ACK:
            self._send(build_ping_frame(frame.payload, ack=True).serialize())
        elif frame.type == FRAME_GOAWAY:
            if frame.length < 8:
                raise ValueError("Invalid HTTP/2 GOAWAY frame")
            self._goaway_received = True
            self._goaway_last_stream_id = (
                int.from_bytes(frame.payload[:4], "big") & 0x7FFFFFFF
            )
            if self._pooled_connection is not None:
                self._pooled_connection.mark_goaway()
            for stream_id, stream in self._streams.items():
                if stream_id > self._goaway_last_stream_id:
                    stream.error = H2StreamError(
                        f"HTTP/2 stream {stream_id} rejected by GOAWAY"
                    )
