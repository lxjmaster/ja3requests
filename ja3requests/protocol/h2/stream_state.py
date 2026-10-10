"""Byte-driven HTTP/2 stream state shared by synchronous and async drivers."""

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
    build_ping_frame,
    build_rst_stream_frame,
    build_settings_frame,
    build_window_update_frame,
    data_payload,
    header_block_fragment,
)


class H2StreamError(ConnectionError):
    """A single stream failed while the underlying connection may remain usable."""


class H2ResponseHeaderError(H2StreamError):
    """A decoded HTTP field block is malformed; HPACK state remains usable."""


class _Stream:
    def __init__(self, send_window, receive_window):
        self.send_window = send_window
        self.receive_window = receive_window
        self.headers = None
        self.header_block = b""
        self.header_open = False
        self.header_end_stream = False
        self.body = bytearray()
        # The peer's END_STREAM closes only the response direction. Uploads
        # may still need stream credit until our END_STREAM or a peer reset.
        self.done = False
        self.send_done = False
        self.error = None


class H2StreamState(H2Connection):
    """Apply frames and flow control without owning threads or network waits."""

    def __init__(
        self,
        send_func,
        recv_func=None,
        settings=None,
        pseudo_header_order=None,
        priority_frames=None,
    ):
        super().__init__(
            send_func,
            recv_func,
            settings=settings,
            pseudo_header_order=pseudo_header_order,
            priority_frames=priority_frames,
        )
        self._streams = {}
        self._failed = None
        self._pooled_connection = None
        self._buffered_bytes = 0

    @property
    def receive_buffer_limit(self):
        """DATA queue budget, without changing the advertised fingerprint.

        Reserve the announced connection window in addition to one full stream
        window, so one paused consumer cannot exhaust all connection credit.
        Several paused consumers may apply connection-wide backpressure.
        """
        return self._connection_receive_target + self._local_settings[4]

    def _response_stream(self, stream_id):
        stream = self._streams.get(stream_id)
        if stream is None:
            raise H2StreamError(f"HTTP/2 stream {stream_id} is closed")
        return stream

    def _check_response_error(self, stream):
        if stream.error:
            raise stream.error
        # A transport EOF after END_STREAM does not invalidate a complete body.
        if self._failed is not None and not stream.done:
            raise ConnectionError("HTTP/2 connection failed") from self._failed

    def _replenish_stream_window(self, stream_id, stream):
        if stream.done or stream.error:
            return
        target = self._local_settings[4]
        # Only application consumption or discarded padding creates credit.
        increment = target - stream.receive_window - len(stream.body)
        if increment > 0 and stream.receive_window <= target // 2:
            self._send(build_window_update_frame(stream_id, increment).serialize())
            stream.receive_window += increment

    def _account_connection_data(self, length):
        self._connection_receive_window -= length
        if self._connection_receive_window < 0:
            raise ValueError("HTTP/2 connection receive window exceeded")
        self._replenish_connection_window()

    def _replenish_connection_window(self):
        if self._failed is not None:
            return
        target = self._connection_receive_target
        # Outstanding receive credit and queued DATA share the same budget.
        available = (
            self.receive_buffer_limit
            - self._buffered_bytes
            - self._connection_receive_window
        )
        increment = min(target - self._connection_receive_window, available)
        if increment > 0 and self._connection_receive_window <= target // 2:
            self._send(build_window_update_frame(0, increment).serialize())
            self._connection_receive_window += increment

    def _discard_body(self, stream):
        self._buffered_bytes -= len(stream.body)
        stream.body.clear()
        if self._failed is None:
            self._replenish_connection_window()

    def _clear_header_buffers(self):
        super()._clear_header_buffers()
        for stream in tuple(self._streams.values()):
            stream.header_block = b""
            stream.header_open = False

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
                    self._discard_body(stream)
            return
        stream = self._streams.get(frame.stream_id)
        if stream is None or stream.error is not None:
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
            if frame.type == FRAME_RST_STREAM:
                # A server can finish its response and reset an unfinished
                # upload, notably with NO_ERROR. Preserve the complete response.
                stream.send_done = True
                return
            if frame.type != FRAME_WINDOW_UPDATE or stream.send_done:
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
                decoded = self._decode_headers(stream.header_block)
                stream.header_block = b""
                stream.header_open = False
                try:
                    status = self._validate_response_headers(
                        decoded, trailers=stream.headers is not None
                    )
                    if stream.headers is None:
                        if status < 200:
                            if stream.header_end_stream:
                                raise ValueError("HTTP/2 interim response ended stream")
                        else:
                            stream.headers = decoded
                    elif not stream.header_end_stream:
                        raise ValueError("Invalid HTTP/2 response trailers")
                except ValueError as error:
                    stream.error = H2ResponseHeaderError(str(error))
                    stream.error.__cause__ = error
                    self._discard_body(stream)
                    self._send(build_rst_stream_frame(frame.stream_id, 1).serialize())
                    return
                if stream.header_end_stream:
                    stream.done = True
        elif frame.type == FRAME_DATA:
            if stream.header_open:
                raise ValueError("HTTP/2 DATA before complete response headers")
            if stream.headers is None:
                raise ValueError("HTTP/2 DATA before response headers")
            if frame.length > self._connection_receive_window:
                raise ValueError("HTTP/2 connection receive window exceeded")
            stream.receive_window -= frame.length
            if stream.receive_window < 0:
                raise ValueError("HTTP/2 stream receive window exceeded")
            payload = data_payload(frame)
            stream.body.extend(payload)
            self._buffered_bytes += len(payload)
            if self._buffered_bytes > self.receive_buffer_limit:
                raise ValueError("HTTP/2 connection DATA buffer exceeded")
            if frame.flags & FLAG_END_STREAM:
                stream.done = True
            self._account_connection_data(frame.length)
            self._replenish_stream_window(frame.stream_id, stream)
        elif frame.type == FRAME_RST_STREAM:
            stream.error = H2StreamError(
                f"HTTP/2 stream {frame.stream_id} reset by peer"
            )
            self._discard_body(stream)

    def _update_send_windows(self, delta):
        for stream in self._streams.values():
            stream.send_window += delta
            if stream.send_window > 0x7FFFFFFF:
                raise ValueError("HTTP/2 stream send window overflow")

    def _handle_connection_frame(self, frame):
        if frame.type == FRAME_SETTINGS:
            if frame.flags & FLAG_ACK:
                if frame.length:
                    raise ValueError("Invalid HTTP/2 SETTINGS ACK")
                return
            self._apply_peer_settings(frame.payload)
            if self._pooled_connection is not None:
                self._pooled_connection.set_max_concurrent_streams(
                    self._peer_settings[3]
                )
            self._send(build_settings_frame(ack=True).serialize())
        elif frame.type == FRAME_WINDOW_UPDATE:
            self._connection_send_window += self._window_increment(frame)
            if self._connection_send_window > 0x7FFFFFFF:
                raise ValueError("HTTP/2 connection send window overflow")
        elif frame.type == FRAME_PING and not frame.flags & FLAG_ACK:
            self._send(build_ping_frame(frame.payload, ack=True).serialize())
        elif frame.type == FRAME_GOAWAY:
            self._receive_goaway(frame)
            if self._pooled_connection is not None:
                self._pooled_connection.mark_goaway()
            for stream_id, stream in self._streams.items():
                if stream_id > self._goaway_last_stream_id:
                    stream.error = H2StreamError(
                        f"HTTP/2 stream {stream_id} rejected by GOAWAY"
                    )
                    self._discard_body(stream)
