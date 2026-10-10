"""
ja3requests.protocol.h2.connection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

HTTP/2 connection management.
Handles connection preface, settings exchange, and request/response flow.
"""

from ja3requests.protocol.h2.frame import (
    H2Frame,
    CONNECTION_PREFACE,
    FRAME_SETTINGS,
    FRAME_HEADERS,
    FRAME_DATA,
    FRAME_WINDOW_UPDATE,
    FRAME_GOAWAY,
    FRAME_PING,
    FRAME_RST_STREAM,
    FRAME_PUSH_PROMISE,
    FRAME_CONTINUATION,
    FRAME_PRIORITY,
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    FLAG_ACK,
    FLAG_PADDED,
    build_settings_frame,
    build_window_update_frame,
    build_headers_frame,
    build_data_frame,
    build_ping_frame,
    build_rst_stream_frame,
    build_priority_frame,
    normalize_settings,
    validate_initial_window,
    normalize_pseudo_header_order,
    normalize_priority_frames,
    data_payload,
    header_block_fragment,
    parse_settings_pairs,
    DEFAULT_SETTINGS,
    SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_ENABLE_PUSH,
    SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_MAX_HEADER_LIST_SIZE,
)
from ja3requests.protocol.h2.hpack import (
    HeaderLimitError,
    HPACKEncoder,
    HPACKDecoder,
    validate_header_fields,
)
from ja3requests.protocol.tls.debug import debug


class H2GoAwayError(ConnectionError):
    """A non-graceful connection error, retaining the peer's GOAWAY metadata."""

    def __init__(self, error_code, last_stream_id):
        self.error_code = error_code
        self.last_stream_id = last_stream_id
        super().__init__(
            f"HTTP/2 GOAWAY error {error_code}; last stream {last_stream_id}"
        )


class H2Connection:
    """
    HTTP/2 connection handler.

    Manages the connection lifecycle:
    1. Send connection preface + SETTINGS
    2. Exchange SETTINGS ACK
    3. Send HEADERS + DATA frames for requests
    4. Receive and assemble response HEADERS + DATA
    """

    def __init__(
        self,
        send_func,
        recv_func,
        settings=None,
        pseudo_header_order=None,
        priority_frames=None,
    ):
        """
        :param send_func: Callable to send bytes (e.g., tls.encrypt + socket.send)
        :param recv_func: Callable to receive bytes
        :param settings: Exact ordered SETTINGS mapping or pairs; None uses defaults
        """
        self._send = send_func
        self._recv = recv_func
        self._encoder = HPACKEncoder()
        self._next_stream_id = 1  # Client streams are odd-numbered
        self._wire_settings = normalize_settings(settings)
        self._pseudo_header_order = normalize_pseudo_header_order(pseudo_header_order)
        self._priority_frames = normalize_priority_frames(priority_frames)
        self._local_settings = dict(DEFAULT_SETTINGS)
        self._local_settings.update(self._wire_settings)
        # Decoded headers need a local budget even when ID 6 is not advertised.
        # Keep the previous 16 KiB budget as that fallback; explicit ID 6,
        # including zero, overrides it without adding fields to wire SETTINGS.
        header_limit = self._local_settings[SETTINGS_MAX_HEADER_LIST_SIZE]
        self._decoder = HPACKDecoder(
            self._local_settings[SETTINGS_HEADER_TABLE_SIZE], header_limit
        )
        # A local allocation bound, not an additional wire SETTINGS value.
        # Huffman representation can use almost four bytes per decoded octet;
        # retain room for that representation and bounded table-size updates.
        self._header_block_limit = max(65536, 4 * header_limit)
        self._header_block_bytes = 0
        self._failed = None
        self._peer_settings = dict(DEFAULT_SETTINGS)
        self._preface_sent = False
        self._server_preface_received = False
        self._peer_settings_received = False
        self._recv_buffer = b""
        self._continuation_stream = None
        self._ignored_header_block = b""
        self._pending_frames = []
        self._goaway_received = False
        self._goaway_last_stream_id = None
        self._goaway_error_code = None
        self._connection_receive_target = 65535
        self._connection_receive_window = 65535
        self._connection_send_window = 65535
        self._active_send_stream = None
        self._stream_send_window = 0
        self._active_receive_stream = None
        self._stream_receive_window = 0

    def set_transport(self, send_func, recv_func):
        """Bind the current owner, or clear callbacks while pooled and idle."""
        self._send = send_func
        self._recv = recv_func

    def initiate(self, window_update_increment=None):
        """
        Send HTTP/2 connection preface and initial SETTINGS.

        :param window_update_increment: Optional initial WINDOW_UPDATE value
            for H2 fingerprint customization.
        """
        validate_initial_window(window_update_increment)
        if self._preface_sent:
            raise RuntimeError("HTTP/2 connection is already initiated")
        # Send connection preface magic
        self._send(CONNECTION_PREFACE)

        # Send SETTINGS frame
        settings_frame = build_settings_frame(self._wire_settings)
        self._send(settings_frame.serialize())
        self._preface_sent = True
        debug(f"H2: Sent SETTINGS: {self._wire_settings}")

        # Send WINDOW_UPDATE if specified (for H2 fingerprinting)
        if window_update_increment:
            wu_frame = build_window_update_frame(0, window_update_increment)
            self._send(wu_frame.serialize())
            self._connection_receive_target += window_update_increment
            self._connection_receive_window += window_update_increment
            debug(f"H2: Sent WINDOW_UPDATE increment={window_update_increment}")

        for priority in self._priority_frames:
            self._send(build_priority_frame(*priority).serialize())

    def _prepare_request_headers(self, method, authority, path, headers, scheme):
        """Prepare all sender paths before stream or HPACK state changes."""
        pseudo = {
            ":method": method,
            ":authority": authority,
            ":scheme": scheme,
            ":path": path,
        }
        fields = []
        for name, value in headers or ():
            try:
                name = name.decode('utf-8') if isinstance(name, bytes) else name
            except UnicodeError as error:
                raise ValueError(
                    "HTTP/2 header fields must contain valid UTF-8"
                ) from error
            fields.append(
                (name.lower(), value if isinstance(value, (str, bytes)) else str(value))
            )
        excluded = {
            "host",
            "connection",
            "transfer-encoding",
            "upgrade",
            "keep-alive",
            "proxy-connection",
        }
        for name, value in fields:
            if name == "connection":
                tokens = value.decode("ascii") if isinstance(value, bytes) else value
                excluded.update(token.strip().lower() for token in tokens.split(","))
        result = [(name, pseudo[name]) for name in self._pseudo_header_order]
        for name, value in fields:
            if name in excluded:
                continue
            if name.startswith(":"):
                raise ValueError("HTTP/2 regular headers cannot contain pseudo-headers")
            if name == "te":
                text = value.decode("ascii") if isinstance(value, bytes) else value
                if text.strip().lower() != "trailers":
                    raise ValueError("HTTP/2 TE only supports trailers")
            result.append((name, value))
        validate_header_fields(result)
        return result

    def send_request(
        self, method, authority, path, headers=None, body=None, scheme="https"
    ):
        """
        Send an HTTP/2 request.

        :param method: HTTP method
        :param authority: Host header value
        :param path: Request path
        :param headers: Additional headers as list of (name, value) tuples
        :param body: Request body bytes
        :param scheme: URL scheme
        :return: Stream ID used for this request
        """
        if body is not None and not isinstance(body, bytes):
            raise TypeError("HTTP/2 request body must be bytes")
        h2_headers = self._prepare_request_headers(
            method, authority, path, headers, scheme
        )
        if self._failed is not None:
            raise self._failed
        if self._goaway_received:
            raise ConnectionError("HTTP/2 connection received GOAWAY")
        if body and self._preface_sent and not self._peer_settings_received:
            self._await_peer_settings()
        stream_id = self._next_stream_id
        self._next_stream_id += 2
        self._active_receive_stream = stream_id
        self._stream_receive_window = self._local_settings[4]

        # Encode headers with HPACK
        header_block = self._encoder.encode_headers(h2_headers)

        # Send the complete header block before any DATA frames.
        end_stream = body is None or len(body) == 0
        for frame in self._header_frames(
            stream_id, header_block, end_stream=end_stream
        ):
            self._send(frame.serialize())
        debug(f"H2: Sent HEADERS on stream {stream_id}")

        # Send DATA frame if body present
        if body:
            self._active_send_stream = stream_id
            self._stream_send_window = self._peer_settings[4]
            try:
                self._send_body(stream_id, body)
            finally:
                self._active_send_stream = None
            debug(f"H2: Sent DATA on stream {stream_id}: {len(body)} bytes")

        return stream_id

    def _header_frames(self, stream_id, block, end_stream):
        """Split an encoded block; callers serialize the entire frame sequence."""
        frame_size = self._peer_settings[SETTINGS_MAX_FRAME_SIZE]
        for offset in range(0, max(1, len(block)), frame_size):
            fragment = block[offset : offset + frame_size]
            last = offset + frame_size >= len(block)
            if offset == 0:
                yield build_headers_frame(
                    stream_id,
                    fragment,
                    end_stream=end_stream,
                    end_headers=last,
                )
            else:
                yield H2Frame(
                    FRAME_CONTINUATION,
                    FLAG_END_HEADERS if last else 0,
                    stream_id,
                    fragment,
                )

    def _await_peer_settings(self):
        """Apply the server's initial stream window before sending request DATA."""
        while not self._peer_settings_received:
            for frame in self._read_frames():
                if frame.stream_id != 0:
                    raise ValueError("HTTP/2 stream frame before peer SETTINGS")
                self._handle_connection_frame(frame)
                if self._goaway_received:
                    raise ConnectionError("HTTP/2 connection received GOAWAY")

    def _send_body(self, stream_id, body):
        """Send DATA within both peer flow-control windows."""
        offset = 0
        while offset < len(body):
            size = min(
                len(body) - offset,
                self._peer_settings[5],
                self._connection_send_window,
                self._stream_send_window,
            )
            if size <= 0:
                self._wait_for_send_window(stream_id)
                continue
            end = offset + size
            frame = build_data_frame(
                stream_id, body[offset:end], end_stream=end == len(body)
            )
            self._send(frame.serialize())
            self._connection_send_window -= size
            self._stream_send_window -= size
            offset = end

    @staticmethod
    def _window_increment(frame):
        if frame.length != 4:
            raise ValueError("Invalid HTTP/2 WINDOW_UPDATE frame")
        increment = int.from_bytes(frame.payload, "big") & 0x7FFFFFFF
        if increment == 0:
            raise ValueError("Invalid HTTP/2 WINDOW_UPDATE increment")
        return increment

    @staticmethod
    def _response_status(headers):
        statuses = [value for name, value in headers if name == ":status"]
        if len(statuses) != 1:
            raise ValueError("Invalid HTTP/2 response :status")
        value = statuses[0]
        if len(value) != 3 or any(char not in "0123456789" for char in value):
            raise ValueError("Invalid HTTP/2 response :status")
        status = int(value)
        if status < 100 or status > 599 or status == 101:
            raise ValueError("Invalid HTTP/2 response :status")
        return status

    @classmethod
    def _validate_response_headers(cls, headers, trailers=False):
        """Validate a fully decoded block before exposing any HTTP fields."""
        regular_seen = False
        for name, value in headers:
            pseudo = name.startswith(":")
            token = name[1:] if pseudo else name
            if not token or any(
                char not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz"
                for char in token
            ):
                raise ValueError("Invalid HTTP/2 response field name")
            if any(char in value for char in "\x00\r\n") or (
                value and (value[0] in " \t" or value[-1] in " \t")
            ):
                raise ValueError("Invalid HTTP/2 response field value")
            if pseudo:
                if trailers or regular_seen or name != ":status":
                    raise ValueError("Invalid HTTP/2 response pseudo-header :status")
            else:
                regular_seen = True
                if name in (
                    "connection",
                    "proxy-connection",
                    "keep-alive",
                    "transfer-encoding",
                    "upgrade",
                    "te",
                ):
                    raise ValueError(
                        "Invalid HTTP/2 connection-specific response field"
                    )
        return None if trailers else cls._response_status(headers)

    def _wait_for_send_window(self, stream_id):
        """Process control frames while retaining an early response."""
        for frame in self._read_frames():
            if frame.type == FRAME_PRIORITY:
                if (
                    not self._handle_priority_frame(frame)
                    and frame.stream_id == stream_id
                ):
                    raise ConnectionError(
                        f"Invalid HTTP/2 PRIORITY on stream {stream_id}"
                    )
                continue
            if frame.stream_id == 0:
                self._handle_connection_frame(frame)
                if self._goaway_received and stream_id > self._goaway_last_stream_id:
                    raise ConnectionError("HTTP/2 stream rejected by GOAWAY")
            elif frame.stream_id == stream_id and frame.type == FRAME_WINDOW_UPDATE:
                self._stream_send_window += self._window_increment(frame)
                if self._stream_send_window > 0x7FFFFFFF:
                    raise ValueError("HTTP/2 stream send window overflow")
            elif frame.stream_id == stream_id and frame.type == FRAME_RST_STREAM:
                raise ConnectionError(f"HTTP/2 stream {stream_id} reset by peer")
            else:
                flow_accounted = (
                    frame.stream_id == stream_id and frame.type == FRAME_DATA
                )
                if flow_accounted:
                    self._account_response_data(frame)
                self._pending_frames.append((frame, flow_accounted))
                if frame.stream_id == stream_id and frame.flags & FLAG_END_STREAM:
                    raise ConnectionError("HTTP/2 response ended before request body")

    def receive_response(self, stream_id):
        """
        Receive and assemble an HTTP/2 response for the given stream.

        :param stream_id: Stream ID to receive response for
        :return: (headers_list, body_bytes)
        """
        if self._failed is not None:
            raise self._failed
        response_headers = None
        response_body = b""
        header_block = b""
        header_open = False
        header_end_stream = False
        end_stream = False
        if self._active_receive_stream != stream_id:
            self._active_receive_stream = stream_id
            self._stream_receive_window = self._local_settings[4]

        while not end_stream:
            if self._pending_frames:
                frames, self._pending_frames = self._pending_frames, []
            else:
                frames = [(frame, False) for frame in self._read_frames()]
            for index, (frame, flow_accounted) in enumerate(frames):
                if end_stream and frame.stream_id == stream_id:
                    if frame.type in (FRAME_DATA, FRAME_HEADERS, FRAME_CONTINUATION):
                        raise ValueError("HTTP/2 response frame after END_STREAM")
                    if frame.type in (FRAME_WINDOW_UPDATE, FRAME_RST_STREAM):
                        continue
                if frame.type == FRAME_PRIORITY:
                    if (
                        not self._handle_priority_frame(frame)
                        and frame.stream_id == stream_id
                    ):
                        raise ConnectionError(
                            f"Invalid HTTP/2 PRIORITY on stream {stream_id}"
                        )
                    continue
                if frame.stream_id == 0:
                    # Connection-level frame
                    self._handle_connection_frame(frame)
                    if (
                        self._goaway_received
                        and stream_id > self._goaway_last_stream_id
                    ):
                        raise ConnectionError("HTTP/2 stream rejected by GOAWAY")
                    continue

                if frame.stream_id != stream_id:
                    if frame.type == FRAME_DATA:
                        self._account_connection_data(frame.length)
                    elif frame.type in (FRAME_HEADERS, FRAME_CONTINUATION):
                        self._discard_header_fragment(frame)
                    continue

                if frame.type in (FRAME_HEADERS, FRAME_CONTINUATION):
                    if frame.type == FRAME_HEADERS:
                        header_block = header_block_fragment(frame)
                        header_open = True
                        header_end_stream = bool(frame.flags & FLAG_END_STREAM)
                    elif not header_open:
                        raise ValueError("HTTP/2 CONTINUATION without HEADERS")
                    else:
                        header_block += frame.payload
                    if frame.flags & FLAG_END_HEADERS:
                        decoded = self._decode_headers(header_block)
                        try:
                            status = self._validate_response_headers(
                                decoded, trailers=response_headers is not None
                            )
                            if response_headers is None:
                                if status < 200:
                                    if header_end_stream:
                                        raise ValueError(
                                            "HTTP/2 interim response ended stream"
                                        )
                                else:
                                    response_headers = decoded
                            elif not header_end_stream:
                                raise ValueError("Invalid HTTP/2 response trailers")
                        except ValueError:
                            self._active_receive_stream = None
                            self._pending_frames[0:0] = frames[index + 1 :]
                            self._send(build_rst_stream_frame(stream_id, 1).serialize())
                            raise
                        header_block = b""
                        header_open = False
                        if header_end_stream:
                            end_stream = True

                elif frame.type == FRAME_DATA:
                    if header_open:
                        raise ValueError("HTTP/2 DATA before complete response headers")
                    if response_headers is None:
                        raise ValueError("HTTP/2 DATA before response headers")
                    if not flow_accounted:
                        self._account_response_data(frame)
                    response_body += data_payload(frame)
                    if frame.flags & FLAG_END_STREAM:
                        end_stream = True

                elif frame.type == FRAME_RST_STREAM:
                    raise ConnectionError(f"HTTP/2 stream {stream_id} reset by peer")

        self._active_receive_stream = None
        return response_headers, response_body

    def _account_response_data(self, frame):
        """Release receive credit when DATA is read, even during an upload."""
        self._account_connection_data(frame.length)
        self._stream_receive_window -= frame.length
        if self._stream_receive_window < 0:
            raise ValueError("HTTP/2 stream receive window exceeded")
        target = self._local_settings[4]
        if (
            not frame.flags & FLAG_END_STREAM
            and self._stream_receive_window < target // 2
        ):
            increment = target - self._stream_receive_window
            self._send(
                build_window_update_frame(frame.stream_id, increment).serialize()
            )
            self._stream_receive_window += increment

    def _account_connection_data(self, length):
        """Replenish the connection window as response DATA is consumed."""
        self._connection_receive_window -= length
        if self._connection_receive_window < 0:
            raise ValueError("HTTP/2 connection receive window exceeded")
        if self._connection_receive_window < self._connection_receive_target // 2:
            increment = (
                self._connection_receive_target - self._connection_receive_window
            )
            self._send(build_window_update_frame(0, increment).serialize())
            self._connection_receive_window += increment

    def _read_frames(self):
        """Read and parse frames from the connection."""
        return self._feed_frames(self._recv(65535))

    def _feed_frames(self, data):
        """Validate a byte block with the same state for sync and async I/O."""
        if self._failed is not None:
            raise self._failed
        if data:
            self._recv_buffer += data

        frames, self._recv_buffer = H2Frame.parse_all(
            self._recv_buffer,
            max_payload_size=self._local_settings[SETTINGS_MAX_FRAME_SIZE],
        )
        if self._preface_sent and not self._server_preface_received and frames:
            first = frames[0]
            if (
                first.type != FRAME_SETTINGS
                or first.flags & FLAG_ACK
                or first.stream_id != 0
            ):
                raise ValueError(
                    "Invalid HTTP/2 server preface: initial SETTINGS required"
                )
            self._server_preface_received = True
        if any(frame.type == FRAME_PUSH_PROMISE for frame in frames):
            raise ConnectionError("HTTP/2 PUSH_PROMISE received while push is disabled")
        for frame in frames:
            if frame.stream_id == 0 and frame.type in (
                FRAME_DATA,
                FRAME_HEADERS,
                FRAME_PRIORITY,
                FRAME_RST_STREAM,
                FRAME_CONTINUATION,
            ):
                raise ValueError(f"HTTP/2 {frame.type_name} requires a stream")
            if frame.stream_id != 0 and frame.type in (
                FRAME_SETTINGS,
                FRAME_PING,
                FRAME_GOAWAY,
            ):
                raise ValueError(f"HTTP/2 {frame.type_name} requires stream 0")
            if frame.type == FRAME_RST_STREAM and frame.length != 4:
                raise ValueError("Invalid HTTP/2 RST_STREAM length")
            if frame.type == FRAME_PING and frame.length != 8:
                raise ValueError("Invalid HTTP/2 PING length")
            if frame.type == FRAME_SETTINGS and frame.flags & FLAG_ACK and frame.length:
                raise ValueError("Invalid HTTP/2 SETTINGS ACK")
            if self._continuation_stream is not None:
                if (
                    frame.type != FRAME_CONTINUATION
                    or frame.stream_id != self._continuation_stream
                ):
                    raise ValueError("HTTP/2 field block interrupted")
            elif frame.type == FRAME_CONTINUATION:
                raise ValueError("HTTP/2 CONTINUATION without HEADERS")
            if frame.type in (FRAME_HEADERS, FRAME_CONTINUATION):
                fragment = (
                    header_block_fragment(frame)
                    if frame.type == FRAME_HEADERS
                    else frame.payload
                )
                size = (
                    0 if frame.type == FRAME_HEADERS else self._header_block_bytes
                ) + len(fragment)
                if size > self._header_block_limit:
                    self._header_limit_failed(
                        HeaderLimitError(
                            "HTTP/2 compressed header block limit exceeded"
                        )
                    )
                self._header_block_bytes = 0 if frame.flags & FLAG_END_HEADERS else size
            if frame.type == FRAME_HEADERS and not frame.flags & FLAG_END_HEADERS:
                self._continuation_stream = frame.stream_id
            elif frame.type == FRAME_CONTINUATION and frame.flags & FLAG_END_HEADERS:
                self._continuation_stream = None
            if frame.type == FRAME_DATA and frame.flags & FLAG_PADDED:
                data_payload(frame)
            if (
                self._preface_sent
                and frame.type
                in (FRAME_DATA, FRAME_HEADERS, FRAME_RST_STREAM, FRAME_WINDOW_UPDATE)
                and frame.stream_id != 0
                and (
                    frame.stream_id % 2 == 0 or frame.stream_id >= self._next_stream_id
                )
            ):
                raise ValueError(f"HTTP/2 frame on idle stream {frame.stream_id}")
        if not data and not frames:
            raise ConnectionError("HTTP/2 connection closed before END_STREAM")
        return frames

    def _handle_priority_frame(self, frame):
        """Ignore valid legacy priorities; reset a stream on a size error."""
        if frame.length == 5:
            return True
        self._send(build_rst_stream_frame(frame.stream_id, 6).serialize())
        return False

    def _discard_header_fragment(self, frame):
        """Keep HPACK state in sync while discarding a closed stream's headers."""
        if frame.type == FRAME_HEADERS:
            self._ignored_header_block = header_block_fragment(frame)
        else:
            self._ignored_header_block += frame.payload
        if frame.flags & FLAG_END_HEADERS:
            self._decode_headers(self._ignored_header_block)
            self._ignored_header_block = b""

    def _clear_header_buffers(self):
        self._header_block_bytes = 0
        self._ignored_header_block = b""
        self._recv_buffer = b""
        self._pending_frames.clear()

    def _header_limit_failed(self, error):
        self._failed = error
        self._clear_header_buffers()
        raise error

    def _decode_headers(self, block):
        try:
            return self._decoder.decode_headers(block)
        except HeaderLimitError as error:
            self._header_limit_failed(error)

    def _receive_goaway(self, frame):
        if frame.length < 8:
            raise ValueError("Invalid HTTP/2 GOAWAY frame")
        self._goaway_received = True
        self._goaway_last_stream_id = (
            int.from_bytes(frame.payload[:4], "big") & 0x7FFFFFFF
        )
        self._goaway_error_code = int.from_bytes(frame.payload[4:8], "big")
        if self._goaway_error_code:
            error = H2GoAwayError(self._goaway_error_code, self._goaway_last_stream_id)
            self._failed = error
            self._clear_header_buffers()
            raise error

    def _update_send_windows(self, delta):
        if self._active_send_stream is not None:
            self._stream_send_window += delta
            if self._stream_send_window > 0x7FFFFFFF:
                raise ValueError("HTTP/2 stream send window overflow")

    def _apply_peer_settings(self, payload):
        """Apply each entry, so intermediate limits and table eviction matter."""
        try:
            for key, value in parse_settings_pairs(payload):
                if key == SETTINGS_ENABLE_PUSH and value != 0:
                    raise ValueError("Invalid server HTTP/2 ENABLE_PUSH setting")
                if key == 4:
                    if value > 0x7FFFFFFF:
                        raise ValueError("Invalid HTTP/2 initial stream window")
                    self._update_send_windows(value - self._peer_settings[4])
                if key == 5 and not 16384 <= value <= 16777215:
                    raise ValueError("Invalid HTTP/2 maximum frame size")
                if key == SETTINGS_HEADER_TABLE_SIZE:
                    self._encoder.set_table_size(value)
                self._peer_settings[key] = value
        except ValueError as error:
            self._failed = error
            self._clear_header_buffers()
            raise
        self._peer_settings_received = True

    def _handle_connection_frame(self, frame):
        """Handle connection-level (stream 0) frames."""
        if frame.type == FRAME_SETTINGS:
            if frame.flags & FLAG_ACK:
                debug("H2: Received SETTINGS ACK")
            else:
                self._apply_peer_settings(frame.payload)
                debug(f"H2: Received peer SETTINGS: {self._peer_settings}")
                # Send SETTINGS ACK
                ack = build_settings_frame(ack=True)
                self._send(ack.serialize())

        elif frame.type == FRAME_PING:
            if not (frame.flags & FLAG_ACK):
                # Respond to PING with ACK
                pong = build_ping_frame(frame.payload, ack=True)
                self._send(pong.serialize())

        elif frame.type == FRAME_GOAWAY:
            self._receive_goaway(frame)
            debug(f"H2: Received GOAWAY: {frame.payload.hex()}")

        elif frame.type == FRAME_WINDOW_UPDATE:
            self._connection_send_window += self._window_increment(frame)
            if self._connection_send_window > 0x7FFFFFFF:
                raise ValueError("HTTP/2 connection send window overflow")
            debug(f"H2: Received WINDOW_UPDATE: stream={frame.stream_id}")

    def close(self):
        """Send GOAWAY and close connection."""
        from ja3requests.protocol.h2.frame import build_goaway_frame

        goaway = build_goaway_frame(0)
        try:
            self._send(goaway.serialize())
        except OSError:
            pass
