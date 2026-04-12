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
    FLAG_END_STREAM,
    FLAG_END_HEADERS,
    FLAG_ACK,
    build_settings_frame,
    build_window_update_frame,
    build_headers_frame,
    build_data_frame,
    build_ping_frame,
    parse_settings_payload,
    DEFAULT_SETTINGS,
)
from ja3requests.protocol.h2.hpack import HPACKEncoder, HPACKDecoder
from ja3requests.protocol.tls.debug import debug


class H2Connection:
    """
    HTTP/2 connection handler.

    Manages the connection lifecycle:
    1. Send connection preface + SETTINGS
    2. Exchange SETTINGS ACK
    3. Send HEADERS + DATA frames for requests
    4. Receive and assemble response HEADERS + DATA
    """

    def __init__(self, send_func, recv_func, settings=None):
        """
        :param send_func: Callable to send bytes (e.g., tls.encrypt + socket.send)
        :param recv_func: Callable to receive bytes
        :param settings: Custom SETTINGS dict for H2 fingerprinting
        """
        self._send = send_func
        self._recv = recv_func
        self._encoder = HPACKEncoder()
        self._decoder = HPACKDecoder()
        self._next_stream_id = 1  # Client streams are odd-numbered
        self._local_settings = dict(DEFAULT_SETTINGS)
        if settings:
            self._local_settings.update(settings)
        self._peer_settings = dict(DEFAULT_SETTINGS)
        self._recv_buffer = b""

    def initiate(self, window_update_increment=None):
        """
        Send HTTP/2 connection preface and initial SETTINGS.

        :param window_update_increment: Optional initial WINDOW_UPDATE value
            for H2 fingerprint customization.
        """
        # Send connection preface magic
        self._send(CONNECTION_PREFACE)

        # Send SETTINGS frame
        settings_frame = build_settings_frame(self._local_settings)
        self._send(settings_frame.serialize())
        debug(f"H2: Sent SETTINGS: {self._local_settings}")

        # Send WINDOW_UPDATE if specified (for H2 fingerprinting)
        if window_update_increment:
            wu_frame = build_window_update_frame(0, window_update_increment)
            self._send(wu_frame.serialize())
            debug(f"H2: Sent WINDOW_UPDATE increment={window_update_increment}")

    def send_request(self, method, authority, path, headers=None, body=None, scheme="https"):
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
        stream_id = self._next_stream_id
        self._next_stream_id += 2

        # Build pseudo-headers + regular headers
        h2_headers = [
            (":method", method),
            (":authority", authority),
            (":scheme", scheme),
            (":path", path),
        ]
        if headers:
            for name, value in headers:
                lower_name = name.lower()
                # Skip connection-specific headers
                if lower_name in ("host", "connection", "transfer-encoding", "upgrade"):
                    continue
                h2_headers.append((lower_name, value))

        # Encode headers with HPACK
        header_block = self._encoder.encode_headers(h2_headers)

        # Send HEADERS frame
        end_stream = body is None or len(body) == 0
        headers_frame = build_headers_frame(stream_id, header_block, end_stream=end_stream)
        self._send(headers_frame.serialize())
        debug(f"H2: Sent HEADERS on stream {stream_id}")

        # Send DATA frame if body present
        if body:
            data_frame = build_data_frame(stream_id, body, end_stream=True)
            self._send(data_frame.serialize())
            debug(f"H2: Sent DATA on stream {stream_id}: {len(body)} bytes")

        return stream_id

    def receive_response(self, stream_id):
        """
        Receive and assemble an HTTP/2 response for the given stream.

        :param stream_id: Stream ID to receive response for
        :return: (headers_list, body_bytes)
        """
        response_headers = []
        response_body = b""
        header_block = b""
        headers_complete = False
        end_stream = False

        while not end_stream:
            frames = self._read_frames()
            for frame in frames:
                if frame.stream_id == 0:
                    # Connection-level frame
                    self._handle_connection_frame(frame)
                    continue

                if frame.stream_id != stream_id:
                    continue

                if frame.type == FRAME_HEADERS:
                    header_block += frame.payload
                    if frame.flags & FLAG_END_HEADERS:
                        response_headers = self._decoder.decode_headers(header_block)
                        headers_complete = True
                    if frame.flags & FLAG_END_STREAM:
                        end_stream = True

                elif frame.type == FRAME_DATA:
                    response_body += frame.payload
                    if frame.flags & FLAG_END_STREAM:
                        end_stream = True

                elif frame.type == FRAME_RST_STREAM:
                    debug(f"H2: RST_STREAM on stream {stream_id}")
                    end_stream = True

        return response_headers, response_body

    def _read_frames(self):
        """Read and parse frames from the connection."""
        data = self._recv(65535)
        if data:
            self._recv_buffer += data

        frames, self._recv_buffer = H2Frame.parse_all(self._recv_buffer)
        return frames

    def _handle_connection_frame(self, frame):
        """Handle connection-level (stream 0) frames."""
        if frame.type == FRAME_SETTINGS:
            if frame.flags & FLAG_ACK:
                debug("H2: Received SETTINGS ACK")
            else:
                # Parse and store peer settings
                self._peer_settings.update(parse_settings_payload(frame.payload))
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
            debug(f"H2: Received GOAWAY: {frame.payload.hex()}")

        elif frame.type == FRAME_WINDOW_UPDATE:
            debug(f"H2: Received WINDOW_UPDATE: stream={frame.stream_id}")

    def close(self):
        """Send GOAWAY and close connection."""
        from ja3requests.protocol.h2.frame import build_goaway_frame
        goaway = build_goaway_frame(0)
        try:
            self._send(goaway.serialize())
        except OSError:
            pass
