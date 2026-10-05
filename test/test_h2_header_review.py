"""Request header fragmentation against bounded peers and concurrent writers."""

from concurrent.futures import ThreadPoolExecutor
import socket
import struct
import threading

import pytest

from ja3requests.protocol.h2.connection import H2Connection
from ja3requests.protocol.h2.frame import (
    FLAG_ACK,
    FLAG_END_HEADERS,
    FRAME_CONTINUATION,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_PING,
    FRAME_RST_STREAM,
    H2Frame,
    SETTINGS_INITIAL_WINDOW_SIZE,
    build_window_update_frame,
)
from ja3requests.protocol.h2.hpack import HPACKDecoder
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    recv_with_ragged_eof,
)
from test.test_h2_streaming import connected


def read_frame(conn):
    """Read frame fields independently of the client's parser."""
    header = read_exact(conn, 9)
    size = int.from_bytes(header[:3], "big")
    kind, flags, stream = struct.unpack("!BBI", header[3:])
    return kind, flags, stream, read_exact(conn, size)


@pytest.mark.parametrize("connection_type", [H2Connection, H2MultiplexConnection])
@pytest.mark.parametrize("frame_size", [16384, 32768])
@pytest.mark.parametrize("body", [None, b"upload"])
def test_large_request_headers_interoperate_with_frame_limited_peer(
    connection_type, frame_size, body
):
    observed = []
    decoded = []
    rejected = []
    value = "x" * 60000
    method = "POST" if body else "GET"

    def peer(sock):
        assert read_exact(sock, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        sock.sendall(h2_frame(4, 0, 0, struct.pack("!HIHI", 5, frame_size, 6, 131072)))
        decoder = HPACKDecoder()
        for _ in range(2):
            while True:
                frame = read_frame(sock)
                kind, flags, stream, fragment = frame
                if kind == 1:
                    break
                assert kind == 4
                if not flags & 1:
                    sock.sendall(h2_frame(4, 1, 0))
            frames = []
            ended = bool(flags & 1)
            while True:
                if len(fragment) > frame_size:
                    rejected.append(len(fragment))
                    sock.sendall(h2_frame(7, 0, 0, struct.pack("!II", 0, 6)))
                    return
                frames.append(frame)
                if flags & 4:
                    break
                frame = read_frame(sock)
                kind, flags, current_stream, fragment = frame
                assert (kind, current_stream) == (9, stream)
                assert not flags & 1
            observed.append(frames)
            decoded.append(decoder.decode_headers(b"".join(part[3] for part in frames)))
            received_body = b""
            while not ended:
                kind, flags, current_stream, fragment = read_frame(sock)
                # Legacy may acknowledge peer SETTINGS between header and body.
                if kind == 4:
                    assert flags == 1 and current_stream == 0 and not fragment
                    continue
                assert (kind, current_stream) == (0, stream)
                assert len(fragment) <= frame_size
                received_body += fragment
                ended = bool(flags & 1)
            expected_body = (body or b"") if stream == 1 else b""
            assert received_body == expected_body
            sock.sendall(h2_frame(1, 5, stream, b"\x88"))
        while recv_with_ragged_eof(sock, 4096):
            pass

    with LocalServer(peer) as server:
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=2)
        conn = connection_type(sock.sendall, sock.recv)
        try:
            conn.initiate()
            if connection_type is H2Connection:
                conn._await_peer_settings()
            first = conn.send_request(
                method,
                "example.test",
                "/",
                headers=[("x-large", value), ("x-token", "reusable")],
                body=body,
            )
            assert conn.receive_response(first) == ([(':status', '200')], b"")
            second = conn.send_request(
                "GET", "example.test", "/", headers=[("x-token", "reusable")]
            )
            assert conn.receive_response(second) == ([(':status', '200')], b"")
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                # A rejecting peer can close before client cleanup begins.
                pass
            sock.close()
            if isinstance(conn, H2MultiplexConnection) and conn._reader is not None:
                conn._reader.join(2)
                assert not conn._reader.is_alive()
    assert not rejected
    assert [len(frame[3]) for frame in observed[0][:-1]] == [frame_size] * (
        len(observed[0]) - 1
    )
    assert len(observed[0]) > 1
    assert observed[0][0][1] == (0 if body else 1)
    assert all(frame[1] == 0 for frame in observed[0][1:-1])
    assert observed[0][-1][1] == 4
    assert decoded[0] == [
        (":method", method),
        (":authority", "example.test"),
        (":scheme", "https"),
        (":path", "/"),
        ("x-large", value),
        ("x-token", "reusable"),
    ]
    assert decoded[1] == [(":method", "GET"), *decoded[0][1:4], ("x-token", "reusable")]
    assert b"reusable" not in observed[1][0][3]


@pytest.mark.parametrize("connection_type", [H2Connection, H2MultiplexConnection])
def test_small_request_headers_keep_original_wire_bytes(connection_type):
    sent = []
    conn = connection_type(sent.append, lambda _size: b"")
    conn._peer_settings_received = True
    assert (
        conn.send_request("GET", "example.test", "/", headers=[("x-small", "v")]) == 1
    )
    block = b"\x82\x41\x0cexample.test\x87\x84\x40\x07x-small\x01v"
    assert sent == [h2_frame(1, 5, 1, block)]


def test_multiplex_header_block_excludes_other_writes_and_cancel():
    started = threading.Event()
    resume = threading.Event()
    with connected(peer_settings={SETTINGS_INITIAL_WINDOW_SIZE: 0}) as (conn, wire):
        with ThreadPoolExecutor(max_workers=4) as executor:
            upload = executor.submit(
                conn.send_request,
                "POST",
                "example.test",
                "/",
                body=b"upload",
                timeout=2,
            )
            with wire.condition:
                assert wire.condition.wait_for(
                    lambda: any(frame.type == FRAME_HEADERS for frame in wire.sent),
                    timeout=2,
                )

            def block_first_header(raw):
                wire.send(raw)
                frame, _ = H2Frame.parse(raw)
                if frame.type == FRAME_HEADERS and frame.stream_id == 3:
                    started.set()
                    assert resume.wait(2)

            conn._transport_send = block_first_header
            large = executor.submit(
                conn.send_request,
                "GET",
                "example.test",
                "/",
                headers=[("x-large", "x" * 60000)],
                timeout=2,
            )
            try:
                assert started.wait(2)
                later = executor.submit(conn.send_request, "GET", "example.test", "/")
                cancel = executor.submit(conn.cancel_stream, 3)
                wire.feed(
                    H2Frame(FRAME_PING, 0, 0, b"busyread"),
                    build_window_update_frame(1, 6),
                )
            finally:
                resume.set()
            assert large.result(2) == 3
            assert later.result(2) == 5
            assert cancel.result(2) is None
            assert upload.result(2) == 1
            wire.flush()
            frames = wire.sent
            first = next(
                i
                for i, frame in enumerate(frames)
                if frame.type == FRAME_HEADERS and frame.stream_id == 3
            )
            last = next(
                i
                for i, frame in enumerate(frames[first:], first)
                if frame.flags & FLAG_END_HEADERS
            )
            assert last > first
            assert all(
                frame.type == FRAME_CONTINUATION and frame.stream_id == 3
                for frame in frames[first + 1 : last + 1]
            )
            following = frames[last + 1 :]
            for kind, stream in [
                (FRAME_DATA, 1),
                (FRAME_HEADERS, 5),
                (FRAME_RST_STREAM, 3),
            ]:
                assert any(
                    frame.type == kind and frame.stream_id == stream
                    for frame in following
                )
            assert any(
                frame.type == FRAME_PING
                and frame.flags == FLAG_ACK
                and frame.payload == b"busyread"
                for frame in following
            )
