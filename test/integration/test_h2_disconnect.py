"""HTTP/2 EOF must fail instead of polling a closed transport forever."""

import socket

import pytest

from ja3requests.protocol.h2.connection import H2Connection
from test.mock_servers.local import LocalServer, h2_frame


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00\x00",  # Incomplete frame header.
        h2_frame(1, 4, 1, b"\x88"),  # Headers without END_STREAM.
        h2_frame(0, 1, 1, b"body")[:-1],  # Incomplete final DATA frame.
    ],
)
def test_h2_disconnect_before_end_stream(payload):
    with LocalServer(lambda conn: conn.sendall(payload)) as server:
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as conn:
            h2 = H2Connection(conn.sendall, conn.recv)
            with pytest.raises(ConnectionError, match="before END_STREAM"):
                h2.receive_response(1)


def test_h2_frames_split_across_reads():
    payload = h2_frame(1, 4, 1, b"\x88") + h2_frame(0, 1, 1, b"body")
    with LocalServer(lambda conn: conn.sendall(payload)) as server:
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as conn:
            h2 = H2Connection(conn.sendall, lambda size: conn.recv(min(size, 2)))
            headers, body = h2.receive_response(1)
    assert headers == [(":status", "200")]
    assert body == b"body"
