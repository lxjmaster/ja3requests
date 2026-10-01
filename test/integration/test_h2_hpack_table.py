"""Exercise HPACK table updates over a local TLS HTTP/2 connection."""

import struct

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from test.mock_servers.local import LocalServer, h2_frame, read_exact, tls12_context


def _read_request_headers(conn):
    while True:
        header = read_exact(conn, 9)
        payload = read_exact(conn, int.from_bytes(header[:3], "big"))
        if header[3] == 1:
            return int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
        if header[3] == 4 and not header[4] & 1:
            settings = dict(struct.iter_unpack("!HI", payload))
            assert settings[1] == 64
            conn.sendall(h2_frame(4, 1, 0))


def _h2_config():
    config = TlsConfig.legacy()
    config.alpn_protocols = ["h2", "http/1.1"]
    config.h2_settings = {1: 64}
    return config


def test_hpack_shrink_and_reinsert_across_responses(local_certificate):
    observed = []
    first = b"\x88\x40\x07x-token\x05value"
    second = b"\x20\x3f\x21\x88\x40\x06x-next\x05fresh"
    third = b"\x88\xbe"

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        for block in (first, second, third):
            stream = _read_request_headers(conn)
            observed.append(stream)
            conn.sendall(h2_frame(1, 5, stream, block))

    with LocalServer(handler, tls12_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=_h2_config(), pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            responses = [session.get(url + path, timeout=3) for path in ("a", "b", "c")]

    assert observed == [1, 3, 5]
    assert responses[0].headers["x-token"] == "value"
    assert responses[1].headers["x-next"] == "fresh"
    assert responses[2].headers["x-next"] == "fresh"
    assert "x-token" not in responses[2].headers


def test_hpack_update_above_advertised_limit_fails_connection(local_certificate):
    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        stream = _read_request_headers(conn)
        # 0x3f 0x22 is a table size update to 65, above our SETTINGS value 64.
        conn.sendall(h2_frame(1, 5, stream, b"\x3f\x22\x88"))

    with LocalServer(handler, tls12_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=_h2_config(), pool=ConnectionPool()) as session:
            with pytest.raises(ConnectionError) as failure:
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
            cause = failure.value
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assert "advertised limit" in str(cause)
            assert session.pool.get_stats()["total_connections"] == 0


@pytest.mark.parametrize(
    ("block", "error"),
    [
        (b"\x3f", "Truncated HPACK"),
        (b"\x40\x05ab", "Truncated HPACK"),
        (b"\x00\x01x\x81\xff", "Invalid HPACK Huffman"),
    ],
)
def test_malformed_hpack_response_fails_connection(local_certificate, block, error):
    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        stream = _read_request_headers(conn)
        conn.sendall(h2_frame(1, 5, stream, block))

    with LocalServer(handler, tls12_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=_h2_config(), pool=ConnectionPool()) as session:
            with pytest.raises(ConnectionError) as failure:
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
            cause = failure.value
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assert error in str(cause)
            assert session.pool.get_stats()["total_connections"] == 0
