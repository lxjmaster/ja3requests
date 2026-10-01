"""Headers on a locally reset stream still update connection HPACK state."""

import threading

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from test.mock_servers.local import LocalServer, h2_frame, read_exact, tls13_context


def test_cancelled_stream_headers_preserve_hpack_table(local_certificate):
    first_timed_out = threading.Event()
    observed = {"streams": [], "reset": None}
    # The first block inserts x-token: value; 0xbe references dynamic index 62.
    first_block = b"\x88\x40\x07x-token\x05value"
    second_block = b"\x88\xbe"

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while not observed["streams"]:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            if header[3] == 4 and not header[4] & 1:
                conn.sendall(h2_frame(4, 1, 0))
            elif header[3] == 1:
                observed["streams"].append(int.from_bytes(header[5:9], "big"))

        assert first_timed_out.wait(3)
        first = observed["streams"][0]
        conn.sendall(
            h2_frame(1, 1, first, first_block[:2])
            + h2_frame(9, 4, first, first_block[2:])
        )

        while len(observed["streams"]) < 2:
            header = read_exact(conn, 9)
            length = int.from_bytes(header[:3], "big")
            payload = read_exact(conn, length)
            stream = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            if header[3] == 3:
                observed["reset"] = (stream, payload)
            elif header[3] == 1:
                observed["streams"].append(stream)
        conn.sendall(
            h2_frame(1, 4, observed["streams"][1], second_block)
            + h2_frame(0, 1, observed["streams"][1], b"ok")
        )

    config = TlsConfig()
    config.tls_version = 0x0304
    config.cipher_suites = [0x1301]
    config.supported_groups = [29]
    config.signature_algorithms = [0x0804]
    config.alpn_protocols = ["h2", "http/1.1"]

    with LocalServer(handler, tls13_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            with pytest.raises(ConnectionError, match="timed out"):
                session.get(url + "slow", timeout=0.2)
            first_timed_out.set()
            response = session.get(url + "next", timeout=3)
            assert response.content == b"ok"
            assert response.headers["x-token"] == "value"

    assert observed["streams"] == [1, 3]
    assert observed["reset"] == (1, b"\x00\x00\x00\x08")
