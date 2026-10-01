"""HTTP/2 padding is flow-controlled but excluded from response bodies."""

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from test.mock_servers.local import LocalServer, h2_frame, read_exact, tls13_context


def h2_config():
    config = TlsConfig()
    config.tls_version = 0x0304
    config.cipher_suites = [0x1301]
    config.supported_groups = [29]
    config.signature_algorithms = [0x0804]
    config.alpn_protocols = ["h2", "http/1.1"]
    return config


def read_request_stream(conn):
    assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    conn.sendall(h2_frame(4, 0, 0))
    while True:
        header = read_exact(conn, 9)
        read_exact(conn, int.from_bytes(header[:3], "big"))
        if header[3] == 4 and not header[4] & 1:
            conn.sendall(h2_frame(4, 1, 0))
        elif header[3] == 1:
            return int.from_bytes(header[5:9], "big") & 0x7FFFFFFF


@pytest.mark.parametrize("pooled", [False, True])
def test_padded_response_body_over_tls(local_certificate, pooled):
    def handler(conn):
        stream = read_request_stream(conn)
        conn.sendall(
            h2_frame(1, 4, stream, b"\x88")
            + h2_frame(0, 8, stream, b"\x02first\x00\x00")
            + h2_frame(0, 9, stream, b"\x00second")
        )

    with LocalServer(handler, tls13_context(*local_certificate, alpn="h2")) as server:
        with Session(
            tls_config=h2_config(),
            use_pooling=pooled,
            pool=ConnectionPool() if pooled else None,
        ) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
            assert response.content == b"firstsecond"


def test_invalid_data_padding_discards_connection(local_certificate):
    connections = 0

    def handler(conn):
        nonlocal connections
        connections += 1
        stream = read_request_stream(conn)
        response = h2_frame(1, 4, stream, b"\x88")
        if connections == 1:
            response += h2_frame(0, 9, stream, b"\x02x")
        else:
            response += h2_frame(0, 1, stream, b"ok")
        conn.sendall(response)

    with LocalServer(
        handler, tls13_context(*local_certificate, alpn="h2"), connections=2
    ) as server:
        with Session(tls_config=h2_config(), pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            with pytest.raises(ConnectionError) as failure:
                session.get(url + "bad", timeout=3)
            cause = failure.value
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assert "Invalid HTTP/2 DATA padding" in str(cause)
            assert session.pool.get_stats()["total_connections"] == 0
            assert session.get(url + "good", timeout=3).content == b"ok"

    assert connections == 2
