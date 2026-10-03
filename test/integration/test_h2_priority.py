"""Legacy HTTP/2 priority fields should not corrupt response headers."""

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from test.mock_servers.local import LocalServer, h2_frame, read_exact, tls13_context


def test_priority_frames_and_headers_fields_keep_connection_usable(local_certificate):
    observed = {"streams": [], "reset": None}

    def read_frame(conn):
        header = read_exact(conn, 9)
        payload = read_exact(conn, int.from_bytes(header[:3], "big"))
        return header[3], header[4], int.from_bytes(header[5:9], "big"), payload

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while len(observed["streams"]) < 2:
            kind, flags, stream, _ = read_frame(conn)
            if kind == 4 and not flags & 1:
                conn.sendall(h2_frame(4, 1, 0))
            elif kind == 1:
                observed["streams"].append(stream)
                if len(observed["streams"]) == 1:
                    conn.sendall(h2_frame(2, 0, 9, b"\x00\x00\x00\x00\x0f"))
                    conn.sendall(
                        h2_frame(1, 0x28, stream, b"\x02\x00\x00\x00\x03\x0f\x00\x00")
                        + h2_frame(9, 4, stream, b"\x88")
                        + h2_frame(0, 1, stream, b"first")
                    )
                else:
                    conn.sendall(h2_frame(2, 0, 9, b"\x00" * 4))
                    while observed["reset"] is None:
                        reset_kind, _, reset_stream, payload = read_frame(conn)
                        if reset_kind == 3 and reset_stream == 9:
                            observed["reset"] = payload
                    conn.sendall(
                        h2_frame(1, 4, stream, b"\x88")
                        + h2_frame(0, 1, stream, b"second")
                    )

    config = TlsConfig.legacy()
    config.tls_version = 0x0304
    config.cipher_suites = [0x1301]
    config.supported_groups = [29]
    config.signature_algorithms = [0x0804]
    config.alpn_protocols = ["h2", "http/1.1"]

    with LocalServer(handler, tls13_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            assert session.get(url + "first", timeout=3).content == b"first"
            assert session.get(url + "second", timeout=3).content == b"second"

    assert observed["streams"] == [1, 3]
    assert observed["reset"] == b"\x00\x00\x00\x06"
