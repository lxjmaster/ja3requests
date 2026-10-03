"""A peer cannot push responses after the client disables HTTP/2 push."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    recv_with_ragged_eof,
    serve_h2_serial,
    tls13_context,
)


def test_push_promise_fails_concurrent_streams_and_reconnects(local_certificate):
    first_seen = threading.Event()
    observed = {"streams": [], "settings": None, "reconnected": {}}
    connection_count = 0

    def handler(conn):
        nonlocal connection_count
        connection_count += 1
        if connection_count == 2:
            serve_h2_serial(conn, observed["reconnected"], count=1)
            return

        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while len(observed["streams"]) < 2:
            header = read_exact(conn, 9)
            payload = read_exact(conn, int.from_bytes(header[:3], "big"))
            kind, flags = header[3:5]
            stream = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            if kind == 4 and not flags & 1:
                observed["settings"] = dict(
                    (
                        int.from_bytes(payload[i : i + 2], "big"),
                        int.from_bytes(payload[i + 2 : i + 6], "big"),
                    )
                    for i in range(0, len(payload), 6)
                )
                conn.sendall(h2_frame(4, 1, 0))
            elif kind == 1:
                observed["streams"].append(stream)
                first_seen.set()

        conn.sendall(h2_frame(5, 4, observed["streams"][0], b"\x00\x00\x00\x02\x82"))
        while recv_with_ragged_eof(conn, 4096):
            pass

    config = TlsConfig()
    config.tls_version = 0x0304
    config.cipher_suites = [0x1301]
    config.supported_groups = [29]
    config.signature_algorithms = [0x0804]
    config.alpn_protocols = ["h2", "http/1.1"]

    with LocalServer(
        handler, tls13_context(*local_certificate, alpn="h2"), connections=2
    ) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(session.get, url + "first", timeout=3)
                assert first_seen.wait(3)
                second = executor.submit(session.get, url + "second", timeout=3)
                for request in (first, second):
                    with pytest.raises(ConnectionError) as failure:
                        request.result(timeout=4)
                    cause = failure.value
                    while cause.__cause__ is not None:
                        cause = cause.__cause__
                    assert "PUSH_PROMISE" in str(cause)
            assert session.pool.get_stats()["total_connections"] == 0
            assert session.get(url + "next", timeout=3).content == b"ok"

    assert observed["settings"][2] == 0
    assert observed["streams"] == [1, 3]
    assert observed["reconnected"]["streams"] == [1]
