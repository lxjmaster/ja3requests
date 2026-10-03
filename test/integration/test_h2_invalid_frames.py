"""Invalid HTTP/2 frame envelopes fail the pooled TLS connection."""

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    recv_with_ragged_eof,
    tls12_context,
)


def test_headers_on_stream_zero_discard_connection(local_certificate):
    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while True:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            if header[3] == 1:
                conn.sendall(h2_frame(1, 4, 0, b"\x88"))
                return

    config = TlsConfig()
    config.alpn_protocols = ["h2", "http/1.1"]
    with LocalServer(handler, tls12_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            with pytest.raises(ConnectionError) as failure:
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
            cause = failure.value
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assert "HEADERS requires a stream" in str(cause)
            assert session.pool.get_stats()["total_connections"] == 0


def test_oversized_header_declaration_discard_connection(local_certificate):
    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while True:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            if header[3] == 1:
                conn.sendall(h2_frame(1, 4, 1, b"x" * 16385)[:9])
                return

    config = TlsConfig()
    config.alpn_protocols = ["h2", "http/1.1"]
    with LocalServer(handler, tls12_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            with pytest.raises(ConnectionError) as failure:
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
            cause = failure.value
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assert "maximum frame size" in str(cause)
            assert session.pool.get_stats()["total_connections"] == 0


def test_data_before_response_headers_discards_connection(local_certificate):
    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while True:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            if header[3] == 1:
                stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
                conn.sendall(h2_frame(0, 1, stream_id, b"unexpected"))
                return

    config = TlsConfig()
    config.alpn_protocols = ["h2", "http/1.1"]
    with LocalServer(handler, tls12_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            with pytest.raises(ConnectionError) as failure:
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
            cause = failure.value
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assert "before response headers" in str(cause)
            assert session.pool.get_stats()["total_connections"] == 0


@pytest.mark.parametrize("pooled", [False, True])
def test_missing_response_status_fails_over_tls(local_certificate, pooled):
    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while True:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            if header[3] == 1:
                stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
                conn.sendall(h2_frame(1, 5, stream_id))
                return

    config = TlsConfig()
    config.alpn_protocols = ["h2", "http/1.1"]
    pool = ConnectionPool() if pooled else None
    with LocalServer(handler, tls12_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, use_pooling=pooled, pool=pool) as session:
            with pytest.raises(ConnectionError) as failure:
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
            cause = failure.value
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assert ":status" in str(cause)
            if pooled:
                assert pool.get_stats()["total_connections"] == 0


@pytest.mark.parametrize("pooled", [False, True])
def test_data_after_end_stream_fails_over_tls(local_certificate, pooled):
    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while True:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            if header[3] == 1:
                stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
                conn.sendall(
                    h2_frame(1, 5, stream_id, b"\x88")
                    + h2_frame(0, 0, stream_id, b"late")
                )
                return

    config = TlsConfig()
    config.alpn_protocols = ["h2", "http/1.1"]
    pool = ConnectionPool() if pooled else None
    with LocalServer(handler, tls12_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, use_pooling=pooled, pool=pool) as session:
            with pytest.raises(ConnectionError) as failure:
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
            cause = failure.value
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assert "after END_STREAM" in str(cause)
            if pooled:
                assert pool.get_stats()["total_connections"] == 0


@pytest.mark.parametrize("pooled", [False, True])
def test_response_before_initial_settings_fails_over_tls(local_certificate, pooled):
    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 1, 0) + h2_frame(4, 0, 0))
        try:
            while True:
                header = read_exact(conn, 9)
                read_exact(conn, int.from_bytes(header[:3], "big"))
                if header[3] == 1:
                    stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
                    conn.sendall(h2_frame(1, 5, stream_id, b"\x88"))
                    while recv_with_ragged_eof(conn, 4096):
                        pass
                    return
        except (EOFError, ConnectionResetError):
            return

    config = TlsConfig()
    config.alpn_protocols = ["h2", "http/1.1"]
    pool = ConnectionPool() if pooled else None
    with LocalServer(handler, tls12_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, use_pooling=pooled, pool=pool) as session:
            with pytest.raises(ConnectionError) as failure:
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
            cause = failure.value
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assert "server preface" in str(cause)
            if pooled:
                assert pool.get_stats()["total_connections"] == 0


@pytest.mark.parametrize("pooled", [False, True])
@pytest.mark.parametrize(
    "frame_type,flags,payload,offset",
    [
        (0, 0, b"unexpected", 2),  # Future client stream.
        (1, 4, b"\x88", 1),  # Unpromised server stream.
    ],
)
def test_frame_on_idle_stream_fails_over_tls(
    local_certificate, pooled, frame_type, flags, payload, offset
):
    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while True:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            if header[3] == 1:
                stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
                conn.sendall(h2_frame(frame_type, flags, stream_id + offset, payload))
                return

    config = TlsConfig()
    config.alpn_protocols = ["h2", "http/1.1"]
    pool = ConnectionPool() if pooled else None
    with LocalServer(handler, tls12_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, use_pooling=pooled, pool=pool) as session:
            with pytest.raises(ConnectionError) as failure:
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
            cause = failure.value
            while cause.__cause__ is not None:
                cause = cause.__cause__
            assert "idle stream" in str(cause)
            if pooled:
                assert pool.get_stats()["total_connections"] == 0
