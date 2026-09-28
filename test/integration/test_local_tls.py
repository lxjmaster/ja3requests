"""Exercise real TLS encryption and ALPN routing against Python/OpenSSL."""

import ssl

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from test.mock_servers.local import LocalServer, read_headers, serve_h2, tls12_context


def test_tls12_http_and_pool_reuse(local_certificate):
    requests = []

    def handler(conn):
        assert conn.version() == "TLSv1.2"
        assert conn.selected_alpn_protocol() == "http/1.1"
        for _ in range(2):
            requests.append(read_headers(conn))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")

    config = TlsConfig()
    config.alpn_protocols = ["http/1.1"]
    with LocalServer(handler, tls12_context(*local_certificate)) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            for path in ("/first", "/second"):
                response = session.get(
                    f"https://127.0.0.1:{server.port}{path}", timeout=2
                )
                assert response.status_code == 200
                assert response.content == b"hello"
    # Both requests were received on the same accepted TLS connection.
    assert requests[0].startswith(b"GET /first HTTP/1.1\r\n")
    assert requests[1].startswith(b"GET /second HTTP/1.1\r\n")


def test_tls12_alpn_h2_fingerprint(local_certificate):
    observed = {}
    config = TlsConfig()
    config.alpn_protocols = ["h2", "http/1.1"]
    config.h2_settings = {1: 12345, 4: 1048576}
    config.h2_window_update = 65536
    context = tls12_context(*local_certificate, alpn="h2")
    with LocalServer(lambda conn: serve_h2(conn, observed), context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert response.status_code == 200
            assert response.content == b"hello h2"
    assert observed["settings"][1] == 12345
    assert observed["settings"][4] == 1048576
    assert observed["window"] == 65536
    assert observed["stream"] == 1


def test_tls12_h2_sequential_requests_use_separate_connections(local_certificate):
    observed = []

    def handler(conn):
        exchange = {}
        serve_h2(conn, exchange)
        observed.append(exchange)

    config = TlsConfig()
    config.alpn_protocols = ["h2", "http/1.1"]
    context = tls12_context(*local_certificate, alpn="h2")
    with LocalServer(handler, context, connections=2) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            for path in ("/first", "/second"):
                response = session.get(
                    f"https://127.0.0.1:{server.port}{path}", timeout=2
                )
                assert response.content == b"hello h2"
    assert len(observed) == 2


def test_tls12_no_shared_cipher_fails(local_certificate):
    context = tls12_context(*local_certificate, cipher="ECDHE-RSA-AES128-GCM-SHA256")
    # The client offers only RSA AES128-SHA, so OpenSSL must reject it.
    server = LocalServer(
        lambda conn: pytest.fail("Handshake unexpectedly succeeded"), context
    )
    with pytest.raises(ssl.SSLError, match="NO_SHARED_CIPHER"):
        with server:
            with Session(pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=1)
