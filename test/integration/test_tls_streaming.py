"""Authenticated streaming through project-owned TLS, with an independent peer."""

import socket
import ssl
import threading

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from test import test_network_streaming as wire
from test.mock_servers.local import (
    LocalServer,
    read_headers,
    serve_socks,
    tls12_context,
    tls13_context,
)


@pytest.fixture(params=[12, 13], ids=["tls12", "tls13"])
def streaming_tls_peer(request, trusted_certificates, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    config = TlsConfig.secure()
    config.alpn_protocols = ["http/1.1"]
    certificate = trusted_certificates.leaves["valid"]
    if request.param == 12:
        config.cipher_suites = [0x1301, 0xC02F]
        context = tls12_context(*certificate, cipher="ECDHE-RSA-AES128-GCM-SHA256")
    else:
        config.cipher_suites = [0x1301]
        context = tls13_context(*certificate)
    return config, context


def close_tls_body(conn):
    """Send authenticated close_notify for an EOF-delimited response."""
    try:
        raw = conn.unwrap()
    except ssl.SSLError as error:
        # The current client closes TCP after reading the peer close_notify.
        if "eof" not in str(error).lower():
            raise
    else:
        raw.close()


@pytest.mark.parametrize("framing", ["length", "chunked", "close"])
def test_tls_headers_and_body_prefix_precede_tail(streaming_tls_peer, framing):
    config, context = streaming_tls_peer
    gate = wire.framed_gate(
        framing, finish=close_tls_body if framing == "close" else None
    )
    with LocalServer(gate.serve, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            wire.assert_gated_delivery(
                session,
                "https://127.0.0.1:%d/stream" % server.port,
                gate,
                b"alphaomega",
            )


def test_tls_gzip_prefix_is_decoded_incrementally(streaming_tls_peer):
    config, context = streaming_tls_peer
    gate, expected = wire.compressed_gate("gzip")
    with LocalServer(gate.serve, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            wire.assert_gated_delivery(
                session, "https://127.0.0.1:%d/stream" % server.port, gate, expected
            )


def test_tls_complete_chunked_body_reuses_the_same_connection(streaming_tls_peer):
    config, context = streaming_tls_peer
    observed = []
    with LocalServer(
        lambda conn: wire.serve_reusable_response(conn, observed), context
    ) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            wire.assert_complete_then_reuse(
                session, "https://127.0.0.1:%d" % server.port
            )
    assert observed == [b"GET /first HTTP/1.1", b"GET /second HTTP/1.1"]


@pytest.mark.parametrize("consume_prefix", [False, True])
def test_tls_early_close_discards_unread_connection(streaming_tls_peer, consume_prefix):
    config, context = streaming_tls_peer
    peer = wire.EarlyClosePeer()
    with LocalServer(peer.serve, context, connections=2) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            wire.assert_close_then_reconnect(
                session, "https://127.0.0.1:%d" % server.port, consume_prefix
            )
    assert peer.requests == [b"GET /first HTTP/1.1", b"GET /second HTTP/1.1"]


def test_tls_truncated_body_fails_during_iteration(streaming_tls_peer):
    config, context = streaming_tls_peer

    def serve(conn):
        read_headers(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc")

    with LocalServer(serve, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.get(
                "https://127.0.0.1:%d/stream" % server.port, stream=True, timeout=3
            )
            try:
                with pytest.raises(ConnectionError):
                    list(response.iter_content(chunk_size=2))
            finally:
                response.close()


def test_tls_body_read_preserves_socket_timeout(streaming_tls_peer):
    config, context = streaming_tls_peer
    release = threading.Event()

    def serve(conn):
        read_headers(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc")
        assert release.wait(5), "Timed-out response was not closed"

    with LocalServer(serve, context) as server:
        try:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                response = session.get(
                    "https://127.0.0.1:%d/stream" % server.port,
                    stream=True,
                    timeout=(3, 0.2),
                )
                try:
                    chunks = response.iter_content(chunk_size=3)
                    wire.assert_prefix(chunks, b"abc")
                    with pytest.raises(socket.timeout):
                        next(chunks)
                finally:
                    response.close()
        finally:
            release.set()


def test_tls_connect_proxy_preserves_incremental_body_delivery(streaming_tls_peer):
    config, context = streaming_tls_peer
    gate = wire.framed_gate("length")
    tunnels = []

    def serve(conn):
        tunnels.append(read_headers(conn))
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        with context.wrap_socket(conn, server_side=True) as secure_conn:
            gate.serve(secure_conn)

    with LocalServer(serve) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            wire.assert_gated_delivery(
                session,
                "https://localhost/stream",
                gate,
                b"alphaomega",
                proxies={"https": "http://127.0.0.1:%d" % server.port},
            )
    assert tunnels[0].startswith(b"CONNECT localhost:443 HTTP/1.1\r\n")


def test_tls_socks_proxy_preserves_incremental_body_delivery(streaming_tls_peer):
    config, context = streaming_tls_peer
    # One representative authenticated TLS path for each SOCKS wire version.
    version = 4 if context.maximum_version == ssl.TLSVersion.TLSv1_2 else 5
    gate = wire.framed_gate("length")
    observed = {}

    def tunnel(conn):
        with context.wrap_socket(conn, server_side=True) as secure_conn:
            gate.serve(secure_conn)

    def serve(conn):
        serve_socks(conn, observed, version=version, tunnel_handler=tunnel)

    with LocalServer(serve) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            wire.assert_gated_delivery(
                session,
                "https://localhost/stream",
                gate,
                b"alphaomega",
                proxies={"https": "socks%d://127.0.0.1:%d" % (version, server.port)},
            )
    assert observed["host"] == b"localhost"
    assert observed["port"] == 443
