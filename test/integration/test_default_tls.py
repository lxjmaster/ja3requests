"""Breaking-release defaults through public entry points and real TLS peers."""

import socket
import ssl

import pytest

import ja3requests
import ja3requests.sessions as sessions_module
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls import TLS
from test.mock_servers.local import (
    LocalServer,
    read_headers,
    recv_with_ragged_eof,
    tls12_context,
    tls13_context,
)


def peer_context(version, certificate):
    if version == 13:
        return tls13_context(*certificate)
    return tls12_context(*certificate, cipher="ECDHE-RSA-AES128-GCM-SHA256")


@pytest.fixture
def isolated_default_pool(monkeypatch):
    pool = ConnectionPool()
    monkeypatch.setattr(sessions_module, "get_default_pool", lambda: pool)
    yield pool
    pool.close_all()


@pytest.mark.parametrize("version", [12, 13])
@pytest.mark.parametrize(
    "entry",
    [
        "Session",
        "session",
        "request",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
    ],
)
def test_default_entry_points_verify_real_tls(
    trusted_certificates, monkeypatch, isolated_default_pool, version, entry
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    observed = []

    def handler(conn):
        observed.append(
            (conn.version(), conn.selected_alpn_protocol(), read_headers(conn))
        )
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    with LocalServer(
        handler, peer_context(version, trusted_certificates.leaves["valid"])
    ) as server:
        url = f"https://127.0.0.1:{server.port}/"
        if entry in ("Session", "session"):
            with getattr(ja3requests, entry)() as session:
                assert session.tls_config.verify_cert is True
                response = session.get(url, timeout=3)
        elif entry == "request":
            response = ja3requests.request("GET", url, timeout=3)
        else:
            response = getattr(ja3requests, entry)(url, timeout=3)
        assert response.status_code == 200
    assert observed[0][:2] == (f"TLSv1.{version - 10}", "http/1.1")
    method = "GET" if entry in ("Session", "session", "request") else entry.upper()
    assert observed[0][2].startswith(method.encode() + b" / HTTP/1.1\r\n")


@pytest.mark.parametrize("version", [12, 13])
@pytest.mark.parametrize("variant", ["wrong-host", "expired", "bad-signature"])
@pytest.mark.parametrize("pooled", [False, True])
@pytest.mark.parametrize("alpn", ["http/1.1", "h2"])
def test_default_rejects_invalid_certificate_before_http(
    trusted_certificates, monkeypatch, version, variant, pooled, alpn
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    requests = []
    pool = ConnectionPool() if pooled else None
    config = TlsConfig()
    config.alpn_protocols = [alpn]
    context = peer_context(version, trusted_certificates.leaves[variant])
    context.set_alpn_protocols([alpn])
    with pytest.raises(ssl.SSLError):
        with LocalServer(
            lambda conn: requests.append(read_headers(conn)),
            context,
        ) as server:
            with Session(tls_config=config, pool=pool, use_pooling=pooled) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
    assert requests == []
    if pool:
        assert pool.get_stats()["total_connections"] == 0


@pytest.mark.parametrize("version", [12, 13])
def test_default_rejects_untrusted_private_ca(
    trusted_certificates, local_certificate, monkeypatch, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(local_certificate[0]))
    requests = []
    with pytest.raises(ssl.SSLError):
        with LocalServer(
            lambda conn: requests.append(read_headers(conn)),
            peer_context(version, trusted_certificates.leaves["valid"]),
        ) as server:
            with Session(use_pooling=False) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
    assert requests == []


def test_default_does_not_downgrade_to_rsa_only_peer(local_certificate):
    with pytest.raises(ssl.SSLError, match="NO_SHARED_CIPHER"):
        with LocalServer(
            lambda conn: pytest.fail("Unsupported legacy peer received HTTP"),
            tls12_context(*local_certificate),
        ) as server:
            with Session(use_pooling=False) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=3)


@pytest.mark.parametrize("version", [12, 13])
def test_verify_false_is_local_and_cannot_supply_next_verified_connection(
    trusted_certificates, monkeypatch, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    requests = []

    def handler(conn):
        requests.append(read_headers(conn))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        # The following verified request must discard this unverified socket.
        assert recv_with_ragged_eof(conn, 1) == b""

    with pytest.raises(ssl.SSLError):
        with LocalServer(
            handler,
            peer_context(version, trusted_certificates.leaves["wrong-host"]),
            connections=2,
        ) as server:
            with Session(pool=ConnectionPool()) as session:
                url = f"https://127.0.0.1:{server.port}/"
                assert session.get(url, verify=False, timeout=3).content == b"ok"
                assert session.tls_config.verify_cert is True
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(url, timeout=3)
    assert len(requests) == 1


def test_legacy_opt_in_reaches_rsa_only_self_signed_peer(local_certificate):
    observed = []

    def handler(conn):
        observed.append((conn.version(), conn.cipher()[0], read_headers(conn)))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, tls12_context(*local_certificate)) as server:
        with Session(tls_config=TlsConfig.legacy(), use_pooling=False) as session:
            assert (
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3).content
                == b"ok"
            )
    assert observed[0][:2] == ("TLSv1.2", "AES128-SHA")


@pytest.mark.parametrize("configure", [False, True, "preview"])
def test_direct_protocol_without_config_verifies_tls13(
    trusted_certificates, monkeypatch, configure
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    observed = []

    def handler(conn):
        observed.append(conn.version())

    with LocalServer(
        handler, tls13_context(*trusted_certificates.leaves["valid"])
    ) as server:
        with socket.create_connection(("127.0.0.1", server.port), timeout=3) as conn:
            tls = TLS(conn, server_host="127.0.0.1", server_port=server.port)
            if configure == "preview":
                assert tls.body is not None
            elif configure:
                tls.set_payload()
            assert tls.handshake() is True
            assert tls._cert_verified is True
            assert tls._is_tls13 is True
    assert observed == ["TLSv1.3"]
