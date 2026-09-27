"""Finished verification gates real TLS 1.2 HTTP requests and pool insertion."""

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.extensions import (
    ExtendedMasterSecretExtension,
    SessionTicketExtension,
)
from test.integration.test_certificate_verification import config_and_context
from test.integration.test_local_tls13 import fragmented_reads
from test.mock_servers.local import LocalServer, read_headers, tls12_context


@pytest.mark.parametrize(
    "variant,cipher,suite",
    [
        ("valid", "ECDHE-RSA-AES256-GCM-SHA384", 0xC030),
        ("valid-ecdsa", "ECDHE-ECDSA-AES256-GCM-SHA384", 0xC02C),
    ],
)
@pytest.mark.parametrize("use_ems", [False, True])
def test_tls12_sha384_interop(
    trusted_certificates, monkeypatch, fragmented_reads, variant, cipher, suite, use_ems
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    config = TlsConfig.secure()
    config.tls_version = 0x0303
    config.cipher_suites = [suite]
    if not use_ems:
        config.extensions = []
    context = tls12_context(*trusted_certificates.leaves[variant], cipher=cipher)

    def handler(conn):
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert response.content == b"ok"


def test_secure_profile_sha384_fallback(trusted_certificates, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(
        *trusted_certificates.leaves["valid"],
        cipher="ECDHE-RSA-AES256-GCM-SHA384",
    )

    def handler(conn):
        assert conn.version() == "TLSv1.2"
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=TlsConfig.secure(), pool=ConnectionPool()) as session:
            assert (
                session.get(f"https://127.0.0.1:{server.port}/", timeout=2).content
                == b"ok"
            )


def test_sha384_bad_finished_never_sends_http(trusted_certificates, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(
        *trusted_certificates.leaves["valid"],
        cipher="ECDHE-RSA-AES256-GCM-SHA384",
    )
    original = TLS._verify_server_finished
    checked = []
    requests = []

    def corrupt(handshake, message, transcript):
        checked.append(True)
        return original(handshake, message[:-1] + bytes([message[-1] ^ 1]), transcript)

    def handler(conn):
        try:
            requests.append(read_headers(conn))
        except EOFError:
            pass

    monkeypatch.setattr(TLS, "_verify_server_finished", corrupt)
    with LocalServer(handler, context) as server:
        with Session(tls_config=TlsConfig.secure(), pool=ConnectionPool()) as session:
            with pytest.raises(ConnectionError, match="TLS handshake failed"):
                session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert session.pool.get_stats()["total_connections"] == 0
    assert checked == [True]
    assert requests == []


def test_tls12_rsa_extended_master_secret(trusted_certificates, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    config, context = config_and_context(12, trusted_certificates.leaves["valid"])
    config.extensions.append(ExtendedMasterSecretExtension())
    config.verify_cert = True

    def handler(conn):
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            assert (
                session.get(f"https://127.0.0.1:{server.port}/", timeout=2).content
                == b"ok"
            )


@pytest.mark.parametrize("version", [12, "12-ecdhe"])
def test_tls12_finished_with_tickets_and_fragmented_reads(
    trusted_certificates, monkeypatch, fragmented_reads, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    config, context = config_and_context(version, trusted_certificates.leaves["valid"])
    config.extensions.append(SessionTicketExtension())
    requests = []

    def handler(conn):
        for _ in range(2):
            requests.append(read_headers(conn))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            for _ in range(2):
                assert (
                    session.get(
                        f"https://127.0.0.1:{server.port}/", verify=True, timeout=2
                    ).content
                    == b"ok"
                )
    assert len(requests) == 2


@pytest.mark.parametrize("version", [12, "12-ecdhe"])
def test_bad_finished_never_sends_http_or_enters_pool(
    trusted_certificates, monkeypatch, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    original = TLS._verify_server_finished
    checked = []

    def corrupt(handshake, message, transcript):
        checked.append(True)
        return original(handshake, message[:-1] + bytes([message[-1] ^ 1]), transcript)

    monkeypatch.setattr(TLS, "_verify_server_finished", corrupt)
    config, context = config_and_context(version, trusted_certificates.leaves["valid"])
    requests = []

    def handler(conn):
        try:
            requests.append(read_headers(conn))
        except EOFError:
            pass

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            with pytest.raises(ConnectionError, match="TLS handshake failed"):
                session.get(f"https://127.0.0.1:{server.port}/", verify=True, timeout=2)
            assert session.pool.get_stats()["total_connections"] == 0
    assert checked == [True]
    assert requests == []
