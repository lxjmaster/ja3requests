"""TLS 1.3 post-handshake client authentication against OpenSSL."""

import ssl

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls.extensions import PostHandshakeAuthExtension
from test.integration.test_local_tls13 import fragmented_reads  # noqa: F401
from test.mock_servers.local import LocalServer, read_headers, tls13_context


def pha_context(certificates, verify_mode):
    context = tls13_context(*certificates.leaves["valid"])
    context.load_verify_locations(cafile=str(certificates.ca_path))
    context.post_handshake_auth = True
    context.verify_mode = verify_mode
    context.num_tickets = 0
    return context


@pytest.mark.parametrize("client_variant", ["client-rsa", "client-ecdsa", None])
@pytest.mark.parametrize("cipher", [0x1301, 0x1302])
def test_post_handshake_authentication(
    trusted_certificates, monkeypatch, fragmented_reads, client_variant, cipher
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = pha_context(trusted_certificates, ssl.CERT_OPTIONAL)
    config = TlsConfig.secure()
    config.cipher_suites = [cipher]
    config.extensions.append(PostHandshakeAuthExtension())
    if client_variant:
        certificate, key = trusted_certificates.leaves[client_variant]
        config.client_cert = str(certificate)
        config.client_key = str(key)
    observed = []

    def handler(conn):
        observed.append((read_headers(conn), conn.getpeercert(binary_form=True)))
        conn.verify_client_post_handshake()
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        observed.append((read_headers(conn), conn.getpeercert(binary_form=True)))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            assert session.get(url, timeout=3).content == b"ok"
            assert session.get(url, timeout=3).content == b"ok"
    assert len(observed) == 2
    assert observed[0][1] is None
    assert bool(observed[1][1]) is bool(client_variant)


def test_post_handshake_auth_requires_client_extension(
    trusted_certificates, monkeypatch
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = pha_context(trusted_certificates, ssl.CERT_OPTIONAL)
    config = TlsConfig.secure()
    denied = []

    def handler(conn):
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        with pytest.raises(ssl.SSLError):
            conn.verify_client_post_handshake()
        denied.append(True)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, use_pooling=False) as session:
            assert (
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3).content
                == b"ok"
            )
    assert denied == [True]


def test_post_handshake_auth_rejects_mismatched_key(trusted_certificates, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = pha_context(trusted_certificates, ssl.CERT_OPTIONAL)
    config = TlsConfig.secure()
    config.extensions.append(PostHandshakeAuthExtension())
    config.client_cert = str(trusted_certificates.leaves["client-rsa"][0])
    config.client_key = str(trusted_certificates.leaves["client-ecdsa"][1])

    def handler(conn):
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.verify_client_post_handshake()
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        with pytest.raises((ssl.SSLError, EOFError, TimeoutError)):
            read_headers(conn)

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, use_pooling=False) as session:
            with pytest.raises(ConnectionError):
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
