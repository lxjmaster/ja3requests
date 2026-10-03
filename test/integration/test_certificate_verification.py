"""Verify actual trust, identity and validity against independent local peers."""

import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls.certificate_verify import CertificateVerifier
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.tls13 import TLS13Handshake
from test.integration.test_local_tls13 import fragmented_reads, tls13_config
from test.mock_servers.local import (
    LocalServer,
    read_headers,
    tls12_context,
    tls13_context,
)
from test.mock_servers.local import serve_socks


def certificate_message(path):
    cert = x509.load_pem_x509_certificate(path.read_bytes())
    der = cert.public_bytes(serialization.Encoding.DER)
    entry = len(der).to_bytes(3, "big") + der
    return len(entry).to_bytes(3, "big") + entry


def config_and_context(version, certificate):
    if version == 13:
        return tls13_config(), tls13_context(*certificate)
    config = TlsConfig.legacy()
    if version == "12-ecdhe":
        config.cipher_suites = [0xC02F]
        config.supported_groups = [23]
        config.signature_algorithms = [0x0804, 0x0401]
        return config, tls12_context(*certificate, cipher="ECDHE-RSA-AES128-GCM-SHA256")
    return config, tls12_context(*certificate)


@pytest.mark.parametrize(
    "variant,hostname,valid",
    [
        ("valid", "localhost", True),
        ("valid", "127.0.0.1", True),
        ("wrong-host", "localhost", False),
        ("expired", "localhost", False),
        ("bad-signature", "localhost", False),
    ],
)
def test_certificate_policy(trusted_certificates, variant, hostname, valid):
    verifier = CertificateVerifier(ca_certs=str(trusted_certificates.ca_path))
    result, error = verifier.verify_certificate(
        hostname, certificate_message(trusted_certificates.leaves[variant][0])
    )
    assert result is valid, error
    assert (error is None) is valid


def test_self_signed_peer_is_not_a_trust_anchor(
    trusted_certificates, local_certificate
):
    verifier = CertificateVerifier(ca_certs=str(trusted_certificates.ca_path))
    result, error = verifier.verify_certificate(
        "localhost", certificate_message(local_certificate[0])
    )
    assert result is False
    assert error


def test_ecdsa_leaf_is_trusted(trusted_certificates):
    verifier = CertificateVerifier(ca_certs=str(trusted_certificates.ca_path))
    valid, error = verifier.verify_certificate(
        "127.0.0.1", certificate_message(trusted_certificates.leaves["valid-ecdsa"][0])
    )
    assert valid, error


@pytest.mark.parametrize("client_variant", ["client-rsa", "client-ecdsa"])
def test_tls12_client_certificate_authentication(
    trusted_certificates, monkeypatch, client_variant
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(
        *trusted_certificates.leaves["valid"],
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
    )
    context.load_verify_locations(cafile=str(trusted_certificates.ca_path))
    context.verify_mode = ssl.CERT_REQUIRED
    client_cert, client_key = trusted_certificates.leaves[client_variant]
    config = TlsConfig.secure()
    config.tls_version = 0x0303
    config.cipher_suites = [0xC02F]
    config.client_cert = str(client_cert)
    config.client_key = str(client_key)

    def handler(conn):
        assert conn.getpeercert(binary_form=True)
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            assert (
                session.get(f"https://127.0.0.1:{server.port}/", timeout=2).content
                == b"ok"
            )


def test_tls12_rejects_mismatched_client_private_key(trusted_certificates, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(
        *trusted_certificates.leaves["valid"],
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
    )
    context.load_verify_locations(cafile=str(trusted_certificates.ca_path))
    context.verify_mode = ssl.CERT_REQUIRED
    config = TlsConfig.secure()
    config.tls_version = 0x0303
    config.cipher_suites = [0xC02F]
    config.client_cert = str(trusted_certificates.leaves["client-rsa"][0])
    config.client_key = str(trusted_certificates.leaves["client-ecdsa"][1])
    requests = []

    def handler(conn):
        requests.append(read_headers(conn))

    with pytest.raises(ssl.SSLError):
        with LocalServer(handler, context) as server:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
    assert requests == []


@pytest.mark.parametrize("client_variant", ["client-rsa", "client-ecdsa"])
@pytest.mark.parametrize("cipher", [0x1301, 0x1302])
def test_tls13_client_certificate_authentication(
    trusted_certificates, monkeypatch, fragmented_reads, client_variant, cipher
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls13_context(*trusted_certificates.leaves["valid"])
    context.load_verify_locations(cafile=str(trusted_certificates.ca_path))
    context.verify_mode = ssl.CERT_REQUIRED
    client_cert, client_key = trusted_certificates.leaves[client_variant]
    config = TlsConfig.secure()
    config.cipher_suites = [cipher]
    config.client_cert = str(client_cert)
    config.client_key = str(client_key)

    def handler(conn):
        assert conn.getpeercert(binary_form=True)
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, use_pooling=False) as session:
            assert (
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3).content
                == b"ok"
            )
            assert config.session_cache.get_tls13("127.0.0.1", server.port) is None


def test_tls13_optional_client_certificate_can_be_empty(
    trusted_certificates, monkeypatch
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls13_context(*trusted_certificates.leaves["valid"])
    context.load_verify_locations(cafile=str(trusted_certificates.ca_path))
    context.verify_mode = ssl.CERT_OPTIONAL
    config = TlsConfig.secure()

    def handler(conn):
        assert conn.getpeercert(binary_form=True) is None
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, use_pooling=False) as session:
            assert (
                session.get(f"https://127.0.0.1:{server.port}/", timeout=3).content
                == b"ok"
            )


def test_tls13_rejects_mismatched_client_private_key(trusted_certificates, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls13_context(*trusted_certificates.leaves["valid"])
    context.load_verify_locations(cafile=str(trusted_certificates.ca_path))
    context.verify_mode = ssl.CERT_REQUIRED
    config = TlsConfig.secure()
    config.client_cert = str(trusted_certificates.leaves["client-rsa"][0])
    config.client_key = str(trusted_certificates.leaves["client-ecdsa"][1])
    requests = []

    def handler(conn):
        requests.append(read_headers(conn))

    with pytest.raises(ssl.SSLError):
        with LocalServer(handler, context) as server:
            with Session(tls_config=config, use_pooling=False) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
    assert requests == []


@pytest.mark.parametrize("version", [12, 13, "12-ecdhe"])
def test_verified_request_and_pool_reuse(trusted_certificates, monkeypatch, version):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    requests = []

    def handler(conn):
        for _ in range(2):
            requests.append(read_headers(conn))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    config, context = config_and_context(version, trusted_certificates.leaves["valid"])
    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            for _ in range(2):
                response = session.get(
                    f"https://127.0.0.1:{server.port}/", verify=True, timeout=2
                )
                assert response.content == b"ok"
    assert len(requests) == 2
    assert config.verify_cert is False


@pytest.mark.parametrize("version", [12, 13, "12-ecdhe"])
@pytest.mark.parametrize("variant", ["wrong-host", "expired", "bad-signature"])
def test_bad_certificate_aborts_before_http(
    trusted_certificates, monkeypatch, version, variant
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    config, context = config_and_context(version, trusted_certificates.leaves[variant])
    with pytest.raises(ssl.SSLError):
        with LocalServer(
            lambda conn: pytest.fail("Unverified request reached server"), context
        ) as server:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(
                        f"https://127.0.0.1:{server.port}/", verify=True, timeout=2
                    )


@pytest.mark.parametrize("version", [12, 13])
def test_verify_upgrade_cannot_reuse_unverified_connection(
    trusted_certificates, local_certificate, monkeypatch, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    requests = []

    def handler(conn):
        for _ in range(2):
            try:
                headers = read_headers(conn)
            except EOFError:
                return
            requests.append(headers)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    context = (tls12_context if version == 12 else tls13_context)(*local_certificate)
    config = TlsConfig.legacy() if version == 12 else tls13_config()
    with pytest.raises(ssl.SSLError):
        with LocalServer(handler, context, connections=2) as server:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                url = f"https://127.0.0.1:{server.port}/"
                assert session.get(url, verify=False, timeout=2).content == b"ok"
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(url, verify=True, timeout=2)
                assert session.pool.get_stats()["total_connections"] == 0
    assert len(requests) == 1


@pytest.mark.parametrize("version", [13, "12-ecdhe"])
def test_tampered_handshake_signature_is_rejected(
    trusted_certificates, monkeypatch, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    owner = TLS13Handshake if version == 13 else TLS
    method = (
        "_verify_certificate_signature"
        if version == 13
        else "_parse_server_key_exchange"
    )
    original = getattr(owner, method)
    checked = []

    def corrupt_signature(handshake, data):
        checked.append(True)
        return original(handshake, data[:-1] + bytes([data[-1] ^ 1]))

    monkeypatch.setattr(owner, method, corrupt_signature)
    config, context = config_and_context(version, trusted_certificates.leaves["valid"])
    with pytest.raises(ssl.SSLError):
        with LocalServer(
            lambda conn: pytest.fail("Unauthenticated handshake accepted"), context
        ) as server:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(
                        f"https://127.0.0.1:{server.port}/", verify=True, timeout=2
                    )
    assert checked == [True]


@pytest.mark.parametrize("proxy_kind", ["http", "socks5"])
@pytest.mark.parametrize("hostname", ["localhost", "wrong.invalid"])
def test_proxy_verifies_destination_not_sni(
    trusted_certificates, monkeypatch, proxy_kind, hostname
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    config, context = config_and_context(13, trusted_certificates.leaves["valid"])
    config.server_name = "localhost"
    requests = []

    def tls_endpoint(raw):
        with context.wrap_socket(raw, server_side=True) as conn:
            requests.append(read_headers(conn))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    def handler(conn):
        if proxy_kind == "socks5":
            serve_socks(conn, {}, tunnel_handler=tls_endpoint)
        else:
            assert read_headers(conn).startswith(f"CONNECT {hostname}:443 ".encode())
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            tls_endpoint(conn)

    server = LocalServer(handler)

    def request():
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            return session.get(
                f"https://{hostname}/",
                verify=True,
                timeout=2,
                proxies={"https": f"{proxy_kind}://127.0.0.1:{server.port}"},
            )

    if hostname == "localhost":
        with server:
            assert request().content == b"ok"
        assert len(requests) == 1
    else:
        with pytest.raises(ssl.SSLError):
            with server:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    request()
        assert requests == []


def test_peer_supplied_root_does_not_extend_trust(
    trusted_certificates, local_certificate
):
    leaf = certificate_message(trusted_certificates.leaves["valid"][0])[3:]
    root = certificate_message(trusted_certificates.ca_path)[3:]
    presented = len(leaf + root).to_bytes(3, "big") + leaf + root
    verifier = CertificateVerifier(ca_certs=str(local_certificate[0]))
    valid, error = verifier.verify_certificate("localhost", presented)
    assert valid is False
    assert error
