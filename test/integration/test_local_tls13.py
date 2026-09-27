"""TLS 1.3 interoperability through the existing public Session API."""

import ssl

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.tls13 import TLS13Handshake
from ja3requests.sockets.https import HttpsSocket
from test.mock_servers.local import LocalServer, read_headers, serve_h2, tls13_context
from test.mock_servers.local import tls12_context


def tls13_config(cipher=0x1301):
    config = TlsConfig()
    config.tls_version = 0x0304
    config.cipher_suites = [cipher]
    config.supported_groups = [29]
    config.signature_algorithms = [0x0804]
    config.alpn_protocols = ["http/1.1"]
    return config


@pytest.fixture(params=[False, True], ids=["normal-reads", "fragmented-reads"])
def fragmented_reads(request, monkeypatch):
    if not request.param:
        return
    original = HttpsSocket._new_conn

    class FragmentedSocket:
        def __init__(self, conn):
            self.conn = conn

        def recv(self, size, *args):
            return self.conn.recv(min(size, 7), *args)

        def __getattr__(self, name):
            return getattr(self.conn, name)

    def connect(transport, host, port):
        return FragmentedSocket(original(transport, host, port))

    monkeypatch.setattr(HttpsSocket, "_new_conn", connect)


@pytest.mark.parametrize("cipher", [0x1301, 0x1302, 0x1303])
def test_tls13_http_and_pool_reuse(local_certificate, fragmented_reads, cipher):
    requests = []

    def handler(conn):
        assert conn.version() == "TLSv1.3"
        assert conn.selected_alpn_protocol() == "http/1.1"
        for _ in range(2):
            requests.append(read_headers(conn))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")

    with LocalServer(handler, tls13_context(*local_certificate)) as server:
        with Session(tls_config=tls13_config(cipher), pool=ConnectionPool()) as session:
            for path in ("/first", "/second"):
                response = session.get(
                    f"https://127.0.0.1:{server.port}{path}", timeout=2
                )
                assert response.status_code == 200
                assert response.content == b"hello"
    assert requests[0].startswith(b"GET /first HTTP/1.1\r\n")
    assert requests[1].startswith(b"GET /second HTTP/1.1\r\n")


@pytest.mark.parametrize("cipher", [0x1301, 0x1302, 0x1303])
def test_tls13_h2_alpn_and_session_tickets(local_certificate, fragmented_reads, cipher):
    observed = {}
    config = tls13_config(cipher)
    config.alpn_protocols = ["h2", "http/1.1"]
    config.h2_settings = {1: 12345}
    config.h2_window_update = 65536
    context = tls13_context(*local_certificate, alpn="h2")
    # OpenSSL emits tickets before application data. They must not look like EOF.
    context.num_tickets = 2
    with LocalServer(lambda conn: serve_h2(conn, observed), context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert response.status_code == 200
            assert response.content == b"hello h2"
    assert observed["settings"][1] == 12345
    assert observed["window"] == 65536


def test_tls13_invalid_finished_aborts_before_http(local_certificate, monkeypatch):
    original = TLS13Handshake.verify_server_finished
    checks = []

    def corrupt_finished(handshake, data):
        checks.append(data)
        return original(handshake, data[:-1] + bytes([data[-1] ^ 1]))

    monkeypatch.setattr(TLS13Handshake, "verify_server_finished", corrupt_finished)
    server = LocalServer(
        lambda conn: pytest.fail("Client sent invalid Finished"),
        tls13_context(*local_certificate),
    )
    # The client must close before OpenSSL completes its side of the handshake.
    with pytest.raises(ssl.SSLError):
        with server:
            with Session(tls_config=tls13_config(), pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
    assert len(checks) == 1


def test_tls13_verify_true_is_not_silently_ignored(local_certificate):
    requests = []

    def handler(conn):
        requests.append(read_headers(conn))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    config = tls13_config()
    config.server_name = "wrong.invalid"
    config.verify_cert = True
    server = LocalServer(handler, tls13_context(*local_certificate))
    with pytest.raises(ssl.SSLError):
        with server:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(
                        f"https://127.0.0.1:{server.port}/", timeout=2, verify=True
                    )
    assert requests == []


@pytest.mark.parametrize("version", [12, 13])
def test_browser_preset_negotiates_verified_tls(
    trusted_certificates, monkeypatch, fragmented_reads, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves["valid"]
    if version == 12:
        context = tls12_context(*certificate, cipher="ECDHE-RSA-AES128-GCM-SHA256")
    else:
        context = tls13_context(*certificate)

    def handler(conn):
        assert conn.version() == f"TLSv1.{version - 10}"
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    config = TlsConfig.from_browser("chrome", 120)
    config.verify_cert = True
    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert response.content == b"ok"


def test_browser_preset_rejects_bad_certificate_on_tls12_fallback(
    trusted_certificates, monkeypatch
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves["wrong-host"]
    context = tls12_context(*certificate, cipher="ECDHE-RSA-AES128-GCM-SHA256")
    config = TlsConfig.from_browser("chrome", 120)
    config.verify_cert = True
    verified = []
    original_verify = TLS._verify_server_certificate

    def record_verification(tls, certificate_data):
        verified.append(True)
        return original_verify(tls, certificate_data)

    monkeypatch.setattr(TLS, "_verify_server_certificate", record_verification)
    with pytest.raises(ssl.SSLError):
        with LocalServer(
            lambda conn: pytest.fail("Unverified request reached server"), context
        ) as server:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
    assert verified


@pytest.mark.parametrize(
    "version,certificate_variant,cipher",
    [
        (13, "valid", None),
        (13, "valid-ecdsa", None),
        (12, "valid", "ECDHE-RSA-AES128-GCM-SHA256"),
        (12, "valid-ecdsa", "ECDHE-ECDSA-AES128-GCM-SHA256"),
    ],
)
def test_secure_profile_verified_interop(
    trusted_certificates,
    monkeypatch,
    fragmented_reads,
    version,
    certificate_variant,
    cipher,
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves[certificate_variant]
    context = (
        tls13_context(*certificate)
        if version == 13
        else tls12_context(*certificate, cipher=cipher)
    )

    def handler(conn):
        assert conn.version() == f"TLSv1.{version - 10}"
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    config = TlsConfig.secure()
    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert response.content == b"ok"


@pytest.mark.parametrize("version", [12, 13])
def test_secure_profile_rejects_bad_certificate(
    trusted_certificates, monkeypatch, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves["wrong-host"]
    context = (
        tls13_context(*certificate)
        if version == 13
        else tls12_context(*certificate, cipher="ECDHE-RSA-AES128-GCM-SHA256")
    )
    verified = []
    original_verify = TLS._verify_server_certificate

    def record_verification(tls, certificate_data):
        verified.append(True)
        return original_verify(tls, certificate_data)

    monkeypatch.setattr(TLS, "_verify_server_certificate", record_verification)
    config = TlsConfig.secure()
    with pytest.raises(ssl.SSLError):
        with LocalServer(
            lambda conn: pytest.fail("Unverified request reached server"), context
        ) as server:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
    assert verified
