"""TLS 1.2 Session ID resumption against an independent OpenSSL peer."""

import ssl

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.extensions import SessionTicketExtension
from test.integration.test_local_tls13 import fragmented_reads
from test.mock_servers.local import LocalServer, read_headers, tls12_context


@pytest.mark.parametrize(
    "suite,cipher",
    [
        (0x002F, "AES128-SHA"),
        (0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"),
        (0xC030, "ECDHE-RSA-AES256-GCM-SHA384"),
    ],
)
def test_verified_tls12_session_id_resumption(
    trusted_certificates, monkeypatch, fragmented_reads, suite, cipher
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(*trusted_certificates.leaves["valid"], cipher=cipher)
    context.options |= ssl.OP_NO_TICKET
    reused = []

    def handler(conn):
        reused.append(conn.session_reused)
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    config = TlsConfig.secure()
    config.tls_version = 0x0303
    config.cipher_suites = [suite]
    with LocalServer(
        handler, context, connections=2, retain_tls_sessions=True
    ) as server:
        with Session(tls_config=config, use_pooling=False) as session:
            url = f"https://127.0.0.1:{server.port}/"
            assert session.get(url, timeout=3).content == b"ok"
            entry = config.session_cache.get("127.0.0.1", server.port)
            assert entry is not None
            assert entry.extended_master_secret and entry.verified
            assert session.get(url, timeout=3).content == b"ok"
    assert reused == [False, True]


def test_tls13_profile_can_resume_tls12_fallback(trusted_certificates, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(
        *trusted_certificates.leaves["valid"],
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
    )
    context.options |= ssl.OP_NO_TICKET
    reused = []

    def handler(conn):
        reused.append(conn.session_reused)
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(
        handler, context, connections=2, retain_tls_sessions=True
    ) as server:
        with Session(tls_config=TlsConfig.secure(), use_pooling=False) as session:
            url = f"https://127.0.0.1:{server.port}/"
            assert session.get(url, timeout=3).content == b"ok"
            assert session.get(url, timeout=3).content == b"ok"
    assert reused == [False, True]


def test_unknown_session_id_falls_back_to_verified_full_handshake(
    trusted_certificates, monkeypatch
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(
        *trusted_certificates.leaves["valid"],
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
    )
    context.options |= ssl.OP_NO_TICKET
    reused = []

    def handler(conn):
        reused.append(conn.session_reused)
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    config = TlsConfig.secure()
    config.tls_version = 0x0303
    config.cipher_suites = [0xC02F]
    with LocalServer(
        handler, context, connections=2, retain_tls_sessions=True
    ) as server:
        with Session(tls_config=config, use_pooling=False) as session:
            url = f"https://127.0.0.1:{server.port}/"
            assert session.get(url, timeout=3).content == b"ok"
            entry = config.session_cache.get("127.0.0.1", server.port)
            entry.session_id = b"unknown-session-id"
            assert session.get(url, timeout=3).content == b"ok"
    assert reused == [False, False]


def test_bad_resumed_server_finished_sends_no_http(trusted_certificates, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(
        *trusted_certificates.leaves["valid"],
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
    )
    context.options |= ssl.OP_NO_TICKET
    original = TLS._verify_server_finished
    checked = []
    requests = []

    def corrupt_resumed(handshake, message, transcript):
        if handshake._resumed_session is not None:
            checked.append(True)
            message = message[:-1] + bytes([message[-1] ^ 1])
        return original(handshake, message, transcript)

    def handler(conn):
        requests.append(read_headers(conn))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    monkeypatch.setattr(TLS, "_verify_server_finished", corrupt_resumed)
    config = TlsConfig.secure()
    config.tls_version = 0x0303
    config.cipher_suites = [0xC02F]
    server = LocalServer(handler, context, connections=2, retain_tls_sessions=True)
    with pytest.raises(ssl.SSLError):
        with server:
            with Session(tls_config=config, use_pooling=False) as session:
                url = f"https://127.0.0.1:{server.port}/"
                assert session.get(url, timeout=3).content == b"ok"
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(url, timeout=3)
    assert checked == [True]
    assert len(requests) == 1


@pytest.mark.parametrize(
    "suite,cipher",
    [
        (0xC02F, "ECDHE-RSA-AES128-GCM-SHA256"),
        (0xC030, "ECDHE-RSA-AES256-GCM-SHA384"),
    ],
)
def test_verified_tls12_ticket_resumption(
    trusted_certificates, monkeypatch, fragmented_reads, suite, cipher
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(*trusted_certificates.leaves["valid"], cipher=cipher)
    reused = []

    def handler(conn):
        reused.append(conn.session_reused)
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    config = TlsConfig.secure()
    config.tls_version = 0x0303
    config.cipher_suites = [suite]
    config.extensions.append(SessionTicketExtension())
    with LocalServer(handler, context, connections=2) as server:
        with Session(tls_config=config, use_pooling=False) as session:
            url = f"https://127.0.0.1:{server.port}/"
            assert session.get(url, timeout=3).content == b"ok"
            entry = config.session_cache.get_tls12_ticket("127.0.0.1", server.port)
            assert entry is not None
            assert entry.extended_master_secret and entry.verified
            assert config.session_cache.get("127.0.0.1", server.port) is None
            assert session.get(url, timeout=3).content == b"ok"
    assert reused == [False, True]


def test_rejected_tls12_ticket_falls_back_to_full_handshake(
    trusted_certificates, monkeypatch
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(
        *trusted_certificates.leaves["valid"],
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
    )
    reused = []

    def handler(conn):
        reused.append(conn.session_reused)
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    config = TlsConfig.secure()
    config.tls_version = 0x0303
    config.cipher_suites = [0xC02F]
    config.extensions.append(SessionTicketExtension())
    with LocalServer(handler, context, connections=2) as server:
        with Session(tls_config=config, use_pooling=False) as session:
            url = f"https://127.0.0.1:{server.port}/"
            assert session.get(url, timeout=3).content == b"ok"
            entry = config.session_cache.get_tls12_ticket("127.0.0.1", server.port)
            entry.ticket = b"invalid-ticket"
            assert session.get(url, timeout=3).content == b"ok"
            assert (
                config.session_cache.get_tls12_ticket("127.0.0.1", server.port).ticket
                != b"invalid-ticket"
            )
    assert reused == [False, False]


def test_bad_ticket_resumed_finished_sends_no_http(trusted_certificates, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    context = tls12_context(
        *trusted_certificates.leaves["valid"],
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
    )
    original = TLS._verify_server_finished
    checked = []
    requests = []

    def corrupt_resumed(handshake, message, transcript):
        if handshake._resumed_session is not None:
            checked.append(handshake._resumed_session.is_ticket)
            message = message[:-1] + bytes([message[-1] ^ 1])
        return original(handshake, message, transcript)

    def handler(conn):
        requests.append(read_headers(conn))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    monkeypatch.setattr(TLS, "_verify_server_finished", corrupt_resumed)
    config = TlsConfig.secure()
    config.tls_version = 0x0303
    config.cipher_suites = [0xC02F]
    config.extensions.append(SessionTicketExtension())
    server = LocalServer(handler, context, connections=2)
    with pytest.raises(ssl.SSLError):
        with server:
            with Session(tls_config=config, use_pooling=False) as session:
                url = f"https://127.0.0.1:{server.port}/"
                assert session.get(url, timeout=3).content == b"ok"
                assert (
                    config.session_cache.get_tls12_ticket("127.0.0.1", server.port)
                    is not None
                )
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(url, timeout=3)
                assert (
                    config.session_cache.get_tls12_ticket("127.0.0.1", server.port)
                    is None
                )
    assert checked == [True]
    assert len(requests) == 1
