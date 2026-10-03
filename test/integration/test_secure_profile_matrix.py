"""Explicit secure-profile suites and groups against independent TLS peers."""

import ssl

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls import TLS
from test.integration.test_local_tls13 import fragmented_reads
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    read_headers,
    tls12_context,
    tls13_context,
)


HTTP1_CASES = [
    pytest.param(
        13,
        0x1301,
        "TLS_AES_128_GCM_SHA256",
        "valid",
        "X25519",
        id="tls13-aes128-rsa-x25519",
    ),
    pytest.param(
        13,
        0x1301,
        "TLS_AES_128_GCM_SHA256",
        "valid-ecdsa",
        "prime256v1",
        id="tls13-aes128-ecdsa-p256",
    ),
    pytest.param(
        13,
        0x1302,
        "TLS_AES_256_GCM_SHA384",
        "valid",
        "prime256v1",
        id="tls13-aes256-rsa-p256",
    ),
    pytest.param(
        13,
        0x1302,
        "TLS_AES_256_GCM_SHA384",
        "valid-ecdsa",
        "X25519",
        id="tls13-aes256-ecdsa-x25519",
    ),
    pytest.param(
        13,
        0x1303,
        "TLS_CHACHA20_POLY1305_SHA256",
        "valid",
        "X25519",
        id="tls13-chacha-rsa-x25519",
    ),
    pytest.param(
        13,
        0x1303,
        "TLS_CHACHA20_POLY1305_SHA256",
        "valid-ecdsa",
        "prime256v1",
        id="tls13-chacha-ecdsa-p256",
    ),
    pytest.param(
        12,
        0xC02F,
        "ECDHE-RSA-AES128-GCM-SHA256",
        "valid",
        "X25519",
        id="tls12-aes128-rsa-x25519",
    ),
    pytest.param(
        12,
        0xC030,
        "ECDHE-RSA-AES256-GCM-SHA384",
        "valid",
        "prime256v1",
        id="tls12-aes256-rsa-p256",
    ),
    pytest.param(
        12,
        0xC02B,
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "valid-ecdsa",
        "X25519",
        id="tls12-aes128-ecdsa-x25519",
    ),
    pytest.param(
        12,
        0xC02C,
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "valid-ecdsa",
        "prime256v1",
        id="tls12-aes256-ecdsa-p256",
    ),
]

# HTTP/2 covers both protocols, certificate types and implemented groups.
HTTP2_CASES = [HTTP1_CASES[index] for index in (0, 5, 7, 8)]


def secure_config_and_peer(version, suite, cipher, certificate, group, alpn):
    config = TlsConfig.secure()
    config.cipher_suites = [suite] if version == 13 else [0x1301, suite]
    config.alpn_protocols = [alpn]
    config.validate(strict=True)
    if version == 13:
        context = tls13_context(*certificate, alpn=alpn)
    else:
        context = tls12_context(*certificate, alpn=alpn, cipher=cipher)
    set_peer_group(context, group)
    return config, context


def set_peer_group(context, group):
    """Report a peer API limitation without changing the selected group."""
    try:
        context.set_ecdh_curve(group)
    except ssl.SSLError as error:
        if group == "X25519" and "unknown group" in str(error).lower():
            pytest.skip("Python/OpenSSL peer cannot restrict the X25519 group")
        raise


@pytest.mark.parametrize("version,suite,cipher,certificate_variant,group", HTTP1_CASES)
def test_secure_explicit_suite_and_group_reuses_http1_connection(
    trusted_certificates,
    monkeypatch,
    fragmented_reads,
    version,
    suite,
    cipher,
    certificate_variant,
    group,
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    config, context = secure_config_and_peer(
        version,
        suite,
        cipher,
        trusted_certificates.leaves[certificate_variant],
        group,
        "http/1.1",
    )
    observed = []

    def handler(conn):
        assert conn.version() == f"TLSv1.{version - 10}"
        assert conn.cipher()[0] == cipher
        assert conn.selected_alpn_protocol() == "http/1.1"
        for path in ("/first", "/second"):
            headers = read_headers(conn)
            assert headers.startswith(f"GET {path} HTTP/1.1\r\n".encode())
            observed.append(path)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            for path in ("/first", "/second"):
                response = session.get(
                    f"https://127.0.0.1:{server.port}{path}", timeout=3
                )
                assert response.status_code == 200
                assert response.content == b"ok"
    assert observed == ["/first", "/second"]
    assert config.tls_version == 0x0304 and config.verify_cert


@pytest.mark.parametrize("pooled", [False, True], ids=["sequential", "pooled"])
@pytest.mark.parametrize("version,suite,cipher,certificate_variant,group", HTTP2_CASES)
def test_secure_explicit_http2_paths(
    trusted_certificates,
    monkeypatch,
    fragmented_reads,
    pooled,
    version,
    suite,
    cipher,
    certificate_variant,
    group,
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    config, context = secure_config_and_peer(
        version,
        suite,
        cipher,
        trusted_certificates.leaves[certificate_variant],
        group,
        "h2",
    )
    observed = []

    def handler(conn):
        assert conn.version() == f"TLSv1.{version - 10}"
        assert conn.cipher()[0] == cipher
        assert conn.selected_alpn_protocol() == "h2"
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        remaining = 2 if pooled else 1
        settings_acknowledged = False
        # Receive the peer's SETTINGS ACK before closing, without waiting for
        # transport EOF (a non-pooled client can start another connection).
        while remaining or not settings_acknowledged:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            if header[3] == 4:
                if header[4] & 1:
                    settings_acknowledged = True
                else:
                    conn.sendall(h2_frame(4, 1, 0))
            elif header[3] == 1:
                assert header[4] & 4  # END_HEADERS
                observed.append(stream_id)
                conn.sendall(
                    h2_frame(1, 4, stream_id, b"\x88")
                    + h2_frame(0, 1, stream_id, b"ok")
                )
                remaining -= 1

    pool = ConnectionPool() if pooled else None
    with LocalServer(handler, context, connections=1 if pooled else 2) as server:
        with Session(tls_config=config, use_pooling=pooled, pool=pool) as session:
            for path in ("/first", "/second"):
                response = session.get(
                    f"https://127.0.0.1:{server.port}{path}", timeout=3
                )
                assert response.status_code == 200
                assert response.content == b"ok"
    assert observed == ([1, 3] if pooled else [1, 1])
    assert config.verify_cert


@pytest.mark.parametrize("pooled", [False, True], ids=["sequential", "pooled"])
@pytest.mark.parametrize("version", [12, 13])
def test_secure_http2_rejects_wrong_identity_before_request(
    trusted_certificates, monkeypatch, pooled, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    suite, cipher = (
        (0x1301, "TLS_AES_128_GCM_SHA256")
        if version == 13
        else (0xC02F, "ECDHE-RSA-AES128-GCM-SHA256")
    )
    config, context = secure_config_and_peer(
        version,
        suite,
        cipher,
        trusted_certificates.leaves["wrong-host"],
        "prime256v1",
        "h2",
    )
    verified = []
    original_verify = TLS._verify_server_certificate

    def record_verification(tls, certificate_data):
        verified.append(True)
        return original_verify(tls, certificate_data)

    monkeypatch.setattr(TLS, "_verify_server_certificate", record_verification)
    pool = ConnectionPool() if pooled else None
    with pytest.raises(ssl.SSLError):
        with LocalServer(
            lambda conn: pytest.fail("Unverified HTTP/2 request reached peer"), context
        ) as server:
            with Session(tls_config=config, use_pooling=pooled, pool=pool) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=3)
                if pooled:
                    assert pool.get_stats()["total_connections"] == 0
    assert verified == [True]
    assert config.verify_cert
