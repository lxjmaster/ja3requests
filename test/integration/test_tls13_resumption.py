"""TLS 1.3 ticket resumption against an independent OpenSSL peer."""

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.client_hello_info import inspect_client_hello
from test.wire_client_hello import profile
from test.integration.test_local_tls13 import fragmented_reads
from test.mock_servers.local import LocalServer, read_headers, tls13_context


@pytest.mark.parametrize("cipher", [0x1301, 0x1302, 0x1303])
@pytest.mark.parametrize("reject_ticket", [False, True])
@pytest.mark.parametrize("hello_retry", [False, True])
def test_verified_tls13_resumption_or_full_handshake_fallback(
    trusted_certificates,
    monkeypatch,
    fragmented_reads,
    cipher,
    reject_ticket,
    hello_retry,
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves["valid"]
    context = tls13_context(*certificate, group="prime256v1" if hello_retry else None)
    context.num_tickets = 2
    reused = []

    def handler(conn):
        reused.append(conn.session_reused)
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    config = TlsConfig.secure()
    config.extension_order = [0, 43, 10, 51, 13, 16, 45, 23, 44, 41]
    config.cipher_suites = [cipher]
    observed = []
    original = TLS.handshake

    def handshake(tls):
        result = original(tls)
        observed.append(tls.sent_client_hellos)
        return result

    monkeypatch.setattr(TLS, 'handshake', handshake)
    if hello_retry:
        config.key_share_groups = [29]
    with LocalServer(handler, context, connections=2) as server:
        with Session(tls_config=config, use_pooling=False) as session:
            url = f"https://127.0.0.1:{server.port}/"
            assert session.get(url, timeout=3).content == b"ok"
            ticket = config.session_cache.get_tls13("127.0.0.1", server.port)
            assert ticket is not None
            assert ticket.verified
            if reject_ticket:
                ticket.ticket = b"unknown-ticket"
            assert session.get(url, timeout=3).content == b"ok"
    assert reused == [False, not reject_ticket]
    assert len(observed) == 2
    for flight in observed:
        assert flight[0][1:3] == b'\x03\x01'
        if len(flight) == 2:
            assert flight[1][1:3] == b'\x03\x03'
        for record in flight:
            assert inspect_client_hello(record)['ja3'] == profile(record)['ja3']
    assert 41 not in inspect_client_hello(observed[0][0])['extensions']
    assert inspect_client_hello(observed[1][0])['extensions'][-1] == 41
