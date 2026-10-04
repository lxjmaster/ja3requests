"""TLS 1.3-capable ClientHello must follow the server's valid selection."""

import pytest

from ja3requests import TlsConfig
from ja3requests.exceptions import TLSHandshakeError
from ja3requests.protocol.tls import TLS


def server_hello(cipher_suite, selected_version=None, random_suffix=b"\x00" * 8):
    extensions = b""
    if selected_version is not None:
        extensions = b"\x00\x2b\x00\x02" + selected_version
    return (
        b"\x03\x03"
        + b"\x01" * 24
        + random_suffix
        + b"\x00"
        + cipher_suite.to_bytes(2, "big")
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )


@pytest.mark.parametrize(
    "cipher_suite,selected_version,expected",
    [(0x1301, b"\x03\x04", b"\x03\x04"), (0xC02F, None, b"\x03\x03")],
)
def test_selects_offered_version(cipher_suite, selected_version, expected):
    tls = TLS(None)
    tls._cipher_suites = [0x1301, 0xC02F]
    tls._parse_server_hello(server_hello(cipher_suite, selected_version))
    assert tls._selected_handshake_version() == expected


@pytest.mark.parametrize(
    "cipher_suite,selected_version,random_suffix",
    [
        (0x1303, b"\x03\x04", b"\x00" * 8),
        (0xC02F, b"\x03\x03", b"\x00" * 8),
        (0x1301, None, b"\x00" * 8),
        (0xC02F, None, b"DOWNGRD\x01"),
    ],
)
def test_rejects_invalid_server_selection(
    cipher_suite, selected_version, random_suffix
):
    tls = TLS(None)
    tls._cipher_suites = [0x1301, 0xC02F]
    with pytest.raises(TLSHandshakeError):
        tls._parse_server_hello(server_hello(cipher_suite, selected_version, random_suffix))
        tls._selected_handshake_version()


def test_rejects_truncated_server_hello_extension():
    tls = TLS(None)
    message = server_hello(0x1301, b"\x03\x04")[:-1]
    with pytest.raises(TLSHandshakeError, match="ServerHello extension"):
        tls._parse_server_hello(message)


def test_tls12_rejects_cipher_suite_not_offered_by_client():
    tls = TLS(None)
    config = TlsConfig()
    config.tls_version = 0x0303
    config.cipher_suites = [0xC02F]
    tls.set_payload(config)
    with pytest.raises(TLSHandshakeError, match="unoffered cipher"):
        tls._parse_server_hello(server_hello(0x002F))
    tls._parse_server_hello(server_hello(0xC02F))


def test_tls12_reassembles_handshake_message_across_records():
    tls = TLS(None)
    tls._handshake_messages = b""
    server_hello_done = b"\x0e\x00\x00\x00"
    tls._process_handshake_record(server_hello_done[:2])
    assert not getattr(tls, "_server_hello_done_received", False)
    tls._process_handshake_record(server_hello_done[2:])
    assert tls._server_hello_done_received is True
    assert tls._handshake_messages == server_hello_done


def test_tls13_capable_client_reassembles_tls12_server_hello_before_fallback(monkeypatch):
    body = server_hello(0xC02F)
    message = b"\x02" + len(body).to_bytes(3, "big") + body

    def record(fragment):
        return b"\x16\x03\x03" + len(fragment).to_bytes(2, "big") + fragment

    wire = record(message[:10]) + record(message[10:])

    class FakeConnection:
        def __init__(self):
            self.pending = [wire]

        def sendall(self, data):
            pass

        def recv(self, size):
            return self.pending.pop(0) if self.pending else b""

        def settimeout(self, value):
            pass

    tls = TLS(FakeConnection())
    tls.set_payload(TlsConfig.secure())
    replayed = []
    monkeypatch.setattr(
        tls, "_handshake_tls12", lambda initial_data: replayed.append(initial_data) or True
    )
    assert tls.handshake() is True
    assert replayed == [wire]
