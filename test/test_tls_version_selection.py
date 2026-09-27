"""TLS 1.3-capable ClientHello must follow the server's valid selection."""

import pytest

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
    tls._parse_server_hello(server_hello(cipher_suite, selected_version, random_suffix))
    with pytest.raises(TLSHandshakeError):
        tls._selected_handshake_version()


def test_rejects_truncated_server_hello_extension():
    tls = TLS(None)
    message = server_hello(0x1301, b"\x03\x04")[:-1]
    with pytest.raises(TLSHandshakeError, match="ServerHello extension"):
        tls._parse_server_hello(message)
