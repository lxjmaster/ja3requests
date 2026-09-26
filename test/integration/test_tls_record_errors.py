"""Malformed TLS records must not be silently treated as HTTP/2 EOF."""

import socket
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ja3requests.exceptions import TLSDecryptionError
from ja3requests.sockets.https import HttpsSocket
from ja3requests.protocol.tls.tls13 import TLS13RecordProtection
from test.mock_servers.local import LocalServer


@pytest.mark.parametrize(
    "record,reason",
    [
        (b"\x17\x03\x03\x00\x10short", "Truncated TLS record"),
        (b"\x17\x03\x03\x00\x05short", "too short for GCM"),
    ],
)
def test_invalid_tls_record_propagates_error(record, reason):
    with LocalServer(lambda conn: conn.sendall(record)) as server:
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as conn:
            transport = HttpsSocket(SimpleNamespace())
            transport.conn = conn
            transport.tls = SimpleNamespace(_is_gcm=True)
            with pytest.raises(TLSDecryptionError, match=reason):
                transport._decrypt_single_record()


@pytest.mark.parametrize(
    "reader", ["_decrypt_single_record", "_handle_encrypted_response"]
)
def test_tls13_tampered_application_record_rejected(reader):
    key, iv = b"\x01" * 16, b"\x02" * 12
    plaintext = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n\x17"
    header = b"\x17\x03\x03" + (len(plaintext) + 16).to_bytes(2, "big")
    ciphertext = AESGCM(key).encrypt(iv, plaintext, header)
    record = header + ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
    with LocalServer(lambda conn: conn.sendall(record)) as server:
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as conn:
            transport = HttpsSocket(SimpleNamespace())
            transport.conn = conn
            transport.tls = SimpleNamespace(
                _is_tls13=True, _tls13_server_rp=TLS13RecordProtection(key, iv)
            )
            with pytest.raises(TLSDecryptionError, match="authentication failed"):
                getattr(transport, reader)()
