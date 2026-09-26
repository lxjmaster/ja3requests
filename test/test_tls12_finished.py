"""Independent TLS 1.2 Finished records for authentication boundary tests."""

import hashlib
import hmac
import io

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ja3requests.protocol.tls import TLS


CCS = b"\x14\x03\x03\x00\x01\x01"
TRANSCRIPT = b"fixture transcript through client Finished"
MASTER = b"m" * 48
KEY = b"k" * 16
MAC_KEY = b"a" * 20
IV = b"i" * 4


def finished(transcript=TRANSCRIPT):
    seed = b"server finished" + hashlib.sha256(transcript).digest()
    a1 = hmac.new(MASTER, seed, hashlib.sha256).digest()
    verify_data = hmac.new(MASTER, a1 + seed, hashlib.sha256).digest()[:12]
    return b"\x14\x00\x00\x0c" + verify_data


def encrypted_record(payload, gcm, seq=0, bad_padding=False):
    prefix = seq.to_bytes(8, "big") + b"\x16\x03\x03" + len(payload).to_bytes(2, "big")
    if gcm:
        explicit = seq.to_bytes(8, "big")
        body = explicit + AESGCM(KEY).encrypt(IV + explicit, payload, prefix)
    else:
        plain = payload + hmac.new(MAC_KEY, prefix + payload, hashlib.sha1).digest()
        count = 16 - len(plain) % 16
        pad = bytes([count - 1]) * count
        if bad_padding:
            pad = bytes([pad[0] ^ 1]) + pad[1:]
        encryptor = Cipher(algorithms.AES(KEY), modes.CBC(b"v" * 16)).encryptor()
        body = b"v" * 16 + encryptor.update(plain + pad) + encryptor.finalize()
    return b"\x16\x03\x03" + len(body).to_bytes(2, "big") + body


class Wire:
    def __init__(self, data, chunk=65535):
        self.data = io.BytesIO(data)
        self.chunk = chunk

    def recv(self, size):
        return self.data.read(min(size, self.chunk))


def client(wire, gcm):
    tls = TLS(wire)
    tls._master_secret = MASTER
    tls._handshake_messages = TRANSCRIPT
    tls._selected_cipher_suite = 0xC02F if gcm else 0x002F
    tls._is_gcm = gcm
    tls._server_write_key = KEY
    tls._server_write_iv = IV
    tls._server_write_mac_key = MAC_KEY
    return tls


@pytest.mark.parametrize("gcm", [False, True])
@pytest.mark.parametrize("chunk", [1, 65535])
def test_valid_finished_keeps_application_data_unread(gcm, chunk):
    message = finished()
    wire = Wire(CCS + encrypted_record(message, gcm) + b"application-record", chunk)
    tls = client(wire, gcm)
    assert tls._wait_for_server_handshake_completion() is True
    assert tls._server_seq_num == 1
    assert tls._handshake_messages == TRANSCRIPT + message
    assert wire.data.read() == b"application-record"


@pytest.mark.parametrize("gcm", [False, True])
@pytest.mark.parametrize(
    "fault", ["verify-data", "tag", "sequence", "no-ccs", "duplicate-ccs", "truncated"]
)
def test_invalid_finished_is_rejected(gcm, fault):
    message = finished()
    if fault == "verify-data":
        message = message[:-1] + bytes([message[-1] ^ 1])
    record = encrypted_record(message, gcm, seq=1 if fault == "sequence" else 0)
    if fault == "tag":
        record = record[:-1] + bytes([record[-1] ^ 1])
    if fault == "truncated":
        record = record[:-1]
    prefix = b"" if fault == "no-ccs" else CCS
    if fault == "duplicate-ccs":
        prefix += CCS
    tls = client(Wire(prefix + record), gcm)
    assert tls._wait_for_server_handshake_completion() is False
    assert tls._handshake_messages == TRANSCRIPT


def test_cbc_rejects_inconsistent_padding_bytes():
    tls = client(
        Wire(CCS + encrypted_record(finished(), False, bad_padding=True)), False
    )
    assert tls._wait_for_server_handshake_completion() is False


@pytest.mark.parametrize("gcm", [False, True])
def test_fragmented_finished_and_ticket_transcript(gcm):
    ticket = b"\x04\x00\x00\x07\x00\x00\x00\x3c\x00\x01t"
    ticket_record = b"\x16\x03\x03" + len(ticket).to_bytes(2, "big") + ticket
    message = finished(TRANSCRIPT + ticket)
    wire = Wire(
        ticket_record
        + CCS
        + encrypted_record(message[:5], gcm)
        + encrypted_record(message[5:], gcm, seq=1),
        chunk=3,
    )
    tls = client(wire, gcm)
    assert tls._wait_for_server_handshake_completion() is True
    assert tls._server_seq_num == 2
    assert tls._handshake_messages == TRANSCRIPT + ticket + message
