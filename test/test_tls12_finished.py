"""Independent TLS 1.2 Finished records for authentication boundary tests."""

import hashlib
import hmac
import io
import socket
import threading

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.session_cache import TLSSessionCache


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
    "outcome,handshake_timeout",
    [
        ("fragmented", None),
        ("fragmented", 10.0),
        ("timeout", 0.05),
        ("eof", None),
        ("eof", 10.0),
    ],
)
def test_full_handshake_finished_receive_boundary(
    monkeypatch, gcm, outcome, handshake_timeout
):
    message = finished()
    first_flight = CCS + encrypted_record(message[:5], gcm)
    remainder = encrypted_record(message[5:], gcm, seq=1)
    recv_entered = threading.Event()
    allow_recv = threading.Event()
    remainder_requested = threading.Event()
    timed_out = threading.Event()
    done = threading.Event()
    read_timeouts = []
    timeout_changes = []
    results = []
    errors = []
    conn, peer = socket.socketpair()

    class ObservedSocket:
        received = 0

        def settimeout(self, timeout):
            timeout_changes.append(timeout)
            conn.settimeout(timeout)

        def recv(self, size):
            read_timeouts.append(conn.gettimeout())
            if len(read_timeouts) == 1:
                recv_entered.set()
                if not allow_recv.wait(3):
                    raise RuntimeError("Test did not release the first receive")
            if self.received == len(first_flight):
                remainder_requested.set()
            try:
                data = conn.recv(min(size, 3))
            except socket.timeout:
                timed_out.set()
                raise
            self.received += len(data)
            return data

    tls = client(ObservedSocket(), gcm)
    tls._handshake_timeout = handshake_timeout
    tls._verify_cert = True
    tls._cert_verified = True
    # The fixture transcript and keys represent the completed client flight.
    # Keep the actual record reader, decryption and Finished verification.
    monkeypatch.setattr(tls, "_parse_server_handshake_messages", lambda data: None)
    monkeypatch.setattr(tls, "_send_client_finishing_messages", lambda: None)

    def handshake():
        try:
            results.append(tls._handshake_tls12())
        except Exception as error:
            errors.append(error)
        finally:
            done.set()

    worker = threading.Thread(target=handshake, daemon=True)
    try:
        peer.settimeout(3)
        worker.start()
        assert recv_entered.wait(3), "Full handshake never requested server Finished"
        assert not done.is_set()
        expected_timeout = handshake_timeout if handshake_timeout is not None else 5.0
        assert read_timeouts == [expected_timeout]
        assert tls._handshake_messages == TRANSCRIPT
        assert tls._resumed_session is None

        if outcome != "timeout":
            peer.sendall(first_flight)
        if outcome == "eof":
            peer.shutdown(socket.SHUT_WR)
        allow_recv.set()
        if outcome == "fragmented":
            assert remainder_requested.wait(3), "Fragmented Finished was not read"
            assert not done.is_set()
            assert tls._handshake_messages == TRANSCRIPT
            peer.sendall(remainder)

        # These waits bound a failed test; they are not latency assertions.
        assert done.wait(3), "Full handshake did not finish after peer completion"
        assert errors == []
        assert results == [outcome == "fragmented"]
        assert timed_out.is_set() is (outcome == "timeout")
        assert all(value == expected_timeout for value in read_timeouts)
        assert timeout_changes[0] == expected_timeout
        assert timeout_changes[-1] is None
        assert conn.gettimeout() is None
        assert tls._handshake_messages == (
            TRANSCRIPT + message if outcome == "fragmented" else TRANSCRIPT
        )
        if outcome == "fragmented":
            assert tls._server_seq_num == 2
    finally:
        allow_recv.set()
        peer.close()
        if worker.ident is not None:
            worker.join(3)
        conn.close()
        assert not worker.is_alive(), "Full-handshake worker did not terminate"


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
    tls._server_offered_session_ticket = True
    assert tls._wait_for_server_handshake_completion() is True
    assert tls._server_seq_num == 2
    assert tls._handshake_messages == TRANSCRIPT + ticket + message
    assert tls._new_session_ticket == (60, b"t")


def test_ticket_is_not_cached_before_valid_finished():
    ticket = b"\x04\x00\x00\x07\x00\x00\x00\x3c\x00\x01t"
    ticket_record = b"\x16\x03\x03" + len(ticket).to_bytes(2, "big") + ticket
    message = finished(TRANSCRIPT + ticket)
    corrupted = message[:-1] + bytes([message[-1] ^ 1])
    cache = TLSSessionCache()
    tls = client(Wire(ticket_record + CCS + encrypted_record(corrupted, True)), True)
    tls._server_offered_session_ticket = True
    tls._session_cache = cache
    tls._server_host = "example.com"
    assert tls._wait_for_server_handshake_completion() is False
    assert tls._new_session_ticket == (0, b"")
    assert cache.get_tls12_ticket("example.com", 443) is None


def test_unsolicited_ticket_is_rejected():
    ticket = b"\x04\x00\x00\x07\x00\x00\x00\x3c\x00\x01t"
    ticket_record = b"\x16\x03\x03" + len(ticket).to_bytes(2, "big") + ticket
    tls = client(Wire(ticket_record + CCS + encrypted_record(finished(), True)), True)
    assert tls._wait_for_server_handshake_completion() is False
