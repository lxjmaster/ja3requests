"""TLS 1.3 post-handshake traffic-key updates at the record boundary."""

import hashlib
import struct
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from ja3requests.exceptions import TLSDecryptionError
from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.protocol.tls.tls13 import (
    TLS13_CIPHER_PARAMS,
    TLS13Handshake,
    TLS13KeySchedule,
    TLS13RecordProtection,
)
from ja3requests.sockets.https import HttpsSocket


class ScriptedConnection:
    def __init__(self, incoming=b""):
        self.incoming = incoming
        self.sent = []

    def recv(self, size):
        chunk, self.incoming = (
            self.incoming[: min(size, 7)],
            self.incoming[min(size, 7) :],
        )
        return chunk

    def sendall(self, data):
        self.sent.append(data)


def next_secret(secret, hash_algorithm):
    label = b"tls13 traffic upd"
    info = struct.pack("!H", len(secret)) + bytes([len(label)]) + label + b"\x00"
    return HKDFExpand(algorithm=hash_algorithm, length=len(secret), info=info).derive(
        secret
    )


def make_transport(cipher):
    key_length, hash_algo = TLS13_CIPHER_PARAMS[cipher]
    schedule = TLS13KeySchedule(hash_algo)
    client_secret = b"\x11" * schedule.hash_len
    server_secret = b"\x22" * schedule.hash_len
    schedule.client_application_traffic_secret = client_secret
    schedule.server_application_traffic_secret = server_secret
    cipher_type = "chacha20-poly1305" if cipher == 0x1303 else "aes-gcm"
    client_key, client_iv = schedule.derive_traffic_keys(client_secret, key_length)
    server_key, server_iv = schedule.derive_traffic_keys(server_secret, key_length)
    handshake = TLS13Handshake(None, None, 29, b"")
    handshake._key_schedule = schedule
    handshake._hash_algo = hash_algo
    handshake._key_length = key_length
    handshake._cipher_type = cipher_type
    handshake._client_app_rp = TLS13RecordProtection(client_key, client_iv, cipher_type)
    handshake._server_app_rp = TLS13RecordProtection(server_key, server_iv, cipher_type)
    peer_server_rp = TLS13RecordProtection(server_key, server_iv, cipher_type)
    peer_client_rp = TLS13RecordProtection(client_key, client_iv, cipher_type)
    connection = ScriptedConnection()
    transport = HttpsSocket(SimpleNamespace())
    transport.conn = connection
    transport.tls = SimpleNamespace(
        _is_tls13=True,
        _tls13_handshake=handshake,
        _tls13_client_rp=handshake._client_app_rp,
        _tls13_server_rp=handshake._server_app_rp,
    )
    return transport, handshake, peer_server_rp, peer_client_rp


def read_record(protection, record):
    return protection.decrypt(record[5:], record[:5])


@pytest.mark.parametrize(
    "cipher,hash_algorithm",
    [
        (0x1301, hashes.SHA256()),
        (0x1302, hashes.SHA384()),
        (0x1303, hashes.SHA256()),
    ],
)
@pytest.mark.parametrize("reader", ["h1", "h2"])
def test_server_key_update_rotates_both_directions(cipher, hash_algorithm, reader):
    transport, handshake, peer_server, peer_client = make_transport(cipher)
    old_server_secret = handshake._key_schedule.server_application_traffic_secret
    old_client_secret = handshake._key_schedule.client_application_traffic_secret
    ticket = b"\x04\x00\x00\x03abc"
    key_update = b"\x18\x00\x00\x01\x01"
    records = [
        peer_server.encrypt(0x16, ticket[:2]),
        peer_server.encrypt(0x16, ticket[2:]),
        peer_server.encrypt(0x16, key_update),
    ]
    next_server_secret = next_secret(old_server_secret, hash_algorithm)
    next_client_secret = next_secret(old_client_secret, hash_algorithm)
    server_key, server_iv = handshake._key_schedule.derive_traffic_keys(
        next_server_secret, handshake._key_length
    )
    peer_server.update_keys(server_key, server_iv)
    body = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        if reader == "h1"
        else b"h2-data"
    )
    records.append(peer_server.encrypt(0x17, body))
    transport.conn.incoming = b"".join(records)

    if reader == "h1":
        assert transport._handle_encrypted_response().read() == body
    else:
        assert transport._decrypt_single_record() == body
    assert (
        handshake._key_schedule.server_application_traffic_secret == next_server_secret
    )
    assert (
        handshake._key_schedule.client_application_traffic_secret == next_client_secret
    )
    assert handshake._server_app_rp.seq_num == 1
    assert len(transport.conn.sent) == 1
    assert read_record(peer_client, transport.conn.sent[0]) == (
        0x16,
        b"\x18\x00\x00\x01\x00",
    )

    client_key, client_iv = handshake._key_schedule.derive_traffic_keys(
        next_client_secret, handshake._key_length
    )
    peer_client.update_keys(client_key, client_iv)
    assert read_record(peer_client, transport._encrypt_application_data(b"next")) == (
        0x17,
        b"next",
    )


@pytest.mark.parametrize(
    "reader", ["_decrypt_single_record", "_handle_encrypted_response"]
)
@pytest.mark.parametrize("message", [b"\x18\x00\x00\x01\x02", b"\x18\x00\x00\x00"])
def test_invalid_key_update_is_rejected(reader, message):
    transport, _, peer_server, _ = make_transport(0x1301)
    transport.conn.incoming = peer_server.encrypt(0x16, message)
    with pytest.raises(TLSDecryptionError, match="post-handshake"):
        getattr(transport, reader)()


@pytest.mark.parametrize(
    "reader", ["_decrypt_single_record", "_handle_encrypted_response"]
)
def test_old_server_key_cannot_encrypt_after_key_update(reader):
    transport, _, peer_server, _ = make_transport(0x1301)
    transport.conn.incoming = peer_server.encrypt(
        0x16, b"\x18\x00\x00\x01\x00"
    ) + peer_server.encrypt(0x17, b"stale")
    with pytest.raises(TLSDecryptionError, match="authentication failed"):
        getattr(transport, reader)()


@pytest.mark.parametrize(
    "reader", ["_decrypt_single_record", "_handle_encrypted_response"]
)
def test_fragmented_key_update_rotates_before_next_record(reader):
    transport, handshake, peer_server, _ = make_transport(0x1301)
    update = b"\x18\x00\x00\x01\x00"
    records = [
        peer_server.encrypt(0x16, update[:3]),
        peer_server.encrypt(0x16, update[3:]),
    ]
    secret = next_secret(
        handshake._key_schedule.server_application_traffic_secret, hashes.SHA256()
    )
    key, iv = handshake._key_schedule.derive_traffic_keys(secret, handshake._key_length)
    peer_server.update_keys(key, iv)
    body = (
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        if reader == "_handle_encrypted_response"
        else b"h2"
    )
    records.append(peer_server.encrypt(0x17, body))
    transport.conn.incoming = b"".join(records)
    result = getattr(transport, reader)()
    assert (result.read() if reader == "_handle_encrypted_response" else result) == body


def test_application_data_cannot_interrupt_fragmented_key_update():
    transport, _, peer_server, _ = make_transport(0x1301)
    transport.conn.incoming = peer_server.encrypt(
        0x16, b"\x18\x00"
    ) + peer_server.encrypt(0x17, b"unexpected")
    with pytest.raises(TLSDecryptionError, match="Incomplete"):
        transport._decrypt_single_record()


def test_key_update_before_finished_is_rejected():
    handshake = TLS13Handshake(None, None, 29, b"")
    with pytest.raises(ValueError, match="before Finished"):
        handshake.parse_encrypted_handshake(b"\x18\x00\x00\x01\x00")


def test_client_can_request_key_update():
    transport, handshake, _, peer_client = make_transport(0x1301)
    transport.send_key_update(request_update=True)
    assert read_record(peer_client, transport.conn.sent[0]) == (
        0x16,
        b"\x18\x00\x00\x01\x01",
    )
    secret = handshake._key_schedule.client_application_traffic_secret
    key, iv = handshake._key_schedule.derive_traffic_keys(secret, handshake._key_length)
    peer_client.update_keys(key, iv)
    assert read_record(
        peer_client, transport._encrypt_application_data(b"updated")
    ) == (
        0x17,
        b"updated",
    )


def test_key_update_requires_an_established_tls13_connection():
    transport = HttpsSocket(SimpleNamespace())
    with pytest.raises(ValueError, match="application keys"):
        transport.send_key_update()


def test_pool_policy_distinguishes_initial_key_share_selection():
    config = TlsConfig.secure()
    default = HttpsSocket._tls_policy_key(config, "example.com")
    config.key_share_groups = [29]
    assert HttpsSocket._tls_policy_key(config, "example.com") != default
