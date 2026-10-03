"""Transcript boundaries and Finished validation, independent of TLS framing."""

import hashlib
import hmac
import struct

import pytest

from ja3requests.protocol.tls.tls13 import (
    TLS13Handshake,
    TLS13KeySchedule,
    TLS13RecordProtection,
)


def message(kind, body):
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def handshake():
    hs = TLS13Handshake(None, None, 29, b"hello transcript")
    hs._key_schedule = TLS13KeySchedule()
    hs._key_schedule.compute_handshake_secret(b"shared secret", hs._transcript)
    hs._client_handshake_rp = TLS13RecordProtection(b"\x01" * 16, b"\x02" * 12)
    return hs


def finished(hs, transcript):
    key = hs._key_schedule.compute_finished_key(
        hs._key_schedule.server_handshake_traffic_secret
    )
    return message(
        20, hmac.new(key, hashlib.sha256(transcript).digest(), hashlib.sha256).digest()
    )


@pytest.mark.parametrize("split", [1, 3, 5, 7, 20, 41])
def test_finished_validated_after_reassembling_messages(split):
    hs = handshake()
    extensions = message(8, b"\x00\x00")
    initial = hs._transcript
    wire = extensions + finished(hs, initial + extensions)
    messages = hs.parse_encrypted_handshake(wire[:split])
    messages += hs.parse_encrypted_handshake(wire[split:])
    assert [kind for kind, _ in messages] == [8, 20]
    assert hs._transcript == initial + wire
    client, server = hs.derive_application_keys()
    # Appending a client Finished must not change the application-key context.
    hs.build_client_finished()
    later_client, later_server = hs.derive_application_keys()
    assert (client.key, client.iv) == (later_client.key, later_client.iv)
    assert (server.key, server.iv) == (later_server.key, later_server.iv)


def test_invalid_finished_rejected_without_advancing_transcript():
    hs = handshake()
    initial = hs._transcript
    valid = finished(hs, initial)
    invalid = valid[:-1] + bytes([valid[-1] ^ 1])
    with pytest.raises(ValueError, match="invalid server Finished"):
        hs.parse_encrypted_handshake(invalid)
    assert hs._transcript == initial
    assert hs._server_finished_transcript is None


@pytest.mark.parametrize("body", [b"", b"\x00\x04\x00", b"\x00\x05\x00\x10\x00\x05x"])
def test_malformed_encrypted_extensions_rejected(body):
    hs = handshake()
    with pytest.raises(ValueError, match="TLS 1.3:"):
        hs.parse_encrypted_handshake(message(8, body))


def test_verified_handshake_requires_certificate_verify():
    hs = handshake()
    hs._certificate_verifier = lambda data: None
    with pytest.raises(ValueError, match="missing server CertificateVerify"):
        hs.parse_encrypted_handshake(finished(hs, hs._transcript))


def test_client_certificate_request_signature_algorithms():
    hs = handshake()
    algorithms = b"\x00\x04\x08\x04\x04\x03"
    extension = struct.pack("!HH", 13, len(algorithms)) + algorithms
    request = b"\x00" + len(extension).to_bytes(2, "big") + extension
    messages = hs.parse_encrypted_handshake(
        message(8, b"\x00\x00") + message(13, request)
    )
    assert [kind for kind, _ in messages] == [8, 13]
    assert hs._client_certificate_requested is True
    assert hs._client_signature_algorithms == (0x0804, 0x0403)


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\x01x\x00\x00",
        b"\x00\x00\x00",
        b"\x00\x00\x04\x00\x0d\x00\x00",
        b"\x00\x00\x08\x00\x0d\x00\x04\x00\x03\x08\x04",
    ],
)
def test_malformed_client_certificate_request_is_rejected(body):
    hs = handshake()
    hs.parse_encrypted_handshake(message(8, b"\x00\x00"))
    transcript = hs._transcript
    with pytest.raises(ValueError, match="CertificateRequest|signature algorithms"):
        hs.parse_encrypted_handshake(message(13, body))
    assert hs._transcript == transcript


def post_handshake_request(context):
    algorithms = b"\x00\x02\x08\x04"
    extension = struct.pack("!HH", 13, len(algorithms)) + algorithms
    body = (
        bytes([len(context)]) + context + len(extension).to_bytes(2, "big") + extension
    )
    return message(13, body)


def test_post_handshake_auth_reassembles_and_keeps_transcripts_independent():
    hs = handshake()
    hs._post_handshake_auth = True
    hs._server_finished_transcript = hs._transcript
    hs.build_client_finished()
    hs.derive_application_keys()
    base = hs._transcript
    peer = TLS13RecordProtection(hs._client_app_rp.key, hs._client_app_rp.iv)

    first = post_handshake_request(b"first")
    assert hs.process_post_handshake(first[:5]) == []
    first_records = hs.process_post_handshake(first[5:])
    assert len(first_records) == 1
    assert hs._transcript == base
    certificate = []
    wire = first_records[0]
    while wire:
        size = int.from_bytes(wire[3:5], "big")
        kind, body = peer.decrypt(wire[5 : 5 + size], wire[:5])
        assert kind == 22
        certificate.append(body)
        wire = wire[5 + size :]
    assert [part[0] for part in certificate] == [11, 20]
    assert certificate[0][4:10] == b"\x05first"
    finished_key = hs._key_schedule.compute_finished_key(
        hs._key_schedule.client_application_traffic_secret
    )
    expected = hmac.new(
        finished_key,
        hashlib.sha256(base + first + certificate[0]).digest(),
        hashlib.sha256,
    )
    assert certificate[1][4:] == expected.digest()

    second = post_handshake_request(b"second")
    second_records = hs.process_post_handshake(second)
    assert second_records
    wire = second_records[0]
    parts = []
    while wire:
        size = int.from_bytes(wire[3:5], "big")
        _, body = peer.decrypt(wire[5 : 5 + size], wire[:5])
        parts.append(body)
        wire = wire[5 + size :]
    assert parts[0][4:11] == b"\x06second"
    expected = hmac.new(
        finished_key,
        hashlib.sha256(base + second + parts[0]).digest(),
        hashlib.sha256,
    )
    assert parts[1][4:] == expected.digest()
    update = hs.build_key_update()
    kind, body = peer.decrypt(update[5:], update[:5])
    assert kind == 22
    assert body == b"\x18\x00\x00\x01\x00"
    peer = TLS13RecordProtection(hs._client_app_rp.key, hs._client_app_rp.iv)
    third = post_handshake_request(b"third")
    wire = hs.process_post_handshake(third)[0]
    parts = []
    while wire:
        size = int.from_bytes(wire[3:5], "big")
        _, body = peer.decrypt(wire[5 : 5 + size], wire[:5])
        parts.append(body)
        wire = wire[5 + size :]
    rotated_key = hs._key_schedule.compute_finished_key(
        hs._key_schedule.client_application_traffic_secret
    )
    expected = hmac.new(
        rotated_key,
        hashlib.sha256(base + third + parts[0]).digest(),
        hashlib.sha256,
    )
    assert parts[1][4:] == expected.digest()
    assert rotated_key != finished_key
    with pytest.raises(ValueError, match="context"):
        hs.process_post_handshake(first)


def test_post_handshake_auth_without_advertisement_is_rejected():
    hs = handshake()
    hs._server_finished_transcript = hs._transcript
    hs.build_client_finished()
    hs.derive_application_keys()
    with pytest.raises(ValueError, match="Unexpected"):
        hs.process_post_handshake(post_handshake_request(b"context"))


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\x01\x00\x00\x00",
        b"\x00\x00\x00\x00",
        b"\x00\x00\x00\x01x",
        b"\x00\x00\x00\x03\x00\x00\x00",
    ],
)
def test_tls13_malformed_certificate_is_rejected(body):
    hs = handshake()
    with pytest.raises(ValueError, match="TLS 1.3:"):
        hs.parse_encrypted_handshake(message(11, body))
