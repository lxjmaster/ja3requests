"""Transcript boundaries and Finished validation, independent of TLS framing."""

import hashlib
import hmac

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
