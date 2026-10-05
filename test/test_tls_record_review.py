"""Authenticated record endings must agree across the two transport drivers."""

import asyncio
import hashlib
import hmac
import io
import socket
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ja3requests.async_transport import AsyncTransport
from ja3requests.exceptions import TLSDecryptionError
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.tls13 import TLS13RecordProtection
from ja3requests.sockets.https import HttpsSocket, TLSRecordCodec


KEY = b'k' * 16
IV = b'i' * 12
MAC_KEY = b'm' * 20
PROTOCOLS = ['tls12-cbc', 'tls12-gcm', 'tls13']


def encrypted_record(
    protocol,
    kind,
    payload,
    sequence=0,
    bad_padding=False,
    padding_count=None,
    bad_padding_index=0,
):
    """Encode an independent peer record, including its authenticated type."""
    prefix = bytes([kind]) + b'\x03\x03'
    if protocol == 'tls13':
        plaintext = payload + bytes([kind])
        header = b'\x17\x03\x03' + (len(plaintext) + 16).to_bytes(2, 'big')
        nonce = bytes(a ^ b for a, b in zip(IV, sequence.to_bytes(12, 'big')))
        return header + AESGCM(KEY).encrypt(nonce, plaintext, header)
    aad = sequence.to_bytes(8, 'big') + prefix + len(payload).to_bytes(2, 'big')
    if protocol == 'tls12-gcm':
        explicit = sequence.to_bytes(8, 'big')
        encrypted = explicit + AESGCM(KEY).encrypt(IV[:4] + explicit, payload, aad)
    else:
        plaintext = payload + hmac.new(MAC_KEY, aad + payload, hashlib.sha1).digest()
        count = padding_count or 16 - len(plaintext) % 16
        assert 1 <= count <= 256 and (len(plaintext) + count) % 16 == 0
        padding = bytes([count - 1]) * count
        if bad_padding:
            padding = (
                padding[:bad_padding_index]
                + bytes([padding[bad_padding_index] ^ 1])
                + padding[bad_padding_index + 1 :]
            )
        encryptor = Cipher(algorithms.AES(KEY), modes.CBC(b'v' * 16)).encryptor()
        encrypted = b'v' * 16 + encryptor.update(plaintext + padding)
        encrypted += encryptor.finalize()
    return prefix + len(encrypted).to_bytes(2, 'big') + encrypted


def tls_state(protocol):
    tls = TLS(None)
    tls._is_tls13 = protocol == 'tls13'
    tls._is_gcm = protocol == 'tls12-gcm'
    tls._selected_cipher_suite = 0xC02F if tls._is_gcm else 0x002F
    tls._server_write_key = KEY
    tls._server_write_iv = IV[:4]
    tls._server_write_mac_key = MAC_KEY
    tls._server_seq_num = 0
    if tls._is_tls13:
        tls._tls13_server_rp = TLS13RecordProtection(KEY, IV)
    return tls


def read_wire(adapter, protocol, wire):
    """Exercise the actual drivers, including asynchronous socket reads."""
    tls = tls_state(protocol)
    if adapter == 'sync':
        incoming = io.BytesIO(wire)
        transport = HttpsSocket(SimpleNamespace())
        transport.tls = tls
        transport.conn = SimpleNamespace(recv=incoming.read)
        chunks = []
        while True:
            chunk = transport._decrypt_single_record()
            if chunk is None:
                return b''.join(chunks)
            chunks.append(chunk)

    async def scenario():
        left, right = socket.socketpair()
        transport = AsyncTransport(left)
        transport.tls = tls
        transport._codec = TLSRecordCodec(tls)
        try:
            right.sendall(wire)
            right.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = await transport.read(65536)
                if not chunk:
                    return b''.join(chunks)
                chunks.append(chunk)
        finally:
            await transport.aclose()
            right.close()

    return asyncio.run(scenario())


@pytest.mark.parametrize('adapter', ['sync', 'async'])
@pytest.mark.parametrize('protocol', PROTOCOLS)
def test_empty_records_preserve_sequence_before_authenticated_close(adapter, protocol):
    wire = encrypted_record(protocol, 23, b'')
    wire += encrypted_record(protocol, 23, b'prefix', sequence=1)
    wire += encrypted_record(protocol, 21, b'\x01\x00', sequence=2)
    assert read_wire(adapter, protocol, wire) == b'prefix'


@pytest.mark.parametrize('adapter', ['sync', 'async'])
@pytest.mark.parametrize('protocol', ['tls12-cbc', 'tls12-gcm'])
@pytest.mark.parametrize('fault', ['tag', 'sequence', 'type', 'plaintext'])
def test_tls12_close_alert_must_authenticate(adapter, protocol, fault):
    record = encrypted_record(
        protocol,
        23 if fault == 'type' else 21,
        b'\x01\x00',
        sequence=1 if fault == 'sequence' else 0,
    )
    if fault == 'tag':
        record = record[:-1] + bytes([record[-1] ^ 1])
    elif fault == 'type':
        record = b'\x15' + record[1:]
    elif fault == 'plaintext':
        record = b'\x15\x03\x03\x00\x02\x01\x00'
    with pytest.raises(TLSDecryptionError):
        read_wire(adapter, protocol, record)


@pytest.mark.parametrize('adapter', ['sync', 'async'])
def test_tls12_close_alert_rejects_invalid_cbc_padding(adapter):
    record = encrypted_record('tls12-cbc', 21, b'\x01\x00', bad_padding=True)
    with pytest.raises(TLSDecryptionError):
        read_wire(adapter, 'tls12-cbc', record)


@pytest.mark.parametrize('adapter', ['sync', 'async'])
@pytest.mark.parametrize('offset', [0, 11, 22])
def test_tls12_application_record_rejects_invalid_cbc_padding(adapter, offset):
    record = encrypted_record(
        'tls12-cbc',
        23,
        b'body',
        padding_count=24,
        bad_padding=True,
        bad_padding_index=offset,
    )
    with pytest.raises(TLSDecryptionError):
        read_wire(adapter, 'tls12-cbc', record)


@pytest.mark.parametrize('adapter', ['sync', 'async'])
@pytest.mark.parametrize(
    'payload,padding_count',
    [(b'x' * 11, 1), (b'body', 8), (b'body', 24), (b'x' * 12, 256)],
)
def test_tls12_application_record_accepts_valid_cbc_padding(
    adapter, payload, padding_count
):
    record = encrypted_record('tls12-cbc', 23, payload, padding_count=padding_count)
    record += encrypted_record('tls12-cbc', 21, b'\x01\x00', sequence=1)
    assert read_wire(adapter, 'tls12-cbc', record) == payload


def test_invalid_cbc_record_does_not_advance_the_receive_sequence():
    tls = tls_state('tls12-cbc')
    codec = TLSRecordCodec(tls)
    invalid = encrypted_record('tls12-cbc', 23, b'body', bad_padding=True)
    with pytest.raises(TLSDecryptionError):
        codec.decode_record(invalid[:5], invalid[5:])
    assert tls._server_seq_num == 0

    valid = encrypted_record('tls12-cbc', 23, b'body')
    assert codec.decode_record(valid[:5], valid[5:]) == (23, b'body')
    assert tls._server_seq_num == 1


@pytest.mark.parametrize('adapter', ['sync', 'async'])
@pytest.mark.parametrize('protocol', PROTOCOLS)
@pytest.mark.parametrize('payload', [b'', b'\x01', b'\x01\x00extra', b'\x02\x50'])
def test_malformed_or_error_alert_is_not_eof(adapter, protocol, payload):
    record = encrypted_record(protocol, 21, payload)
    with pytest.raises(TLSDecryptionError):
        read_wire(adapter, protocol, record)


@pytest.mark.parametrize('adapter', ['sync', 'async'])
@pytest.mark.parametrize('level', [2, 3])
def test_tls12_close_alert_requires_warning_level(adapter, level):
    record = encrypted_record('tls12-gcm', 21, bytes([level, 0]))
    with pytest.raises(TLSDecryptionError):
        read_wire(adapter, 'tls12-gcm', record)


@pytest.mark.parametrize('adapter', ['sync', 'async'])
def test_tls13_close_alert_ignores_legacy_level(adapter):
    record = encrypted_record('tls13', 21, b'\x02\x00')
    assert read_wire(adapter, 'tls13', record) == b''


@pytest.mark.parametrize('adapter', ['sync', 'async'])
@pytest.mark.parametrize('protocol', PROTOCOLS)
def test_unexpected_record_is_not_eof(adapter, protocol):
    record = encrypted_record(protocol, 20, b'\x01')
    with pytest.raises(TLSDecryptionError):
        read_wire(adapter, protocol, record)
