"""TLS 1.3 ticket cache and ClientHello policy boundaries."""

import time
from types import SimpleNamespace

import pytest

from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.protocol.tls.extensions import SessionTicketExtension
from ja3requests.protocol.tls.session_cache import TLSSessionCache
from ja3requests.protocol.tls.tls13 import TLS13Handshake, TLS13KeyExchange


def test_ticket_lifetime_and_global_ttl():
    cache = TLSSessionCache(ttl=10)
    cache.put_tls13(
        "example.com",
        443,
        b"ticket",
        b"p" * 32,
        0x1301,
        1,
        5,
        "example.com",
        verified=True,
        verified_hostname="example.com",
    )
    entry = cache.get_tls13("example.com", 443)
    assert entry.obfuscated_age() >= 5
    entry.received_at = time.monotonic() - 2
    assert cache.get_tls13("example.com", 443) is None


def test_ticket_expires_with_verified_certificate():
    cache = TLSSessionCache()
    cache.put_tls13(
        "example.com",
        443,
        b"ticket",
        b"p" * 32,
        0x1301,
        300,
        5,
        "example.com",
        verified=True,
        verified_hostname="example.com",
        certificate_expires_at=time.time() - 1,
    )
    assert cache.get_tls13("example.com", 443) is None


def test_cache_limit_and_remove_cover_both_tls_versions():
    cache = TLSSessionCache(max_size=1)
    cache.put("example.com", 443, b"session", b"secret", 0xC02F)
    cache.put_tls13(
        "example.com", 443, b"ticket", b"p" * 32, 0x1301, 300, 5, "example.com"
    )
    assert cache.get("example.com", 443) is None
    assert len(cache) == 1
    cache.remove("example.com", 443)
    assert cache.get_tls13("example.com", 443) is None


@pytest.mark.parametrize("opaque_ticket", [b"", b"\x00\x29"])
def test_verified_request_does_not_offer_unverified_ticket(opaque_ticket):
    cache = TLSSessionCache()
    cache.put_tls13(
        "example.com", 443, b"ticket", b"p" * 32, 0x1301, 300, 5, "example.com"
    )
    config = TlsConfig.secure()
    config.session_cache = cache
    if opaque_ticket:
        # Opaque extension payloads may contain the PSK type's byte sequence.
        config.extensions.append(SessionTicketExtension(opaque_ticket))
    tls = TLS(None, session_cache=cache, server_host="example.com", server_port=443)
    tls.set_payload(config)
    assert tls._tls13_psk is None
    encoded = tls.body.extensions
    assert int.from_bytes(encoded[:2], "big") == len(encoded) - 2
    offset = 2
    while offset < len(encoded):
        assert offset + 4 <= len(encoded)
        kind = int.from_bytes(encoded[offset : offset + 2], "big")
        size = int.from_bytes(encoded[offset + 2 : offset + 4], "big")
        assert kind != 0x0029
        offset += 4 + size
    assert offset == len(encoded)


def test_client_certificate_does_not_offer_cached_psk():
    cache = TLSSessionCache()
    cache.put_tls13(
        "example.com",
        443,
        b"ticket",
        b"p" * 32,
        0x1301,
        300,
        5,
        "example.com",
        verified=True,
        verified_hostname="example.com",
    )
    config = TlsConfig.secure()
    config.client_cert = b"configured-client-certificate"
    config.client_key = b"configured-client-key"
    tls = TLS(None, session_cache=cache, server_host="example.com", server_port=443)
    tls.set_payload(config)
    assert tls._tls13_psk is None
    assert b"\x00\x29" not in tls.body.extensions


def test_ticket_requires_same_sni_and_offered_cipher():
    cache = TLSSessionCache()
    cache.put_tls13(
        "example.com",
        443,
        b"ticket",
        b"p" * 32,
        0x1301,
        300,
        5,
        "example.com",
        verified=True,
        verified_hostname="example.com",
    )
    config = TlsConfig.secure()
    config.session_cache = cache
    config.server_name = "other.example.com"
    tls = TLS(None, session_cache=cache, server_host="example.com", server_port=443)
    tls.set_payload(config)
    assert tls._tls13_psk is None
    config.server_name = "example.com"
    config.cipher_suites = [0x1302]
    tls.set_payload(config)
    assert tls._tls13_psk is None


@pytest.mark.parametrize("suite,selected", [(0x1301, 1), (0x1302, 0)])
def test_server_cannot_select_unknown_or_incompatible_psk(suite, selected):
    private_key, _ = TLS13KeyExchange.generate_x25519_keypair()
    _, public_key = TLS13KeyExchange.generate_x25519_keypair()
    ticket = SimpleNamespace(cipher_suite=0x1301, psk=b"p" * 32)
    handshake = TLS13Handshake(None, private_key, 29, b"hello", offered_psk=ticket)
    share = b"\x00\x1d" + len(public_key).to_bytes(2, "big") + public_key
    extensions = b"\x00\x33" + len(share).to_bytes(2, "big") + share
    extensions += b"\x00\x29\x00\x02" + selected.to_bytes(2, "big")
    server_hello = (
        b"\x03\x03"
        + bytes(32)
        + b"\x00"
        + suite.to_bytes(2, "big")
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    assert not handshake.process_server_hello(server_hello)
