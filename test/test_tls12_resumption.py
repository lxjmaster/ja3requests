"""TLS 1.2 Session ID offer and ServerHello validation boundaries."""

import time

import pytest

from ja3requests.exceptions import TLSHandshakeError
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.protocol.tls.extensions import SessionTicketExtension
from ja3requests.protocol.tls.session_cache import TLSSessionCache


def make_tls(cache, verify=True, ticket=False):
    config = TlsConfig.secure()
    config.tls_version = 0x0303
    config.cipher_suites = [0xC02F]
    config.verify_cert = verify
    if ticket:
        config.extensions.append(SessionTicketExtension())
    tls = TLS(None, session_cache=cache, server_host="example.com", server_port=443)
    tls.set_payload(config)
    return tls


def put_session(cache, **kwargs):
    values = dict(
        tls_version=b"\x03\x03",
        extended_master_secret=True,
        verified=True,
        verified_hostname="example.com",
        sni="example.com",
    )
    values.update(kwargs)
    cache.put("example.com", 443, b"session-id", b"m" * 48, 0xC02F, **values)


def put_ticket(cache, **kwargs):
    values = dict(
        tls_version=b"\x03\x03",
        extended_master_secret=True,
        verified=True,
        verified_hostname="example.com",
        sni="example.com",
    )
    values.update(kwargs)
    cache.put_tls12_ticket(
        "example.com", 443, b"ticket", b"m" * 48, 0xC02F, 300, **values
    )


@pytest.mark.parametrize(
    "override",
    [
        {"extended_master_secret": False},
        {"verified": False},
        {"verified_hostname": "other.example.com"},
        {"sni": "other.example.com"},
        {"is_ticket": True},
        {"certificate_expires_at": time.time() - 1},
    ],
)
def test_incompatible_session_is_not_offered(override):
    cache = TLSSessionCache()
    put_session(cache, **override)
    tls = make_tls(cache)
    assert tls._offered_session is None
    assert tls.body.session_id == b"\x00"


def test_removing_tls12_session_keeps_tls13_ticket():
    cache = TLSSessionCache()
    put_session(cache)
    cache.put_tls13(
        "example.com",
        443,
        b"ticket",
        b"p" * 32,
        0x1301,
        300,
        5,
        "example.com",
    )
    cache.remove_tls12("example.com", 443, b"session-id")
    assert cache.get("example.com", 443) is None
    assert cache.get_tls13("example.com", 443) is not None


def test_ticket_offer_keeps_session_id_cache_separate():
    cache = TLSSessionCache()
    put_session(cache)
    put_ticket(cache)
    tls = make_tls(cache, ticket=True)
    assert tls._offered_session is cache.get_tls12_ticket("example.com", 443)
    assert len(tls.body.session_id) == 32
    assert tls.body.session_id != b"session-id"
    extension = next(
        ext for ext in tls.body._custom_extensions if ext.extension_type == 0x0023
    )
    assert extension.ticket == b"ticket"
    assert cache.get("example.com", 443).session_id == b"session-id"


@pytest.mark.parametrize(
    "override",
    [
        {"extended_master_secret": False},
        {"verified": False},
        {"verified_hostname": "other.example.com"},
        {"sni": "other.example.com"},
        {"certificate_expires_at": time.time() - 1},
    ],
)
def test_incompatible_ticket_is_not_offered(override):
    cache = TLSSessionCache()
    put_ticket(cache, **override)
    tls = make_tls(cache, ticket=True)
    assert tls._offered_session is None
    assert tls.body.session_id == b"\x00"


def test_incompatible_ticket_falls_back_to_valid_session_id():
    cache = TLSSessionCache()
    put_session(cache)
    put_ticket(cache, verified=False)
    tls = make_tls(cache, ticket=True)
    assert tls._offered_session is cache.get("example.com", 443)
    assert tls.body.session_id == b"session-id"


def test_ticket_lifetime_does_not_expire_session_id():
    cache = TLSSessionCache(max_size=2)
    put_session(cache)
    put_ticket(cache)
    entry = cache.get_tls12_ticket("example.com", 443)
    entry.received_at -= 301
    assert cache.get_tls12_ticket("example.com", 443) is None
    assert cache.get("example.com", 443) is not None


@pytest.mark.parametrize(
    "field,value",
    [
        ("_selected_cipher_suite", 0xC030),
        ("_extended_master_secret", False),
        ("_server_legacy_version", b"\x03\x01"),
        ("_selected_compression_method", 1),
    ],
)
def test_echoed_session_id_rejects_changed_parameters(field, value):
    cache = TLSSessionCache()
    put_session(cache)
    tls = make_tls(cache)
    assert tls.body.session_id == b"session-id"
    tls._server_session_id = b"session-id"
    tls._server_legacy_version = b"\x03\x03"
    tls._selected_cipher_suite = 0xC02F
    tls._extended_master_secret = True
    tls._selected_compression_method = 0
    setattr(tls, field, value)
    with pytest.raises(TLSHandshakeError, match="resumed"):
        tls._check_resumed_server_hello()
