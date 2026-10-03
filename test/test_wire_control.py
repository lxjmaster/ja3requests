"""Wire configuration acceptance, independent of project-side inspection."""

import json
import socket
from pathlib import Path

import pytest

from ja3requests import TlsConfig
from ja3requests.exceptions import TLSHandshakeError
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.client_hello_info import inspect_client_hello
from ja3requests.protocol.tls.extensions import ExtendedMasterSecretExtension
from test.wire_client_hello import decode, profile


@pytest.mark.parametrize('name', ['secure', 'legacy', 'chrome120'])
def test_published_baseline(name):
    configs = {
        'secure': TlsConfig(),
        'legacy': TlsConfig.legacy(),
        'chrome120': TlsConfig.from_browser('chrome', 120),
    }
    expected = json.loads(
        (Path(__file__).parent / 'fixtures/wire_baseline.json').read_text()
    )
    tls = TLS(None, server_host='example.com')
    tls.set_payload(configs[name])
    assert profile(tls.body.message) == expected[name]


@pytest.mark.parametrize('identity', [b'', b'\0', b'example-session', b'x' * 32])
def test_session_id_is_sent(identity):
    config = TlsConfig()
    config.session_id = identity
    left, right = socket.socketpair()
    try:
        tls = TLS(left, server_host='example.com')
        tls.set_payload(config)
        tls._send_client_hello(tls.body)
        received = right.recv(65535)
        assert decode(received)['session_id'] == identity
        assert tls.sent_client_hellos == (received,)
        assert inspect_client_hello(received)['ja3'] == profile(received)['ja3']
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize(
    'field,value',
    [
        ('compression_methods', [0, 1]),
        ('session_id', b'x' * 33),
        ('session_id', 'bad'),
        ('supported_groups', []),
        ('cipher_suites', []),
        ('client_random', b''),
        ('client_hello_record_version', 0x0304),
    ],
)
def test_invalid_config_fails_before_send(field, value):
    config = TlsConfig()
    with pytest.raises((TLSHandshakeError, ValueError)):
        setattr(config, field, value)
        TLS(None).set_payload(config)


def test_exact_order_and_record_version():
    config = TlsConfig()
    config.extension_order = [0, 10, 13, 16, 43, 45, 51, 23]
    config.client_hello_record_version = 0x0303
    tls = TLS(None, server_host='example.com')
    tls.set_payload(config)
    hello = decode(tls.body.message)
    assert [k for k, _ in hello['extensions']] == config.extension_order
    assert hello['record_version'] == '0303'
    config.extension_order.pop()
    with pytest.raises(ValueError, match='every emitted'):
        TLS(None, server_host='example.com').set_payload(config)


def test_duplicate_extension_is_not_silently_sent():
    config = TlsConfig()
    config.extensions.append(ExtendedMasterSecretExtension())
    with pytest.raises(ValueError, match='Duplicate'):
        TLS(None).set_payload(config)


@pytest.mark.parametrize('record', [b'', b'\x16\x03\x01\x00\x04\x01\x00\x00\x00'])
def test_inspector_rejects_truncation(record):
    with pytest.raises(ValueError):
        inspect_client_hello(record)


def test_custom_declarations_cannot_disagree_with_handshake_state():
    from ja3requests.protocol.tls.extensions import (
        SupportedGroupsExtension,
        KeyShareExtension,
    )

    for extension in (
        SupportedGroupsExtension([24]),
        KeyShareExtension([(29, b'x' * 32)]),
    ):
        config = TlsConfig()
        config.extensions.append(extension)
        with pytest.raises(TLSHandshakeError):
            TLS(None).set_payload(config)


def test_unknown_extension_encoding_is_available_without_claiming_protocol_support():
    from ja3requests.protocol.tls.extensions import Extension

    class Opaque(Extension):
        extension_type = 60000

        def encode(self):
            return b'example'

    config = TlsConfig()
    config.extensions.append(Opaque())
    tls = TLS(None)
    tls.set_payload(config)
    assert dict(decode(tls.body.message)['extensions'])[60000] == b'example'


@pytest.mark.parametrize('identity', [b'explicit', b''])
def test_explicit_session_id_is_not_replaced_by_tls12_cache(identity):
    from ja3requests.protocol.tls.session_cache import TLSSessionCache
    from test.test_tls12_resumption import put_session

    cache = TLSSessionCache()
    put_session(cache)
    config = TlsConfig()
    config.tls_version = 0x0303
    config.session_id = identity
    tls = TLS(None, session_cache=cache, server_host='example.com', server_port=443)
    tls.set_payload(config)
    assert tls._offered_session is None
    assert decode(tls.body.message)['session_id'] == identity


def test_custom_sni_cannot_diverge_from_cache_identity():
    from ja3requests.protocol.tls.extensions import SNIExtension

    config = TlsConfig()
    config.extensions.append(SNIExtension('other.example'))
    with pytest.raises(TLSHandshakeError, match='Custom SNI'):
        TLS(None, server_host='example.com').set_payload(config)
    config.server_name = 'other.example'
    tls = TLS(None, server_host='example.com')
    tls.set_payload(config)
    assert tls._server_name == 'other.example'
