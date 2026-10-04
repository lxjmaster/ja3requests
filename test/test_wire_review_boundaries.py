"""Protocol boundaries for configurable ClientHello fields."""

from types import SimpleNamespace

import pytest

from ja3requests import TlsConfig
from ja3requests.exceptions import TLSHandshakeError
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.extensions import PSKKeyExchangeModesExtension
from ja3requests.protocol.tls.session_cache import TLSSessionCache
from test import test_tls13_handshake as retry_messages
from test.test_tls_version_selection import server_hello
from test.wire_client_hello import decode


@pytest.mark.parametrize('version', [0x0301, 0x0302, 0x0303])
@pytest.mark.parametrize('protocol', [0x0303, 0x0304])
def test_record_version_depends_on_offered_protocol(protocol, version):
    config = TlsConfig()
    config.tls_version = protocol
    config.client_hello_record_version = version
    tls = TLS(None)
    if protocol == 0x0304 and version == 0x0302:
        with pytest.raises(TLSHandshakeError, match='record version'):
            tls.set_payload(config)
    else:
        tls.set_payload(config)
        assert tls.body.message[1:3] == version.to_bytes(2, 'big')


@pytest.mark.parametrize('version', [0x0301, 0x0303])
@pytest.mark.parametrize('group', [None, 24])
def test_retry_always_uses_tls12_record_header(version, group):
    config = TlsConfig()
    config.supported_groups = [29, 24]
    config.key_share_groups = [29]
    config.client_hello_record_version = version
    sent = []
    tls = TLS(SimpleNamespace(sendall=sent.append))
    tls.set_payload(config)
    tls._send_client_hello(tls.body)
    tls._handshake_messages = tls.body.handshake_message
    retry = retry_messages.TestTLS13HelloRetryRequest.retry(group=group, cookie=b'cookie')
    suite, selected, cookie = tls._parse_hello_retry_request(retry)
    tls._send_retried_client_hello(retry, suite, selected, cookie)
    assert sent[0][1:3] == version.to_bytes(2, 'big')
    assert sent[1][1:3] == b'\x03\x03'
    assert decode(sent[0])['random'] == decode(sent[1])['random']
    assert config.client_hello_record_version == version


@pytest.mark.parametrize('identity', [b'', b'\0', b'identity', b'x' * 32])
@pytest.mark.parametrize('matches', [False, True])
def test_tls13_requires_session_id_echo(identity, matches):
    config = TlsConfig()
    config.session_id = identity
    tls = TLS(None)
    tls.set_payload(config)
    # Read the actual serialized ID, including explicit empty and one-byte zero.
    offered = decode(tls.body.message)['session_id']
    echo = offered if matches else (b'wrong' if not offered else b'')
    hello = server_hello(0x1301, b'\x03\x04')
    hello = hello[:34] + bytes([len(echo)]) + echo + hello[35:]
    tls._parse_server_hello(hello)
    if matches:
        assert tls._selected_handshake_version() == b'\x03\x04'
    else:
        with pytest.raises(TLSHandshakeError, match='session ID'):
            tls._selected_handshake_version()


def test_tls12_fallback_can_assign_a_different_session_id():
    config = TlsConfig()
    config.session_id = b'client-id'
    tls = TLS(None)
    tls.set_payload(config)
    hello = server_hello(0xC02F)
    hello = hello[:34] + b'\x06server' + hello[35:]
    tls._parse_server_hello(hello)
    assert tls._selected_handshake_version() == b'\x03\x03'


@pytest.mark.parametrize('modes', [[0], [0, 1], [1, 0], [2], [1, 1], [1]])
@pytest.mark.parametrize('cached', [False, True])
def test_psk_modes_match_implemented_resumption(modes, cached):
    cache = TLSSessionCache()
    if cached:
        cache.put_tls13(
            'example.com', 443, b'ticket', b'p' * 32, 0x1301, 300, 0,
            'example.com', verified=True, verified_hostname='example.com',
        )
    config = TlsConfig()
    config.extensions.append(PSKKeyExchangeModesExtension(modes))
    tls = TLS(None, session_cache=cache, server_host='example.com', server_port=443)
    if modes != [1]:
        with pytest.raises(TLSHandshakeError, match='Custom extension conflicts'):
            tls.set_payload(config)
        assert tls.sent_client_hellos == ()
    else:
        tls.set_payload(config)
        extensions = dict(decode(tls.body.message)['extensions'])
        assert extensions[45] == b'\x01\x01'
        assert (41 in extensions) == cached
