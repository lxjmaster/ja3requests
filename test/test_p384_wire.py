"""P-384 encoding and retry failure boundaries, without a TLS backend client."""

from types import SimpleNamespace

import pytest

from ja3requests import TlsConfig
from ja3requests.exceptions import TLSHandshakeError
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.tls13 import TLS13KeyExchange
from test.test_tls13_handshake import TestTLS13HelloRetryRequest as RetryMessages
from test.test_tls13_handshake import TestTLS13ServerHelloParsing as ServerMessages
from ja3requests.protocol.tls.tls13 import TLS13Handshake
from test.wire_client_hello import decode, profile


def test_p384_shared_secret_and_fresh_shares():
    a, ap = TLS13KeyExchange.generate_secp384r1_keypair()
    b, bp = TLS13KeyExchange.generate_secp384r1_keypair()
    assert len(ap) == len(bp) == 97 and ap[0] == bp[0] == 4 and ap != bp
    ab = TLS13KeyExchange.compute_secp384r1_shared_secret(a, bp)
    ba = TLS13KeyExchange.compute_secp384r1_shared_secret(b, ap)
    assert ab == ba and len(ab) == 48


def test_p384_server_hello_requires_offered_private_key():
    private, _ = TLS13KeyExchange.generate_x25519_keypair()
    _, public = TLS13KeyExchange.generate_secp384r1_keypair()
    hello = ServerMessages()._build_server_hello(group=24, pub_key=public)
    hs = TLS13Handshake(None, private, 29, b'ch')
    assert not hs.process_server_hello(hello)
    assert hs._key_schedule is None


def test_p384_invalid_server_point_cannot_install_traffic_keys():
    private, _ = TLS13KeyExchange.generate_secp384r1_keypair()
    hello = ServerMessages()._build_server_hello(group=24, pub_key=b'\x04' + b'\0' * 96)
    hs = TLS13Handshake(None, private, 24, b'ch')
    with pytest.raises(ValueError):
        hs.process_server_hello(hello)
    assert hs._key_schedule is None


@pytest.mark.parametrize(
    'point', [b'', b'\x04' + b'\0' * 96, b'\x02' + b'x' * 48, b'\x04' + b'x' * 95]
)
def test_p384_rejects_malformed_point(point):
    private, _ = TLS13KeyExchange.generate_secp384r1_keypair()
    with pytest.raises(ValueError):
        TLS13KeyExchange.compute_secp384r1_shared_secret(private, point)


@pytest.mark.parametrize('group', [23, 25, 29, 65535])
def test_retry_rejects_unadvertised_or_already_offered_group(group):
    config = TlsConfig()
    config.supported_groups = [29, 24]
    config.key_share_groups = [29]
    tls = TLS(None)
    tls.set_payload(config)
    with pytest.raises(TLSHandshakeError):
        tls._parse_hello_retry_request(RetryMessages.retry(group=group))


def test_retry_generates_fresh_p384_and_preserves_exact_order_with_cookie():
    public = []
    for _ in range(2):
        sent = []
        config = TlsConfig()
        config.supported_groups = [29, 24]
        config.key_share_groups = [29]
        config.extension_order = [43, 10, 51, 13, 16, 45, 23]
        tls = TLS(SimpleNamespace(sendall=sent.append))
        tls.set_payload(config)
        tls._handshake_messages = tls.body.handshake_message
        retry = RetryMessages.retry(group=24, cookie=b'cookie')
        suite, group, cookie = tls._parse_hello_retry_request(retry)
        tls._send_retried_client_hello(retry, suite, group, cookie)
        assert profile(sent[0])['key_shares'] == [[24, 97]]
        assert [
            k for k, _ in decode(sent[0])['extensions']
        ] == config.extension_order + [44]
        public.append(dict(decode(sent[0])['extensions'])[51])
    assert public[0] != public[1]
