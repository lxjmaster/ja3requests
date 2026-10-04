"""Independent OpenSSL P-384 peer, project-owned client and wire observation."""

import ssl

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.client_hello_info import inspect_client_hello
from ja3requests.sockets.https import HttpsSocket
from test.mock_servers.local import LocalServer, read_headers, tls13_context
from test.wire_client_hello import decode, profile


@pytest.mark.parametrize('retry', [False, True])
@pytest.mark.parametrize('fragmented', [False, True])
@pytest.mark.parametrize('cipher', [0x1301, 0x1302])
def test_p384_handshake_and_retry(
    trusted_certificates, monkeypatch, retry, fragmented, cipher
):
    wrap = ssl.SSLContext.wrap_socket

    def server_only(context, *args, **kwargs):
        assert kwargs.get('server_side') is True, 'Client delegated TLS to OpenSSL'
        return wrap(context, *args, **kwargs)

    monkeypatch.setattr(ssl.SSLContext, 'wrap_socket', server_only)
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    received = []
    original_connect = HttpsSocket._new_conn

    class Tap:
        def __init__(self, conn):
            self.conn = conn

        def recv(self, size, *args):
            return self.conn.recv(min(size, 7) if fragmented else size, *args)

        def sendall(self, data):
            if data[:1] == b'\x16' and data[5:6] == b'\x01':
                received.append(data)
            return self.conn.sendall(data)

        def __getattr__(self, name):
            return getattr(self.conn, name)

    monkeypatch.setattr(
        HttpsSocket,
        '_new_conn',
        lambda self, host, port: Tap(original_connect(self, host, port)),
    )
    config = TlsConfig()
    config.supported_groups = [29, 24]
    config.key_share_groups = [29] if retry else [24]
    config.cipher_suites = [cipher]
    config.session_id = b'\0'  # Exercise the formerly ambiguous nonempty zero ID.
    config.extension_order = [0, 43, 10, 51, 13, 16, 45, 23]
    context = tls13_context(*trusted_certificates.leaves['valid'], group='secp384r1')
    sent = []
    original_handshake = TLS.handshake

    def handshake(tls):
        result = original_handshake(tls)
        sent.extend(tls.sent_client_hellos)
        return result

    monkeypatch.setattr(TLS, 'handshake', handshake)

    def handler(conn):
        assert conn.version() == 'TLSv1.3'
        assert read_headers(conn).startswith(b'GET / HTTP/1.1')
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            assert (
                session.get('https://127.0.0.1:%s/' % server.port, timeout=3).content
                == b'ok'
            )
    assert received == sent and len(sent) == (2 if retry else 1)
    assert sent[0][1:3] == b'\x03\x01'
    if retry:
        assert sent[1][1:3] == b'\x03\x03'
    assert profile(sent[-1])['key_shares'] == [[24, 97]]
    for record in sent:
        assert decode(record)['session_id'] == b'\0'
        assert [k for k, _ in decode(record)['extensions']] == config.extension_order
        assert inspect_client_hello(record)['ja3'] == profile(record)['ja3']
    if retry:
        assert decode(sent[0])['random'] == decode(sent[1])['random']


@pytest.mark.parametrize('version', ['TLSv1.2', 'TLSv1.3'])
def test_chrome154_subset_interoperates(trusted_certificates, monkeypatch, version):
    from test.mock_servers.local import tls12_context

    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves['valid']
    context = (
        tls13_context(*certificate)
        if version == 'TLSv1.3'
        else tls12_context(*certificate, cipher='ECDHE-RSA-AES128-GCM-SHA256')
    )

    def handler(conn):
        assert conn.version() == version
        assert read_headers(conn).startswith(b'GET / HTTP/1.1')
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')

    with LocalServer(handler, context) as server:
        with Session(
            tls_config=TlsConfig.from_browser('chrome', 154), use_pooling=False
        ) as session:
            assert (
                session.get('https://127.0.0.1:%s/' % server.port, timeout=3).content
                == b'ok'
            )
