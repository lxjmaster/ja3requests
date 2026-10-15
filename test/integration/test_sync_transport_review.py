"""Wire regressions for synchronous protocol selection and proxy TLS setup."""

import socket
import threading

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.requests.request import Request
from ja3requests.response import Response
from test.integration.test_sync_redirect_replay import BorrowedFile, http1_request
from test.mock_servers.local import (
    LocalServer,
    read_exact,
    read_headers,
    serve_h2_serial,
    serve_socks,
    tls12_context,
    tls13_context,
)


@pytest.fixture(params=[12, 13], ids=['tls12', 'tls13'])
def tls_peer(request, trusted_certificates, monkeypatch):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    config = TlsConfig.secure()
    certificate = trusted_certificates.leaves['valid']
    if request.param == 12:
        context = tls12_context(*certificate, cipher='ECDHE-RSA-AES128-GCM-SHA256')
    else:
        context = tls13_context(*certificate)
    return config, context


def routed_peer(route, handler):
    """Terminate an owned tunnel, then pass its socket to the independent peer."""

    def serve(conn):
        if route == 'connect':
            read_headers(conn)
            conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            handler(conn)
        elif route.startswith('socks'):
            serve_socks(conn, {}, version=int(route[-1]), tunnel_handler=handler)
        else:
            handler(conn)

    return serve


def proxy_options(route, port):
    if route == 'direct':
        return {}
    scheme = 'http' if route == 'connect' else route
    return {'proxies': {'https': '%s://127.0.0.1:%d' % (scheme, port)}}


@pytest.mark.parametrize('route', ['direct', 'connect', 'socks4', 'socks5'])
def test_transport_https_without_tls_config_still_handshakes(tls_peer, route):
    _, context = tls_peer
    seen = []

    def destination(conn):
        with context.wrap_socket(conn, server_side=True) as secured:
            seen.append(http1_request(secured))
            secured.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')

    with LocalServer(routed_peer(route, destination)) as peer:
        prepared = Request(
            'POST',
            'https://127.0.0.1:%d/private' % peer.port,
            data=b'private-body',
            headers={'Authorization': 'Bearer tls-only-token'},
            timeout=3,
            **proxy_options(route, peer.port),
        ).request()
        assert prepared.tls_config is None
        with Response(prepared, prepared.send()) as response:
            assert response.status_code == 200
    assert seen[0][:2] == ('POST', '/private') and seen[0][3] == b'private-body'
    assert seen[0][2]['authorization'] == 'Bearer tls-only-token'


@pytest.mark.parametrize('route', ['connect', 'socks4', 'socks5'])
@pytest.mark.parametrize('entry', ['session', 'transport'])
def test_prepared_https_rejects_plaintext_tunnel_before_body_reads(route, entry):
    seen = []
    borrowed = BorrowedFile(b'private-body')

    def plaintext(conn):
        header = read_exact(conn, 5)
        assert header[0] == 22  # TLS handshake record, never an HTTP method.
        hello = read_exact(conn, int.from_bytes(header[3:5], 'big'))
        assert hello[0] == 1  # ClientHello
        seen.append(header + hello)
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')
        conn.shutdown(socket.SHUT_WR)
        assert conn.recv(1) == b''

    with LocalServer(routed_peer(route, plaintext)) as peer, Session(
        use_pooling=False
    ) as session:
        prepared = Request(
            'POST',
            'https://destination.test/private',
            data=borrowed if entry == 'session' else b'private-body',
            headers={'Authorization': 'Bearer tls-only-token'},
            timeout=3,
            **proxy_options(route, peer.port),
        ).request()
        with pytest.raises(ConnectionError, match='TLS handshake failed'):
            if entry == 'session':
                session.send(prepared)
            else:
                prepared.send()
        assert not session._uploads
    assert len(seen) == 1
    assert b'private-body' not in seen[0] and b'tls-only-token' not in seen[0]
    assert borrowed.reads == 0 and not borrowed.closed


@pytest.mark.parametrize('route', ['direct', 'connect', 'socks4', 'socks5'])
def test_sync_h1_override_changes_actual_alpn_without_mutating_config(tls_peer, route):
    config, context = tls_peer
    config.alpn_protocols = ['h2', 'http/1.1']
    context.set_alpn_protocols(['h2', 'http/1.1'])
    observed = []

    def tls(conn):
        with context.wrap_socket(conn, server_side=True) as secured:
            observed.append(secured.selected_alpn_protocol())
            assert read_headers(secured).startswith(b'GET / HTTP/1.1\r\n')
            secured.sendall(
                b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'
            )

    with LocalServer(routed_peer(route, tls)) as peer, Session(
        tls_config=config, use_pooling=False
    ) as session:
        url = 'https://localhost:%d/' % peer.port
        assert (
            session.get(
                url, h1=True, timeout=2, **proxy_options(route, peer.port)
            ).content
            == b'ok'
        )
    assert observed == ['http/1.1']
    assert config.alpn_protocols == ['h2', 'http/1.1']


@pytest.mark.parametrize('route', ['connect', 'socks4', 'socks5'])
@pytest.mark.parametrize('explicit_sni', [None, 'localhost'])
def test_proxy_sni_follows_destination_and_preserves_explicit_config(
    tls_peer, route, explicit_sni
):
    config, context = tls_peer
    config.server_name = explicit_sni
    observed = []
    context.set_servername_callback(lambda conn, name, ctx: observed.append(name))

    def tls(conn):
        with context.wrap_socket(conn, server_side=True) as secured:
            read_headers(secured)
            secured.sendall(
                b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'
            )

    with LocalServer(routed_peer(route, tls), connections=2) as peer, Session(
        tls_config=config, use_pooling=False
    ) as session:
        for host in ('localhost', '127.0.0.1'):
            assert (
                session.get(
                    'https://%s/' % host, timeout=2, **proxy_options(route, peer.port)
                ).content
                == b'ok'
            )
            assert config.server_name == explicit_sni
    assert observed == (
        ['localhost', '127.0.0.1'] if explicit_sni is None else ['localhost'] * 2
    )


@pytest.mark.parametrize('route', ['connect', 'socks4', 'socks5'])
def test_proxy_tls_handshake_obeys_connect_timeout(tls_peer, route):
    config, _ = tls_peer

    def stalled(conn):
        header = read_exact(conn, 5)
        read_exact(conn, int.from_bytes(header[3:5], 'big'))
        # The client must time out and close, without a server EOF completing
        # the handshake. A missing timeout waits for the internal 5-second limit.
        conn.settimeout(1)
        assert conn.recv(1) == b''

    with LocalServer(routed_peer(route, stalled)) as peer, Session(
        tls_config=config, use_pooling=False
    ) as session:
        with pytest.raises(ConnectionError, match='TLS handshake failed'):
            session.get(
                'https://localhost/',
                timeout=(0.1, 2),
                **proxy_options(route, peer.port),
            )


def test_sync_h1_override_does_not_reuse_or_replace_h2_pool_entry(tls_peer):
    config, context = tls_peer
    config.alpn_protocols = ['h2', 'http/1.1']
    context.set_alpn_protocols(['h2', 'http/1.1'])
    observed = []
    h2 = {}

    class ConcurrentPeer(LocalServer):
        def _serve(self):
            workers = []

            def serve(raw):
                try:
                    raw.settimeout(5)
                    with raw, context.wrap_socket(raw, server_side=True) as secured:
                        self.handler(secured)
                except Exception as error:
                    self.errors.append(error)

            try:
                for _ in range(2):
                    raw, _ = self.listener.accept()
                    worker = threading.Thread(target=serve, args=(raw,), daemon=True)
                    workers.append(worker)
                    worker.start()
                for worker in workers:
                    worker.join(5)
                    assert not worker.is_alive(), 'TLS peer survived cleanup'
            except Exception as error:
                self.errors.append(error)

    def tls(conn):
        protocol = conn.selected_alpn_protocol()
        observed.append(protocol)
        if protocol == 'h2':
            serve_h2_serial(conn, h2, count=2)
        else:
            read_headers(conn)
            conn.sendall(
                b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'
            )

    with ConcurrentPeer(tls) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        url = 'https://localhost:%d/' % peer.port
        for h1 in (False, True, False):
            assert session.get(url, h1=h1, timeout=2).content == b'ok'
    assert observed == ['h2', 'http/1.1']
    assert h2['streams'] == [1, 3]
    assert config.alpn_protocols == ['h2', 'http/1.1']
