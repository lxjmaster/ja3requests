"""Read-policy boundaries on actual HTTP1 sends and independent loopback peers."""

import io
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from ja3requests import Session
from ja3requests.pool import ConnectionPool
from ja3requests.sockets.http import HttpSocket
from ja3requests.sockets.https import HttpsSocket
from ja3requests.sockets.proxy import ProxySocket
from ja3requests.sockets.socks import SocksProxySocket
from test.integration.conftest import trusted_certificates
from test.integration.test_h2_streaming_network import trusted_h2_peer
from test.integration.test_sync_redirect_replay import http1_request
from test.integration.test_sync_transport_review import routed_peer
from test.mock_servers.local import (
    LocalServer,
    read_exact,
    read_headers,
    recv_with_ragged_eof,
)
from test.test_sync_upload import slow_upload_source


class RecordingConnection:
    def __init__(self, timeout=7):
        self.timeout = timeout
        self.timeout_calls = []
        self.messages = []

    def settimeout(self, timeout):
        self.timeout = timeout
        self.timeout_calls.append(timeout)

    def gettimeout(self):
        return self.timeout

    def sendall(self, message):
        self.messages.append(message)


@pytest.mark.parametrize('policy,expected', [('phase', None), ('legacy', 0.25)])
def test_http_send_replaces_or_preserves_prior_socket_budget(policy, expected):
    context = SimpleNamespace(
        data=None,
        message=b'GET / HTTP/1.1\r\n\r\n',
        read_timeout=0.25,
        read_timeout_policy=policy,
    )
    transport = HttpSocket(context)
    connection = RecordingConnection()
    transport.conn = connection
    assert transport.send() is connection
    context.read_timeout = None
    assert transport.send() is connection
    assert connection.gettimeout() == expected
    assert connection.timeout_calls == ([0.25, None] if policy == 'phase' else [0.25])
    assert connection.messages == [context.message, context.message]


def test_low_level_http_context_without_policy_keeps_legacy_socket_budget():
    transport = HttpSocket(
        SimpleNamespace(data=None, message=b'GET', read_timeout=None)
    )
    transport.conn = RecordingConnection()
    transport.send()
    assert transport.conn.gettimeout() == 7
    assert not transport.conn.timeout_calls


@pytest.mark.parametrize('policy', ['legacy', 'phase'])
@pytest.mark.parametrize('budget', [None, 0, 2.5])
def test_https_send_applies_selected_budget_before_encrypted_writes(
    monkeypatch, policy, budget
):
    transport = HttpsSocket(
        SimpleNamespace(
            data=None,
            message=b'GET / HTTP/1.1\r\n\r\n',
            read_timeout=budget,
            read_timeout_policy=policy,
        )
    )
    transport.conn = RecordingConnection()
    encrypted = []

    def encrypt(message):
        encrypted.append((message, transport.conn.gettimeout()))
        return b'encrypted:' + message

    monkeypatch.setattr(transport, '_encrypt_application_data', encrypt)
    response = transport._send_h1()
    expected = 15.0 if policy == 'legacy' and budget is None else budget
    assert transport.conn.timeout_calls == [expected]
    assert encrypted == [(transport.context.message, expected)]
    assert transport.conn.messages == [b'encrypted:' + transport.context.message]
    assert response.reader.transport is transport


@pytest.fixture(params=['http', 'tls12', 'tls13'])
def h1_peer(request, trusted_certificates, monkeypatch):
    if request.param == 'http':
        return 'http', None, None
    config, context = trusted_h2_peer(
        trusted_certificates, monkeypatch, int(request.param[-2:])
    )
    config.alpn_protocols = ['http/1.1']
    context.set_alpn_protocols(['http/1.1'])
    return 'https', config, context


@pytest.fixture
def sent_timeouts(monkeypatch):
    """Observe effective real-socket settings without replacing network I/O."""
    observed = []
    for cls, name in (
        (HttpSocket, 'send'),
        (HttpsSocket, '_send_h1'),
        (ProxySocket, 'send'),
        (SocksProxySocket, 'send'),
    ):
        original = getattr(cls, name)

        def send(transport, _original=original):
            result = _original(transport)
            observed.append(
                (
                    id(transport.conn),
                    transport.conn.gettimeout(),
                    transport.context.read_timeout_policy,
                )
            )
            return result

        monkeypatch.setattr(cls, name, send)
    return observed


def peer_handler(route, context, application):
    def destination(conn):
        if context is None:
            application(conn)
        else:
            with context.wrap_socket(conn, server_side=True) as secured:
                assert secured.selected_alpn_protocol() == 'http/1.1'
                application(secured)

    return routed_peer(route, destination)


def route_options(route, scheme, port):
    if route == 'direct':
        return {}
    proxy_scheme = 'http' if route == 'connect' else route
    return {'proxies': {scheme: '%s://127.0.0.1:%d' % (proxy_scheme, port)}}


@pytest.mark.parametrize('route', ['direct', 'connect', 'socks4', 'socks5'])
@pytest.mark.parametrize('upload', [False, True])
def test_phase_none_routes_deliver_headers_before_gated_body_and_release_upload(
    h1_peer, sent_timeouts, route, upload
):
    scheme, config, context = h1_peer
    allow_body = threading.Event()
    seen = []
    borrowed = io.BytesIO(b'upload') if upload else None

    def application(conn):
        seen.append(http1_request(conn))
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n')
        assert allow_body.wait(3), 'Client did not return at response headers'
        conn.sendall(b'body-end')

    with LocalServer(peer_handler(route, context, application)) as peer, Session(
        tls_config=config, use_pooling=False
    ) as session:
        session.read_timeout_policy = 'phase'
        response = None
        try:
            response = session.request(
                'PUT' if upload else 'GET',
                '%s://127.0.0.1:%d/' % (scheme, peer.port),
                data=borrowed,
                stream=True,
                timeout=(2, None),
                **route_options(route, scheme, peer.port),
            )
            assert response.status_code == 200 and not allow_body.is_set()
            assert sent_timeouts
            assert all(
                timeout is None and policy == 'phase'
                for _, timeout, policy in sent_timeouts
            )
            with ThreadPoolExecutor(max_workers=1) as executor:
                reading = executor.submit(lambda: response.content)
                try:
                    assert not reading.done()
                finally:
                    allow_body.set()
                assert reading.result(timeout=2) == b'body-end'
            assert not session._uploads
            if upload:
                assert response.request.data._closed and not borrowed.closed
        finally:
            allow_body.set()
            if response is not None:
                response.close()
    assert seen[0][3] == (b'upload' if upload else b'')


def test_phase_none_resets_reused_real_http1_connection(h1_peer, sent_timeouts):
    scheme, config, context = h1_peer
    seen = []

    def application(conn):
        for _ in range(2):
            seen.append(http1_request(conn))
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')

    with LocalServer(peer_handler('direct', context, application)) as peer, Session(
        tls_config=config, pool=ConnectionPool()
    ) as session:
        session.read_timeout_policy = 'phase'
        url = '%s://127.0.0.1:%d/' % (scheme, peer.port)
        for budget in (0.25, None):
            with session.get(url, timeout=(2, budget)) as response:
                assert response.content == b'ok'
        assert len(sent_timeouts) == 2
        assert sent_timeouts[0][0] == sent_timeouts[1][0]
        assert [timeout for _, timeout, _ in sent_timeouts] == [0.25, None]
    assert len(seen) == 2


@pytest.mark.parametrize('upload', [False, True])
def test_phase_finite_read_still_expires_without_body_progress(h1_peer, upload):
    scheme, config, context = h1_peer

    def application(conn):
        http1_request(conn)
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n')
        while recv_with_ragged_eof(conn, 4096):
            pass

    with LocalServer(peer_handler('direct', context, application)) as peer, Session(
        tls_config=config, use_pooling=False
    ) as session:
        session.read_timeout_policy = 'phase'
        with session.request(
            'PUT' if upload else 'GET',
            '%s://127.0.0.1:%d/' % (scheme, peer.port),
            data=iter([b'body']) if upload else None,
            timeout=(2, 0.1),
            stream=True,
        ) as response:
            with pytest.raises((TimeoutError, socket.timeout)):
                response.content
        assert not session._uploads


@pytest.mark.parametrize('route', ['direct', 'connect', 'socks4', 'socks5'])
def test_phase_finite_upload_progress_keeps_individual_wait_budget(h1_peer, route):
    scheme, config, context = h1_peer
    seen = []

    def application(conn):
        seen.append(http1_request(conn))
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')

    with LocalServer(peer_handler(route, context, application)) as peer, Session(
        tls_config=config, use_pooling=False
    ) as session:
        session.read_timeout_policy = 'phase'
        with session.put(
            '%s://127.0.0.1:%d/' % (scheme, peer.port),
            data=slow_upload_source(),
            timeout=(2, 0.25),
            **route_options(route, scheme, peer.port),
        ) as response:
            assert response.content == b'ok'
        assert not session._uploads
    assert seen[0][3] == b'piece' * 8


@pytest.mark.parametrize('route', ['direct', 'connect', 'socks4', 'socks5'])
def test_phase_none_early_response_joins_worker_before_returning_borrowed_file(
    h1_peer, route
):
    scheme, config, context = h1_peer
    entered, release = threading.Event(), threading.Event()

    class BorrowedFile(io.BytesIO):
        def __init__(self):
            super().__init__(b'prefixdiscarded')
            self.reads = 0

        def read(self, size=-1):
            self.reads += 1
            if self.reads == 1:
                return super().read(6)
            entered.set()
            assert release.wait(3), 'Source worker was not released during cleanup'
            return super().read(size)

    borrowed = BorrowedFile()

    def application(conn):
        read_headers(conn)
        assert read_exact(conn, 11) == b'6\r\nprefix\r\n'
        assert entered.wait(2)
        conn.sendall(b'HTTP/1.1 413 Stop\r\nContent-Length: 2\r\n\r\nok')

    with LocalServer(peer_handler(route, context, application)) as peer, Session(
        tls_config=config, use_pooling=False
    ) as session:
        session.read_timeout_policy = 'phase'
        response = None
        try:
            response = session.put(
                '%s://127.0.0.1:%d/' % (scheme, peer.port),
                data=borrowed,
                stream=True,
                timeout=(2, None),
                **route_options(route, scheme, peer.port),
            )
            assert response.status_code == 413
            owner = response.response._upload_owner
            assert owner.worker.is_alive() and not owner.complete
            with ThreadPoolExecutor(max_workers=1) as executor:
                closing = executor.submit(response.close)
                try:
                    assert not closing.done()
                finally:
                    release.set()
                closing.result(timeout=2)
            assert not owner.worker.is_alive()
            assert not session._uploads
            assert response.request.data._closed
        finally:
            release.set()
            if response is not None:
                response.close()
    assert not borrowed.closed and borrowed.reads == 2
