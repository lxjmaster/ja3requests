"""Final sync request validation and SOCKS failure ownership."""

import socket

import pytest

from ja3requests import HTTPRetry, Session
from ja3requests.base import BaseSocket
from ja3requests.contexts.context import HTTPContext
from ja3requests.exceptions import NotAllowedRequestMethod, NotAllowedScheme
from ja3requests.protocol.exceptions import ProxyError, ProxyTimeoutError
from ja3requests.requests.request import Request
from ja3requests.sockets.socks import SocksProxySocket
from test.integration.test_sync_redirect_replay import BorrowedFile


@pytest.mark.parametrize('scheme', ['http', 'https'])
@pytest.mark.parametrize('entry', ['hook', 'session-send', 'transport-send'])
@pytest.mark.parametrize('edit', ['scheme', 'method'])
def test_sync_invalid_final_request_fails_before_source_or_connection(
    monkeypatch, scheme, entry, edit
):
    opened = []
    source = BorrowedFile(b'private-body')

    def connect(*args):
        opened.append(True)
        raise AssertionError('Invalid request reached connection work')

    def change(request):
        if edit == 'scheme':
            replacement = 'https' if scheme == 'http' else 'http'
            request.url = request.url.replace(scheme + '://', replacement + '://')
        else:
            request.method = 'GET /first HTTP/1.1\r\nHost: localhost\r\n\r\nGET'

    monkeypatch.setattr(BaseSocket, '_new_conn', connect)
    error = NotAllowedScheme if edit == 'scheme' else NotAllowedRequestMethod
    with Session(use_pooling=False, retry=HTTPRetry(total=2)) as session:
        with pytest.raises(error):
            url = scheme + '://127.0.0.1:1/private'
            if entry == 'hook':
                session.post(
                    url,
                    data=source,
                    hooks={'before_request': [change]},
                    headers={'Authorization': 'Bearer private-token'},
                )
            else:
                request = Request('POST', url, data=source).request()
                change(request)
                if entry == 'session-send':
                    session.send(request)
                else:
                    request.send()
    assert not opened and source.reads == 0 and source.tell() == 0
    assert not source.closed


@pytest.mark.parametrize('version', [4, 5])
@pytest.mark.parametrize('entry', ['socket', 'http', 'https'])
@pytest.mark.parametrize('fault', ['reject', 'timeout', 'truncated', 'unexpected'])
def test_sync_socks_handshake_failures_close_even_with_retained_exception(
    monkeypatch, version, entry, fault
):
    client, peer = socket.socketpair()
    client.settimeout(0.05)
    peer.settimeout(1)
    monkeypatch.setattr(SocksProxySocket, '_new_conn', lambda *args: client)
    error = ProxyError
    if fault == 'unexpected':

        def fail(*args):
            raise ValueError('handshake callback failed')

        monkeypatch.setattr(SocksProxySocket, '_socks%d_handshake' % version, fail)
        error = ValueError
    elif fault == 'timeout':
        error = ProxyTimeoutError
    else:
        if version == 5:
            reply = b'\x05\x00\x05\x05\x00\x01'
        else:
            reply = b'\x00\x5b' + b'\x00' * 6
        if fault == 'truncated':
            reply = reply[:1]
        peer.sendall(reply)
        if fault == 'truncated':
            peer.shutdown(socket.SHUT_WR)

    session = Session(use_pooling=False)
    sock = None
    try:
        with pytest.raises(error) as caught:
            if entry == 'socket':
                context = HTTPContext()
                context.set_payload(
                    method='GET',
                    start_line='http://destination.test/',
                    headers={'X-Test': 'ok'},
                    proxy='socks%d://127.0.0.1:1080' % version,
                    timeout=1,
                )
                sock = SocksProxySocket(context, socks_version=version)
                sock.new_conn()
            else:
                session.get(
                    entry + '://destination.test/',
                    proxies={entry: 'socks%d://127.0.0.1:1080' % version},
                    timeout=1,
                )
        session.close()
        # Keep the traceback alive: garbage collection must not provide cleanup.
        assert caught.value is not None and client.fileno() == -1
        if sock is not None:
            assert sock.conn is None
        if fault == 'timeout':
            # socket.timeout became a TimeoutError alias only in Python 3.10.
            assert isinstance(caught.value.__cause__, socket.timeout)
        while peer.recv(4096):
            pass
    finally:
        session.close()
        client.close()
        peer.close()
