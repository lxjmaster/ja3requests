"""Destination bytes after sync hooks, binary buffering and proxy selection."""

import io

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.protocol.h2.hpack import HPACKDecoder
from ja3requests.requests.request import Request
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    h2_readers,
    start_h2,
    trusted_h2_peer,
)
from test.integration.test_request_wire_review import read_h2_request
from test.integration.test_sync_redirect_replay import (
    BorrowedFile,
    http1_request,
    multipart_parts,
)
from test.integration.test_sync_transport_review import proxy_options, routed_peer
from test.mock_servers.local import LocalServer, h2_frame


@pytest.fixture(
    params=[('http', 13), ('h1', 12), ('h1', 13), ('h2', 12), ('h2', 13)],
    ids=['http', 'tls12-h1', 'tls13-h1', 'tls12-h2', 'tls13-h2'],
)
def request_peer(request, trusted_certificates, monkeypatch):
    protocol, version = request.param
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    if protocol == 'h1':
        config.alpn_protocols = ['http/1.1']
        context.set_alpn_protocols(['http/1.1'])
    return protocol, config, context


def capture_request(conn, protocol, seen):
    if protocol == 'h2':
        start_h2(conn)
        stream, headers, body, block = read_h2_request(conn, HPACKDecoder())
        seen.append((headers[':method'], headers[':path'], headers, body))
        # The default HPACK policy uses raw literal strings. Check the actual
        # block too, independently of the decoder's interpretation.
        assert b'proxy-authorization' not in block
        assert b'proxy-secret' not in block
        conn.sendall(h2_frame(1, 5, stream, b'\x88'))
        await_transport_close(conn)
    else:
        seen.append(http1_request(conn))
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')


@pytest.mark.parametrize('route', ['direct', 'connect', 'socks4', 'socks5'])
@pytest.mark.parametrize('entry', ['prepared', 'replacement', 'clear', 'explicit'])
@pytest.mark.parametrize('upload', [False, True])
@pytest.mark.parametrize(
    'protocol,version', [('h1', 12), ('h1', 13), ('h2', 12), ('h2', 13)]
)
def test_sync_prepared_https_resolves_tls_policy_after_hooks(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    route,
    entry,
    upload,
    protocol,
    version,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    if protocol == 'h1':
        config.alpn_protocols = ['http/1.1']
        context.set_alpn_protocols(['http/1.1'])
    session_config = config
    if entry == 'explicit':
        session_config = TlsConfig.secure()
        session_config.alpn_protocols = ['h2' if protocol == 'h1' else 'http/1.1']
    seen = []
    body = b'private-body'
    headers = {'Authorization': 'Bearer tls-only-token'}

    def destination(conn):
        with context.wrap_socket(conn, server_side=True) as secured:
            assert secured.selected_alpn_protocol() == (
                'http/1.1' if protocol == 'h1' else 'h2'
            )
            capture_request(secured, protocol, seen)

    with LocalServer(routed_peer(route, destination)) as peer, Session(
        tls_config=session_config, use_pooling=False
    ) as session:
        url = 'https://127.0.0.1:%d/private' % peer.port
        arguments = dict(
            data=iter([body]) if upload else body,
            headers=headers,
            timeout=3,
            **proxy_options(route, peer.port),
        )

        def before(request):
            if entry == 'replacement':
                return Request('POST', url, **arguments).request()
            request.tls_config = None

        if entry in ('prepared', 'explicit'):
            prepared = Request(
                'POST',
                url,
                tls_config=config if entry == 'explicit' else None,
                **arguments,
            ).request()
            response = session.send(prepared)
        else:
            response = session.post(
                url, hooks={'before_request': [before]}, **arguments
            )
        assert response.status_code == 200 and response.request.tls_config is config
        response.close()
        assert not session._uploads
    assert len(seen) == 1
    assert seen[0][:2] == ('POST', '/private') and seen[0][3] == body
    assert seen[0][2]['authorization'] == headers['Authorization']


@pytest.mark.parametrize('route', ['direct', 'socks4', 'socks5'])
@pytest.mark.parametrize('upload', [False, True])
def test_sync_direct_and_socks_keep_proxy_auth_out_of_destination(
    request_peer, h2_readers, route, upload
):
    protocol, config, context = request_peer
    scheme = 'http' if protocol == 'http' else 'https'
    seen = []
    credentials = b'Basic proxy-secret'
    caller_headers = {
        'Proxy-Authorization': credentials,
        'Authorization': 'Bearer target',
    }

    def before(request):
        request.headers['pRoXy-aUtHoRiZaTiOn'] = request.headers.pop(
            'Proxy-Authorization'
        )

    def application(conn):
        capture_request(conn, protocol, seen)

    def destination(conn):
        if protocol == 'http':
            application(conn)
        else:
            with context.wrap_socket(conn, server_side=True) as secured:
                application(secured)

    with LocalServer(routed_peer(route, destination)) as peer, Session(
        tls_config=config, use_pooling=False
    ) as session:
        proxies = (
            None
            if route == 'direct'
            else {scheme: '%s://127.0.0.1:%d' % (route, peer.port)}
        )
        response = session.post(
            '%s://127.0.0.1:%d/private' % (scheme, peer.port),
            data=iter([b'body']) if upload else b'body',
            headers=caller_headers,
            proxies=proxies,
            hooks={'before_request': [before]},
            timeout=3,
        )
        assert response.status_code == 200
        assert response.request.headers['pRoXy-aUtHoRiZaTiOn'] == credentials
        assert caller_headers['Proxy-Authorization'] == credentials
        response.close()
        assert not session._uploads
    assert len(seen) == 1
    _, _, headers, body = seen[0]
    assert 'proxy-authorization' not in headers
    assert headers['authorization'] == 'Bearer target' and body == b'body'


@pytest.mark.parametrize('entry', ['request', 'prepared', 'hook'])
@pytest.mark.parametrize(
    'body', [b'\x00\xffbody', b'\x80payload', b'\xc3\xa9', b'\xff=\x80&\x00']
)
def test_sync_buffered_bytes_are_opaque_and_length_matches_wire(
    request_peer, h2_readers, entry, body
):
    protocol, config, context = request_peer
    scheme = 'http' if protocol == 'http' else 'https'
    seen = []

    def before(request):
        request.data = body

    with LocalServer(
        lambda conn: capture_request(conn, protocol, seen),
        context if protocol != 'http' else None,
    ) as peer, Session(tls_config=config, use_pooling=False) as session:
        url = '%s://127.0.0.1:%d/binary' % (scheme, peer.port)
        arguments = {'headers': {'Content-Type': 'application/octet-stream'}}
        if entry == 'prepared':
            prepared = Request(
                'POST', url, data=body, tls_config=config, timeout=3, **arguments
            ).request()
            assert prepared.data == body
            response = session.send(prepared)
        else:
            response = session.post(
                url,
                data=b'old' if entry == 'hook' else body,
                hooks={'before_request': [before]} if entry == 'hook' else None,
                timeout=3,
                **arguments,
            )
        assert response.status_code == 200 and response.request.data == body
    assert seen[0][3] == body
    assert seen[0][2]['content-length'] == str(len(body))


def test_sync_hook_can_return_transport_for_new_scheme(request_peer, h2_readers):
    protocol, config, context = request_peer
    scheme = 'http' if protocol == 'http' else 'https'
    original_scheme = 'https' if scheme == 'http' else 'http'
    seen, replacements = [], []

    def before(request):
        replacement = Request(
            'POST',
            request.url.replace(original_scheme + '://', scheme + '://'),
            data=b'replaced',
            tls_config=config,
            timeout=3,
        ).request()
        replacements.append(replacement)
        return replacement

    with LocalServer(
        lambda conn: capture_request(conn, protocol, seen),
        context if protocol != 'http' else None,
    ) as peer, Session(tls_config=config, use_pooling=False) as session:
        response = session.get(
            '%s://127.0.0.1:%d/replaced' % (original_scheme, peer.port),
            hooks={'before_request': [before]},
        )
        assert response.status_code == 200 and response.request is replacements[0]
    assert seen[0][:2] == ('POST', '/replaced') and seen[0][3] == b'replaced'


def test_sync_hook_valid_method_and_url_edits_reach_destination(
    request_peer, h2_readers
):
    protocol, config, context = request_peer
    scheme = 'http' if protocol == 'http' else 'https'
    seen = []

    def before(request):
        request.method = 'put'
        request.url = request.url.replace('/original', '/changed?q=1')

    with LocalServer(
        lambda conn: capture_request(conn, protocol, seen),
        context if protocol != 'http' else None,
    ) as peer, Session(tls_config=config, use_pooling=False) as session:
        response = session.post(
            '%s://127.0.0.1:%d/original' % (scheme, peer.port),
            data=b'unchanged',
            hooks={'before_request': [before]},
            timeout=3,
        )
        assert response.status_code == 200
    assert seen[0][:2] == ('PUT', '/changed?q=1') and seen[0][3] == b'unchanged'


def test_sync_multipart_utf8_form_bytes_preserve_fields_and_borrowed_file(
    request_peer, h2_readers
):
    protocol, config, context = request_peer
    scheme = 'http' if protocol == 'http' else 'https'
    seen = []
    borrowed = io.BytesIO(b'\x00\xfffile')
    borrowed.name = 'payload.bin'
    with LocalServer(
        lambda conn: capture_request(conn, protocol, seen),
        context if protocol != 'http' else None,
    ) as peer, Session(tls_config=config, use_pooling=False) as session:
        response = session.post(
            '%s://127.0.0.1:%d/multipart' % (scheme, peer.port),
            data=b'name=%E4%B8%AD%E6%96%87&empty=',
            files={'file': borrowed},
            timeout=3,
        )
        assert response.status_code == 200
    assert multipart_parts(seen[0]) == [
        ('name', None, '中文'.encode('utf-8')),
        ('empty', None, b''),
        ('file', 'payload.bin', b'\x00\xfffile'),
    ]
    assert not borrowed.closed


@pytest.mark.parametrize('route', ['direct', 'connect', 'socks4', 'socks5'])
@pytest.mark.parametrize('method', ['POST', 'PUT'])
@pytest.mark.parametrize('edit', ['data', 'data_files', 'files_data', 'remove_files'])
def test_sync_first_hook_uses_final_files_when_encoding_form(
    request_peer, h2_readers, route, method, edit
):
    protocol, config, context = request_peer
    scheme = 'http' if protocol == 'http' else 'https'
    seen = []
    borrowed = BorrowedFile(b'\x00\xfffile')

    def before(request):
        if edit == 'files_data':
            request.files = {'file': borrowed}
        request.data = {'field': '修改后的值', 'empty': ''}
        if edit == 'data_files':
            request.files = {'file': borrowed}
        elif edit == 'remove_files':
            request.files = None

    def destination(conn):
        if protocol == 'http':
            capture_request(conn, protocol, seen)
        else:
            with context.wrap_socket(conn, server_side=True) as secured:
                capture_request(secured, protocol, seen)

    with LocalServer(routed_peer(route, destination)) as peer, Session(
        tls_config=config, use_pooling=False
    ) as session:
        proxy_scheme = 'http' if route == 'connect' else route
        response = session.request(
            method,
            '%s://127.0.0.1:%d/multipart' % (scheme, peer.port),
            data={'field': 'original'},
            files={'file': borrowed} if edit in ('data', 'remove_files') else None,
            proxies=(
                {scheme: '%s://127.0.0.1:%d' % (proxy_scheme, peer.port)}
                if route != 'direct'
                else None
            ),
            hooks={'before_request': [before]},
            timeout=3,
        )
        assert response.status_code == 200
        assert bool(response.request.files) == (edit != 'remove_files')
        response.close()
        assert not session._uploads
    assert len(seen) == 1 and seen[0][:2] == (method, '/multipart')
    if edit == 'remove_files':
        assert seen[0][2]['content-type'] == 'application/x-www-form-urlencoded'
        assert (
            seen[0][3] == b'field=%E4%BF%AE%E6%94%B9%E5%90%8E%E7%9A%84%E5%80%BC&empty='
        )
        assert int(seen[0][2]['content-length']) == len(seen[0][3])
    else:
        assert multipart_parts(seen[0]) == [
            ('field', None, '修改后的值'.encode('utf-8')),
            ('empty', None, b''),
            ('file', 'payload.bin', b'\x00\xfffile'),
        ]
    assert borrowed.reads == 1 and not borrowed.closed
