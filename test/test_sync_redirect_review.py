"""Wire regressions for entity headers on synchronous bodyless redirects."""

import pytest

from ja3requests import Session
from ja3requests.contexts.context import HTTPContext
from test.mock_servers.local import LocalServer, read_headers


ENTITY_HEADERS = {'content-length', 'content-type', 'transfer-encoding'}


def _redirect_peer(observed, redirects):
    def serve(conn):
        lines = read_headers(conn).decode('latin1').split('\r\n')
        headers = {
            name.lower(): value
            for name, value in (line.split(': ', 1) for line in lines[1:] if line)
        }
        index = len(observed)
        if index < len(redirects):
            status, location = redirects[index]
            reply = (
                'HTTP/1.1 %d Redirect\r\nLocation: %s\r\n'
                'Content-Length: 0\r\nConnection: close\r\n\r\n'
            ) % (status, location)
        else:
            reply = (
                'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'
            )
        conn.sendall(reply.encode('ascii'))
        # The client closes after consuming this response. Reading until that
        # EOF captures the actual request body without trusting a stale length.
        body = bytearray()
        while True:
            chunk = conn.recv(1024)
            if not chunk:
                break
            body.extend(chunk)
        observed.append((lines[0], headers, bytes(body)))

    return serve


@pytest.mark.parametrize(
    'arguments,body,content_type',
    [
        ({'data': b'abc'}, b'abc', 'application/x-www-form-urlencoded'),
        ({'json': {'a': 1}}, b'{"a": 1}', 'application/json'),
    ],
    ids=['data', 'json'],
)
def test_sync_redirect_drops_entity_headers_with_request_body(
    arguments, body, content_type
):
    observed = []
    with LocalServer(_redirect_peer(observed, [(302, '/next')]), connections=2) as peer:
        with Session(use_pooling=False) as session:
            response = session.post(
                'http://127.0.0.1:%d/start' % peer.port,
                headers={'X-Trace': 'retained'},
                timeout=2,
                **arguments,
            )
            assert response.status_code == 200
            assert response.content == b'ok'

    assert observed[0][0] == 'POST /start HTTP/1.1'
    assert observed[0][1]['content-length'] == str(len(body))
    assert observed[0][1]['content-type'] == content_type
    assert observed[0][2] == body
    assert observed[1][0] == 'GET /next HTTP/1.1'
    assert observed[1][2] == b''
    assert not ENTITY_HEADERS.intersection(observed[1][1])
    assert [item[1]['x-trace'] for item in observed] == ['retained', 'retained']


def test_sync_multihop_redirect_clears_mixed_case_entity_headers_only():
    observed = []
    changed = []

    def after(response):
        if not response.request.url.endswith('/middle'):
            return
        # Change the completed hop's metadata, not its wire request. The next
        # redirect must clear all spellings while preserving unrelated choices.
        headers = response.request.headers
        for name in tuple(headers):
            if name.lower() in ENTITY_HEADERS:
                del headers[name]
        headers.update(
            {
                'cOnTent-LenGth': '77',
                'CONTENT-type': 'application/custom',
                'transfer-ENCODING': 'chunked',
                'x-HoP-Trace': 'from-hook',
            }
        )
        changed.append(response.request.url)

    redirects = [(307, '/middle'), (308, '/final')]
    with LocalServer(_redirect_peer(observed, redirects), connections=3) as peer:
        with Session(use_pooling=False, hooks={'after_request': [after]}) as session:
            response = session.post(
                'http://127.0.0.1:%d/start' % peer.port,
                data=b'abc',
                headers={'X-Trace': 'retained', 'Cookie': 'sid=manual'},
                auth=('user', 'password'),
                timeout=2,
            )
            assert response.status_code == 200
            assert response.content == b'ok'

    assert len(changed) == 1
    assert [item[0] for item in observed] == [
        'POST /start HTTP/1.1',
        'GET /middle HTTP/1.1',
        'GET /final HTTP/1.1',
    ]
    assert [item[2] for item in observed] == [b'abc', b'', b'']
    for _, headers, _ in observed[1:]:
        assert not ENTITY_HEADERS.intersection(headers)
        assert headers['x-trace'] == 'retained'
        assert headers['cookie'] == 'sid=manual'
        assert headers['authorization'] == observed[0][1]['authorization']
    assert observed[-1][1]['x-hop-trace'] == 'from-hook'


def test_sync_params_are_inserted_before_fragment_and_host_keeps_port():
    observed = []
    with LocalServer(_redirect_peer(observed, []), connections=1) as peer:
        with Session(use_pooling=False) as session:
            response = session.get(
                'http://127.0.0.1:%d/path?before=one#fragment' % peer.port,
                params={'q': 'a b'},
                timeout=2,
            )
            assert response.status_code == 200

    assert observed[0][0] == 'GET /path?before=one&q=a+b HTTP/1.1'
    assert observed[0][1]['host'] == '127.0.0.1:%d' % peer.port


@pytest.mark.parametrize(
    'suffix,target',
    [
        ('/resource;version=2?x=1#fragment', '/resource;version=2?x=1&q=2'),
        ('/resource;#fragment', '/resource;?q=2'),
        ('/a;b/c;d?x=1', '/a;b/c;d?x=1&q=2'),
        ('/encoded%3Btext;v=2', '/encoded%3Btext;v=2?q=2'),
    ],
)
def test_sync_request_retains_semicolon_path_components(suffix, target):
    observed = []
    with LocalServer(_redirect_peer(observed, [])) as peer, Session(
        use_pooling=False
    ) as session:
        response = session.get(
            'http://127.0.0.1:%d%s' % (peer.port, suffix), params={'q': '2'}, timeout=2
        )
        assert response.status_code == 200
    assert observed[0][0] == 'GET %s HTTP/1.1' % target


def test_sync_context_formats_bracketed_ipv6_authority():
    context = HTTPContext()
    context.set_payload(
        method='GET',
        start_line='http://[::1]:8080/path',
        port=8080,
        headers={'X-Test': 'ok'},
    )

    assert context.destination_address == '::1'
    assert context.start_line == 'GET /path HTTP/1.1'
    assert context.headers['Host'] == '[::1]:8080'


@pytest.mark.parametrize(
    'name,value',
    [
        ('X-Test', 'good\r\nInjected: yes'),
        ('X-Test', 'bad\x00value'),
        ('X\n-Test', 'value'),
    ],
)
def test_sync_header_controls_are_rejected_at_serialization(name, value):
    context = HTTPContext()
    context.set_payload(
        method='GET',
        start_line='http://example.test/path',
        headers={'X-Test': 'ok'},
    )
    # Mutating the prepared mapping models a hook edit after the normal setter.
    context.headers.clear()
    context.headers[name] = value

    with pytest.raises(ValueError, match='Invalid HTTP header'):
        _ = context.message
