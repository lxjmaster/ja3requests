"""Wire regressions for cookie identity, deletion and retry/header ownership."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from ja3requests import AsyncSession, HTTPRetry, Session
from ja3requests.cookies import Ja3RequestsCookieJar, create_cookie
from test.mock_servers.local import LocalServer, read_exact, read_headers


def _jar(*cookies):
    jar = Ja3RequestsCookieJar()
    for cookie in cookies:
        jar.set_cookie(cookie)
    return jar


def _cookie(name='sid', value='old', **kwargs):
    return create_cookie(name, value, domain='127.0.0.1', **kwargs)


def _receive(conn, observed):
    wire = read_headers(conn)
    lines = wire.decode('latin1').split('\r\n')
    headers = dict(line.split(': ', 1) for line in lines[1:] if line)
    body = read_exact(conn, int(headers.get('Content-Length', '0')))
    observed.append((lines[0], headers, body))


def _respond(conn, status=200, headers=()):
    wire = 'HTTP/1.1 %d Test\r\nConnection: close\r\nContent-Length: 2\r\n' % status
    wire += ''.join('%s: %s\r\n' % item for item in headers)
    conn.sendall((wire + '\r\nok').encode('latin1'))


def _pairs(request):
    return [
        pair.strip() for pair in request[1].get('Cookie', '').split(';') if pair.strip()
    ]


def _run(api, server, *, jar=None, hooks=None, followup=None, method='GET', **kwargs):
    url = 'http://127.0.0.1:%d/account/one' % server.port
    retry = HTTPRetry(total=1, backoff_factor=0, raise_on_status=False)

    async def run_async():
        async with AsyncSession(use_pooling=False, retry=retry, hooks=hooks) as session:
            session.cookies = jar.copy() if jar is not None else _jar()
            response = await session.request(method, url, timeout=2, **kwargs)
            assert await response.read() == b'ok'
            if followup is not None:
                await session.get(url + followup, timeout=2)
            return response.status_code, session.cookies.copy(), session.cookies.copy()

    if api == 'async':
        return asyncio.run(run_async())
    with Session(use_pooling=False, retry=retry, hooks=hooks) as session:
        session.cookies = jar.copy() if jar is not None else _jar()
        response = session.request(method, url, timeout=2, **kwargs)
        assert response.content == b'ok'
        if followup is not None:
            session.get(url + followup, timeout=2)
        return response.status_code, session._cookies.copy(), session.cookies


@pytest.mark.parametrize('api', ['sync', 'async'])
@pytest.mark.parametrize('initial', [False, True])
def test_status_retry_refreshes_cookies_without_changing_payload(api, initial):
    observed = []

    def serve(conn):
        _receive(conn, observed)
        if len(observed) == 1:
            _respond(conn, 503, [('Set-Cookie', 'sid=new; Path=/')])
        else:
            _respond(conn)

    with LocalServer(serve, connections=2) as server:
        status, stored, _ = _run(
            api,
            server,
            jar=_jar(_cookie()) if initial else None,
            method='PUT',
            data=b'replay=unchanged',
        )
    assert status == 200
    assert _pairs(observed[0]) == (['sid=old'] if initial else [])
    assert _pairs(observed[1]) == ['sid=new']
    assert [item[2] for item in observed] == [b'replay=unchanged'] * 2
    assert stored.get('sid') == 'new'


@pytest.mark.parametrize('api', ['sync', 'async'])
@pytest.mark.parametrize('policy', ['retry', 'redirect'])
@pytest.mark.parametrize(
    'expiry', ['Max-Age=0', 'Expires=Thu, 01 Jan 1970 00:00:00 GMT']
)
@pytest.mark.parametrize('path', ['/', '/account'])
def test_response_deletion_updates_existing_jars_before_followup(
    api, policy, expiry, path
):
    observed = []
    cookies = [_cookie(path=path)]
    if path == '/account':
        cookies.append(_cookie(value='wide', path='/'))

    def serve(conn):
        _receive(conn, observed)
        if len(observed) == 1:
            _respond(
                conn,
                503 if policy == 'retry' else 302,
                [
                    ('Set-Cookie', 'sid=; %s; Path=%s' % (expiry, path)),
                    ('Location', '/account/two'),
                ],
            )
        else:
            _respond(conn)

    with LocalServer(serve, connections=2) as server:
        status, stored, published = _run(api, server, jar=_jar(*cookies))
    assert status == 200
    assert _pairs(observed[1]) == (['sid=wide'] if path == '/account' else [])
    for jar in (stored, published):
        assert not any(cookie.name == 'sid' and cookie.path == path for cookie in jar)
        if path == '/account':
            assert jar.get('sid', path='/') == 'wide'


@pytest.mark.parametrize('api', ['sync', 'async'])
def test_wire_keeps_duplicate_cookie_names_in_path_order_and_filters_scope(api):
    observed = []

    def serve(conn):
        _receive(conn, observed)
        _respond(conn)

    jar = _jar(
        _cookie(value='wide', path='/'),
        _cookie(value='narrow', path='/account'),
        _cookie('secure', 'hidden', secure=True),
        _cookie('expired', 'hidden', expires=1),
        _cookie('path', 'hidden', path='/elsewhere'),
        create_cookie('host', 'hidden', domain='elsewhere.invalid'),
    )
    with LocalServer(serve) as server:
        _run(api, server, jar=jar)
    assert _pairs(observed[0]) == ['sid=narrow', 'sid=wide']


@pytest.mark.parametrize('api', ['sync', 'async'])
@pytest.mark.parametrize('policy', ['retry', 'redirect'])
@pytest.mark.parametrize(
    'source', ['header', 'hook', 'lowercase_hook', 'remove_header', 'remove_auto']
)
def test_explicit_cookie_choice_survives_followup(api, policy, source):
    observed = []
    calls = []

    def before(request):
        calls.append(request.url)
        if not request.url.endswith('/one'):
            return
        if source == 'hook':
            request.headers['Cookie'] = 'sid=manual'
        elif source == 'lowercase_hook':
            request.headers['cookie'] = 'sid=manual'
            request.headers['x-Hook-CaSe'] = 'preserved'
        elif source in ('remove_header', 'remove_auto'):
            request.headers.pop('Cookie', None)

    def serve(conn):
        _receive(conn, observed)
        if len(observed) == 1:
            _respond(
                conn,
                503 if policy == 'retry' else 302,
                [('Set-Cookie', 'sid=new; Path=/'), ('Location', '/account/two')],
            )
        else:
            _respond(conn)

    headers = (
        {'cOOkie': 'sid=manual'} if source in ('header', 'remove_header') else None
    )
    with LocalServer(serve, connections=2) as server:
        status, stored, _ = _run(
            api,
            server,
            jar=_jar(_cookie()),
            headers=headers,
            hooks={'before_request': [before]},
        )
    assert status == 200
    expected = [] if source.startswith('remove') else ['sid=manual']
    assert [_pairs(item) for item in observed] == [expected] * 2
    assert stored.get('sid') == 'new'
    assert len(calls) == (1 if policy == 'retry' else 2)
    if source == 'lowercase_hook' and api == 'sync':
        assert observed[0][1]['x-Hook-CaSe'] == 'preserved'


@pytest.mark.parametrize('mutation', ['setter', 'inplace', 'clear', 'remove_header'])
def test_sync_mutable_prepared_cookie_view_keeps_hook_priority(mutation):
    observed = []

    def before(request):
        if mutation == 'setter':
            request.cookies = {'sid': 'hook'}
        elif mutation in ('inplace', 'remove_header'):
            request.cookies['sid'] = 'hook'
            if mutation == 'remove_header':
                request.headers.pop('Cookie', None)
        else:
            request.cookies.clear()

    def serve(conn):
        _receive(conn, observed)
        _respond(
            conn,
            503 if len(observed) == 1 else 200,
            [('Set-Cookie', 'sid=new; Path=/')],
        )

    with LocalServer(serve, connections=2) as server:
        _, stored, _ = _run(
            'sync', server, jar=_jar(_cookie()), hooks={'before_request': [before]}
        )
    expected = [] if mutation in ('clear', 'remove_header') else ['sid=hook']
    assert [_pairs(item) for item in observed] == [expected] * 2
    assert stored.get('sid') == 'new'


@pytest.mark.parametrize('api', ['sync', 'async'])
def test_request_cookie_remains_local_across_retry(api):
    observed = []

    def serve(conn):
        _receive(conn, observed)
        _respond(
            conn,
            503 if len(observed) == 1 else 200,
            [('Set-Cookie', 'sid=new; Path=/')],
        )

    with LocalServer(serve, connections=3) as server:
        _, stored, _ = _run(
            api,
            server,
            cookies=_jar(_cookie('temporary', 'once', path='/account')),
            followup='/later',
        )
    assert _pairs(observed[0]) == ['temporary=once']
    assert _pairs(observed[1]) == ['temporary=once', 'sid=new']
    assert _pairs(observed[2]) == ['sid=new']
    assert stored.get('temporary') is None


@pytest.mark.parametrize('api', ['sync', 'async'])
@pytest.mark.parametrize('as_bytes', [False, True], ids=['str', 'bytes'])
@pytest.mark.parametrize('initial', [False, True])
def test_request_string_cookies_merge_without_persisting(api, as_bytes, initial):
    observed = []
    cookies = 'sid=argument; temporary="token=="; empty=; repeated=first; repeated=last'
    if as_bytes:
        cookies = cookies.encode()

    def serve(conn):
        _receive(conn, observed)
        _respond(conn)

    jar = _jar(_cookie(), _cookie('existing', 'persisted')) if initial else None
    with LocalServer(serve, connections=2) as server:
        _, stored, _ = _run(api, server, jar=jar, cookies=cookies, followup='/later')
    retained = ['sid=old', 'existing=persisted'] if initial else []
    assert _pairs(observed[0]) == (retained or ['sid=argument']) + [
        'temporary=token==',
        'empty=',
        'repeated=last',
    ]
    assert _pairs(observed[1]) == retained
    assert stored.get_dict() == (
        {'sid': 'old', 'existing': 'persisted'} if initial else {}
    )


@pytest.mark.parametrize('api', ['sync', 'async'])
@pytest.mark.parametrize(
    'cookies', ['sid=argument; temporary=once', b'sid=argument; temporary=once']
)
@pytest.mark.parametrize('source', ['header', 'hook'])
def test_explicit_header_and_hook_override_request_string_cookies(api, cookies, source):
    observed = []

    def before(request):
        request.headers['Cookie'] = 'sid=hook'

    def serve(conn):
        _receive(conn, observed)
        _respond(conn)

    with LocalServer(serve) as server:
        _, stored, _ = _run(
            api,
            server,
            jar=_jar(_cookie()),
            cookies=cookies,
            headers={'cOOkie': 'sid=header'},
            hooks={'before_request': [before]} if source == 'hook' else None,
        )
    assert _pairs(observed[0]) == ['sid=' + source]
    assert stored.get_dict() == {'sid': 'old'}


@pytest.mark.parametrize('api', ['sync', 'async'])
def test_same_origin_redirect_reselects_cookie_path(api):
    observed = []

    def serve(conn):
        _receive(conn, observed)
        if len(observed) == 1:
            _respond(conn, 302, [('Location', '/outside')])
        else:
            _respond(conn)

    with LocalServer(serve, connections=2) as server:
        _run(api, server, jar=_jar(_cookie(path='/account')))
    assert _pairs(observed[0]) == ['sid=old']
    assert _pairs(observed[1]) == []


@pytest.mark.parametrize('api', ['sync', 'async'])
def test_cross_origin_chain_does_not_restore_explicit_cookie_or_auth(api):
    observed = []

    def target(conn):
        _receive(conn, observed)
        _respond(conn, 302, [('Location', source_url + '/returned')])

    def source(conn):
        _receive(conn, observed)
        if len(observed) == 1:
            _respond(conn, 302, [('Location', target_url)])
        else:
            _respond(conn)

    with LocalServer(target) as target_server:
        target_url = 'http://127.0.0.1:%d/' % target_server.port
        with LocalServer(source, connections=2) as source_server:
            source_url = 'http://127.0.0.1:%d' % source_server.port
            _run(
                api,
                source_server,
                headers={'Cookie': 'manual=secret', 'Proxy-Authorization': 'secret'},
                auth=('user', 'secret'),
                cookies={'temporary': 'once'},
            )
    assert _pairs(observed[0]) == ['manual=secret']
    assert 'Authorization' in observed[0][1]
    for request in observed[1:]:
        assert (
            not {'Cookie', 'Authorization', 'Proxy-Authorization'} & request[1].keys()
        )


@pytest.mark.parametrize('api', ['sync', 'async'])
def test_concurrent_request_does_not_contaminate_retry_cookie_snapshot(api):
    observed = []
    received = threading.Event()
    resume = threading.Event()

    def slow(conn):
        _receive(conn, observed)
        if len(observed) == 1:
            received.set()
            assert resume.wait(3)
            _respond(conn, 503, [('Set-Cookie', 'sid=retry; Path=/')])
        else:
            _respond(conn)

    def concurrent(conn):
        read_headers(conn)
        _respond(conn, 200, [('Set-Cookie', 'concurrent=other; Path=/')])

    retry = HTTPRetry(total=1, backoff_factor=0)
    with LocalServer(slow, connections=2) as slow_server:
        with LocalServer(concurrent) as other_server:
            url = 'http://127.0.0.1:%d/' % slow_server.port
            other_url = 'http://127.0.0.1:%d/' % other_server.port
            if api == 'sync':
                with Session(use_pooling=False, retry=retry) as session:
                    session.cookies = _jar(_cookie())
                    with ThreadPoolExecutor(max_workers=1) as workers:
                        pending = workers.submit(
                            session.get, url, cookies={'temporary': 'once'}, timeout=2
                        )
                        try:
                            assert received.wait(2)
                            session.get(other_url, timeout=2)
                        finally:
                            resume.set()
                        assert pending.result(timeout=3).status_code == 200
                    stored = session._cookies.copy()
            else:

                async def run():
                    async with AsyncSession(use_pooling=False, retry=retry) as session:
                        session.cookies = _jar(_cookie())
                        pending = asyncio.create_task(
                            session.get(url, cookies={'temporary': 'once'}, timeout=2)
                        )
                        try:
                            assert await asyncio.get_running_loop().run_in_executor(
                                None, received.wait, 2
                            )
                            await session.get(other_url, timeout=2)
                        finally:
                            resume.set()
                        assert (await pending).status_code == 200
                        return session.cookies.copy()

                stored = asyncio.run(run())
    assert _pairs(observed[0]) == ['sid=old', 'temporary=once']
    assert _pairs(observed[1]) == ['sid=retry', 'temporary=once']
    assert stored.get('sid') == 'retry'
    assert stored.get('concurrent') == 'other'
    assert stored.get('temporary') is None


def test_sync_concurrent_deletion_does_not_resurface_from_request_snapshot():
    deleting_requests = []
    pending_requests = []
    deleting_received = threading.Event()
    pending_received = threading.Event()
    send_deletion = threading.Event()
    send_pending = threading.Event()

    def deleting(conn):
        _receive(conn, deleting_requests)
        deleting_received.set()
        assert send_deletion.wait(3)
        _respond(conn, 200, [('Set-Cookie', 'sid=; Max-Age=0; Path=/')])

    def pending(conn):
        _receive(conn, pending_requests)
        if len(pending_requests) == 1:
            pending_received.set()
            assert send_pending.wait(3)
            _respond(conn, 503)
        else:
            _respond(conn)

    with LocalServer(deleting) as deleting_server:
        with LocalServer(pending, connections=2) as pending_server:
            with Session(
                use_pooling=False, retry=HTTPRetry(total=1, backoff_factor=0)
            ) as session:
                session.cookies = _jar(_cookie())
                with ThreadPoolExecutor(max_workers=2) as workers:
                    deletion = workers.submit(
                        session.get,
                        'http://127.0.0.1:%d/' % deleting_server.port,
                        timeout=2,
                    )
                    try:
                        assert deleting_received.wait(2)
                        other = workers.submit(
                            session.get,
                            'http://127.0.0.1:%d/' % pending_server.port,
                            cookies={'temporary': 'once'},
                            timeout=2,
                        )
                        assert pending_received.wait(2)
                        send_deletion.set()
                        assert deletion.result(timeout=2).status_code == 200
                        assert session._cookies.get('sid') is None
                        assert session.cookies.get('sid') is None
                        assert session.cookies.get('temporary') == 'once'
                    finally:
                        send_deletion.set()
                        send_pending.set()
                    assert other.result(timeout=2).status_code == 200
                assert session.cookies.get('sid') is None
                assert session.cookies.get('temporary') == 'once'
                assert session._cookies.get('temporary') is None
    # B's in-flight snapshot is still its own, even after A deletes the session cookie.
    assert [_pairs(request) for request in pending_requests] == [
        ['sid=old', 'temporary=once']
    ] * 2


@pytest.mark.parametrize(
    'cookies', [{'sid': 'explicit'}, 'sid=explicit', b'sid=explicit']
)
@pytest.mark.parametrize('set_cookie', [False, True])
def test_sync_cookie_setter_inputs_are_normalized_before_response_extraction(
    cookies, set_cookie
):
    observed = []

    def serve(conn):
        _receive(conn, observed)
        _respond(
            conn, headers=[('Set-Cookie', 'other=new; Path=/')] if set_cookie else []
        )

    with LocalServer(serve) as server:
        with Session(use_pooling=False) as session:
            session.cookies = cookies
            response = session.get('http://127.0.0.1:%d/' % server.port, timeout=2)
            assert response.status_code == 200
            assert session.cookies.get('sid') == 'explicit'
            assert session._cookies.get('other') == ('new' if set_cookie else None)
    assert _pairs(observed[0]) == ['sid=explicit']


def test_sync_explicit_cookie_assignment_and_load_reset_request_view(
    tmp_path, monkeypatch
):
    path = tmp_path / 'cookies.json'
    _jar(_cookie('loaded', 'value')).save(path, include_session=True)
    with Session(use_pooling=False) as session:
        monkeypatch.setattr(session, 'send', lambda *args, **kwargs: None)
        session.cookies = _jar(_cookie())
        session.get('http://127.0.0.1/', cookies={'temporary': 'once'})
        assert session.cookies.get('temporary') == 'once'
        snapshot = session.cookies
        snapshot.clear()
        assert session.cookies.get('sid') == 'old'
        session.cookies = _jar(_cookie('assigned', 'value'))
        assert session.cookies.get('assigned') == 'value'
        assert session.cookies.get('temporary') is None
        session.get('http://127.0.0.1/', cookies={'temporary': 'again'})
        assert session.cookies.get('temporary') == 'again'
        invalid_path = tmp_path / 'invalid.json'
        invalid_path.write_text('{}', encoding='utf-8')
        with pytest.raises(ValueError):
            session.load_cookies(invalid_path, include_session=True)
        assert session.cookies.get('temporary') == 'again'
        assert session.cookies.get('assigned') == 'value'
        assert session.load_cookies(path, include_session=True) == 1
        assert session.cookies.get('loaded') == 'value'
        assert session.cookies.get('temporary') is None
        assert session.cookies.get('assigned') is None
