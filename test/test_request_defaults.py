"""Opt-in assignment, preparation and compatibility boundaries without I/O."""

import asyncio
from collections import UserList
from unittest.mock import patch
from urllib.parse import urlsplit

import pytest

from ja3requests import AsyncSession, Session
from ja3requests.cookies import Ja3RequestsCookieJar
from ja3requests.requests.request import Request


@pytest.fixture(params=[Session, AsyncSession])
def session(request):
    client = request.param(use_pooling=False)
    yield client
    if isinstance(client, AsyncSession):
        asyncio.run(client.aclose())
    else:
        client.close()


def test_assignment_is_detached_and_clearing_is_explicit(session):
    assert session.request_defaults is None
    headers = {'X-Default': b'value', 'X-Number': 2}
    params = [['tag', 'one'], ['tag', 'two']]
    value = {'headers': headers, 'params': params}
    session.request_defaults = value
    headers['X-Default'] = 'changed'
    params[0][1] = 'changed'
    value.clear()
    snapshot = session.request_defaults
    assert snapshot == {
        'headers': {'X-Default': b'value', 'X-Number': 2},
        'params': (('tag', 'one'), ('tag', 'two')),
    }
    snapshot['headers']['X-Default'] = 'detached'
    snapshot['params'] = ()
    assert session.request_defaults['headers']['X-Default'] == b'value'
    assert session.request_defaults['params'] == (('tag', 'one'), ('tag', 'two'))
    for empty in [None, {}, {'headers': {}, 'params': []}, {'headers': None}]:
        session.request_defaults = empty
        assert session.request_defaults is None
    session.request_defaults = {'params': UserList([('q', 'one')])}
    assert session.request_defaults == {'params': (('q', 'one'),)}


@pytest.mark.parametrize(
    'value,error',
    [
        ([], TypeError),
        ({'timeout': 1}, TypeError),
        ({'auth': ('u', 'p')}, TypeError),
        ({'cookies': {}}, TypeError),
        ({'proxies': {}}, TypeError),
        ({'tls_config': None}, TypeError),
        ({'headers': []}, TypeError),
        ({'headers': {1: 'value'}}, TypeError),
        ({'headers': {'X-Test': None}}, TypeError),
        ({'headers': {'X-Test': []}}, TypeError),
        ({'headers': {'X-Test': 'a', 'x-test': 'b'}}, ValueError),
        ({'headers': {'': 'value'}}, ValueError),
        ({'headers': {'X(Bad': 'value'}}, ValueError),
        ({'headers': {'X-Test': 'a\r\nb'}}, ValueError),
        ({'headers': {'X-Test': b'a\x00b'}}, ValueError),
        ({'headers': {'X-Test': b'a\x7fb'}}, ValueError),
        ({'params': 'q=one'}, TypeError),
        ({'params': b'q=one'}, TypeError),
        ({'params': {'q': 1}}, TypeError),
        ({'params': {b'q': 'one'}}, TypeError),
        ({'params': [('q',)]}, TypeError),
        ({'params': [('q', ['one'])]}, TypeError),
        ({'params': iter([('q', 'one')])}, TypeError),
        ({'headers': {'X-New': 'new'}, 'params': {'q': 1}}, TypeError),
    ],
)
def test_invalid_assignment_is_atomic(session, value, error):
    session.request_defaults = {'headers': {'X-Original': 'kept'}}
    with pytest.raises(error):
        session.request_defaults = value
    assert session.request_defaults == {'headers': {'X-Original': 'kept'}}


@pytest.mark.parametrize(
    'name',
    [
        'Authorization',
        'Proxy-Authorization',
        'Cookie',
        'Host',
        'Content-Length',
        'Transfer-Encoding',
    ],
)
def test_origin_and_framing_headers_are_not_defaults(session, name):
    with pytest.raises(ValueError, match='not allowed'):
        session.request_defaults = {'headers': {name.swapcase(): 'value'}}


def capture(client, defaults, *, stored=None, **kwargs):
    if client == 'sync':
        with Session(use_pooling=False) as current:
            current.request_defaults = defaults
            if stored is not None:
                current.cookies = stored.copy()
            with patch.object(current, 'send', side_effect=lambda ready, **_: ready):
                return current.get('http://example.test/path?url=kept', **kwargs)

    async def run():
        async with AsyncSession(use_pooling=False) as current:
            current.request_defaults = defaults
            if stored is not None:
                current.cookies = stored.copy()
            if client == 'prepared':
                return await current.prepare_request(
                    'GET', 'http://example.test/path?url=kept', **kwargs
                )

            async def submitted(ready, *_):
                return ready

            with patch.object(current, '_submit', submitted):
                return await current.get('http://example.test/path?url=kept', **kwargs)

    return asyncio.run(run())


@pytest.mark.parametrize('client', ['sync', 'async', 'prepared'])
@pytest.mark.parametrize(
    'headers',
    [None, {}, {'x-default': 'explicit', 'user-agent': 'caller', 'X-Other': 3}],
)
def test_headers_precedence_and_native_empty_behavior(client, headers):
    defaults = {
        'headers': {
            'X-Default': 'configured',
            'X-Bytes': b'\xc3\xa9',
            'X-Number': 2,
            'User-Agent': 'configured',
        }
    }
    ready = capture(client, defaults, headers=headers)
    values = {name.lower(): value for name, value in ready.headers.items()}
    if headers == {}:
        assert 'x-default' not in values
        assert ('user-agent' in values) == (client == 'sync')
    else:
        assert values['x-default'] == ('explicit' if headers else 'configured')
        assert values['x-bytes'] == b'\xc3\xa9'
        assert str(values['x-number']) == '2'
        assert 'user-agent' in values and values['accept'] == '*/*'
        assert values['user-agent'] == ('caller' if headers else 'configured')
        assert sum(name.lower() == 'x-default' for name in ready.headers) == 1


@pytest.mark.parametrize('client', ['sync', 'async', 'prepared'])
@pytest.mark.parametrize(
    'params,expected',
    [
        (None, 'tag=a&tag=b&page=1'),
        ({}, ''),
        ([], ''),
        ((), ''),
        ('', ''),
        (b'', ''),
        ('raw=%2F', 'raw=%2F'),
        (b'raw=%2F', 'raw=%2F'),
        ({'tag': 'x'}, 'page=1&tag=x'),
        ([('tag', 'x'), ('tag', 'y')], 'page=1&tag=x&tag=y'),
        ({b'tag': 'x'}, 'tag=a&tag=b&page=1&tag=x'),
    ],
)
def test_query_order_duplicates_raw_and_empty_inputs(client, params, expected):
    defaults = {'params': [('tag', 'a'), ('tag', 'b'), ('page', '1')]}
    ready = capture(client, defaults, params=params)
    assert urlsplit(ready.url).query == 'url=kept' + (
        '&' + expected if expected else ''
    )


@pytest.mark.parametrize('client', ['sync', 'async', 'prepared'])
def test_fields_opt_in_independently_and_keep_native_list_encoding(client):
    ready = capture(client, {'params': {'page': '1'}}, headers={'X-Only': 'one'})
    assert 'User-Agent' not in ready.headers
    ready = capture(
        client, {'headers': {'X-Default': 'one'}}, params={'tag': ['a', 'b']}
    )
    baseline = capture(client, None, params={'tag': ['a', 'b']})
    assert ready.url == baseline.url
    ready = capture(client, {'params': {'page': '1'}}, params={'tag': ['a', 'b']})
    assert (
        urlsplit(ready.url).query
        == 'url=kept&page=1&' + urlsplit(baseline.url).query.split('&', 1)[1]
    )


@pytest.mark.parametrize('client', ['sync', 'async', 'prepared'])
@pytest.mark.parametrize('kind', ['none', 'empty', 'dict', 'jar', 'explicit'])
def test_defaults_keep_cookie_scope_and_native_overlay_rules(client, kind):
    stored = Ja3RequestsCookieJar()
    stored.set('sid', 'stored', domain='example.test', path='/')
    stored.set('hidden', 'secure', domain='example.test', path='/', secure=True)
    stored.set('outside', 'hidden', domain='elsewhere.test', path='/')
    jar = Ja3RequestsCookieJar()
    jar.set('sid', 'local', domain='example.test', path='/')
    cookies = {
        'none': None,
        'empty': {},
        'dict': {'sid': 'local'},
        'jar': jar,
        'explicit': None,
    }[kind]
    ready = capture(
        client,
        {'headers': {'X-Default': 'one'}, 'params': {'d': 'one'}},
        stored=stored,
        cookies=cookies,
        headers={'Cookie': 'sid=explicit'} if kind == 'explicit' else None,
    )
    assert (
        ready.headers['Cookie']
        == 'sid='
        + {
            'none': 'stored',
            'empty': 'stored',
            'dict': 'stored',
            'jar': 'local',
            'explicit': 'explicit',
        }[kind]
    )


def test_sync_legacy_observations_assignments_and_direct_send_are_isolated():
    with Session(use_pooling=False) as current:
        with patch.object(current, 'send', side_effect=lambda ready, **_: ready):
            current.get(
                'http://a.example/',
                auth=('u', 'p'),
                params={'old': 'one'},
                headers={'X-Old': 'one', 'Cookie': 'old=one'},
                proxies={'http': 'http://proxy.example:8080'},
            )
            assert current.auth == ('u', 'p')
            assert current.headers['X-Old'] == 'one'
            assert current.params and current.proxies
            current.request_defaults = {'headers': {'X-Default': 'one'}}
            ready = current.get('http://b.example/')
            assert ready.auth is None and ready.proxy is None
            assert urlsplit(ready.url).query == ''
            assert 'X-Default' in ready.headers
            assert not {'Authorization', 'Cookie', 'X-Old'} & ready.headers.keys()
            current.headers = {'X-Legacy': 'assigned'}
            current.params = {'legacy': 'assigned'}
            current.auth = ('legacy', 'password')
            current.proxies = {'http': 'http://legacy.example:8080'}
            ready = current.get('http://b.example/')
            assert ready.auth is None and ready.proxy is None
            assert 'X-Legacy' not in ready.headers and '?' not in ready.url
        # Standalone preparation is independent of Session defaults.
        ready = Request('GET', 'http://b.example/').request()
        assert 'X-Default' not in ready.headers
