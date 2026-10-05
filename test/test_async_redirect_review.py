"""Loopback regressions for Cookie snapshots across redirect origins."""

import asyncio

import pytest

from ja3requests import AsyncSession, HTTPRetry
from ja3requests.cookies import Ja3RequestsCookieJar
from test.test_async_session import Peer


def _cookie_pairs(request):
    return set(filter(None, request[2].get('Cookie', '').split('; ')))


@pytest.mark.parametrize('cross_origin', [False, True], ids=['same', 'cross'])
@pytest.mark.parametrize('operation', ['replace', 'add', 'delete'])
def test_concurrent_cookie_update_does_not_change_redirect_snapshot(
    cross_origin, operation
):
    async def run():
        started = asyncio.Event()
        resume = asyncio.Event()
        concurrent_cookie = (
            'sid=; Max-Age=0; Path=/'
            if operation == 'delete'
            else 'sid=concurrent; Path=/'
        )

        async def target_route(_method, path, *_):
            if path == '/concurrent':
                return 200, {'Set-Cookie': concurrent_cookie}, b'ok'
            return 200, {}, b'ok'

        async with Peer(target_route) as target:

            async def source_route(_method, path, *_):
                if path == '/start':
                    started.set()
                    await resume.wait()
                    location = target.url + '/finish' if cross_origin else '/finish'
                    return 302, {'Location': location}, b''
                return 200, {}, b'ok'

            async with Peer(source_route) as source:
                async with AsyncSession() as session:
                    if operation != 'add':
                        session.cookies.set(
                            'sid', 'initial', domain='127.0.0.1', path='/'
                        )
                    pending = asyncio.create_task(
                        session.get(source.url + '/start', timeout=2)
                    )
                    try:
                        await asyncio.wait_for(started.wait(), 2)
                        await session.get(target.url + '/concurrent', timeout=2)
                    finally:
                        resume.set()
                    assert (await pending).status_code == 200
                    final_peer = target if cross_origin else source
                    final = next(
                        item for item in final_peer.requests if item[1] == '/finish'
                    )
                    assert _cookie_pairs(final) == (
                        set() if operation == 'add' else {'sid=initial'}
                    )
                    # Sending from the snapshot must not overwrite newer state.
                    assert session.cookies.get('sid') == (
                        None if operation == 'delete' else 'concurrent'
                    )

    asyncio.run(run())


@pytest.mark.parametrize('update', ['none', 'set', 'delete'])
def test_redirect_snapshot_retains_own_updates_and_drops_request_cookies(update):
    async def run():
        attempts = 0

        async def target_route(*_):
            return (
                302,
                {
                    'Location': source.url + '/returned',
                    'Set-Cookie': 'temporary=target; Path=/',
                },
                b'',
            )

        async with Peer(target_route) as target:

            async def source_route(_method, path, *_):
                nonlocal attempts
                if path == '/start':
                    attempts += 1
                    if attempts == 1:
                        headers = {}
                        if update != 'none':
                            headers['Set-Cookie'] = (
                                'sid=retry; Path=/'
                                if update == 'set'
                                else 'sid=; Max-Age=0; Path=/'
                            )
                        return 503, headers, b'retry'
                    return 302, {'Location': '/redirect'}, b''
                if path == '/redirect':
                    return 302, {'Location': target.url + '/next'}, b''
                return 200, {}, b'ok'

            async with Peer(source_route) as source:
                async with AsyncSession(
                    retry=HTTPRetry(total=1, backoff_factor=0)
                ) as session:
                    session.cookies.set('sid', 'initial', domain='127.0.0.1', path='/')
                    cookies = Ja3RequestsCookieJar()
                    cookies.set('sid', 'request', domain='127.0.0.1', path='/')
                    cookies.set('temporary', 'once')
                    response = await session.get(
                        source.url + '/start', cookies=cookies, timeout=2
                    )
                    assert response.status_code == 200
                    assert [item[1] for item in source.requests] == [
                        '/start',
                        '/start',
                        '/redirect',
                        '/returned',
                    ]
                    assert _cookie_pairs(source.requests[0]) == {
                        'sid=request',
                        'temporary=once',
                    }
                    before_cross = {
                        'none': {'sid=request'},
                        'set': {'sid=retry'},
                        'delete': set(),
                    }[update]
                    for item in source.requests[1:3]:
                        assert _cookie_pairs(item) == before_cross | {'temporary=once'}
                    after_cross = {
                        'none': {'sid=initial'},
                        'set': {'sid=retry'},
                        'delete': set(),
                    }[update]
                    assert len(target.requests) == 1
                    assert _cookie_pairs(target.requests[0]) == after_cross
                    assert _cookie_pairs(source.requests[-1]) == after_cross | {
                        'temporary=target'
                    }
                    assert session.cookies.get_dict() == dict(
                        pair.split('=', 1)
                        for pair in after_cross | {'temporary=target'}
                    )

    asyncio.run(run())
