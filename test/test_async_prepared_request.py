"""Prepared async requests: inspected bytes, snapshots and real send ownership."""

import asyncio
import hashlib
import hmac
import io
import json
import ssl

import pytest

from ja3requests import (
    AsyncConnectionPool,
    AsyncPreparedRequest,
    AsyncSession,
    HTTPRetry,
    InvalidData,
    TlsConfig,
)
from ja3requests.exceptions import Timeout
from ja3requests.protocol.h2.hpack import HPACKDecoder
from test.integration.conftest import trusted_certificates
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    receive_frame,
    start_h2,
    trusted_h2_peer,
)
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    read_headers,
    tls12_context,
    tls13_context,
)
from test.test_async_lifecycle_review import GatedPeer
from test.test_async_session import Peer, ok


def signature(prepared):
    payload = (
        prepared.method.encode() + b'\n' + prepared.url.encode() + b'\n' + prepared.body
    )
    return hmac.new(b'test-only-key', payload, hashlib.sha256).hexdigest()


@pytest.mark.parametrize(
    'name,value',
    [
        ('X-Test', 'bad\x00value'),
        ('X-Test', b'bad\x01value'),
        ('X-Test', 'bad\x7fvalue'),
        ('X\x00Test', 'value'),
        ('X(Test', 'value'),
        ('X/Bad', 'value'),
        ('Xé', 'value'),
    ],
)
@pytest.mark.parametrize(
    'entry', ['request', 'prepare', 'derive', 'request-hook', 'send-hook']
)
def test_async_rejects_invalid_fields_before_network(name, value, entry):
    async def run():
        async with Peer(ok) as peer, AsyncSession() as session:

            def invalid(request):
                request.headers[name] = value

            with pytest.raises(ValueError, match='Invalid HTTP header'):
                if entry == 'request':
                    await session.get(peer.url, headers={name: value}, timeout=1)
                elif entry == 'prepare':
                    await session.prepare_request(
                        'GET', peer.url, headers={name: value}
                    )
                elif entry == 'derive':
                    prepared = await session.prepare_request('GET', peer.url)
                    prepared.with_headers(dict(prepared.headers, **{name: value}))
                elif entry == 'request-hook':
                    await session.get(
                        peer.url, timeout=1, hooks={'before_request': [invalid]}
                    )
                else:
                    prepared = await session.prepare_request('GET', peer.url)
                    await session.send(
                        prepared, timeout=1, hooks={'before_request': [invalid]}
                    )
            assert peer.connections == 0 and not peer.requests
            assert not session._requests and not session.pool._entries

    asyncio.run(run())


def test_async_valid_token_and_horizontal_tab_are_preserved():
    async def run():
        async with Peer(ok) as peer, AsyncSession() as session:
            prepared = await session.prepare_request(
                'GET', peer.url, headers={'X!Token': b'one\ttwo'}
            )
            await session.send(prepared, timeout=1)
            await session.get(peer.url, headers={'X!Token': 'one\ttwo'}, timeout=1)
            assert [request[2]['X!Token'] for request in peer.requests] == [
                'one\ttwo'
            ] * 2

    asyncio.run(run())


@pytest.mark.parametrize(
    'options, expected',
    [
        ({}, b''),
        ({'data': b'\x00\xff'}, b'\x00\xff'),
        ({'data': 'hello 世界'}, 'hello 世界'.encode()),
        ({'data': {'name': ['one', 'two']}}, b'name=one&name=two'),
        ({'data': [('name', 'one'), ('name', 'two')]}, b'name=one&name=two'),
        ({'data': (('a', 1), ('a', 2))}, b'a=1&a=2'),
        ({'json': {'a': 1}}, b'{"a": 1}'),
        ({'json': b'{"a":1}'}, b'{"a":1}'),
        ({'json': '{"a":1}'}, b'{"a":1}'),
    ],
)
def test_prepare_encodes_without_connection_or_hooks(options, expected):
    async def run():
        seen = []
        async with Peer(ok) as peer:
            async with AsyncSession(hooks={'before_request': [seen.append]}) as session:
                prepared = await session.prepare_request(
                    'post',
                    peer.url + '/path?before=one#fragment',
                    params=[('q', 'a b'), ('q', 'two')],
                    **options
                )
                assert isinstance(prepared, AsyncPreparedRequest)
                assert prepared.method == 'POST'
                assert prepared.url == peer.url + '/path?before=one&q=a+b&q=two'
                assert prepared.body == expected
                assert prepared.headers['Content-Length'] == str(len(expected))
                assert seen == [] and peer.connections == 0
                assert not session._requests and not session.pool._entries
                assert repr(prepared) == '<AsyncPreparedRequest [POST]>'
                with pytest.raises(AttributeError):
                    prepared.body = b'changed'
                with pytest.raises(AttributeError):
                    prepared.url = peer.url + '/different'
                with pytest.raises(TypeError):
                    prepared.headers['X-Test'] = 'changed'

    asyncio.run(run())


def test_signed_header_copy_and_two_sends_keep_input_snapshots():
    async def run():
        headers, data, params = (
            {'X-Input': 'original'},
            {'value': ['original']},
            {'q': 'old'},
        )
        async with Peer(ok) as peer:
            async with AsyncSession() as session:
                prepared = await session.prepare_request(
                    'POST', peer.url, headers=headers, data=data, params=params
                )
                headers['X-Input'] = 'changed'
                data['value'].append('changed')
                params['q'] = 'changed'
                replacement = dict(prepared.headers, Authorization=signature(prepared))
                signed = prepared.with_headers(replacement)
                replacement['Authorization'] = 'changed'
                assert 'Authorization' not in prepared.headers
                assert signed.body == b'value=original'
                for _ in range(2):
                    response = await session.send(signed, timeout=1)
                    assert response.content == b'ok'
                assert peer.connections == 1
                for method, path, sent, body in peer.requests:
                    assert (method, path, body) == ('POST', '/?q=old', signed.body)
                    assert sent['Authorization'] == signature(signed)
                    assert sent['X-Input'] == 'original'
                assert signed.headers['Authorization'] == signature(signed)
                assert not session._requests

    asyncio.run(run())


@pytest.mark.parametrize(
    'url_style, suffix, params, expected_path',
    [
        ('normal', '', None, '/'),
        ('normal', '?q=1', None, '/?q=1'),
        ('normal', '#fragment', None, '/'),
        ('normal', '?before=one#fragment', {'q': 'a b'}, '/?before=one&q=a+b'),
        ('normal', '/?q=1', None, '/?q=1'),
        ('normal', '/encoded%2Fsegment?x=%2F', None, '/encoded%2Fsegment?x=%2F'),
        ('normal', '//signed', None, '//signed'),
        ('normal', '///signed', None, '///signed'),
        (
            'normal',
            '//encoded%2f/../?q=a%2Bb&q=%2F',
            None,
            '//encoded%2f/../?q=a%2Bb&q=%2F',
        ),
        ('normal', '/signed?', None, '/signed'),
        ('uppercase-scheme', '/signed', None, '/signed'),
        ('zero-port', '/signed', None, '/signed'),
    ],
)
def test_http1_peer_verifies_signature_from_received_url(
    url_style, suffix, params, expected_path
):
    async def run():
        async def route(method, path, headers, body):
            wire_url = 'http://' + headers['Host'] + path
            payload = method.encode() + b'\n' + wire_url.encode() + b'\n' + body
            expected = hmac.new(b'test-only-key', payload, hashlib.sha256).hexdigest()
            valid = headers['Authorization'] == expected
            return (200 if valid else 401), {}, b'ok' if valid else b'bad signature'

        async with Peer(route) as peer, AsyncSession() as session:
            url = peer.url
            if url_style == 'uppercase-scheme':
                url = url.replace('http://', 'HTTP://')
            elif url_style == 'zero-port':
                authority, port = url.rsplit(':', 1)
                url = authority + ':0' + port
            prepared = await session.prepare_request(
                'POST', url + suffix, params=params, data=b'signed root'
            )
            signed = prepared.with_headers(
                dict(prepared.headers, Authorization=signature(prepared))
            )
            for _ in range(2):
                response = await session.send(signed, timeout=1, allow_redirects=False)
                assert response.status_code == 200, response.content
            assert prepared.url == signed.url == peer.url + expected_path
            assert [request[1] for request in peer.requests] == [expected_path] * 2

    asyncio.run(run())


@pytest.mark.parametrize(
    'url, expected_url, expected_host',
    [
        (
            'HTTP://EXAMPLE.TEST:00080/signed?',
            'http://example.test/signed',
            'example.test',
        ),
        (
            'HTTPS://BÜCHER.test:00443/encoded%2f?q=%2f&q=two',
            'https://xn--bcher-kva.test/encoded%2f?q=%2f&q=two',
            'xn--bcher-kva.test',
        ),
        (
            'HTTPS://[2001:DB8::1]:00443/signed?',
            'https://[2001:db8::1]/signed',
            '[2001:db8::1]',
        ),
        (
            'HTTP://[2001:DB8::1]:08080',
            'http://[2001:db8::1]:8080/',
            '[2001:db8::1]:8080',
        ),
    ],
)
def test_prepare_normalizes_destination_authority_without_network(
    url, expected_url, expected_host
):
    async def run():
        async with AsyncSession() as session:
            prepared = await session.prepare_request('POST', url, data=b'body')
            assert prepared.url == expected_url
            assert prepared.headers['Host'] == expected_host
            derived = prepared.with_headers(
                dict(prepared.headers, Authorization=signature(prepared))
            )
            assert derived.url == prepared.url
            assert not session.pool._entries and not session._requests

    asyncio.run(run())


def test_normalized_url_retains_explicit_host_and_destination_cookie_selection():
    async def run():
        async with AsyncSession() as session:
            session.cookies.set('sid', 'destination', domain='example.test', path='/')
            session.cookies.set('sid', 'virtual', domain='virtual.test', path='/')
            prepared = await session.prepare_request(
                'GET',
                'HTTP://EXAMPLE.TEST:00080/signed?',
                headers={'Host': 'virtual.test'},
            )
            assert prepared.url == 'http://example.test/signed'
            assert prepared.headers['Host'] == 'virtual.test'
            assert prepared.headers['Cookie'] == 'sid=destination'
            derived = prepared.with_headers(dict(prepared.headers, Host='other.test'))
            assert derived.url == prepared.url
            assert derived.headers['Host'] == 'other.test'
            assert derived.headers['Cookie'] == 'sid=destination'
            assert not session.pool._entries and not session._requests

    asyncio.run(run())


def test_prepare_selects_idna_destination_cookies_before_signing():
    async def run():
        async with AsyncSession() as session:
            session.cookies.set('sid', 'idna', domain='xn--bcher-kva.test', path='/')
            prepared = await session.prepare_request(
                'GET', 'HTTPS://BÜCHER.test:00443/'
            )
            assert prepared.url == 'https://xn--bcher-kva.test/'
            assert prepared.headers['Cookie'] == 'sid=idna'
            assert not session.pool._entries and not session._requests

    asyncio.run(run())


def test_header_derivation_validates_and_preserves_framing():
    async def run():
        async with AsyncSession() as session:
            request = await session.prepare_request(
                'POST', 'http://example.test', data=b'abc'
            )
            derived = request.with_headers(
                {'x-signature': 'ok', 'content-length': '99'}
            )
            assert dict(derived.headers) == {
                'X-Signature': 'ok',
                'Content-Length': '3',
                'Host': 'example.test',
            }
            for headers in (
                {'X-Test': 'a\r\nb'},
                {'Bad Header': 'x'},
                {'Transfer-Encoding': 'chunked'},
            ):
                with pytest.raises(ValueError):
                    request.with_headers(headers)
            assert request.body == b'abc' and 'X-Signature' not in request.headers

    with pytest.raises(TypeError, match='prepare_request'):
        AsyncPreparedRequest()
    asyncio.run(run())


@pytest.mark.parametrize('kind', ['file', 'sync', 'async', 'adapter'])
def test_prepare_rejects_sources_without_advancing_or_closing(kind):
    events = []

    class File(io.BytesIO):
        def read(self, *_):
            events.append('read')
            return b''

        def seek(self, *_):
            events.append('seek')
            return 0

    def chunks():
        events.append('pull')
        yield b'body'

    async def async_chunks():
        events.append('async pull')
        yield b'body'

    from ja3requests._upload import UploadSource

    handle = File(b'body')
    source = {
        'file': handle,
        'sync': chunks(),
        'async': async_chunks(),
        'adapter': UploadSource(handle),
    }[kind]

    async def run():
        async with AsyncSession() as session:
            with pytest.raises(InvalidData, match='buffered'):
                await session.prepare_request('POST', 'http://127.0.0.1:1', data=source)
            with pytest.raises(TypeError, match='files'):
                await session.prepare_request(
                    'POST', 'http://127.0.0.1:1', files={'body': handle}
                )
            assert events == [] and not handle.closed
            assert not session.pool._entries and not session._requests

    asyncio.run(run())


def test_tls_proxy_cookie_snapshots_and_per_send_config_isolation(monkeypatch):
    async def run():
        config = TlsConfig.secure()
        config.client_cert, config.client_key = 'snapshot-cert.pem', b'snapshot-key'
        config.alpn_protocols = ['h2', 'http/1.1']
        routes = {'https': 'http://proxy.test:8080'}
        async with Peer(ok) as peer:
            async with AsyncSession(tls_config=config) as session:
                session.cookies.set('sid', 'old', domain='127.0.0.1', path='/')
                coroutine = session.prepare_request(
                    'GET',
                    peer.url,
                    tls_config=config,
                    proxies=routes,
                    verify=True,
                    h1=True,
                )
                config.client_cert = 'at-await.pem'
                prepared = await coroutine
                config.client_cert, config.client_key = None, None
                config.verify_cert = False
                config.alpn_protocols.append('other')
                routes['https'] = 'http://changed.test:9'
                session.cookies.set('sid', 'new', domain='127.0.0.1', path='/')
                cache = config.session_cache
                original = session._attempt
                observed = []

                async def attempt(metadata, selected, proxies, budgets):
                    observed.append(selected)
                    assert selected.verify_cert is True
                    assert selected.client_cert == 'at-await.pem'
                    assert selected.client_key == b'snapshot-key'
                    assert selected.alpn_protocols == ['http/1.1']
                    assert selected.session_cache is cache
                    assert proxies == {'https': 'http://proxy.test:8080'}
                    result = await original(metadata, selected, proxies, budgets)
                    selected.client_cert = 'attempt-only.pem'
                    proxies.clear()
                    return result

                monkeypatch.setattr(session, '_attempt', attempt)
                for _ in range(2):
                    await session.send(prepared, timeout=1)
                assert observed[0] is not observed[1]
                assert [r[2]['Cookie'] for r in peer.requests] == ['sid=old'] * 2
                assert prepared.headers['Cookie'] == 'sid=old'
                assert session.cookies.get('sid') == 'new'

    asyncio.run(run())


def test_concurrent_send_hook_and_response_mutation_are_isolated():
    async def run():
        entered = 0
        gate = asyncio.Event()

        async def before(request, label):
            nonlocal entered
            request.headers['X-Call'] = label
            entered += 1
            if entered == 2:
                gate.set()
            await gate.wait()

        async with Peer(ok) as peer:
            async with AsyncSession() as session:
                prepared = await session.prepare_request('POST', peer.url, data=b'body')

                async def send(label):
                    async def hook(request):
                        await before(request, label)

                    return await session.send(
                        prepared, timeout=1, hooks={'before_request': [hook]}
                    )

                responses = await asyncio.wait_for(
                    asyncio.gather(send('one'), send('two')), 2
                )
                assert {r[2]['X-Call'] for r in peer.requests} == {'one', 'two'}
                assert 'X-Call' not in prepared.headers
                responses[0].request.headers['X-Input'] = 'response-only'
                assert 'X-Input' not in prepared.headers
                assert responses[0].request is not responses[1].request
                assert all(r.content == b'ok' for r in responses)

    asyncio.run(run())


def test_retry_cookie_updates_and_send_time_hook_policy():
    async def run():
        events = []

        async def route(*_):
            if len(peer.requests) == 1:
                return 503, {'Set-Cookie': 'sid=from-retry; Path=/'}, b'retry'
            return 200, {}, b'ok'

        async with Peer(route) as peer:
            async with AsyncSession() as session:
                session.cookies.set('sid', 'old', domain='127.0.0.1', path='/')
                prepared = await session.prepare_request('GET', peer.url)
                session._retry = HTTPRetry(total=1, backoff_factor=0)
                session.hooks['before_request'] = [
                    lambda _: events.append('session-before')
                ]
                response = await session.send(
                    prepared,
                    timeout=1,
                    hooks={
                        'before_request': [lambda _: events.append('call-before')],
                        'after_request': [lambda _: events.append('after')],
                    },
                )
                assert response.content == b'ok'
                assert [r[2]['Cookie'] for r in peer.requests] == [
                    'sid=old',
                    'sid=from-retry',
                ]
                assert events == ['session-before', 'call-before', 'after']
                assert session.cookies.get('sid') == 'from-retry'
                assert prepared.headers['Cookie'] == 'sid=old'
                await session.send(prepared, timeout=1)
                assert peer.requests[-1][2]['Cookie'] == 'sid=old'

    asyncio.run(run())


@pytest.mark.parametrize('keep_cookie', [False, True])
def test_derived_cookie_header_is_explicit_even_when_equal_to_generated(keep_cookie):
    async def run():
        async def route(*_):
            if len(peer.requests) == 1:
                return 503, {'Set-Cookie': 'sid=updated; Path=/'}, b'retry'
            return 200, {}, b'ok'

        async with Peer(route) as peer:
            async with AsyncSession(
                retry=HTTPRetry(total=1, backoff_factor=0)
            ) as session:
                session.cookies.set('sid', 'snapshot', domain='127.0.0.1', path='/')
                prepared = await session.prepare_request('GET', peer.url)
                headers = dict(prepared.headers)
                cookie = headers.pop('Cookie')
                if keep_cookie:
                    headers['cOoKiE'] = cookie
                derived = prepared.with_headers(headers)
                await session.send(derived, timeout=1)
                expected = 'sid=snapshot' if keep_cookie else None
                assert [r[2].get('Cookie') for r in peer.requests] == [
                    expected,
                    expected,
                ]
                assert session.cookies.get('sid') == 'updated'
                assert prepared.headers['Cookie'] == 'sid=snapshot'

    asyncio.run(run())


@pytest.mark.parametrize('status', [307, 308])
@pytest.mark.parametrize('cross_origin', [False, True])
def test_redirect_replays_bytes_and_strips_cross_origin_credentials(
    status, cross_origin
):
    async def run():
        events = []
        async with Peer(ok) as target:

            async def route(_method, path, *_):
                if path == '/one':
                    return (
                        status,
                        {'Location': target.url if cross_origin else '/two'},
                        b'',
                    )
                return 200, {}, b'ok'

            async with Peer(route) as source:
                async with AsyncSession() as session:
                    prepared = await session.prepare_request(
                        'POST',
                        source.url + '/one',
                        data=b'body',
                        auth=('u', 'p'),
                        headers={
                            'Cookie': 'explicit=secret',
                            'Proxy-Authorization': 'secret',
                        },
                    )
                    response = await session.send(
                        prepared,
                        timeout=1,
                        hooks={'before_request': [lambda r: events.append(r.url)]},
                    )
                    assert response.content == b'ok'
                    final = (target if cross_origin else source).requests[-1]
                    assert (final[0], final[3]) == ('POST', b'body')
                    if cross_origin:
                        assert (
                            not {'Authorization', 'Proxy-Authorization', 'Cookie'}
                            & final[2].keys()
                        )
                    else:
                        assert (
                            final[2]['Authorization']
                            == prepared.headers['Authorization']
                        )
                        assert final[2]['Cookie'] == 'explicit=secret'
                    assert len(events) == 2
                    assert (
                        prepared.url.endswith('/one')
                        and prepared.headers['Cookie'] == 'explicit=secret'
                    )

    asyncio.run(run())


def test_rejected_owner_closed_session_and_loop_use_no_transport():
    async def run():
        async with AsyncSession() as session, AsyncSession() as other:
            request = await session.prepare_request('GET', 'http://127.0.0.1:1')
            with pytest.raises(ValueError, match='another AsyncSession'):
                await other.send(request)
            with pytest.raises(TypeError, match='AsyncPreparedRequest'):
                await session.send(object())
            await session.aclose()
            with pytest.raises(RuntimeError, match='closed'):
                await session.send(request)
            with pytest.raises(RuntimeError, match='closed'):
                await session.prepare_request('GET', request.url)
            assert not other.pool._entries

    asyncio.run(run())
    session = AsyncSession()
    loop = asyncio.new_event_loop()
    try:
        request = loop.run_until_complete(
            session.prepare_request('GET', 'http://127.0.0.1:1')
        )
        with pytest.raises(RuntimeError, match='event loops'):
            asyncio.run(session.send(request))
        loop.run_until_complete(session.aclose())
    finally:
        loop.close()


def test_hook_stream_source_is_rejected_without_pull():
    events = []

    def source():
        events.append('pulled')
        yield b'body'

    async def run():
        async with Peer(ok) as peer:
            async with AsyncSession() as session:
                request = await session.prepare_request('POST', peer.url, data=b'old')

                def before(metadata):
                    metadata.body = source()

                with pytest.raises(InvalidData, match='buffered'):
                    await session.send(request, hooks={'before_request': [before]})
                assert peer.connections == 0 and events == []
                assert request.body == b'old' and not session._requests

    asyncio.run(run())


@pytest.mark.parametrize('finish', ['cancel', 'session-close', 'timeout'])
def test_pending_send_cleanup_and_request_remains_reusable(finish):
    async def run():
        async def route(*_):
            if len(peer.requests) == 1:
                await asyncio.Event().wait()
            return 200, {}, b'ok'

        async with Peer(route) as peer:
            async with AsyncSession() as session:
                request = await session.prepare_request('GET', peer.url)
                task = asyncio.create_task(
                    session.send(
                        request, timeout=(1, 0.02) if finish == 'timeout' else None
                    )
                )
                await asyncio.wait_for(peer.received.wait(), 1)
                if finish == 'cancel':
                    task.cancel()
                elif finish == 'session-close':
                    await asyncio.wait_for(session.aclose(), 1)
                with pytest.raises(
                    Timeout if finish == 'timeout' else asyncio.CancelledError
                ):
                    await task
                assert not session._requests and not session.pool._entries
                assert request.method == 'GET'
                if finish != 'session-close':
                    assert (await session.send(request, timeout=1)).content == b'ok'

    asyncio.run(run())


def test_stream_response_transfer_keeps_borrowed_pool_and_recipient_alive():
    async def run():
        async with GatedPeer() as slow, Peer(ok) as ready:
            async with AsyncConnectionPool() as pool:
                donor, recipient = AsyncSession(pool=pool), AsyncSession()
                try:
                    request = await donor.prepare_request('GET', slow.url)
                    response = await donor.send(request, stream=True, timeout=1)
                    ready_request = await recipient.prepare_request('GET', ready.url)
                    transferred = await recipient.send(
                        ready_request,
                        stream=True,
                        timeout=1,
                        hooks={'after_request': [lambda _: response]},
                    )
                    assert transferred is response
                    await donor.aclose()
                    assert not pool._closed and not response.closed
                    slow.allow_body.set()
                    assert await response.read() == b'tail'
                    await recipient.aclose()
                    assert not pool._closed
                finally:
                    await recipient.aclose()
                    await donor.aclose()

    asyncio.run(run())


@pytest.mark.parametrize('finish', ['response-close', 'session-close'])
def test_prepared_stream_early_close_releases_transport_before_peer_eof(finish):
    async def run():
        async with GatedPeer() as peer:
            async with AsyncSession() as session:
                prepared = await session.prepare_request('GET', peer.url)
                response = await session.send(prepared, stream=True, timeout=1)
                transport = response._transport
                assert not response.closed and not peer.allow_body.is_set()
                if finish == 'response-close':
                    await asyncio.wait_for(response.aclose(), 1)
                else:
                    await asyncio.wait_for(session.aclose(), 1)
                assert response.closed and transport.closed
                assert not session.pool._entries and not session._requests
                assert prepared.body == b''

    asyncio.run(run())


@pytest.mark.parametrize('version', [12, 13])
def test_signed_tls_send_retains_verification_and_client_credentials(
    trusted_certificates, monkeypatch, version
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    config = TlsConfig.secure()
    cert, key = trusted_certificates.leaves['client-rsa']
    config.client_cert, config.client_key = str(cert), str(key)
    if version == 12:
        config.tls_version = 0x0303
        config.cipher_suites = [0xC02F]
        context = tls12_context(
            *trusted_certificates.leaves['valid'], cipher='ECDHE-RSA-AES128-GCM-SHA256'
        )
    else:
        context = tls13_context(*trusted_certificates.leaves['valid'])
    context.load_verify_locations(cafile=str(trusted_certificates.ca_path))
    context.verify_mode = ssl.CERT_REQUIRED
    observed = []

    def peer(conn):
        assert conn.getpeercert(), 'Prepared send must retain client-auth credentials'
        wire = read_headers(conn)
        headers = dict(line.split(b': ', 1) for line in wire.split(b'\r\n')[1:] if line)
        body = read_exact(conn, int(headers[b'Content-Length']))
        assert body == b'buffered payload'
        assert headers[b'Authorization'].decode() == observed[0]
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')
        await_transport_close(conn)

    async def run(port):
        async with AsyncSession(tls_config=config) as session:
            request = await session.prepare_request(
                'POST',
                'https://127.0.0.1:%d/' % port,
                data=b'buffered payload',
                tls_config=config,
                verify=True,
            )
            signed = request.with_headers(
                dict(request.headers, Authorization=signature(request))
            )
            observed.append(signature(signed))
            config.client_cert = config.client_key = None
            config.verify_cert = False
            response = await session.send(signed, timeout=3)
            assert response.content == b'ok'
            transport = session.pool._entries[0].transport
            assert transport.tls._cert_verified

    with LocalServer(peer, context) as server:
        asyncio.run(run(server.port))


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize(
    'url_style, path, params, expected_path',
    [
        ('normal', '', [('q', 'one'), ('q', 'two')], '/?q=one&q=two'),
        ('normal', '/signed', [('q', 'one'), ('q', 'two')], '/signed?q=one&q=two'),
        ('normal', '//signed', None, '//signed'),
        ('normal', '///signed', None, '///signed'),
        (
            'normal',
            '//encoded%2f/../?q=a%2Bb&q=%2F',
            None,
            '//encoded%2f/../?q=a%2Bb&q=%2F',
        ),
        ('normal', '/signed?', None, '/signed'),
        ('uppercase-scheme', '/signed', None, '/signed'),
        ('zero-port', '/signed', None, '/signed'),
    ],
)
def test_signed_h2_resend_preserves_inspected_url_and_bytes(
    trusted_certificates, monkeypatch, version, url_style, path, params, expected_path
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)

    def peer(conn):
        start_h2(conn)
        decoder = HPACKDecoder()
        for expected_stream in (1, 3):
            headers, body = None, bytearray()
            while True:
                kind, flags, stream, payload = receive_frame(conn)
                if kind == 1:
                    assert stream == expected_stream
                    headers = dict(decoder.decode_headers(payload))
                elif kind == 0:
                    assert stream == expected_stream
                    body.extend(payload)
                    if flags & 1:
                        break
            assert headers[':method'] == 'POST'
            assert headers[':path'] == expected_path
            assert body == b'buffered h2'
            wire_url = (
                headers[':scheme'] + '://' + headers[':authority'] + headers[':path']
            )
            payload = (
                headers[':method'].encode() + b'\n' + wire_url.encode() + b'\n' + body
            )
            expected = hmac.new(b'test-only-key', payload, hashlib.sha256).hexdigest()
            assert headers['authorization'] == expected
            conn.sendall(
                h2_frame(1, 4, expected_stream, b'\x88')
                + h2_frame(0, 1, expected_stream, b'ok')
            )
        await_transport_close(conn)

    async def run(port):
        async with AsyncSession(tls_config=config) as session:
            url = 'https://127.0.0.1:%d%s' % (port, path)
            if url_style == 'uppercase-scheme':
                url = url.replace('https://', 'HTTPS://')
            elif url_style == 'zero-port':
                url = 'https://127.0.0.1:0%d%s' % (port, path)
            request = await session.prepare_request(
                'POST',
                url,
                params=params,
                data=b'buffered h2',
                tls_config=config,
            )
            assert request.url == 'https://127.0.0.1:%d%s' % (port, expected_path)
            signed = request.with_headers(
                dict(request.headers, Authorization=signature(request))
            )
            config.alpn_protocols = ['http/1.1']
            for _ in range(2):
                response = await session.send(signed, timeout=3)
                assert (
                    response.protocol_version == 'HTTP/2' and response.content == b'ok'
                )
            assert len(session.pool._entries) == 1

    with LocalServer(peer, context) as server:
        asyncio.run(run(server.port))
