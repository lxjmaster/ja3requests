"""Compile-only examples for a consumer of the installed, typed package."""

from io import BytesIO
from pathlib import Path
from typing import AsyncIterator, Dict, Iterator, List, Optional, Tuple, Union

from typing_extensions import assert_type

import ja3requests
from ja3requests import HTTPRetry, Response, Session, TlsConfig
from ja3requests import AsyncConnectionPool, AsyncResponse, AsyncSession
from ja3requests.base import BaseRequest
from ja3requests.cookies import Ja3RequestsCookieJar
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.frame import H2Frame, build_settings_frame
from ja3requests.protocol.h2.hpack import (
    HPACKDecoder,
    HPACKEncoder,
    decode_integer,
    decode_string,
    encode_integer,
    encode_string,
)
from ja3requests.protocol.h2.huffman import huffman_decode, huffman_encode
from ja3requests.protocol.tls.client_hello_info import inspect_client_hello
from ja3requests.requests.request import Request


def before(request: BaseRequest) -> Optional[BaseRequest]:
    request.headers['X-Trace'] = 'typed-consumer'
    return request


def after(response: Response) -> Optional[Response]:
    assert_type(response.status_code, int)
    return None


async def upload_chunks() -> AsyncIterator[bytes]:
    yield b'first'
    yield b'second'


def protocol_value_boundaries(record: bytes) -> None:
    frame = build_settings_frame({1: 4096})
    assert_type(frame, H2Frame)
    assert_type(frame.serialize(), bytes)
    parsed, remaining = H2Frame.parse(record)
    assert_type(parsed, Optional[H2Frame])
    assert_type(remaining, bytes)
    assert_type(H2Frame.parse_all(record), Tuple[List[H2Frame], bytes])
    assert_type(huffman_encode('header'), bytes)
    assert_type(huffman_encode(bytearray(b'header')), bytes)
    assert_type(huffman_decode(iter(record), max_size=1024), bytes)
    assert_type(encode_integer(1337, 5), bytes)
    assert_type(decode_integer(record, 0, 5), Tuple[int, int])
    assert_type(encode_string('header'), bytes)
    assert_type(encode_string(b'header'), bytes)
    assert_type(decode_string(record, 0, max_size=1024), Tuple[bytes, int])
    header_pairs: List[Tuple[Union[str, bytes], Union[str, bytes]]] = [
        ('x-text', 'value'),
        (b'x-bytes', b'value'),
    ]
    encoder = HPACKEncoder()
    encoder.set_table_size(1024)
    assert_type(encoder.encode_headers(iter(header_pairs)), bytes)
    assert_type(encoder.dynamic_table, List[Tuple[str, Union[str, bytes]]])
    decoder = HPACKDecoder(max_table_size=1024, max_header_list_size=4096)
    assert_type(decoder.decode_headers(record), List[Tuple[str, str]])
    assert_type(decoder.dynamic_table, List[Tuple[str, str]])
    hello = inspect_client_hello(record)
    assert_type(hello['version'], int)
    assert_type(hello['groups'], List[int])
    assert_type(hello['key_shares'], List[Tuple[int, int]])
    assert_type(hello['ja3'], str)


def public_calls(url: str, cookie_path: Path) -> None:
    config = TlsConfig.secure()
    config.verify_cert = True
    config.supported_groups = [29, 23]
    config.key_share_groups = [29]
    config.extension_order = [0, 43, 51]
    config.h2_settings = {1: 65536, 2: 0, 4: 6291456}
    config.h2_window_update = 15663105
    config.client_cert = 'client.pem'
    config.client_key = b'PEM bytes'
    assert_type(config.validate(), List[str])
    assert_type(config.get_ja3_string('example.com'), str)
    assert_type(TlsConfig.from_browser('chrome', version=124), TlsConfig)

    retry = HTTPRetry(total=2, allowed_methods={'GET'}, status_forcelist=[503])
    assert_type(retry.get_backoff_time(1), float)
    with ConnectionPool(max_connections_per_host=4, idle_timeout=2.5) as pool:
        assert_type(pool, ConnectionPool)
        assert_type(pool.get_stats()['total_connections'], int)
        with Session(
            tls_config=config,
            pool=pool,
            retry=retry,
            hooks={'before_request': [before], 'after_request': [after]},
        ) as session:
            assert_type(session, Session)
            session.cookies = {'session': 'value'}
            assert_type(session.cookies, Ja3RequestsCookieJar)
            assert_type(session.response, Optional[Response])
            assert_type(session.save_cookies(cookie_path), int)
            assert_type(session.load_cookies(cookie_path, merge=True), int)
            with session.get(
                url,
                params=[('q', 'one'), ('q', 'two')],
                headers={'X-Request': 'one'},
                timeout=(1.0, 3.0),
                stream=True,
                verify=True,
                allow_redirects=False,
                hooks={'after_request': [after]},
            ) as response:
                assert_type(response, Response)
                assert_type(response.iter_content(8192), Iterator[bytes])
                assert_type(response.iter_lines(delimiter=b'\n'), Iterator[bytes])
                assert_type(response.content, bytes)
                assert_type(response.text, str)
                assert_type(response.headers, Dict[str, str])
                assert_type(response.encoding, str)
                assert_type(response.location, Optional[str])
                response.encoding = None
                response.raise_for_status()
            session.request('GET', url, timeout=(None, 2.0), params=b'q=one')
            session.post(url, json={'nested': [1, None, {'ready': True}]})
            session.post(url, files={'body': BytesIO(b'file bytes')})
            session.post(url, files={'parts': [BytesIO(b'one'), 'two.bin']})
            session.put(url, data=(('a', 1), ('b', 'two')), timeout=2)
            session.patch(url, data='a=one')
            assert_type(session.put(url, data=BytesIO(b'file')), Response)
            assert_type(session.post(url, data=iter((b'one', b'two'))), Response)
            session.delete(url, timeout=None)
            session.head(url, h1=True)
            session.options(url)

    assert_type(ja3requests.session(use_pooling=False), Session)
    assert_type(ja3requests.get(url, timeout=(1, 2)), Response)
    assert_type(ja3requests.request('GET', url, params={'page': 2}), Response)
    assert_type(ja3requests.post(url, json=b'{"ready":true}'), Response)
    assert_type(ja3requests.put(url, data={'name': 'one'}), Response)
    assert_type(ja3requests.post(url, data=BytesIO(b'file')), Response)
    assert_type(ja3requests.put(url, data=iter((b'one', b'two'))), Response)
    assert_type(ja3requests.patch(url, data=[('name', 'two')]), Response)
    assert_type(ja3requests.delete(url), Response)
    assert_type(ja3requests.head(url), Response)
    assert_type(ja3requests.options(url), Response)

    prepared = Request('GET', url, timeout=(2, None), cookies={'a': 'b'}).request()
    assert_type(
        prepared.timeout,
        Optional[Union[float, Tuple[Optional[float], Optional[float]]]],
    )
    jar = Ja3RequestsCookieJar()
    jar.set('name', 'value', domain='example.com', path='/')
    assert_type(jar.get('name'), Optional[str])
    assert_type(jar.get('missing', 0), Union[str, int])
    assert_type(jar.get_dict(), Dict[str, Optional[str]])
    assert_type(jar.iterkeys(), Iterator[str])
    assert_type(jar.copy(), Ja3RequestsCookieJar)


async def async_after(response: AsyncResponse) -> Optional[AsyncResponse]:
    assert_type(response.status_code, int)
    return response


async def native_async_calls(url: str) -> None:
    async with AsyncConnectionPool(max_pool_size=4) as pool:
        assert_type(pool, AsyncConnectionPool)
        async with AsyncSession(
            pool=pool, hooks={'after_request': [async_after]}
        ) as session:
            assert_type(session, AsyncSession)
            async with await session.get(
                url, timeout=(1, None), stream=True
            ) as response:
                assert_type(response, AsyncResponse)
                assert_type(response.aiter_content(1024), AsyncIterator[bytes])
                assert_type(response.aiter_lines(delimiter=b'\n'), AsyncIterator[bytes])
                assert_type(await response.read(), bytes)
                assert_type(await response.text(), str)
                assert_type(response.content, bytes)
                assert_type(response.headers, Dict[str, str])
                assert_type(response.location, Optional[str])
                response.encoding = None
                response.raise_for_status()
            assert_type(await session.post(url, data=b'body'), AsyncResponse)
            assert_type(await session.post(url, data=BytesIO(b'file')), AsyncResponse)
            assert_type(
                await session.put(url, data=iter((b'one', b'two'))), AsyncResponse
            )
            assert_type(await session.patch(url, data=upload_chunks()), AsyncResponse)
            assert_type(
                await session.request('POST', url, data=upload_chunks()), AsyncResponse
            )
            assert_type(
                await session.post(
                    url,
                    data=[('field', 'one'), ('field', 'two')],
                    files={'file': [BytesIO(b'file'), Path('second.bin')]},
                ),
                AsyncResponse,
            )
            assert_type(await session.put(url, json={'ok': True}), AsyncResponse)
            assert_type(
                await session.patch(url, headers={'X-Test': 'yes'}), AsyncResponse
            )
            assert_type(await session.delete(url), AsyncResponse)
            assert_type(await session.head(url, h1=True), AsyncResponse)
            assert_type(
                await session.options(url, proxies={'http': 'socks5://localhost:1080'}),
                AsyncResponse,
            )
            session.cookies.set('name', 'value', domain='example.com')
            assert_type(await session.save_cookies(Path('cookies.json')), int)
            assert_type(
                await session.load_cookies(
                    'cookies.json', merge=True, include_session=True
                ),
                int,
            )
            await session.aclose()
