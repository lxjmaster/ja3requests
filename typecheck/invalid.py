"""Every E marker must produce the listed mypy diagnostic; never execute."""

from io import BytesIO, StringIO
from typing import AsyncIterator

import ja3requests
from ja3requests import HTTPRetry, Response, Session, TlsConfig
from ja3requests.cookies import Ja3RequestsCookieJar
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.frame import H2Frame
from ja3requests.protocol.h2.hpack import (
    HPACKDecoder,
    HPACKEncoder,
    decode_integer,
    decode_string,
    encode_integer,
    encode_string,
)
from ja3requests.protocol.h2.huffman import huffman_decode
from ja3requests.protocol.tls.client_hello_info import inspect_client_hello


async def async_bytes() -> AsyncIterator[bytes]:
    yield b'body'


async def async_text() -> AsyncIterator[str]:
    yield 'invalid'


def rejects(url: str, response: Response, session: Session) -> None:
    ja3requests.get(123)  # E: arg-type
    ja3requests.get(url, timeout='slow')  # E: arg-type
    ja3requests.get(url, timeout=(1, 2, 3))  # E: arg-type
    ja3requests.get(url, stream='yes')  # E: arg-type
    ja3requests.get(url, params=123)  # E: arg-type
    ja3requests.post(url, files={'body': ('name.bin', BytesIO())})  # E: dict-item
    ja3requests.post(url, json=[1, 2])  # E: arg-type
    session.get(url, timeout='slow')  # E: arg-type
    session.request('GET', url, verify='false')  # E: arg-type
    session.post(url, auth=('one', 'two', 'three'))  # E: arg-type
    session.get(url, unknown_option=True)  # E: call-arg
    session.post(url, data=StringIO('text'))  # E: arg-type
    session.put(url, data=iter((1, 2)))  # E: arg-type
    session.post(url, data=async_bytes())  # E: arg-type
    ja3requests.post(url, data=async_bytes())  # E: arg-type
    response.iter_content('1024')  # E: arg-type
    response.iter_lines(delimiter='\n')  # E: arg-type
    value: int = response.content  # E: assignment
    name: int = response.headers['Content-Type']  # E: assignment
    HTTPRetry(total='3')  # E: arg-type
    HTTPRetry(allowed_methods={3})  # E: arg-type
    ConnectionPool(max_pool_size='many')  # E: arg-type
    Session(hooks={'after_request': [lambda item: 'replacement']})  # E: arg-type
    config = TlsConfig()
    config.verify_cert = 'yes'  # E: assignment
    config.h2_settings = {'1': 65536}  # E: dict-item
    config.h2_settings = [('1', 65536)]  # E: list-item
    config.h2_pseudo_header_order = [1, 2, 3, 4]  # E: list-item
    config.h2_priority_frames = [(3, 0, '256', False)]  # E: list-item
    config.h2_priority_frames = [(3, 0, 256)]  # E: list-item
    jar = Ja3RequestsCookieJar()
    jar.set('name', 42)  # E: arg-type
    jar.save(42)  # E: arg-type


def rejects_protocol_values(record: bytes) -> None:
    H2Frame.parse('not bytes')  # E: arg-type
    huffman_decode(record, max_size='unbounded')  # E: arg-type
    value: int = inspect_client_hello(record)['ja3']  # E: assignment
    encode_integer('large', 5)  # E: arg-type
    decode_integer(record, 'start', 5)  # E: arg-type
    encode_string(42)  # E: arg-type
    decode_string(record, 0, max_size='unbounded')  # E: arg-type
    HPACKEncoder().encode_headers([('x-header', 42)])  # E: list-item
    HPACKEncoder().set_table_size('large')  # E: arg-type
    HPACKDecoder(max_header_list_size='unbounded')  # E: arg-type
    HPACKDecoder().decode_headers('not bytes')  # E: arg-type


async def async_rejects(
    url: str, response: ja3requests.AsyncResponse, session: ja3requests.AsyncSession
) -> None:
    ja3requests.AsyncSession(pool=ConnectionPool())  # E: arg-type
    ja3requests.AsyncConnectionPool(max_pool_size='many')  # E: arg-type
    await session.get(42)  # E: arg-type
    await session.post(url, timeout='slow')  # E: arg-type
    await session.get(url, timeout=(1, 2, 3))  # E: arg-type
    await session.get(url, stream='yes')  # E: arg-type
    await session.post(url, files={'file': ('name', BytesIO())})  # E: dict-item
    await session.post(url, files={'file': StringIO()})  # E: dict-item
    await session.post(url, data=StringIO('text'))  # E: arg-type
    await session.put(url, data=iter((1, 2)))  # E: arg-type
    await session.post(url, data=async_text())  # E: arg-type
    await session.get(url, unknown_option=True)  # E: call-arg
    await session.save_cookies(42)  # E: arg-type
    await session.save_cookies('cookies.json', include_session='yes')  # E: arg-type
    await session.load_cookies('cookies.json', merge='yes')  # E: arg-type
    saved: str = await session.save_cookies('cookies.json')  # E: assignment
    response.aiter_content('1024')  # E: arg-type
    response.aiter_lines(delimiter='\n')  # E: arg-type
    value: int = await response.read()  # E: assignment
    text: int = await response.text()  # E: assignment
    ja3requests.AsyncSession(
        hooks={'after_request': [lambda item: 'bad']}  # E: arg-type
    )
    prepared = await session.prepare_request('POST', url, data=b'body')
    await session.prepare_request('POST', url, data=BytesIO())  # E: arg-type
    await session.prepare_request('POST', url, data=iter((b'one',)))  # E: arg-type
    await session.prepare_request('POST', url, data=async_bytes())  # E: arg-type
    await session.prepare_request('POST', url, files={})  # E: call-arg
    await session.send(response)  # E: arg-type
    await session.send(prepared, verify=False)  # E: call-arg
    await session.send(prepared, timeout='slow')  # E: arg-type
    await session.send(prepared, stream='yes')  # E: arg-type
    prepared.body = b'changed'  # E: misc
    prepared.headers['X-Test'] = 'changed'  # E: index
    prepared.with_headers({'X-Test': object()})  # E: dict-item
