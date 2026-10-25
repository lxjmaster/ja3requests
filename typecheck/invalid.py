"""Every E marker must produce the listed mypy diagnostic; never execute."""

import asyncio
from io import BytesIO, StringIO
from typing import AsyncIterator, Awaitable, Callable

import ja3requests
from ja3requests import HTTPRetry, Response, Session, TlsConfig
from ja3requests.cookies import Ja3RequestsCookieJar, extract_cookies_to_jar
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
from ja3requests.protocol.tls.crypto import (
    AESCipher,
    ECDHEKeyExchange,
    TLSCrypto,
    get_cipher_info,
)
from ja3requests.protocol.tls.debug import set_debug_level
from ja3requests.protocol.tls.session_cache import TLS12Ticket, TLSSessionCache
from ja3requests._async_utils import owner_task, phase_wait
from ja3requests._cookie_file import load_cookie_file, save_cookie_file
from ja3requests.async_pool import _Entry, _Lease
from ja3requests.utils import (
    Task,
    b,
    default_user_agent,
    dict_from_cookie_string,
    make_headers,
)


def utility_rejects() -> None:
    b(b'not text')  # E: arg-type
    default_user_agent(123)  # E: call-overload
    make_headers(basic_auth=b'user:pass')  # E: arg-type
    make_headers(proxy_basic_auth=b'user:pass')  # E: arg-type
    make_headers(accept_encoding=[b'gzip'])  # E: list-item
    make_headers(keep_alive='yes')  # E: arg-type
    dict_from_cookie_string(123)  # E: arg-type
    Task(lambda: 'done', 'three', ValueError)  # E: arg-type
    Task(lambda: 'done', 3, 'ValueError')  # E: arg-type


def tls_crypto_rejects() -> None:
    TLSCrypto.prf('secret', b'label', b'seed', 48)  # E: arg-type
    TLSCrypto.prf(b'secret', b'label', b'seed', 48, hash_algo=123)  # E: arg-type
    TLSCrypto.derive_keys('key block', 0xC02F)  # E: arg-type
    TLSCrypto.derive_keys(b'key block', 'C02F')  # E: arg-type
    get_cipher_info('C02F')  # E: arg-type
    keys: str = TLSCrypto.derive_keys(b'block', 0xC02F)  # E: assignment
    ECDHEKeyExchange.generate_keypair('23')  # E: arg-type
    ECDHEKeyExchange.compute_shared_secret(b'key', b'peer')  # E: arg-type
    ECDHEKeyExchange.parse_server_ecdhe_params('wire')  # E: arg-type
    parsed = ECDHEKeyExchange.parse_server_ecdhe_params(b'wire')
    if parsed is not None:
        parsed['curve_id'] = b'23'  # E: typeddict-item
    AESCipher.encrypt_cbc('plaintext', b'key', b'iv')  # E: arg-type
    set_debug_level('verbose')  # E: arg-type


def cookie_file_rejects(jar: Ja3RequestsCookieJar) -> None:
    save_cookie_file({}, 'cookies.json')  # E: arg-type
    save_cookie_file(jar, b'cookies.json')  # E: arg-type
    save_cookie_file(jar, 'cookies.json', include_session='yes')  # E: arg-type
    load_cookie_file(jar, 42)  # E: arg-type
    load_cookie_file(jar, 'cookies.json', merge='yes')  # E: arg-type
    load_cookie_file(jar, 'cookies.json', include_session=1)  # E: arg-type
    saved: str = save_cookie_file(jar, 'cookies.json')  # E: assignment
    loaded: str = load_cookie_file(jar, 'cookies.json')  # E: assignment


def session_cache_rejects(cache: TLSSessionCache) -> None:
    TLSSessionCache(max_size='many')  # E: arg-type
    TLSSessionCache(ttl='forever')  # E: arg-type
    cache.get(b'host', 443)  # E: arg-type
    cache.get('host', '443')  # E: arg-type
    cache.put('host', 443, 'id', b'secret', 0xC02F)  # E: arg-type
    cache.put('host', 443, b'id', b'secret', 0xC02F, verified='yes')  # E: arg-type
    cache.put('host', 443, b'id', b'secret', 0xC02F, tls_version=0x0303)  # E: arg-type
    cache.put_tls13('host', 443, b'ticket', 'psk', 0x1301, 300, 5, None)  # E: arg-type
    cache.remove_tls12_ticket('host', 443, 'ticket')  # E: arg-type
    cache.remove_tls13('host', 443, 'ticket')  # E: arg-type
    TLS12Ticket(b'ticket', b'secret', 0xC02F, 300, verified='yes')  # E: arg-type
    TLS12Ticket(b'ticket', b'secret', 0xC02F, 300, unknown=True)  # E: call-arg


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
    session.get(url, h2_headers_priority=('183', True))  # E: arg-type
    session.request('GET', url, verify='false')  # E: arg-type
    session.post(url, auth=('one', 'two', 'three'))  # E: arg-type
    session.get(url, unknown_option=True)  # E: call-arg
    session.post(url, data=StringIO('text'))  # E: arg-type
    session.put(url, data=iter((1, 2)))  # E: arg-type
    session.post(url, data=async_bytes())  # E: arg-type
    session.request_defaults = []  # E: assignment
    session.request_defaults = {'timeout': 1}  # E: assignment
    session.request_defaults = {'headers': {'X-Bad': None}}  # E: assignment
    session.request_defaults = {'params': {'page': 1}}  # E: assignment
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
    config.h2_huffman = 'yes'  # E: assignment
    config.h2_indexing_exclusions = [42]  # E: list-item
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


def sync_pool_rejects(pool: ConnectionPool) -> None:
    pool._h2_connecting.add(('host', 443, 'https'))  # E: arg-type
    pool._h2_connecting.add((('host', '443', 'https'), None))  # E: arg-type


async def pool_rejects(
    pool: ja3requests.AsyncConnectionPool,
    entry: _Entry,
    awaitable_factory: Callable[[], Awaitable[_Entry]],
) -> None:
    async def number() -> int:
        return 1

    async def create() -> _Entry:
        return entry

    await pool._acquire(entry.key, awaitable_factory)  # E: arg-type
    await pool._acquire(entry.key, number)  # E: arg-type
    await pool._acquire(entry.key, create, share_h2='yes')  # E: arg-type
    _Lease(pool, object())  # E: arg-type
    lease = _Lease(pool, entry)
    await lease.release('yes')  # E: arg-type
    pool._retire(object())  # E: arg-type
    pool._waiters.add(asyncio.Future[int]())  # E: arg-type
    pool._cleanup.add(asyncio.create_task(number()))  # E: arg-type


async def response_lifecycle_rejects(response: ja3requests.AsyncResponse) -> None:
    async def number() -> int:
        return 1

    await response.aiter_content().asend(b'bad')  # E: arg-type
    await response.aiter_lines().asend('bad')  # E: arg-type
    response._pending_read = asyncio.Future[str]()  # E: assignment
    task: asyncio.Task[int] = asyncio.create_task(number())
    response._cleanup_task = task  # E: assignment
    response._upload_sources.append(object())  # E: arg-type
    extract_cookies_to_jar({}, object(), object())  # E: arg-type


async def async_rejects(
    url: str, response: ja3requests.AsyncResponse, session: ja3requests.AsyncSession
) -> None:
    owner_task(123)  # E: arg-type
    await phase_wait(async_bytes(), 1, 'read')  # E: arg-type
    await phase_wait(session.get(url), 'slow', 'read')  # E: arg-type
    ja3requests.Timeout('manual').phase = 42  # E: assignment
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
    session.request_defaults = 'invalid'  # E: assignment
    session.request_defaults = {'auth': ('u', 'p')}  # E: assignment
    session.request_defaults = {'headers': {1: 'bad'}}  # E: assignment
    session.request_defaults = {'params': [('page', 1)]}  # E: assignment
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
