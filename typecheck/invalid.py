"""Every E marker must produce the listed mypy diagnostic; never execute."""

from io import BytesIO

import ja3requests
from ja3requests import HTTPRetry, Response, Session, TlsConfig
from ja3requests.cookies import Ja3RequestsCookieJar
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.frame import H2Frame
from ja3requests.protocol.h2.huffman import huffman_decode
from ja3requests.protocol.tls.client_hello_info import inspect_client_hello


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
    jar = Ja3RequestsCookieJar()
    jar.set('name', 42)  # E: arg-type
    jar.save(42)  # E: arg-type


def rejects_protocol_values(record: bytes) -> None:
    H2Frame.parse('not bytes')  # E: arg-type
    huffman_decode(record, max_size='unbounded')  # E: arg-type
    value: int = inspect_client_hello(record)['ja3']  # E: assignment


async def async_rejects(
    url: str, response: ja3requests.AsyncResponse, session: ja3requests.AsyncSession
) -> None:
    ja3requests.AsyncSession(pool=ConnectionPool())  # E: arg-type
    ja3requests.AsyncConnectionPool(max_pool_size='many')  # E: arg-type
    await session.get(42)  # E: arg-type
    await session.post(url, timeout='slow')  # E: arg-type
    await session.get(url, timeout=(1, 2, 3))  # E: arg-type
    await session.get(url, stream='yes')  # E: arg-type
    await session.post(url, files={'file': BytesIO()})  # E: call-arg
    await session.get(url, unknown_option=True)  # E: call-arg
    response.aiter_content('1024')  # E: arg-type
    response.aiter_lines(delimiter='\n')  # E: arg-type
    value: int = await response.read()  # E: assignment
    text: int = await response.text()  # E: assignment
    ja3requests.AsyncSession(
        hooks={'after_request': [lambda item: 'bad']}  # E: arg-type
    )
