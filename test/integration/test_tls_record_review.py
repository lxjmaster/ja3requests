"""Independent OpenSSL peers for request fragmentation and response alerts."""

import asyncio
import hashlib
import ssl

import pytest

from ja3requests import AsyncSession, Session, TlsConfig
from ja3requests.exceptions import TLSDecryptionError
from test.mock_servers.local import (
    LocalServer,
    read_exact,
    read_headers,
    tls12_context,
    tls13_context,
)


@pytest.fixture(params=['tls12-cbc', 'tls12-gcm', 'tls13'])
def record_peer(request, trusted_certificates, monkeypatch):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    config = TlsConfig.secure()
    config.alpn_protocols = ['http/1.1']
    certificate = trusted_certificates.leaves['valid']
    if request.param == 'tls13':
        config.tls_version = 0x0304
        config.cipher_suites = [0x1301]
        context = tls13_context(*certificate)
    else:
        gcm = request.param == 'tls12-gcm'
        config.tls_version = 0x0303
        config.cipher_suites = [0xC02F if gcm else 0x002F]
        context = tls12_context(
            *certificate, cipher='ECDHE-RSA-AES128-GCM-SHA256' if gcm else 'AES128-SHA'
        )
    return config, context


def test_sync_large_post_crosses_authenticated_record_boundaries(record_peer):
    config, context = record_peer
    body = b'0123456789abcdef' * 2048
    digest = hashlib.sha256(body).digest()
    received = []

    def peer(conn):
        headers = read_headers(conn)
        assert headers.startswith(b'POST /upload HTTP/1.1\r\n')
        length = next(
            int(line.partition(b':')[2])
            for line in headers.split(b'\r\n')
            if line.lower().startswith(b'content-length:')
        )
        received.append(read_exact(conn, length))
        result = hashlib.sha256(received[-1]).digest()
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n' + result)

    with LocalServer(peer, context) as server:
        with Session(tls_config=config, use_pooling=False) as session:
            response = session.post(
                'https://127.0.0.1:%d/upload' % server.port, data=body, timeout=3
            )
            assert response.status_code == 200
            assert response.content == digest
    assert received == [body]


def serve_response_alert(raw, context, ending):
    """Have OpenSSL produce either a valid close or a protected fatal alert."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    peer = context.wrap_bio(incoming, outgoing, server_side=True)

    def flush():
        while outgoing.pending:
            raw.sendall(outgoing.read())

    def call(operation, *args):
        while True:
            try:
                result = operation(*args)
            except ssl.SSLWantReadError:
                flush()
                incoming.write(read_exact(raw, 1))
            else:
                flush()
                return result

    call(peer.do_handshake)
    request = b''
    while not request.endswith(b'\r\n\r\n'):
        request += call(peer.read, 1)
    call(peer.write, b'HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nprefix')
    if ending == 'fatal':
        # Inject a bad MAC into the independent server's input. OpenSSL itself
        # encrypts the resulting fatal alert using its negotiated traffic keys.
        incoming.write(b'\x17\x03\x03\x00\x20' + b'\x00' * 32)
        with pytest.raises(ssl.SSLError, match='(?i)decrypt|mac'):
            peer.read(1)
    else:
        with pytest.raises(ssl.SSLWantReadError):
            peer.unwrap()
    flush()


@pytest.mark.parametrize('ending', ['close', 'fatal'])
@pytest.mark.parametrize('stream', [False, True])
@pytest.mark.parametrize('adapter', ['sync', 'async'])
def test_close_delimited_response_distinguishes_fatal_alert(
    record_peer, ending, stream, adapter
):
    config, context = record_peer

    def sync_request(url):
        with Session(tls_config=config, use_pooling=False) as session:
            response = session.get(url, stream=stream, timeout=3)
            try:
                assert response.status_code == 200
                body = (
                    b''.join(response.iter_content(3)) if stream else response.content
                )
                assert body == b'prefix'
            finally:
                response.close()

    async def async_request(url):
        async with AsyncSession(tls_config=config, use_pooling=False) as session:
            response = await session.get(url, stream=stream, timeout=3)
            async with response:
                assert response.status_code == 200
                body = (
                    b''.join([part async for part in response.aiter_content(3)])
                    if stream
                    else response.content
                )
                assert body == b'prefix'

    with LocalServer(lambda raw: serve_response_alert(raw, context, ending)) as server:
        url = 'https://127.0.0.1:%d/body' % server.port

        def consume():
            if adapter == 'sync':
                sync_request(url)
            else:
                asyncio.run(async_request(url))

        if ending == 'fatal':
            error_type = ConnectionError if adapter == 'sync' else TLSDecryptionError
            with pytest.raises(error_type, match='TLS'):
                consume()
        else:
            consume()
