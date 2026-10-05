"""Native async TLS uses independent OpenSSL peers and existing wire oracles."""

import asyncio
import shutil
import socket
import ssl

import pytest

from ja3requests import TlsConfig
from ja3requests.async_transport import AsyncTransport, open_transport
from ja3requests.exceptions import TLSHandshakeError
from ja3requests.protocol.tls.client_hello_info import inspect_client_hello
from ja3requests.protocol.tls.extensions import (
    PostHandshakeAuthExtension,
    SessionTicketExtension,
)
from ja3requests.protocol.tls.session_cache import TLSSessionCache
from ja3requests.protocol.tls.tls13 import TLS13Handshake
from test.wire_client_hello import profile
from test.mock_servers.local import (
    LocalServer,
    read_exact,
    read_headers,
    serve_socks,
    tls12_context,
    tls13_context,
)


async def read_exact_async(transport, size):
    result = b''
    while len(result) < size:
        part = await transport.read(size - len(result))
        assert part, 'Unexpected TLS EOF'
        result += part
    return result


@pytest.mark.parametrize(
    'version,suite,cipher,retry',
    [
        (0x0303, 0x002F, 'AES128-SHA', False),
        (0x0303, 0xC02F, 'ECDHE-RSA-AES128-GCM-SHA256', False),
        (0x0304, 0x1301, None, False),
        (0x0304, 0x1302, None, False),
        (0x0304, 0x1303, None, False),
        (0x0304, 0x1301, None, True),
    ],
)
@pytest.mark.parametrize('fragmented', [False, True])
def test_async_authenticated_full_and_resumed_tls(
    trusted_certificates, monkeypatch, version, suite, cipher, retry, fragmented
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    if fragmented:
        original = AsyncTransport._recv

        async def small_read(transport, size):
            return await original(transport, min(size, 7))

        monkeypatch.setattr(AsyncTransport, '_recv', small_read)
    config = TlsConfig.secure()
    config.session_cache = TLSSessionCache()
    config.tls_version = version
    config.cipher_suites = [suite]
    config.alpn_protocols = ['http/1.1']
    if retry:
        config.key_share_groups = [29]
    certificate = trusted_certificates.leaves['valid']
    if version == 0x0303:
        context = tls12_context(*certificate, cipher=cipher)
        context.options |= ssl.OP_NO_TICKET
    else:
        context = tls13_context(*certificate, group='prime256v1' if retry else None)
    reused = []
    flights = []

    def peer(conn):
        reused.append(conn.session_reused)
        # Data may already follow Finished/tickets before the client starts read.
        conn.sendall(b'early')
        assert read_exact(conn, 4) == b'ping'
        conn.sendall(b'pong')

    async def scenario(port):
        for _ in range(2):
            transport = await open_transport(
                '127.0.0.1', port, tls_config=config, timeout=3
            )
            try:
                assert transport.negotiated_protocol == 'http/1.1'
                assert transport.tls._cert_verified
                assert transport.tls._verified_hostname == '127.0.0.1'
                flights.append(transport.tls.sent_client_hellos)
                assert await read_exact_async(transport, 5) == b'early'
                await transport.write(b'ping')
                assert await read_exact_async(transport, 4) == b'pong'
            finally:
                await transport.aclose()

    with LocalServer(peer, context, connections=2, retain_tls_sessions=True) as server:
        asyncio.run(scenario(server.port))
    assert reused == [False, True]
    for flight in flights:
        for record in flight:
            assert inspect_client_hello(record)['ja3'] == profile(record)['ja3']
    if retry:
        assert all(len(flight) == 2 for flight in flights)
        assert all(flight[1][1:3] == b'\x03\x03' for flight in flights)


@pytest.mark.parametrize(
    'version,late', [(0x0303, False), (0x0304, False), (0x0304, True)]
)
@pytest.mark.parametrize('variant', ['client-rsa', 'client-ecdsa'])
def test_async_client_authentication(
    trusted_certificates, monkeypatch, version, late, variant
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    if version == 0x0303:
        context = tls12_context(
            *trusted_certificates.leaves['valid'], cipher='ECDHE-RSA-AES128-GCM-SHA256'
        )
    else:
        context = tls13_context(*trusted_certificates.leaves['valid'])
    context.load_verify_locations(cafile=str(trusted_certificates.ca_path))
    context.verify_mode = ssl.CERT_REQUIRED
    context.post_handshake_auth = late
    config = TlsConfig.secure()
    config.tls_version = version
    certificate, key = trusted_certificates.leaves[variant]
    config.client_cert, config.client_key = str(certificate), str(key)
    if late:
        config.extensions.append(PostHandshakeAuthExtension())
    observed = []

    def peer(conn):
        assert read_exact(conn, 4) == b'ping'
        if late:
            assert conn.getpeercert(binary_form=True) is None
            conn.verify_client_post_handshake()
        conn.sendall(b'pong')
        assert read_exact(conn, 4) == b'next'
        observed.append(conn.getpeercert(binary_form=True))
        conn.sendall(b'done')

    async def scenario(port):
        transport = await open_transport(
            '127.0.0.1', port, tls_config=config, timeout=3
        )
        try:
            await transport.write(b'ping')
            assert await read_exact_async(transport, 4) == b'pong'
            await transport.write(b'next')
            assert await read_exact_async(transport, 4) == b'done'
        finally:
            await transport.aclose()

    with LocalServer(peer, context) as server:
        asyncio.run(scenario(server.port))
    assert observed and observed[0]


@pytest.mark.parametrize('variant', ['wrong-host', 'expired', 'bad-signature'])
def test_async_bad_identity_never_publishes_transport(
    trusted_certificates, monkeypatch, variant
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    context = tls13_context(*trusted_certificates.leaves[variant])
    received = []
    server = LocalServer(lambda conn: received.append(conn.recv(1)), context)

    async def scenario(port):
        with pytest.raises(TLSHandshakeError):
            await open_transport(
                '127.0.0.1', port, tls_config=TlsConfig.secure(), timeout=2
            )

    # Authentication aborts before the independent server's handshake completes.
    with pytest.raises((ssl.SSLError, ConnectionResetError)):
        with server:
            asyncio.run(scenario(server.port))
    assert received == []


@pytest.mark.parametrize('ticket', [False, True])
def test_async_tls12_fallback_and_ticket_resumption(
    trusted_certificates, monkeypatch, ticket
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    context = tls12_context(
        *trusted_certificates.leaves['valid'], cipher='ECDHE-RSA-AES128-GCM-SHA256'
    )
    config = TlsConfig.secure()
    config.session_cache = TLSSessionCache()
    if ticket:
        config.tls_version = 0x0303
        config.extensions.append(SessionTicketExtension())
    else:
        context.options |= ssl.OP_NO_TICKET
    reused = []

    def peer(conn):
        reused.append(conn.session_reused)
        assert read_exact(conn, 4) == b'ping'
        conn.sendall(b'pong')

    async def scenario(port):
        for _ in range(2):
            transport = await open_transport(
                '127.0.0.1', port, tls_config=config, timeout=2
            )
            try:
                assert not transport.tls._is_tls13
                await transport.write(b'ping')
                assert await read_exact_async(transport, 4) == b'pong'
            finally:
                await transport.aclose()

    with LocalServer(peer, context, connections=2, retain_tls_sessions=True) as server:
        asyncio.run(scenario(server.port))
    assert reused == [False, True]


@pytest.mark.parametrize('scheme', ['http', 'socks4a', 'socks5'])
@pytest.mark.parametrize('host', ['localhost', 'wrong.invalid'])
def test_async_proxy_tls_verifies_destination(
    trusted_certificates, monkeypatch, scheme, host
):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    context = tls13_context(*trusted_certificates.leaves['valid'])
    config = TlsConfig.secure()
    config.server_name = 'localhost'
    received = []

    def endpoint(raw):
        with context.wrap_socket(raw, server_side=True) as conn:
            received.append(read_exact(conn, 4))
            conn.sendall(b'pong')

    def peer(conn):
        if scheme == 'http':
            assert read_headers(conn).startswith(
                ('CONNECT {}:443 '.format(host)).encode()
            )
            conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            endpoint(conn)
        else:
            serve_socks(
                conn,
                {},
                version=4 if scheme == 'socks4a' else 5,
                tunnel_handler=endpoint,
            )

    async def scenario(port):
        transport = await open_transport(
            host,
            443,
            tls_config=config,
            proxy='{}://127.0.0.1:{}'.format(scheme, port),
            timeout=2,
        )
        try:
            await transport.write(b'ping')
            assert await read_exact_async(transport, 4) == b'pong'
        finally:
            await transport.aclose()

    if host == 'localhost':
        with LocalServer(peer) as server:
            asyncio.run(scenario(server.port))
        assert received == [b'ping']
    else:
        with pytest.raises((ssl.SSLError, ConnectionResetError)):
            with LocalServer(peer) as server:
                with pytest.raises(TLSHandshakeError):
                    asyncio.run(scenario(server.port))
        assert received == []


@pytest.mark.skipif(shutil.which('openssl') is None, reason='OpenSSL CLI unavailable')
@pytest.mark.parametrize('initiator', ['server', 'client'])
def test_native_async_openssl_key_update(trusted_certificates, monkeypatch, initiator):
    monkeypatch.setenv('SSL_CERT_FILE', str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves['valid']
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]

    async def scenario():
        updated = asyncio.Event()
        original = TLS13Handshake.process_post_handshake

        def observe(handshake, plaintext):
            result = original(handshake, plaintext)
            if plaintext.startswith(b'\x18\x00\x00\x01'):
                updated.set()
            return result

        monkeypatch.setattr(TLS13Handshake, 'process_post_handshake', observe)
        process = await asyncio.create_subprocess_exec(
            'openssl',
            's_server',
            '-accept',
            '127.0.0.1:{}'.format(port),
            '-cert',
            str(certificate[0]),
            '-key',
            str(certificate[1]),
            '-tls1_3',
            '-no_ticket',
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        transport = None
        try:
            await asyncio.wait_for(process.stdout.readuntil(b'ACCEPT\n'), 3)
            transport = await open_transport(
                '127.0.0.1', port, tls_config=TlsConfig.secure(), timeout=2
            )
            if initiator == 'client':
                await transport.send_key_update(request_update=True)
            await transport.write(b'ping\n')
            await asyncio.wait_for(process.stdout.readuntil(b'ping\n'), 3)
            waiting = asyncio.create_task(read_exact_async(transport, 5))
            if initiator == 'server':
                process.stdin.write(b'K\n')
                await process.stdin.drain()
                await asyncio.wait_for(updated.wait(), 3)
            process.stdin.write(b'pong\n')
            await process.stdin.drain()
            assert await asyncio.wait_for(waiting, 3) == b'pong\n'
            await asyncio.wait_for(updated.wait(), 3)
            # The independent peer must accept data under the rotated client key.
            await transport.write(b'next\n')
            await asyncio.wait_for(process.stdout.readuntil(b'next\n'), 3)
        finally:
            if transport is not None:
                await transport.aclose()
            if process.returncode is None:
                process.terminate()
            try:
                await asyncio.wait_for(process.communicate(), 2)
            except asyncio.TimeoutError:
                process.kill()
                await process.communicate()

    asyncio.run(scenario())
