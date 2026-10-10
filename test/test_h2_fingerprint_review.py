"""Wire contracts for explicit H2 controls and offered TLS application protocols."""

import struct

import pytest

from ja3requests import TlsConfig
from ja3requests.exceptions import TLSHandshakeError
from ja3requests.protocol.h2.connection import H2Connection
from ja3requests.protocol.h2.frame import build_window_update_frame
from ja3requests.protocol.h2.hpack import HPACKDecoder
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.tls13 import TLS13Handshake
from ja3requests.sockets.https import HttpsSocket


@pytest.mark.parametrize(
    'settings', [{4: 12345, 1: 4096, 2: 0}, [(4, 12345), (1, 4096), (2, 0)], {}, []]
)
def test_settings_preserve_explicit_wire_fields(settings):
    writes = []
    config = TlsConfig()
    config.h2_settings = settings
    HttpsSocket._tls_policy_key(config, 'localhost')
    connection = H2Connection(writes.append, None, settings=config.h2_settings)
    connection.initiate()
    expected = list(settings.items()) if isinstance(settings, dict) else settings
    assert list(struct.iter_unpack('!HI', writes[1][9:])) == expected


@pytest.mark.parametrize(
    'settings',
    [{5: 16383}, {5: 16777216}, {4: 2147483648}, {2: 1}, {1: -1}, {True: 1}, {1: True}],
)
def test_invalid_settings_rejected_by_public_config(settings):
    with pytest.raises(ValueError):
        config = TlsConfig()
        config.h2_settings = settings
        config.validate(strict=True)


@pytest.mark.parametrize('increment', [-1, 2147483648, 2147418113, 1.5, True])
def test_initial_window_invalid_before_any_bytes(increment):
    writes = []
    connection = H2Connection(writes.append, None)
    with pytest.raises(ValueError):
        connection.initiate(increment)
    assert not writes


@pytest.mark.parametrize('increment', [0, -1, 2147483648, True, 1.5])
def test_window_frame_does_not_mask_invalid_increment(increment):
    with pytest.raises(ValueError):
        build_window_update_frame(0, increment)


def test_preset_settings_are_independent():
    first = TlsConfig.from_browser('chrome', 120)
    second = TlsConfig.from_browser('chrome', 120)
    original = second.h2_settings[1]
    try:
        first.h2_settings[1] = 1234
        assert second.h2_settings[1] == original
        assert TlsConfig.from_browser('chrome', 120).h2_settings[1] == original
    finally:
        first.h2_settings[1] = original


def test_h2_filters_all_hop_fields():
    writes = []
    connection = H2Connection(writes.append, None)
    connection.send_request(
        'GET',
        'localhost',
        '/',
        headers=[
            ('Connection', b'X-Hop, X-Second'),
            ('X-Hop', 'secret'),
            ('X-Second', 'secret'),
            ('Keep-Alive', 'timeout=1'),
            ('Proxy-Connection', 'keep-alive'),
            ('TE', b'trailers'),
            ('X-End', b'end'),
        ],
    )
    headers = dict(HPACKDecoder().decode_headers(writes[0][9:]))
    assert set(headers) == {':method', ':authority', ':scheme', ':path', 'te', 'x-end'}
    assert headers['te'] == 'trailers'


@pytest.mark.parametrize('value', ['gzip', b'gzip', 'trailers, gzip'])
def test_invalid_te_does_not_consume_stream_or_write(value):
    writes = []
    connection = H2Connection(writes.append, None)
    with pytest.raises(ValueError, match='TE'):
        connection.send_request('GET', 'localhost', '/', headers=[('TE', value)])
    assert not writes
    assert connection.send_request('GET', 'localhost', '/') == 1


class Sink:
    def sendall(self, _data):
        pass


def configured_tls():
    config = TlsConfig()
    config.alpn_protocols = ['http/1.1']
    tls = TLS(Sink())
    tls.set_payload(config)
    tls._send_client_hello(tls.body)
    # Mutating config after send cannot change what the peer was offered.
    config.alpn_protocols.append('h2')
    return tls


def tls12_selection(extension):
    extensions = struct.pack('!HH', 16, len(extension)) + extension
    return (
        b'\x03\x03'
        + b'r' * 32
        + b'\x00\xc0\x2f\x00'
        + struct.pack('!H', len(extensions))
        + extensions
    )


@pytest.mark.parametrize(
    'extension', [b'\x00\x03\x02h2', b'\x00\x09\x02h2', b'\x00\x00', b'\x00\x01\x00']
)
def test_tls12_rejects_unoffered_or_malformed_alpn(extension):
    tls = configured_tls()
    with pytest.raises(TLSHandshakeError, match='ALPN'):
        tls._parse_server_hello(tls12_selection(extension))


def test_tls13_rejects_unsolicited_alpn():
    handshake = TLS13Handshake(None, None, 29, b'ch')
    extension = b'\x00\x10\x00\x05\x00\x03\x02h2'
    with pytest.raises(ValueError, match='ALPN'):
        handshake._parse_encrypted_extensions(
            struct.pack('!H', len(extension)) + extension
        )


@pytest.mark.parametrize(
    'settings', [None, {}, [], [(1, 4096), (1, 8192), (2, 0)], [(65535, 4294967295)]]
)
def test_settings_defaults_empty_duplicates_and_unknown_identifiers(settings):
    from ja3requests.protocol.h2.frame import DEFAULT_SETTINGS

    writes = []
    connection = H2Connection(writes.append, None, settings=settings)
    connection.initiate()
    expected = (
        list(DEFAULT_SETTINGS.items())
        if settings is None
        else list(settings.items()) if isinstance(settings, dict) else settings
    )
    assert list(struct.iter_unpack('!HI', writes[1][9:])) == expected
    if settings and not isinstance(settings, dict) and settings[0][0] == 1:
        assert connection._decoder._max_table_size == 8192
    with pytest.raises(RuntimeError, match='already initiated'):
        connection.initiate()
    assert len(writes) == 2


@pytest.mark.parametrize(
    'settings',
    [
        123,
        'bad',
        [(1,)],
        [(1, 1, 1)],
        [1],
        {65536: 0},
        {1: 4294967296},
        {1: 1.0},
        [(4, -1)],
        [(5, 16384), (5, 0)],
    ],
)
def test_invalid_settings_shape_and_ranges(settings):
    with pytest.raises(ValueError):
        TlsConfig().h2_settings = settings
    with pytest.raises(ValueError):
        H2Connection(lambda _: None, None, settings=settings)


@pytest.mark.parametrize(
    'order',
    [
        [],
        [':method'] * 4,
        [':method', ':authority', ':scheme', 'path'],
        ':method',
        [1, 2, 3, 4],
        [[], ':authority', ':scheme', ':path'],
    ],
)
def test_invalid_pseudo_order(order):
    with pytest.raises(ValueError):
        TlsConfig().h2_pseudo_header_order = order


@pytest.mark.parametrize(
    'priority',
    [
        (0, 0, 1, False),
        (-1, 0, 1, False),
        (2147483648, 0, 1, False),
        (1, 1, 1, False),
        (1, -1, 1, False),
        (1, 2147483648, 1, False),
        (1, 0, 0, False),
        (1, 0, 257, False),
        (1, 0, True, False),
        (1, 0, 1, 1),
        (1, 0, 1),
        1,
    ],
)
def test_invalid_priority(priority):
    with pytest.raises(ValueError):
        TlsConfig().h2_priority_frames = [priority]


@pytest.mark.parametrize('increment', [None, 0, 1, 2147418112])
def test_initial_window_boundaries(increment):
    config = TlsConfig()
    config.h2_window_update = increment
    config.validate(strict=True)
    writes = []
    connection = H2Connection(writes.append, None)
    connection.initiate(increment)
    if increment:
        assert int.from_bytes(writes[2][9:], 'big') == increment
    else:
        assert len(writes) == 2


def test_controls_copy_inputs_recheck_mutation_and_partition_pool():
    config = TlsConfig()
    settings = {2: 0, 4: 65535}
    order = [':method', ':path', ':authority', ':scheme']
    priorities = [(3, 0, 256, True)]
    config.h2_settings, config.h2_pseudo_header_order, config.h2_priority_frames = (
        settings,
        order,
        priorities,
    )
    settings[4], order[0], priorities[0] = 0, 'bad', (0, 0, 1, False)
    config.validate(strict=True)
    base = HttpsSocket._tls_policy_key(config, 'localhost')
    for field, value in [
        ('h2_settings', {}),
        ('h2_window_update', 1),
        ('h2_pseudo_header_order', [':path', ':authority', ':method', ':scheme']),
        ('h2_priority_frames', []),
    ]:
        import copy

        changed = copy.deepcopy(config)
        setattr(changed, field, value)
        assert HttpsSocket._tls_policy_key(changed, 'localhost') != base
    config.h2_settings[4] = 2147483648
    assert config.validate()
    with pytest.raises(ValueError):
        HttpsSocket._tls_policy_key(config, 'localhost')
    with pytest.raises(ValueError):
        config.validate(strict=True)
    assert HttpsSocket._tls_policy_key(
        TlsConfig(), 'localhost'
    ) != HttpsSocket._tls_policy_key(changed, 'localhost')


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('offered', [[], ['http/1.1'], ['h2', 'http/1.1']])
@pytest.mark.parametrize(
    'payload',
    [
        b'\x00\x03\x02h2',
        b'\x00\x0c\x02h2\x08http/1.1',
        b'\x00\x00',
        b'\x00\x04\x02h2x',
        b'\x00\x01\x00',
    ],
)
def test_alpn_exact_selection_contract(version, offered, payload):
    config = TlsConfig()
    config.alpn_protocols = offered
    tls = TLS(Sink())
    tls.set_payload(config)
    tls._send_client_hello(tls.body)
    if version == 12:
        parse = lambda: tls._parse_server_hello(tls12_selection(payload))
        selected = lambda: tls._negotiated_protocol
    else:
        handshake = TLS13Handshake(
            None, None, 29, b'ch', offered_alpn=tls._offered_alpn_protocols
        )
        extension = struct.pack('!HH', 16, len(payload)) + payload
        parse = lambda: handshake._parse_encrypted_extensions(
            struct.pack('!H', len(extension)) + extension
        )
        selected = lambda: handshake._negotiated_protocol
    if payload == b'\x00\x03\x02h2' and 'h2' in offered:
        parse()
        assert selected() == 'h2'
    else:
        with pytest.raises((ValueError, TLSHandshakeError), match='ALPN'):
            parse()


def test_actual_custom_alpn_bytes_control_selection():
    from ja3requests.protocol.tls.layers.client_hello import ClientHello
    from ja3requests.protocol.tls.extensions import ALPNExtension

    tls = TLS(Sink())
    tls.body = ClientHello(
        alpn_protocols=['http/1.1'], _extensions=[ALPNExtension(['h2'])]
    )
    tls._send_client_hello(tls.body)
    tls._parse_server_hello(tls12_selection(b'\x00\x03\x02h2'))
    assert tls._negotiated_protocol == 'h2'
    with pytest.raises(TLSHandshakeError, match='ALPN'):
        tls._parse_server_hello(tls12_selection(b'\x00\x09\x08http/1.1'))


@pytest.mark.parametrize('protocols', [['review/1'], ['h2', 'review/1']])
def test_http_config_rejects_unimplemented_alpn(protocols):
    config = TlsConfig()
    config.alpn_protocols = protocols
    assert any('Unsupported HTTP ALPN' in issue for issue in config.validate())
    with pytest.raises(ValueError, match='Unsupported HTTP ALPN'):
        config.validate(strict=True)
    with pytest.raises(ValueError, match='Unsupported HTTP ALPN'):
        HttpsSocket._tls_policy_key(config, 'localhost')
    with pytest.raises(TLSHandshakeError, match='Unsupported HTTP ALPN'):
        TLS(Sink()).set_payload(config)


def test_raw_client_hello_can_still_encode_non_http_alpn():
    from ja3requests.protocol.tls.layers.client_hello import ClientHello
    from ja3requests.protocol.tls.extensions import ALPNExtension

    hello = ClientHello(_extensions=[ALPNExtension(['review/1'])])
    assert hello.offered_alpn_protocols == (b'review/1',)


@pytest.mark.parametrize('entry', ['sync', 'async', 'async-prepared'])
@pytest.mark.parametrize('route', ['direct', 'connect', 'socks'])
def test_invalid_http_alpn_precedes_network_and_source_preparation(
    monkeypatch, entry, route
):
    import asyncio
    import io
    from ja3requests import Session, AsyncSession
    from ja3requests._upload import UploadSource
    from ja3requests.base import BaseSocket

    def forbidden(*_args, **_kwargs):
        pytest.fail('Invalid ALPN reached connection or upload preparation')

    async def forbidden_async(*_args, **_kwargs):
        forbidden()

    monkeypatch.setattr(BaseSocket, '_new_conn', forbidden)
    monkeypatch.setattr(UploadSource, 'prepare', forbidden)
    monkeypatch.setattr(UploadSource, 'aprepare', forbidden_async)
    monkeypatch.setattr('ja3requests.async_sessions.open_transport', forbidden_async)
    config = TlsConfig()
    config.alpn_protocols.append('review/1')  # Recheck mutable input at send time.
    proxies = (
        {}
        if route == 'direct'
        else {'https': ('http' if route == 'connect' else 'socks5') + '://127.0.0.1:9'}
    )

    async def run():
        async with AsyncSession(tls_config=config) as session:
            with pytest.raises(ValueError, match='Unsupported HTTP ALPN'):
                if entry == 'async-prepared':
                    prepared = await session.prepare_request(
                        'POST', 'https://localhost/', data=b'body', proxies=proxies
                    )
                    await session.send(prepared)
                else:
                    await session.post(
                        'https://localhost/', data=io.BytesIO(b'body'), proxies=proxies
                    )
            assert not session._pool._entries and not session._pool._creating

    if entry == 'sync':
        with Session(tls_config=config, use_pooling=False) as session:
            with pytest.raises(ValueError, match='Unsupported HTTP ALPN'):
                session.post(
                    'https://localhost/', data=io.BytesIO(b'body'), proxies=proxies
                )
    else:
        asyncio.run(run())


def test_sync_unknown_alpn_dispatch_closes_before_http(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    sock = HttpsSocket(SimpleNamespace())
    conn = Mock()
    sock.conn = conn
    sock.tls = SimpleNamespace(_negotiated_protocol='review/1')
    monkeypatch.setattr(sock, '_send_h1', lambda: pytest.fail('HTTP1 was sent'))
    monkeypatch.setattr(sock, '_send_h2', lambda: pytest.fail('HTTP2 was sent'))
    with pytest.raises(TLSHandshakeError, match='Unsupported negotiated ALPN'):
        sock.send()
    conn.close.assert_called_once()
    conn.sendall.assert_not_called()
    assert sock.conn is None and sock.tls is None


def test_serial_controls_and_default_initialization():
    writes = []
    order = [':scheme', ':path', ':authority', ':method']
    connection = H2Connection(
        writes.append,
        None,
        settings={},
        pseudo_header_order=order,
        priority_frames=[(3, 0, 256, True)],
    )
    connection.initiate(1)
    assert [(raw[3], int.from_bytes(raw[5:9], 'big')) for raw in writes[1:]] == [
        (4, 0),
        (8, 0),
        (2, 3),
    ]
    assert writes[3][9:] == b'\x80\x00\x00\x00\xff'
    assert connection.send_request('GET', 'localhost', '/') == 1
    assert [name for name, _ in HPACKDecoder().decode_headers(writes[4][9:])] == order


@pytest.mark.parametrize('version', [12, 13])
def test_duplicate_alpn_and_tls13_wrong_location_rejected(version):
    tls = configured_tls()
    extension = b'\x00\x10\x00\x0b\x00\x09\x08http/1.1'
    duplicate = extension * 2
    if version == 12:
        message = tls12_selection(b'\x00\x09\x08http/1.1')
        message = message[:38] + struct.pack('!H', len(duplicate)) + duplicate
        with pytest.raises(TLSHandshakeError, match='Duplicate'):
            tls._parse_server_hello(message)
        wrong_location = b'\x00\x2b\x00\x02\x03\x04' + extension
        with pytest.raises(
            TLSHandshakeError, match='ALPN must be in EncryptedExtensions'
        ):
            tls._parse_server_hello(
                message[:38] + struct.pack('!H', len(wrong_location)) + wrong_location
            )
    else:
        hs = TLS13Handshake(None, None, 29, b'ch', offered_alpn=(b'http/1.1',))
        with pytest.raises(ValueError, match='duplicate'):
            hs._parse_encrypted_extensions(
                struct.pack('!H', len(duplicate)) + duplicate
            )


@pytest.mark.parametrize('increment', [-1, 2147483648, 2147418113, True, 1.5])
def test_async_invalid_initial_window_has_no_wire_output(increment):
    import asyncio
    from ja3requests.protocol.h2.async_connection import AsyncH2Connection
    from test.test_async_h2 import Wire

    async def run():
        wire = Wire()
        connection = AsyncH2Connection(wire.send, wire.recv)
        with pytest.raises(ValueError):
            await connection.initiate(increment)
        assert not wire.sent and not wire.attempted
        assert not connection._control
        assert connection._reader_task is None and connection._writer_task is None

    asyncio.run(run())


@pytest.mark.parametrize('entry', ['sync', 'async', 'prepared'])
@pytest.mark.parametrize(
    'field,value',
    [
        ('_h2_settings', {4: 2147483648}),
        ('_h2_settings', [(5, 0)]),
        ('_h2_window_update', -1),
        ('_h2_pseudo_header_order', [':path'] * 4),
        ('_h2_priority_frames', [(1, 1, 10, False)]),
    ],
)
def test_mutated_h2_config_rejected_before_connection_or_upload(
    monkeypatch, entry, field, value
):
    import asyncio
    import io
    from ja3requests import AsyncSession, Session

    calls = []
    config = TlsConfig()
    config.alpn_protocols = ['h2']
    setattr(config, field, value)

    def connect(*args, **kwargs):
        calls.append('connection')
        raise AssertionError('Invalid configuration reached connection I/O')

    async def async_connect(*args, **kwargs):
        return connect(*args, **kwargs)

    class Source(io.BytesIO):
        def read(self, *args):
            calls.append('read')
            return super().read(*args)

    monkeypatch.setattr(HttpsSocket, '_new_conn', connect)
    monkeypatch.setattr('ja3requests.async_sessions.open_transport', async_connect)

    async def run():
        async with AsyncSession(tls_config=config) as session:
            with pytest.raises(ValueError):
                if entry == 'prepared':
                    request = await session.prepare_request(
                        'POST', 'https://example.test/', data=b'body'
                    )
                    await session.send(request)
                else:
                    await session.post('https://example.test/', data=Source(b'body'))

    if entry == 'sync':
        with Session(tls_config=config, use_pooling=False) as session:
            with pytest.raises(ValueError):
                session.post('https://example.test/', data=Source(b'body'))
    else:
        asyncio.run(run())
    assert not calls
