"""307/308 replay and ownership observed at actual HTTP1/TLS/H2 peers."""

import copy
import io
import json
import re
import socket
import struct
from email import policy
from email.parser import BytesParser

import pytest

from ja3requests import HTTPRetry, Session
from ja3requests.exceptions import InvalidData, MaxRetriedException, NotAllowedScheme
from ja3requests.requests.request import Request
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.hpack import HPACKDecoder
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    h2_readers,
    receive_frame,
    start_h2,
    trusted_h2_peer,
)
from test.integration.test_request_wire_review import read_h2_request
from test.mock_servers.local import LocalServer, h2_frame, read_exact, read_headers


class BorrowedFile(io.BytesIO):
    def __init__(self, body):
        super().__init__(body)
        self.name = 'payload.bin'
        self.reads = 0

    def read(self, size=-1):
        self.reads += 1
        return super().read(size)


def http1_request(conn):
    lines = read_headers(conn).decode('latin1').split('\r\n')
    method, path, _ = lines[0].split(' ')
    headers = dict(line.split(': ', 1) for line in lines[1:] if line)
    headers = {name.lower(): value for name, value in headers.items()}
    body = bytearray()
    if 'content-length' in headers:
        body.extend(read_exact(conn, int(headers['content-length'])))
    elif 'transfer-encoding' in headers:
        while True:
            line = b''
            while not line.endswith(b'\r\n'):
                line += read_exact(conn, 1)
            size = int(line, 16)
            if not size:
                assert read_exact(conn, 2) == b'\r\n'
                break
            body.extend(read_exact(conn, size))
            assert read_exact(conn, 2) == b'\r\n'
    return method, path, headers, bytes(body)


def multipart_parts(record):
    _, _, headers, body = record
    assert int(headers['content-length']) == len(body)
    message = BytesParser(policy=policy.default).parsebytes(
        b'Content-Type: '
        + headers['content-type'].encode('ascii')
        + b'\r\nMIME-Version: 1.0\r\n\r\n'
        + body
    )
    assert message.is_multipart() and not message.defects
    parts = list(message.iter_parts())
    for part in parts:
        assert not part.defects
        assert set(name.lower() for name in part.keys()) <= {
            'content-disposition',
            'content-type',
        }
    return [
        (
            part.get_param('name', header='content-disposition'),
            part.get_filename(),
            part.get_payload(decode=True),
        )
        for part in parts
    ]


def literal(index, value):
    value = value.encode('ascii')
    assert len(value) < 127
    prefix = bytes([index]) if index < 15 else bytes([15, index - 15])
    return prefix + bytes([len(value)]) + value


def redirect_peer(seen, statuses, protocol, *, read_http1_body=False):
    def serve(conn):
        decoder = HPACKDecoder()
        if protocol == 'h2':
            start_h2(conn)
        for _ in range(len(statuses) + 1):
            index = len(seen)
            if protocol == 'h2':
                stream, headers, body, _ = read_h2_request(conn, decoder)
                method, path = headers[':method'], headers[':path']
            elif index == 0 or read_http1_body:
                method, path, headers, body = http1_request(conn)
            else:
                lines = read_headers(conn).decode('latin1').split('\r\n')
                method, path, _ = lines[0].split(' ')
                headers = {
                    name.lower(): value
                    for name, value in (
                        line.split(': ', 1) for line in lines[1:] if line
                    )
                }
                body = b''
            seen.append((method, path, headers, body))
            status = statuses[index] if index < len(statuses) else 200
            location = '/hop%d' % (index + 1)
            if protocol == 'h2':
                block = (
                    b'\x88'
                    if status == 200
                    else (literal(8, str(status)) + literal(46, location))
                )
                conn.sendall(h2_frame(1, 5, stream, block))
            else:
                reply = 'HTTP/1.1 %d Result\r\nContent-Length: 0\r\n' % status
                if status != 200:
                    reply += 'Location: %s\r\n' % location
                conn.sendall((reply + 'Connection: close\r\n\r\n').encode())
                # Capture buffered bytes through EOF without trusting the very
                # Content-Length whose synchronization this peer verifies.
                received = bytearray(body)
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    received.extend(chunk)
                seen[-1] = (method, path, headers, bytes(received))
                return
        await_transport_close(conn)

    return serve


@pytest.mark.parametrize(
    'protocol,version', [('http', 13), ('h1', 12), ('h1', 13), ('h2', 12), ('h2', 13)]
)
@pytest.mark.parametrize('status', [307, 308])
@pytest.mark.parametrize('initial_body', ['binary', 'hook_text'])
@pytest.mark.parametrize(
    'edit',
    [
        'replay',
        'none',
        'empty',
        'buffered',
        'file',
        'iterator',
        'declared_file',
        'declared_iterator',
    ],
)
def test_connect_redirect_body_edits_keep_actual_bytes_and_framing(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    protocol,
    version,
    status,
    initial_body,
    edit,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    if protocol == 'h1':
        config.alpn_protocols = ['http/1.1']
        context.set_alpn_protocols(['http/1.1'])
    scheme = 'http' if protocol == 'http' else 'https'
    seen, tunnels = [], []
    original = (
        b'\x00\xffabc' if initial_body == 'binary' else '原始正文'.encode('utf-8')
    )
    borrowed = io.BytesIO(b'new')

    def application(conn):
        index = len(seen)
        if protocol == 'h2':
            start_h2(conn)
            stream, headers, body, _ = read_h2_request(conn, HPACKDecoder())
            seen.append((headers[':method'], headers[':path'], headers, body))
            block = (
                literal(8, str(status)) + literal(46, '/hop1')
                if index == 0
                else b'\x88'
            )
            conn.sendall(h2_frame(1, 5, stream, block))
            await_transport_close(conn)
        else:
            redirect_peer(
                seen,
                [status],
                protocol,
                read_http1_body=edit
                in ('file', 'iterator', 'declared_file', 'declared_iterator'),
            )(conn)

    def destination(conn):
        if protocol == 'http':
            application(conn)
        else:
            with context.wrap_socket(conn, server_side=True) as secured:
                application(secured)

    def connect(conn):
        tunnels.append(read_headers(conn))
        conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        destination(conn)

    def before(request):
        if request.url.endswith('/start') and initial_body == 'hook_text':
            request.data = '原始正文'
        if request.url.endswith('/hop1') and edit != 'replay':
            if initial_body == 'binary':
                request.headers['cOnTent-LENGTH'] = request.headers['Content-Length']
            if edit == 'declared_file':
                request.headers['Content-Length'] = '3'
            request.data = {
                'none': None,
                'empty': b'',
                'buffered': b'new',
                'file': borrowed,
                'iterator': iter([b'new']),
                'declared_file': borrowed,
                'declared_iterator': iter([b'new']),
            }[edit]
            if edit == 'declared_iterator':
                request.headers['Content-Length'] = b'3'

    with LocalServer(connect, connections=2) as peer, Session(
        tls_config=config, use_pooling=False, hooks={'before_request': [before]}
    ) as session:
        response = session.post(
            '%s://127.0.0.1:%d/start' % (scheme, peer.port),
            data=original if initial_body == 'binary' else None,
            headers={
                'Proxy-Authorization': 'Basic proxy-secret',
                **(
                    {'Content-Length': str(len(original))}
                    if initial_body == 'binary'
                    else {}
                ),
            },
            proxies={scheme: 'http://127.0.0.1:%d' % peer.port},
            timeout=3,
        )
        assert response.status_code == 200
        response.close()
        assert not session._uploads
    expected = (
        original if edit == 'replay' else b'' if edit in ('none', 'empty') else b'new'
    )
    assert [record[:2] for record in seen] == [('POST', '/start'), ('POST', '/hop1')]
    assert [record[3] for record in seen] == [original, expected]
    assert int(seen[0][2]['content-length']) == len(original)
    assert int(seen[1][2].get('content-length', 0)) == (
        0 if edit == 'iterator' else len(expected)
    )
    assert ('transfer-encoding' in seen[1][2]) == (
        edit == 'iterator' and protocol != 'h2'
    )
    assert all('proxy-authorization' not in record[2] for record in seen)
    assert all(
        b'Proxy-Authorization: Basic proxy-secret' in tunnel for tunnel in tunnels
    )
    assert not borrowed.closed
    if edit in ('file', 'declared_file'):
        assert borrowed.tell() == 3


@pytest.mark.parametrize(
    'protocol,version', [('http', 13), ('h1', 13), ('h2', 12), ('h2', 13)]
)
@pytest.mark.parametrize(
    'body_kind', ['data', 'binary', 'form', 'json', 'multipart', 'file']
)
def test_body_preserving_chain_keeps_actual_bytes_and_borrowed_ownership(
    trusted_certificates, monkeypatch, h2_readers, protocol, version, body_kind
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    if protocol == 'h1':
        config.alpn_protocols = ['http/1.1']
        context.set_alpn_protocols(['http/1.1'])
    borrowed = BorrowedFile(b'prefix\x00\xffpayload')
    borrowed.seek(6)
    arguments = {
        'data': {'data': 'payload'},
        'binary': {'data': b'\x00\xff\x80payload'},
        'form': {'data': {'field': 'a b'}},
        'json': {'json': {'field': 'value'}},
        'multipart': {'data': {'field': 'value'}, 'files': {'file': borrowed}},
        'file': {'data': borrowed},
    }[body_kind]
    seen = []
    statuses = [307, 308]
    if protocol == 'h2':
        handler = redirect_peer(seen, statuses, protocol)
    else:
        # HTTP1 deliberately closes between hops. Derive the next status from
        # the full trace rather than a connection-local request counter.
        def handler(conn):
            record = http1_request(conn)
            index = len(seen)
            seen.append(record)
            status = statuses[index] if index < len(statuses) else 200
            location = 'Location: /hop%d\r\n' % (index + 1) if status != 200 else ''
            conn.sendall(
                (
                    'HTTP/1.1 %d Result\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n'
                    % (status, location)
                ).encode()
            )

    with LocalServer(
        handler,
        context if protocol != 'http' else None,
        connections=1 if protocol == 'h2' else 3,
    ) as peer:
        with ConnectionPool() as pool, Session(tls_config=config, pool=pool) as session:
            response = session.post(
                '%s://127.0.0.1:%d/start'
                % ('http' if protocol == 'http' else 'https', peer.port),
                timeout=3,
                **arguments,
            )
            assert response.status_code == 200
            assert not session._uploads
    assert [record[:2] for record in seen] == [
        ('POST', '/start'),
        ('POST', '/hop1'),
        ('POST', '/hop2'),
    ]
    assert seen[0][3] and all(record[3] == seen[0][3] for record in seen)
    assert len({record[2].get('content-type') for record in seen}) == 1
    assert not borrowed.closed
    if body_kind == 'binary':
        assert seen[0][3] == b'\x00\xff\x80payload'
    if body_kind == 'multipart':
        assert borrowed.reads == 1
        assert b'\x00\xffpayload' in seen[0][3]
    if body_kind == 'file':
        assert seen[0][3] == b'\x00\xffpayload'


def test_early_h2_redirect_replays_without_parent_finalizing_final_stream(
    trusted_certificates, monkeypatch, h2_readers
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    body = b'payload' * 20000
    borrowed = BorrowedFile(b'xx' + body)
    borrowed.seek(2)
    seen = []

    def handler(conn):
        assert read_exact(conn, 24) == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        # No first-hop DATA credit, making the early redirect deterministic.
        conn.sendall(h2_frame(4, 0, 0, b'\x00\x04\x00\x00\x00\x00'))
        decoder, received = HPACKDecoder(), bytearray()
        while True:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 1:
                headers = dict(decoder.decode_headers(payload))
                seen.append((stream, headers[':method'], headers[':path']))
                if len(seen) == 1:
                    conn.sendall(
                        h2_frame(1, 5, stream, literal(8, '307') + literal(46, '/next'))
                    )
                elif len(seen) == 2:
                    conn.sendall(h2_frame(8, 0, stream, len(body).to_bytes(4, 'big')))
                else:
                    conn.sendall(h2_frame(1, 5, stream, b'\x88'))
                    break
            elif kind == 0 and stream == 3:
                received.extend(payload)
                if payload:
                    conn.sendall(h2_frame(8, 0, 0, len(payload).to_bytes(4, 'big')))
                if flags & 1:
                    assert bytes(received) == body
                    conn.sendall(
                        h2_frame(1, 4, stream, b'\x88')
                        + h2_frame(0, 1, stream, b'done')
                    )
        await_transport_close(conn)

    with LocalServer(handler, context) as peer:
        with ConnectionPool() as pool, Session(tls_config=config, pool=pool) as session:
            origin = 'https://127.0.0.1:%d' % peer.port
            response = session.post(
                origin + '/start', data=borrowed, stream=True, timeout=3
            )
            assert response.content == b'done'
            response.close()
            assert session.get(origin + '/reuse', timeout=3).status_code == 200
            assert not session._uploads
    assert seen == [(1, 'POST', '/start'), (3, 'POST', '/next'), (5, 'GET', '/reuse')]
    assert not borrowed.closed


@pytest.mark.parametrize('statuses', [(307,), (308,), (307, 302, 308)])
@pytest.mark.parametrize('method', ['POST', 'PUT', 'HEAD'])
def test_method_and_body_follow_status_without_expanding_legacy_statuses(
    statuses, method
):
    seen = []

    def handler(conn):
        index = len(seen)
        seen.append(http1_request(conn))
        status = statuses[index] if index < len(statuses) else 200
        location = 'Location: /hop%d\r\n' % (index + 1) if status != 200 else ''
        conn.sendall(
            (
                'HTTP/1.1 %d Result\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n'
                % (status, location)
            ).encode()
        )

    with LocalServer(handler, connections=len(statuses) + 1) as peer, Session(
        use_pooling=False
    ) as session:
        response = session.request(
            method,
            'http://127.0.0.1:%d/start' % peer.port,
            data='payload' if method != 'HEAD' else None,
            timeout=3,
        )
        assert response.status_code == 200
    expected_method = method
    expected_body = b'payload' if method != 'HEAD' else b''
    for index, record in enumerate(seen):
        if index and statuses[index - 1] not in (307, 308):
            expected_method, expected_body = 'GET', b''
        assert record[0] == expected_method
        assert record[3] == expected_body


@pytest.mark.parametrize('replace', ['data', 'request', 'file', 'error'])
@pytest.mark.parametrize('hook_scope', ['session', 'request'])
def test_consumed_source_is_rewound_only_if_it_survives_next_hop_hooks(
    replace, hook_scope
):
    seen = []

    def handler(conn):
        seen.append(http1_request(conn))
        reply = '307 Redirect\r\nLocation: /next' if len(seen) == 1 else '200 OK'
        conn.sendall(
            (
                'HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' % reply
            ).encode()
        )

    def before(request):
        if request.url.endswith('/next'):
            if replace == 'data':
                request.data = 'replacement'
            elif replace == 'file':
                request.data = io.BytesIO(b'replacement')
            elif replace == 'request':
                from ja3requests.requests.request import Request

                return Request('POST', request.url, data='replacement').request()
            else:
                raise ValueError('hook failed')

    with LocalServer(handler, connections=1 if replace == 'error' else 2) as peer:
        with Session(
            use_pooling=False,
            hooks={'before_request': [before]} if hook_scope == 'session' else None,
        ) as session:
            options = (
                {'hooks': {'before_request': [before]}}
                if hook_scope == 'request'
                else {}
            )
            if replace == 'error':
                with pytest.raises(ValueError, match='hook failed'):
                    session.post(
                        'http://127.0.0.1:%d/start' % peer.port,
                        data=iter([b'original']),
                        timeout=3,
                        **options,
                    )
            else:
                assert (
                    session.post(
                        'http://127.0.0.1:%d/start' % peer.port,
                        data=iter([b'original']),
                        timeout=3,
                        **options,
                    ).status_code
                    == 200
                )
            assert not session._uploads
    assert seen[0][3] == b'original'
    if replace != 'error':
        assert seen[1][3] == b'replacement'


@pytest.mark.parametrize('total', [0, 1])
def test_retry_exhaustion_still_preserves_307_method_and_replayable_source(total):
    seen = []
    borrowed = BorrowedFile(b'payload')

    def handler(conn):
        seen.append(http1_request(conn))
        reply = (
            '307 Redirect\r\nLocation: /next' if len(seen) <= total + 1 else '200 OK'
        )
        conn.sendall(
            (
                'HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' % reply
            ).encode()
        )

    retry = HTTPRetry(
        total=total, backoff_factor=0, allowed_methods={'POST'}, status_forcelist={307}
    )
    with LocalServer(handler, connections=total + 2) as peer, Session(
        use_pooling=False, retry=retry
    ) as session:
        response = session.post(
            'http://127.0.0.1:%d/start' % peer.port, data=borrowed, timeout=3
        )
        assert response.status_code == 200
        assert not session._uploads
    assert all(record[0] == 'POST' and record[3] == b'payload' for record in seen)
    assert not borrowed.closed


@pytest.mark.parametrize('protocol,status', [('http', 307), ('h2', 308)])
@pytest.mark.parametrize(
    'change,original,expected',
    [
        ('string', {'field': 'original'}, {'field': 'replacement'}),
        ('bool', {'value': 1}, {'value': True}),
        ('float', {'value': 1}, {'value': 1.0}),
        ('nested', {'value': [{'count': 1}]}, {'value': [{'count': True}]}),
        ('order', {'first': 1, 'second': 2}, {'second': 2, 'first': 1}),
    ],
)
def test_redirect_hook_json_mutation_changes_received_body(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    protocol,
    status,
    change,
    original,
    expected,
):
    seen = []
    original = copy.deepcopy(original)
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)

    def before(request):
        if not request.url.endswith('/hop1'):
            return
        if change == 'string':
            request.json['field'] = 'replacement'
        elif change == 'bool':
            request.json['value'] = True
        elif change == 'float':
            request.json['value'] = 1.0
        elif change == 'nested':
            request.json['value'][0]['count'] = True
        else:
            request.json['first'] = request.json.pop('first')

    original_bytes = json.dumps(original).encode()
    with LocalServer(
        redirect_peer(seen, [status], protocol),
        context if protocol == 'h2' else None,
        connections=1 if protocol == 'h2' else 2,
    ) as peer, ConnectionPool() as pool, Session(
        tls_config=config, pool=pool, hooks={'before_request': [before]}
    ) as session:
        response = session.post(
            '%s://127.0.0.1:%d/start'
            % ('https' if protocol == 'h2' else 'http', peer.port),
            json=original,
            timeout=3,
        )
        assert response.status_code == 200
    assert [record[3] for record in seen] == [
        original_bytes,
        json.dumps(expected).encode(),
    ]
    assert all(int(record[2]['content-length']) == len(record[3]) for record in seen)


@pytest.mark.parametrize('protocol,status', [('http', 307), ('h2', 308)])
@pytest.mark.parametrize(
    'body_kind,replacement,expected',
    [
        ('json', None, b''),
        ('json', '', b''),
        ('json', b'', b''),
        ('json', {}, b'{}'),
        ('json', {'value': 'replacement'}, b'{"value": "replacement"}'),
        ('data', None, b''),
        ('data', '', b''),
        ('data', b'', b''),
        ('data', {}, b''),
        ('data', 'replaced-\u03c0', 'replaced-\u03c0'.encode()),
        ('multipart', None, b''),
    ],
)
def test_redirect_hook_body_replacement_synchronizes_actual_length(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    protocol,
    status,
    body_kind,
    replacement,
    expected,
):
    seen = []
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    borrowed = BorrowedFile(b'file payload')
    arguments = {
        'json': {'json': {'value': 1}},
        'data': {'data': 'original'},
        'multipart': {'data': {'field': 'value'}, 'files': {'file': borrowed}},
    }[body_kind]

    def before(request):
        if request.url.endswith('/hop1'):
            # A hook can add another spelling after normal header preparation.
            request.headers['cOnTent-LENGTH'] = request.headers['Content-Length']
            if body_kind == 'multipart':
                request.files = None
                request.data = None
            else:
                setattr(request, body_kind, replacement)

    with LocalServer(
        redirect_peer(seen, [status], protocol),
        context if protocol == 'h2' else None,
        connections=1 if protocol == 'h2' else 2,
    ) as peer, ConnectionPool() as pool, Session(
        tls_config=config, pool=pool, hooks={'before_request': [before]}
    ) as session:
        response = session.post(
            '%s://127.0.0.1:%d/start'
            % ('https' if protocol == 'h2' else 'http', peer.port),
            timeout=3,
            **arguments,
        )
        assert response.status_code == 200
        assert (
            sum(name.lower() == 'content-length' for name in response.request.headers)
            <= 1
        )
    assert [record[:2] for record in seen] == [('POST', '/start'), ('POST', '/hop1')]
    assert seen[0][3]
    assert seen[1][3] == expected
    assert int(seen[1][2].get('content-length', 0)) == len(expected)
    assert 'transfer-encoding' not in seen[1][2]
    assert not borrowed.closed
    if body_kind == 'multipart':
        assert borrowed.reads == 1


@pytest.mark.parametrize('status,total', [(307, 1), (308, 2)])
@pytest.mark.parametrize('body_kind', ['file', 'buffered', 'none'])
def test_redirect_read_error_retries_only_failed_hop_and_finalizes_upload(
    monkeypatch,
    status,
    total,
    body_kind,
):
    seen, requests, uploads = [], [], []
    borrowed = BorrowedFile(b'payload')

    def handler(conn):
        record = http1_request(conn)
        seen.append(record)
        if record[1] == '/start':
            conn.sendall(
                (
                    'HTTP/1.1 %d Redirect\r\nLocation: /next\r\n'
                    'Content-Length: 0\r\nConnection: close\r\n\r\n' % status
                ).encode()
            )
        else:
            # Reset after reading the upload: this exercises the HTTP retry
            # branch for a read error, rather than the socket-connect retries.
            conn.setsockopt(
                socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0)
            )

    retry = HTTPRetry(total=total, backoff_factor=0)
    with LocalServer(handler, connections=total + 2) as peer, Session(
        use_pooling=False, retry=retry, hooks={'before_request': [requests.append]}
    ) as session:
        register = session._register_upload

        def track_upload(upload):
            uploads.append(upload)
            return register(upload)

        monkeypatch.setattr(session, '_register_upload', track_upload)
        data = {'file': borrowed, 'buffered': 'payload', 'none': None}[body_kind]
        with pytest.raises(ConnectionResetError):
            session.put('http://127.0.0.1:%d/start' % peer.port, data=data, timeout=3)
        assert not session._uploads
        assert all(not upload.worker.is_alive() for upload in uploads)
        if body_kind == 'file':
            assert uploads and all(request.data._closed for request in requests)
    assert [record[1] for record in seen] == ['/start'] + ['/next'] * (total + 1)
    assert all(
        record[3] == (b'' if body_kind == 'none' else b'payload') for record in seen
    )
    assert not borrowed.closed


@pytest.mark.parametrize('source_kind', ['file', 'iterator', 'declared'])
def test_redirect_hook_buffered_to_upload_keeps_new_source_framing(source_kind):
    seen = []
    borrowed = io.BytesIO(b'new')
    replacement = borrowed if source_kind == 'file' else iter([b'new'])

    def handler(conn):
        seen.append(http1_request(conn))
        reply = '308 Redirect\r\nLocation: /next' if len(seen) == 1 else '200 OK'
        conn.sendall(
            (
                'HTTP/1.1 %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' % reply
            ).encode()
        )

    def before(request):
        if request.url.endswith('/next'):
            request.headers['cOnTent-LENGTH'] = request.headers['Content-Length']
            if source_kind == 'declared':
                # An explicitly changed length survives body replacement,
                # including when the hook assigns it before the new source.
                request.headers['Content-Length'] = '3'
            request.data = replacement

    with LocalServer(handler, connections=2) as peer, Session(
        use_pooling=False, hooks={'before_request': [before]}
    ) as session:
        response = session.put(
            'http://127.0.0.1:%d/start' % peer.port, data='original', timeout=3
        )
        assert response.status_code == 200
        assert response.request.data._closed
        assert not session._uploads
    assert [record[3] for record in seen] == [b'original', b'new']
    assert seen[1][2].get('content-length') == (
        None if source_kind == 'iterator' else '3'
    )
    assert ('transfer-encoding' in seen[1][2]) == (source_kind == 'iterator')
    assert not borrowed.closed


@pytest.mark.parametrize(
    'location,error',
    [
        ('ftp://127.0.0.1/unsupported', NotAllowedScheme),
        ('http://127.0.0.1:invalid/next', ValueError),
    ],
)
def test_replaced_source_closes_when_later_redirect_construction_fails(location, error):
    seen, requests = [], []
    original, replacement = io.BytesIO(b'first'), io.BytesIO(b'other')

    def handler(conn):
        seen.append(http1_request(conn))
        target = '/next' if len(seen) == 1 else location
        conn.sendall(
            (
                'HTTP/1.1 307 Redirect\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
                % target
            ).encode()
        )

    def before(request):
        requests.append(request)
        if request.url.endswith('/next'):
            request.data = replacement

    with LocalServer(handler, connections=2) as peer, Session(
        use_pooling=False, hooks={'before_request': [before]}
    ) as session:
        with pytest.raises(error):
            session.post(
                'http://127.0.0.1:%d/start' % peer.port, data=original, timeout=3
            )
        assert all(request.data._closed for request in requests)
        assert not session._uploads
    assert [record[3] for record in seen] == [b'first', b'other']
    assert not original.closed and not replacement.closed


@pytest.mark.parametrize('protocol,status', [('http', 307), ('h2', 308)])
@pytest.mark.parametrize(
    'framing', ['automatic', 'declared', 'alias', 'duplicate', 'bytes']
)
@pytest.mark.parametrize('replacement', [None, b''])
def test_redirect_hook_clears_streamed_body_and_all_inherited_lengths(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    protocol,
    status,
    framing,
    replacement,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen, sources = [], []
    borrowed = io.BytesIO(b'payload')

    def before(request):
        if request.url.endswith('/hop1'):
            sources.append(request.data)
            if framing in ('alias', 'bytes'):
                value = request.headers.pop('Content-Length')
                request.headers['cOnTent-LENGTH'] = (
                    value.encode('ascii') if framing == 'bytes' else value
                )
            elif framing == 'duplicate':
                request.headers['cOnTent-LENGTH'] = request.headers['Content-Length']
            request.data = replacement

    with LocalServer(
        redirect_peer(seen, [status], protocol),
        context if protocol == 'h2' else None,
        connections=1 if protocol == 'h2' else 2,
    ) as peer, ConnectionPool() as pool, Session(
        tls_config=config, pool=pool, hooks={'before_request': [before]}
    ) as session:
        response = session.post(
            '%s://127.0.0.1:%d/start'
            % ('https' if protocol == 'h2' else 'http', peer.port),
            data=borrowed,
            headers={'Content-Length': '7'} if framing == 'declared' else None,
            timeout=3,
        )
        assert response.status_code == 200
        assert not session._uploads
        assert not any(
            name.lower() == 'content-length' for name in response.request.headers
        )
    assert [record[3] for record in seen] == [b'payload', b'']
    assert 'content-length' not in seen[1][2]
    assert 'transfer-encoding' not in seen[1][2]
    assert sources[0]._closed and not borrowed.closed


@pytest.mark.parametrize('protocol', ['http', 'h2'])
@pytest.mark.parametrize('replacement', ['file', 'iterator', 'declared', 'request'])
def test_redirect_hook_upload_replacement_keeps_only_new_source_framing(
    trusted_certificates, monkeypatch, h2_readers, protocol, replacement
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen, sources = [], []
    borrowed, new_file = io.BytesIO(b'payload'), io.BytesIO(b'new')
    expected = b'newbody' if replacement == 'request' else b'new'

    def before(request):
        if request.url.endswith('/hop1'):
            sources.append(request.data)
            if replacement == 'request':
                # A replacement request owns its explicit length, even when
                # that length happens to match the previous body's length.
                return Request(
                    'POST',
                    request.url,
                    data=iter([expected]),
                    headers={'Content-Length': '7'},
                    tls_config=config,
                    timeout=3,
                ).request()
            request.headers['cOnTent-LENGTH'] = request.headers['Content-Length']
            if replacement == 'declared':
                request.headers['Content-Length'] = '3'
            request.data = new_file if replacement == 'file' else iter([expected])

    with LocalServer(
        redirect_peer(seen, [307], protocol, read_http1_body=True),
        context if protocol == 'h2' else None,
        connections=1 if protocol == 'h2' else 2,
    ) as peer, ConnectionPool() as pool, Session(
        tls_config=config, pool=pool, hooks={'before_request': [before]}
    ) as session:
        response = session.post(
            '%s://127.0.0.1:%d/start'
            % ('https' if protocol == 'h2' else 'http', peer.port),
            data=borrowed,
            headers={'Content-Length': '7'},
            timeout=3,
        )
        assert response.status_code == 200
        assert response.request.data._closed
        assert not session._uploads
    assert [record[3] for record in seen] == [b'payload', expected]
    expected_length = None if replacement == 'iterator' else str(len(expected))
    assert seen[1][2].get('content-length') == expected_length
    assert ('transfer-encoding' in seen[1][2]) == (
        protocol == 'http' and replacement == 'iterator'
    )
    assert sources[0]._closed and not borrowed.closed and not new_file.closed


@pytest.mark.parametrize('protocol,status', [('http', 307), ('h2', 308)])
@pytest.mark.parametrize('change', ['reorder', 'remove'])
def test_redirect_hook_multipart_file_edits_change_actual_parts(
    trusted_certificates, monkeypatch, h2_readers, protocol, status, change
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = []
    first, second = BorrowedFile(b'first-content'), BorrowedFile(b'second-content')

    def before(request):
        if request.url.endswith('/hop1'):
            if change == 'reorder':
                request.files['first'] = request.files.pop('first')
            else:
                request.files = None

    with LocalServer(
        redirect_peer(seen, [status], protocol),
        context if protocol == 'h2' else None,
        connections=1 if protocol == 'h2' else 2,
    ) as peer, ConnectionPool() as pool, Session(
        tls_config=config, pool=pool, hooks={'before_request': [before]}
    ) as session:
        response = session.post(
            '%s://127.0.0.1:%d/start'
            % ('https' if protocol == 'h2' else 'http', peer.port),
            data={'field': 'value'},
            files={'first': first, 'second': second},
            timeout=3,
        )
        assert response.status_code == 200
    parts = [
        re.findall(br'Content-Disposition: form-data; name="([^"]+)"', record[3])
        for record in seen
    ]
    assert parts[0] == [b'field', b'first', b'second']
    assert parts[1] == (
        [b'field', b'second', b'first'] if change == 'reorder' else [b'field']
    )
    if change == 'reorder':
        assert b'first-content' in seen[1][3] and b'second-content' in seen[1][3]
    else:
        assert seen[1][3] == (
            b'--boundary\r\nContent-Disposition: form-data; name="field"\r\n\r\n'
            b'value\r\n--boundary--'
        )
    assert all(int(record[2]['content-length']) == len(record[3]) for record in seen)
    assert seen[0][2]['content-type'] == seen[1][2]['content-type']
    assert first.reads == second.reads == 1
    assert not first.closed and not second.closed


@pytest.mark.parametrize('protocol', ['http', 'h2'])
@pytest.mark.parametrize('status', [307, 308])
@pytest.mark.parametrize('initial_form', [None, {'field': 'value'}])
def test_multipart_files_survive_absent_and_cleared_form(
    trusted_certificates, monkeypatch, h2_readers, protocol, status, initial_form
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = []
    borrowed = BorrowedFile(b'\x00\xfffile payload')

    def before(request):
        if request.url.endswith('/hop1'):
            request.data = None

    with LocalServer(
        redirect_peer(seen, [status], protocol, read_http1_body=True),
        context if protocol == 'h2' else None,
        connections=1 if protocol == 'h2' else 2,
    ) as peer, ConnectionPool() as pool, Session(
        tls_config=config, pool=pool, hooks={'before_request': [before]}
    ) as session:
        response = session.post(
            '%s://127.0.0.1:%d/start'
            % ('https' if protocol == 'h2' else 'http', peer.port),
            data=initial_form,
            files={'file': borrowed},
            timeout=3,
        )
        assert response.status_code == 200
        assert response.request.data is None and response.request.files
        assert not session._uploads
    expected_file = ('file', 'payload.bin', b'\x00\xfffile payload')
    assert multipart_parts(seen[0]) == (
        [('field', None, b'value')] if initial_form else []
    ) + [expected_file]
    assert multipart_parts(seen[1]) == [expected_file]
    assert borrowed.reads == 1 and not borrowed.closed


@pytest.mark.parametrize('protocol', ['http', 'h2'])
@pytest.mark.parametrize('status', [307, 308])
@pytest.mark.parametrize('change', ['unchanged', 'empty_only', 'mixed'])
def test_multipart_empty_fields_survive_encoding_and_redirect_hooks(
    trusted_certificates, monkeypatch, h2_readers, protocol, status, change
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = []
    borrowed = BorrowedFile(b'file payload')

    def before(request):
        if request.url.endswith('/hop1') and change != 'unchanged':
            request.files = None
            request.data = {'empty': ''}
            if change == 'mixed':
                request.data = {'empty': '', 'ordinary': 'new value'}

    with LocalServer(
        redirect_peer(seen, [status], protocol, read_http1_body=True),
        context if protocol == 'h2' else None,
        connections=1 if protocol == 'h2' else 2,
    ) as peer, ConnectionPool() as pool, Session(
        tls_config=config, pool=pool, hooks={'before_request': [before]}
    ) as session:
        response = session.post(
            '%s://127.0.0.1:%d/start'
            % ('https' if protocol == 'h2' else 'http', peer.port),
            data={'empty': '', 'ordinary': 'value'},
            files={'file': borrowed},
            timeout=3,
        )
        assert response.status_code == 200
    initial = [
        ('empty', None, b''),
        ('ordinary', None, b'value'),
        ('file', 'payload.bin', b'file payload'),
    ]
    assert multipart_parts(seen[0]) == initial
    expected = initial if change == 'unchanged' else [('empty', None, b'')]
    if change == 'mixed':
        expected.append(('ordinary', None, b'new value'))
    assert multipart_parts(seen[1]) == expected
    if change == 'unchanged':
        assert seen[0][3] == seen[1][3]
    assert borrowed.reads == 1 and not borrowed.closed


@pytest.mark.parametrize('protocol,status', [('http', 307), ('h2', 308)])
def test_multipart_quoted_names_round_trip_without_extra_part_headers(
    trusted_certificates, monkeypatch, h2_readers, protocol, status
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = []
    field_name, file_field = '字"\\段', '文"\\件'
    borrowed = BorrowedFile(b'file payload')
    borrowed.name = 'folder/文"\\件.bin'

    def before(request):
        if request.url.endswith('/hop1'):
            request.files = None

    with LocalServer(
        redirect_peer(seen, [status], protocol, read_http1_body=True),
        context if protocol == 'h2' else None,
        connections=1 if protocol == 'h2' else 2,
    ) as peer, ConnectionPool() as pool, Session(
        tls_config=config, pool=pool, hooks={'before_request': [before]}
    ) as session:
        response = session.post(
            '%s://127.0.0.1:%d/start'
            % ('https' if protocol == 'h2' else 'http', peer.port),
            data={field_name: '值'},
            files={file_field: borrowed},
            timeout=3,
        )
        assert response.status_code == 200
    field = (field_name, None, '值'.encode('utf-8'))
    assert multipart_parts(seen[0]) == [
        field,
        (file_field, '文"\\件.bin', b'file payload'),
    ]
    assert multipart_parts(seen[1]) == [field]
    assert borrowed.reads == 1 and not borrowed.closed


@pytest.mark.parametrize('protocol', ['http', 'h2'])
@pytest.mark.parametrize('component', ['form', 'file', 'filename'])
@pytest.mark.parametrize(
    'bad_name', ['field"\r\nX-Injected: yes\r\nX-Other: "', 'bad\nname', 'bad\x00name']
)
def test_multipart_invalid_hook_names_release_resources_and_allow_next_request(
    trusted_certificates, monkeypatch, h2_readers, protocol, component, bad_name
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen, rejected = [], []
    borrowed = BorrowedFile(b'file payload')

    def before(request):
        if request.url.endswith('/hop1'):
            if component == 'form':
                request.files = None
                request.data = {bad_name: 'value'}
            elif component == 'file':
                request.files[bad_name] = request.files.pop('file')
            else:
                request.files['file'][0]['file_name'] = bad_name

    def serve(conn):
        decoder = HPACKDecoder()
        if protocol == 'h2':
            start_h2(conn)
        elif seen and not rejected:
            assert conn.recv(1) == b''
            rejected.append(True)
            return
        for _ in range(2 if protocol == 'h2' else 1):
            if protocol == 'h2':
                stream, headers, body, _ = read_h2_request(conn, decoder)
                record = (headers[':method'], headers[':path'], headers, body)
            else:
                record = http1_request(conn)
            index = len(seen)
            assert record[:2] == (
                ('POST', '/start') if index == 0 else ('GET', '/recovery')
            )
            seen.append(record)
            if protocol == 'h2':
                block = (
                    literal(8, '307') + literal(46, '/hop1') if index == 0 else b'\x88'
                )
                conn.sendall(h2_frame(1, 5, stream, block))
            else:
                status = 307 if index == 0 else 200
                location = 'Location: /hop1\r\n' if index == 0 else ''
                conn.sendall(
                    (
                        'HTTP/1.1 %d Result\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n'
                        % (status, location)
                    ).encode()
                )
        if protocol == 'h2':
            await_transport_close(conn)

    with LocalServer(
        serve,
        context if protocol == 'h2' else None,
        connections=1 if protocol == 'h2' else 3,
    ) as peer, ConnectionPool() as pool, Session(
        tls_config=config, pool=pool, hooks={'before_request': [before]}
    ) as session:
        url = '%s://127.0.0.1:%d' % ('https' if protocol == 'h2' else 'http', peer.port)
        with pytest.raises(InvalidData):
            session.post(
                url + '/start',
                data={'field': 'value'},
                files={'file': borrowed},
                timeout=3,
            )
        assert not session._uploads
        assert all(
            entry['active_streams'] == 0
            for entry in pool.get_stats()['h2_hosts'].values()
        )
        assert session.get(url + '/recovery', timeout=3).status_code == 200
        assert pool.get_stats()['total_connections'] == (1 if protocol == 'h2' else 0)
    assert len(seen) == 2
    assert len(h2_readers) == (1 if protocol == 'h2' else 0)
    assert rejected == ([True] if protocol == 'http' else [])
    assert borrowed.reads == 1 and not borrowed.closed


@pytest.mark.parametrize('protocol', ['http', 'h2'])
@pytest.mark.parametrize('total', [0, 1])
@pytest.mark.parametrize('next_method', ['POST', 'PUT'])
def test_redirect_status_exhaustion_is_owned_by_the_current_hop(
    trusted_certificates, monkeypatch, h2_readers, protocol, total, next_method
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    seen = []
    expected_paths = ['/start'] * (total + 1) + ['/next'] * (
        total + 1 if next_method == 'PUT' else 1
    )

    def handler(conn):
        decoder = HPACKDecoder()
        if protocol == 'h2':
            start_h2(conn)
        for _ in range(len(expected_paths) if protocol == 'h2' else 1):
            if protocol == 'h2':
                stream, headers, body, _ = read_h2_request(conn, decoder)
                record = (headers[':method'], headers[':path'], headers, body)
            else:
                record = http1_request(conn)
            seen.append(record)
            status = 307 if record[1] == '/start' else 503
            if protocol == 'h2':
                block = literal(8, str(status))
                if status == 307:
                    block += literal(46, '/next')
                conn.sendall(h2_frame(1, 5, stream, block))
            else:
                location = 'Location: /next\r\n' if status == 307 else ''
                conn.sendall(
                    (
                        'HTTP/1.1 %d Result\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n'
                        % (status, location)
                    ).encode()
                )
        if protocol == 'h2':
            await_transport_close(conn)

    def before(request):
        if request.url.endswith('/next'):
            request.method = next_method

    with LocalServer(
        handler,
        context if protocol == 'h2' else None,
        connections=1 if protocol == 'h2' else len(expected_paths),
    ) as peer, ConnectionPool() as pool, Session(
        tls_config=config,
        pool=pool,
        retry=HTTPRetry(
            total=total,
            backoff_factor=0,
            status_forcelist={307, 503},
            allowed_methods={'PUT'},
            raise_on_status=True,
        ),
        hooks={'before_request': [before]},
    ) as session:
        url = '%s://127.0.0.1:%d/start' % (
            'https' if protocol == 'h2' else 'http',
            peer.port,
        )
        if next_method == 'PUT':
            with pytest.raises(MaxRetriedException, match='last status: 503'):
                session.put(url, data='payload', timeout=3)
        else:
            assert session.put(url, data='payload', timeout=3).status_code == 503
        assert session.response.status_code == 503
    assert [record[1] for record in seen] == expected_paths
    assert [record[0] for record in seen] == ['PUT'] * (total + 1) + [next_method] * (
        len(expected_paths) - total - 1
    )
    assert all(record[3] == b'payload' for record in seen)
