"""Public async files= against independent HTTP/1 framing and MIME parsers."""

import asyncio
import builtins
import io
import os
import struct
import threading
from email import policy
from email.parser import BytesParser

import pytest

from ja3requests import AsyncSession, HTTPRetry
from ja3requests import _multipart
from ja3requests.exceptions import InvalidData, StreamConsumedError
from test.test_async_upload import UploadPeer, read_body, reply
from test.integration.conftest import trusted_certificates
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    receive_frame,
    start_h2,
    trusted_h2_peer,
)
from test.mock_servers.local import LocalServer, h2_frame


def parts(content_type, body):
    message = BytesParser(policy=policy.default).parsebytes(
        b'Content-Type: '
        + content_type.encode('ascii')
        + b'\r\nMIME-Version: 1.0\r\n\r\n'
        + body
    )
    assert message.is_multipart() and not message.defects
    return [
        (
            part.get_param('name', header='content-disposition'),
            part.get_filename(),
            part.get_payload(decode=True),
        )
        for part in message.iter_parts()
    ]


def track_paths(monkeypatch, paths):
    opened = []
    targets = {os.fspath(path) for path in paths}

    def tracked(path, *args, **kwargs):
        handle = builtins.open(path, *args, **kwargs)
        if os.fspath(path) in targets:
            opened.append(handle)
        return handle

    monkeypatch.setattr(_multipart, 'open', tracked, raising=False)
    return opened


def test_fields_repeated_files_unicode_and_borrowed_offsets(tmp_path, monkeypatch):
    path = tmp_path / 'quote"文.bin'
    path.write_bytes(b'\x00\xffpath')
    opened = track_paths(monkeypatch, [path])
    borrowed = io.BytesIO(b'prefixborrowed')
    borrowed.seek(6)

    async def scenario():
        observed = []

        async def route(reader, writer, _method, _path, headers):
            body = await read_body(reader, headers)
            assert len(body) == int(headers['content-length'])
            assert 'transfer-encoding' not in headers
            observed.extend(parts(headers['content-type'], body))
            await reply(writer)

        async with UploadPeer(route) as peer, AsyncSession() as session:
            response = await session.post(
                peer.url,
                data=[('text', '你好'), ('repeat', 'one'), ('repeat', 'two')],
                files={'files': [path, borrowed]},
                timeout=2,
            )
            assert await response.read() == b'ok'
        assert observed == [
            ('text', None, '你好'.encode()),
            ('repeat', None, b'one'),
            ('repeat', None, b'two'),
            ('files', path.name, b'\x00\xffpath'),
            ('files', 'files', b'borrowed'),
        ]

    asyncio.run(scenario())
    assert len(opened) == 1 and all(handle.closed for handle in opened)
    assert not borrowed.closed


def test_unknown_length_file_uses_chunked_transport():
    class Unknown:
        def __init__(self):
            self.data = io.BytesIO(b'unknown\x00file')
            self.closed = False

        def seekable(self):
            return False

        def read(self, size):
            return self.data.read(size)

        def close(self):
            self.closed = True

    source = Unknown()

    async def scenario():
        async def route(reader, writer, _method, _path, headers):
            assert 'content-length' not in headers
            assert headers['transfer-encoding'] == 'chunked'
            assert parts(headers['content-type'], await read_body(reader, headers)) == [
                ('payload', 'payload', b'unknown\x00file'),
            ]
            await reply(writer)

        async with UploadPeer(route) as peer, AsyncSession() as session:
            await session.post(peer.url, files={'payload': source}, timeout=2)

    asyncio.run(scenario())
    assert not source.closed


@pytest.mark.parametrize(
    'fault', ['raw', 'json', 'type', 'boundary', 'length', 'duplicate', 'hook-type']
)
def test_invalid_multipart_combinations_fail_before_upload(fault):
    borrowed = io.BytesIO(b'data')
    options = {'files': {'file': borrowed}}
    if fault == 'raw':
        options['data'] = iter((b'raw',))
    elif fault == 'json':
        options['json'] = {'bad': True}
    elif fault in ('type', 'boundary'):
        options['headers'] = {
            'Content-Type': (
                'text/plain'
                if fault == 'type'
                else 'multipart/form-data; boundary=wrong'
            )
        }
    elif fault == 'length':
        options['headers'] = {'Content-Length': '1'}
    elif fault == 'duplicate':
        options['headers'] = {'Content-Length': '1', 'content-length': '1'}
    else:

        def hook(request):
            request.headers['Content-Type'] = 'text/plain'

        options['hooks'] = {'before_request': [hook]}

    async def scenario():
        async with AsyncSession() as session:
            with pytest.raises(InvalidData):
                await session.post('http://127.0.0.1:1/', **options)

    asyncio.run(scenario())
    assert not borrowed.closed and borrowed.tell() == 0


@pytest.mark.parametrize('status', [307, 308, 503])
def test_multipart_replay_keeps_boundary_and_reopens_paths(
    tmp_path, monkeypatch, status
):
    path = tmp_path / 'source.bin'
    path.write_bytes(b'path-body')
    opened = track_paths(monkeypatch, [path])
    borrowed = io.BytesIO(b'skipborrowed')
    borrowed.seek(4)

    async def scenario():
        observed = []

        async def route(reader, writer, _method, _path, headers):
            observed.append((headers['content-type'], await read_body(reader, headers)))
            await reply(
                writer,
                status if len(observed) == 1 else 200,
                headers=b'Location: /again\r\n',
            )

        retry = HTTPRetry(total=1, status_forcelist=[503]) if status == 503 else None
        async with UploadPeer(route) as peer, AsyncSession(retry=retry) as session:
            await session.put(peer.url, files={'file': [path, borrowed]}, timeout=2)
        assert len(observed) == 2 and observed[0] == observed[1]
        assert parts(*observed[0]) == [
            ('file', 'source.bin', b'path-body'),
            ('file', 'file', b'borrowed'),
        ]

    asyncio.run(scenario())
    assert len(opened) == 2 and all(handle.closed for handle in opened)
    assert not borrowed.closed


def test_bodyless_redirect_drops_multipart_headers_and_closes_path(
    tmp_path, monkeypatch
):
    path = tmp_path / 'file.bin'
    path.write_bytes(b'data')
    opened = track_paths(monkeypatch, [path])

    async def scenario():
        async def route(reader, writer, method, url, headers):
            if url == '/':
                await read_body(reader, headers)
                await reply(writer, 303, headers=b'Location: /next\r\n')
            else:
                assert method == 'GET'
                assert (
                    not {'content-length', 'content-type', 'transfer-encoding'}
                    & headers.keys()
                )
                assert all(handle.closed for handle in opened)
                await reply(writer)

        async with UploadPeer(route) as peer, AsyncSession() as session:
            await session.post(peer.url, files={'file': path}, timeout=2)

    asyncio.run(scenario())
    assert len(opened) == 1 and opened[0].closed


def test_failure_in_later_part_closes_owned_files_and_preserves_borrowed(
    tmp_path, monkeypatch
):
    path = tmp_path / 'file.bin'
    path.write_bytes(b'data')
    opened = track_paths(monkeypatch, [path])

    class Broken:
        closed = False

        def seekable(self):
            return False

        def read(self, _size):
            raise OSError('broken second part')

        def close(self):
            self.closed = True

    source = Broken()

    async def scenario():
        async def route(reader, _writer, *_args):
            await reader.read()
            return False

        async with UploadPeer(route) as peer, AsyncSession() as session:
            with pytest.raises(InvalidData):
                await session.post(peer.url, files={'file': [path, source]}, timeout=2)

    asyncio.run(scenario())
    assert len(opened) == 1 and opened[0].closed and not source.closed


@pytest.mark.parametrize(
    'action', ['request-cancel', 'response-close', 'session-close']
)
def test_cancel_or_close_joins_pending_owned_path_read(tmp_path, monkeypatch, action):
    path = tmp_path / 'owned.bin'
    path.write_bytes(b'owned-data')

    async def scenario():
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        release = threading.Event()
        opened = []

        class GatedFile:
            def __init__(self, handle):
                self.handle = handle

            def __getattr__(self, name):
                return getattr(self.handle, name)

            def read(self, size):
                loop.call_soon_threadsafe(entered.set)
                assert release.wait(5)
                return self.handle.read(size)

        def open_file(filename, *args, **kwargs):
            handle = builtins.open(filename, *args, **kwargs)
            opened.append(handle)
            return GatedFile(handle)

        monkeypatch.setattr(_multipart, 'open', open_file, raising=False)

        async def route(reader, writer, *_args):
            await entered.wait()
            if action == 'response-close':
                await reply(writer, 413, b'early')
            await reader.read()
            return False

        async with UploadPeer(route) as peer, AsyncSession() as session:
            task = asyncio.create_task(
                session.post(
                    peer.url,
                    files={'file': path},
                    stream=True,
                    timeout=2,
                )
            )
            closer = None
            try:
                await asyncio.wait_for(entered.wait(), 1)
                if action == 'request-cancel':
                    task.cancel()
                elif action == 'response-close':
                    response = await asyncio.wait_for(task, 1)
                    closer = asyncio.create_task(response.aclose())
                else:
                    closer = asyncio.create_task(session.aclose())
                await asyncio.sleep(0)
                assert len(opened) == 1 and not opened[0].closed
                assert not (closer if closer is not None else task).done()
                release.set()
                if closer is not None:
                    await asyncio.wait_for(closer, 2)
                if action != 'response-close':
                    with pytest.raises(asyncio.CancelledError):
                        await task
                assert opened[0].closed and not session.pool._entries
            finally:
                release.set()
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
                if closer is not None:
                    await asyncio.gather(closer, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.parametrize('version', [12, 13])
def test_multipart_over_authenticated_h2_matches_independent_mime_parser(
    trusted_certificates, monkeypatch, version
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    payload = bytes(range(256)) * 512
    observed = []

    def peer(conn):
        start_h2(conn)
        header_block = bytearray()
        stream = None
        while True:
            kind, flags, target, data = receive_frame(conn)
            if kind in (1, 9):
                stream = target
                header_block.extend(data)
                if flags & 4:
                    break
        body = bytearray()
        while True:
            kind, flags, target, data = receive_frame(conn)
            if kind != 0:
                continue
            assert target == stream and len(data) <= 16384
            body.extend(data)
            if data:
                credit = struct.pack('!I', len(data))
                conn.sendall(h2_frame(8, 0, 0, credit) + h2_frame(8, 0, stream, credit))
            if flags & 1:
                break
        boundary = bytes(body).split(b'\r\n', 1)[0][2:]
        content_type = b'multipart/form-data; boundary=' + boundary
        # The request encoder uses non-Huffman literals. HPACK static indexes
        # 31 and 28 independently identify Content-Type and Content-Length.
        assert b'\x5f' + bytes([len(content_type)]) + content_type in header_block
        length = str(len(body)).encode('ascii')
        assert b'\x5c' + bytes([len(length)]) + length in header_block
        observed.extend(parts(content_type.decode(), bytes(body)))
        conn.sendall(h2_frame(1, 4, stream, b'\x88') + h2_frame(0, 1, stream, b'ok'))
        await_transport_close(conn)

    async def scenario(port):
        borrowed = io.BytesIO(payload)
        async with AsyncSession(tls_config=config) as session:
            response = await session.post(
                'https://127.0.0.1:%d/' % port,
                data={'field': 'text'},
                files={'file': borrowed},
                timeout=3,
            )
            assert response.protocol_version == 'HTTP/2'
            assert await response.read() == b'ok'
            assert all(entry.leases == 0 for entry in session.pool._entries)
        assert not borrowed.closed

    with LocalServer(peer, context) as server:
        asyncio.run(scenario(server.port))
    assert observed == [('field', None, b'text'), ('file', 'file', payload)]
