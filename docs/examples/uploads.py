"""Exercise public upload APIs against an independent local HTTP/1 parser."""

import asyncio
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import threading

from ja3requests import AsyncSession, Session
from ja3requests.pool import ConnectionPool


class UploadPeer(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, _format, *args):
        pass

    def do_POST(self):
        try:
            body = bytearray()
            if self.headers.get('Transfer-Encoding') == 'chunked':
                while True:
                    size = int(self.rfile.readline().strip(), 16)
                    if not size:
                        assert self.rfile.readline() == b'\r\n'
                        break
                    body.extend(self.rfile.read(size))
                    assert self.rfile.read(2) == b'\r\n'
                    self.server.prefix_received.set()
            else:
                size = int(self.headers['Content-Length'])
                body.extend(self.rfile.read(size))
                assert len(body) == size
            if self.path == '/multipart':
                envelope = (
                    'Content-Type: %s\r\nMIME-Version: 1.0\r\n\r\n'
                    % self.headers['Content-Type']
                ).encode('utf-8') + body
                message = BytesParser(policy=policy.default).parsebytes(envelope)
                parts = list(message.iter_parts())
                assert [
                    p.get_param('name', header='content-disposition') for p in parts
                ] == ['label', 'label', 'attachment', 'attachment']
                assert [p.get_payload(decode=True) for p in parts] == [
                    b'first',
                    b'second',
                    b'owned path\x00',
                    b'borrowed handle\xff',
                ]
                answer = b'multipart accepted'
            else:
                answer = bytes(body)
            self.send_response(200)
            self.send_header('Content-Length', str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)
            self.wfile.flush()
        except Exception as error:
            self.server.errors.append(error)
            self.close_connection = True


def sync_uploads(url, peer):
    with Session(pool=ConnectionPool()) as session:
        source = BytesIO(b'skipfixed source')
        source.seek(4)
        with session.post(url, data=source, timeout=3) as response:
            assert response.content == b'fixed source'
        assert not source.closed
        peer.prefix_received.clear()

        def chunks():
            yield b'prefix'
            assert peer.prefix_received.wait(3), 'Upload was buffered before sending'
            yield b'tail'

        with session.post(url, data=chunks(), timeout=3) as response:
            assert response.content == b'prefixtail'


async def async_uploads(url, peer, path):
    async with AsyncSession() as session:
        source = BytesIO(b'async file')
        response = await session.post(url, data=source, timeout=3)
        assert await response.read() == b'async file' and not source.closed
        peer.prefix_received.clear()

        async def chunks():
            yield b'prefix'
            assert await asyncio.get_running_loop().run_in_executor(
                None, peer.prefix_received.wait, 3
            )
            yield b'tail'

        response = await session.post(url, data=chunks(), timeout=3)
        assert await response.read() == b'prefixtail'
        borrowed = BytesIO(b'borrowed handle\xff')
        response = await session.post(
            url + '/multipart',
            data=[('label', 'first'), ('label', 'second')],
            files={'attachment': [path, borrowed]},
            timeout=3,
        )
        assert await response.read() == b'multipart accepted'
        assert not borrowed.closed


def main():
    peer = ThreadingHTTPServer(('127.0.0.1', 0), UploadPeer)
    peer.prefix_received = threading.Event()
    peer.errors = []
    server = threading.Thread(target=peer.serve_forever, daemon=True)
    server.start()
    try:
        url = 'http://127.0.0.1:%d' % peer.server_port
        sync_uploads(url, peer)
        with TemporaryDirectory(prefix='ja3requests-upload-demo-') as root:
            path = Path(root) / 'owned.bin'
            path.write_bytes(b'owned path\x00')
            asyncio.run(async_uploads(url, peer, path))
        if peer.errors:
            raise peer.errors[0]
    finally:
        peer.shutdown()
        peer.server_close()
        server.join()
    print(
        'PASS: sync/async fixed and chunked uploads, prefix before EOF, async multipart'
    )


if __name__ == '__main__':
    main()
