"""Streaming response ownership across retries, redirects and body failures."""

import gzip
import io
import zlib
import tracemalloc

import brotli
import pytest

from ja3requests import HTTPRetry, Session
from ja3requests.exceptions import ContentDecodingError
from ja3requests.pool import ConnectionPool
from ja3requests.response import HTTPResponse, Response
from ja3requests.requests.http import HttpRequest
from test.mock_servers.local import LocalServer, read_headers, recv_with_ragged_eof


@pytest.mark.parametrize('policy', ['retry', 'redirect'])
def test_intermediate_stream_is_closed_before_followup_request(policy):
    requests = []
    hooks = []

    def serve(conn):
        requests.append(read_headers(conn))
        if len(requests) == 1:
            status = b'503 Busy' if policy == 'retry' else b'302 Found'
            conn.sendall(
                b'HTTP/1.1 ' + status + b'\r\nContent-Length: 100\r\n'
                b'Location: /next\r\nSet-Cookie: attempt=one; Path=/\r\n\r\nstart'
            )
            assert recv_with_ragged_eof(conn, 1024) == b''
        else:
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok')

    retry = HTTPRetry(total=1, backoff_factor=0) if policy == 'retry' else None
    with LocalServer(serve, connections=2) as server:
        with Session(
            pool=ConnectionPool(), retry=retry, hooks={'after_request': [hooks.append]}
        ) as session:
            with session.get(
                'http://127.0.0.1:%d/start' % server.port, stream=True, timeout=2
            ) as response:
                assert response._body is None
                assert b''.join(response.iter_content()) == b'ok'
                assert session.cookies.get('attempt') == 'one'
    assert len(requests) == 2
    assert b'Cookie: attempt=one' in requests[1]
    assert hooks and all(item is response for item in hooks)


def test_body_failure_after_delivery_does_not_retry_request():
    requests = []

    def serve(conn):
        requests.append(read_headers(conn))
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc')

    with LocalServer(serve) as server:
        with Session(
            pool=ConnectionPool(), retry=HTTPRetry(total=2, backoff_factor=0)
        ) as session:
            with session.get(
                'http://127.0.0.1:%d/' % server.port, stream=True, timeout=2
            ) as response:
                chunks = response.iter_content(3)
                assert next(chunks) == b'abc'
                with pytest.raises(ConnectionError, match='Truncated'):
                    next(chunks)
    assert len(requests) == 1


class MemorySocket:
    def __init__(self, wire):
        self.wire = wire

    def makefile(self, _mode):
        return io.BytesIO(self.wire)


@pytest.mark.parametrize('encoding', ['gzip', 'deflate'])
def test_incremental_decoder_preserves_output_larger_than_read_blocks(encoding):
    body = b'abcd' * 32768
    compressed = gzip.compress(body) if encoding == 'gzip' else zlib.compress(body)
    raw = HTTPResponse(
        MemorySocket(
            (
                'HTTP/1.1 200 OK\r\nContent-Encoding: %s\r\nContent-Length: %d\r\n\r\n'
                % (encoding, len(compressed))
            ).encode()
            + compressed
        )
    )
    raw.handle()
    response = Response(response=raw, stream=True)
    assert b''.join(response.iter_content(127)) == body
    assert response._body is None


def test_concatenated_gzip_members_decode_across_small_reads():
    compressed = gzip.compress(b'first') + gzip.compress(b'second')
    raw = HTTPResponse(
        MemorySocket(
            b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n'
            + b'Content-Length: %d\r\n\r\n' % len(compressed)
            + compressed
        )
    )
    raw.handle()
    assert (
        b''.join(Response(response=raw, stream=True).iter_content(1)) == b'firstsecond'
    )


def test_corrupt_stream_decode_fails_without_returning_raw_bytes():
    raw = HTTPResponse(
        MemorySocket(
            b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 7\r\n\r\ninvalid'
        )
    )
    raw.handle()
    with pytest.raises(ContentDecodingError):
        list(Response(response=raw, stream=True).iter_content(3))


@pytest.mark.parametrize('chunk_size', [1, 7, 1024])
def test_raw_deflate_header_can_coincide_with_a_zlib_header(chunk_size):
    # Legal raw stored block: LEN=156, NLEN=~156, followed by a final empty block.
    compressed = b'\x78\x9c\x00\x63\xff' + b'x' * 156 + b'\x01\x00\x00\xff\xff'
    assert zlib.decompress(compressed, -15) == b'x' * 156
    raw = HTTPResponse(
        MemorySocket(
            b'HTTP/1.1 200 OK\r\nContent-Encoding: deflate\r\n'
            + b'Content-Length: %d\r\n\r\n' % len(compressed)
            + compressed
        )
    )
    raw.handle()
    assert (
        b''.join(Response(response=raw, stream=True).iter_content(chunk_size))
        == b'x' * 156
    )


@pytest.mark.parametrize('status', [200, 503])
@pytest.mark.parametrize('error_type', [RuntimeError, OSError])
def test_failed_response_hook_releases_body_without_retry(status, error_type):
    released, sent = [], []
    raw = HTTPResponse(
        MemorySocket(
            ('HTTP/1.1 %d OK\r\nContent-Length: 6\r\n\r\nabcdef' % status).encode()
        ),
        release=released.append,
    )
    raw.handle()
    request = HttpRequest()
    request.method = 'GET'

    def send(**_kwargs):
        sent.append(True)
        return raw

    def fail(_response):
        raise error_type('hook failure')

    request.send = send
    retry = HTTPRetry(total=1 if status == 200 else 0, backoff_factor=0)
    with Session(
        use_pooling=False, retry=retry, hooks={'after_request': [fail]}
    ) as session:
        with pytest.raises(error_type, match='hook failure'):
            session.send(request, stream=True)
    assert released == [False]
    assert raw.fp is None
    assert len(sent) == 1


def test_brotli_high_expansion_does_not_materialize_the_response():
    size = 32 * 1024 * 1024
    compressed = brotli.compress(b'x' * size, quality=11)
    raw = HTTPResponse(
        MemorySocket(
            b'HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n'
            + b'Content-Length: %d\r\n\r\n' % len(compressed)
            + compressed
        )
    )
    raw.handle()
    response = Response(response=raw, stream=True)
    received = 0
    tracemalloc.start()
    try:
        for chunk in response.iter_content(16384):
            assert chunk.count(b'x') == len(chunk)
            received += len(chunk)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
        response.close()
    assert received == size
    # Python output buffers only; the Brotli native window is separate.
    assert peak < 512 * 1024
