"""Network evidence for incremental HTTP/1.1 delivery and response ownership."""

import socket
import threading
import zlib
from concurrent.futures import ThreadPoolExecutor

import brotli
import pytest

from ja3requests import Session
from ja3requests.exceptions import RequestException
from ja3requests.pool import ConnectionPool
from test.mock_servers.local import (
    LocalServer,
    read_headers,
    recv_with_ragged_eof,
    serve_socks,
)


class GatedBody:
    """Withhold all body bytes until headers return, then withhold the tail."""

    def __init__(self, headers, first, tail, finish=None):
        self.headers = headers
        self.first = first
        self.tail = tail
        self.finish = finish
        self.headers_sent = threading.Event()
        self.allow_first = threading.Event()
        self.allow_tail = threading.Event()
        self.tail_sent = threading.Event()
        self.requests = []

    def release(self):
        self.allow_first.set()
        self.allow_tail.set()

    def serve(self, conn):
        self.requests.append(read_headers(conn))
        conn.sendall(b"HTTP/1.1 200 OK\r\n" + self.headers + b"\r\n")
        self.headers_sent.set()
        assert self.allow_first.wait(5), "Client did not return at response headers"
        conn.sendall(self.first)
        assert self.allow_tail.wait(5), "Client did not yield the available prefix"
        conn.sendall(self.tail)
        self.tail_sent.set()
        if self.finish is not None:
            self.finish(conn)


def framed_gate(framing, first=b"alpha", tail=b"omega", finish=None):
    if framing == "length":
        headers = b"Content-Length: %d\r\n" % (len(first) + len(tail))
    elif framing == "chunked":
        headers = b"Transfer-Encoding: chunked\r\n"
        first = b"%x\r\n" % len(first) + first + b"\r\n"
        tail = b"%x\r\n" % len(tail) + tail + b"\r\n0\r\n\r\n"
    else:
        headers = b"Connection: close\r\n"
    return GatedBody(headers, first, tail, finish=finish)


def assert_gated_delivery(session, url, gate, expected, lines=False, **kwargs):
    """Event order proves delivery; finite waits only bound a failed test."""
    response = None
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            request = executor.submit(
                session.get, url, stream=True, timeout=3, **kwargs
            )
            try:
                assert gate.headers_sent.wait(3), "Peer did not send response headers"
                response = request.result(timeout=2)
                assert response.status_code == 200
                assert not gate.allow_first.is_set()
                iterator = (
                    response.iter_lines(chunk_size=3)
                    if lines
                    else response.iter_content(chunk_size=3)
                )
                gate.allow_first.set()
                first = executor.submit(next, iterator).result(timeout=2)
                assert first
                assert not gate.tail_sent.is_set()
                if lines:
                    assert first == expected[0]
                else:
                    assert len(first) <= 3
                    assert expected.startswith(first)
                gate.allow_tail.set()
                if lines:
                    assert [first] + list(iterator) == expected
                else:
                    assert first + b"".join(iterator) == expected
            finally:
                gate.release()
                if response is None:
                    try:
                        response = request.result(timeout=4)
                    except Exception:
                        # Preserve the original assertion while joining the worker.
                        pass
    finally:
        if response is not None:
            response.close()
    return response


def compressed_gate(encoding):
    first, tail = b"alpha" * 40, b"omega" * 40
    if encoding == "br":
        compressor = brotli.Compressor()
        prefix = compressor.process(first) + compressor.flush()
        suffix = compressor.process(tail) + compressor.finish()
    else:
        bits = {"gzip": 31, "deflate": 15, "raw-deflate": -15}[encoding]
        compressor = zlib.compressobj(wbits=bits)
        prefix = compressor.compress(first) + compressor.flush(zlib.Z_SYNC_FLUSH)
        suffix = compressor.compress(tail) + compressor.flush(zlib.Z_FINISH)
    wire_encoding = "deflate" if encoding == "raw-deflate" else encoding
    headers = (
        "Content-Length: %d\r\nContent-Encoding: %s\r\n"
        % (len(prefix) + len(suffix), wire_encoding)
    ).encode("ascii")
    return GatedBody(headers, prefix, suffix), first + tail


def serve_reusable_response(conn, observed):
    observed.append(read_headers(conn).split(b"\r\n", 1)[0])
    conn.sendall(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"3\r\none\r\n3\r\ntwo\r\n0\r\nX-Finished: yes\r\n\r\n"
    )
    observed.append(read_headers(conn).split(b"\r\n", 1)[0])
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")


def assert_complete_then_reuse(session, url):
    response = session.get(url + "/first", stream=True, timeout=3)
    try:
        assert b"".join(response.iter_content(chunk_size=2)) == b"onetwo"
    finally:
        response.close()
        response.close()
    response = session.get(url + "/second", timeout=3)
    try:
        assert response.content == b"ok"
    finally:
        response.close()


def assert_prefix(iterator, expected):
    """Accept short reads while requiring nonempty, correctly ordered chunks."""
    received = b""
    while len(received) < len(expected):
        chunk = next(iterator)
        assert chunk
        received += chunk
        assert expected.startswith(received)
    assert received == expected


class EarlyClosePeer:
    def __init__(self):
        self.requests = []

    def serve(self, conn):
        self.requests.append(read_headers(conn).split(b"\r\n", 1)[0])
        if len(self.requests) == 1:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhead")
            assert (
                recv_with_ragged_eof(conn, 4096) == b""
            ), "The unread connection was reused instead of discarded"
        else:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")


def assert_close_then_reconnect(session, url, consume_prefix):
    response = session.get(url + "/first", stream=True, timeout=3)
    try:
        if consume_prefix:
            assert_prefix(response.iter_content(chunk_size=4), b"head")
    finally:
        response.close()
        response.close()
    response = session.get(url + "/second", timeout=3)
    try:
        assert response.content == b"ok"
    finally:
        response.close()


@pytest.mark.parametrize("framing", ["length", "chunked", "close"])
def test_http_body_is_available_before_the_peer_sends_its_tail(framing):
    gate = framed_gate(framing)
    hooks = []
    with LocalServer(gate.serve) as server:
        with Session(
            pool=ConnectionPool(), hooks={"after_request": [hooks.append]}
        ) as session:
            response = assert_gated_delivery(
                session, "http://127.0.0.1:%d/stream" % server.port, gate, b"alphaomega"
            )
            assert hooks == [response]


@pytest.mark.parametrize("encoding", ["gzip", "deflate", "raw-deflate", "br"])
def test_http_decodes_compressed_prefix_before_the_peer_sends_its_tail(encoding):
    gate, expected = compressed_gate(encoding)
    with LocalServer(gate.serve) as server:
        with Session(pool=ConnectionPool()) as session:
            assert_gated_delivery(
                session, "http://127.0.0.1:%d/stream" % server.port, gate, expected
            )


def test_http_lines_are_incremental_and_handle_split_crlf():
    gate = framed_gate("length", b"first\r\nsecond\r", b"\nlast")
    with LocalServer(gate.serve) as server:
        with Session(pool=ConnectionPool()) as session:
            assert_gated_delivery(
                session,
                "http://127.0.0.1:%d/stream" % server.port,
                gate,
                [b"first", b"second", b"last"],
                lines=True,
            )


def test_http_complete_chunked_body_and_trailers_allow_connection_reuse():
    observed = []
    with LocalServer(lambda conn: serve_reusable_response(conn, observed)) as server:
        with Session(pool=ConnectionPool()) as session:
            assert_complete_then_reuse(session, "http://127.0.0.1:%d" % server.port)
    assert observed == [b"GET /first HTTP/1.1", b"GET /second HTTP/1.1"]


@pytest.mark.parametrize("consume_prefix", [False, True])
def test_http_early_close_discards_unread_connection(consume_prefix):
    peer = EarlyClosePeer()
    with LocalServer(peer.serve, connections=2) as server:
        with Session(pool=ConnectionPool()) as session:
            assert_close_then_reconnect(
                session, "http://127.0.0.1:%d" % server.port, consume_prefix
            )
    assert peer.requests == [b"GET /first HTTP/1.1", b"GET /second HTTP/1.1"]


@pytest.mark.parametrize(
    "wire",
    [
        b"Content-Length: 6\r\n\r\nabc",
        b"Transfer-Encoding: chunked\r\n\r\n6\r\nabc",
    ],
    ids=["length", "chunked"],
)
def test_http_truncated_stream_raises_instead_of_returning_partial_success(wire):
    def serve(conn):
        read_headers(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\n" + wire)

    with LocalServer(serve) as server:
        with Session(pool=ConnectionPool()) as session:
            response = session.get(
                "http://127.0.0.1:%d/stream" % server.port, stream=True, timeout=2
            )
            try:
                with pytest.raises(ConnectionError):
                    list(response.iter_content(chunk_size=2))
            finally:
                response.close()


def test_http_body_read_preserves_socket_timeout():
    release = threading.Event()

    def serve(conn):
        read_headers(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc")
        assert release.wait(5), "Timed-out response was not closed"

    with LocalServer(serve) as server:
        try:
            with Session(pool=ConnectionPool()) as session:
                response = session.get(
                    "http://127.0.0.1:%d/stream" % server.port,
                    stream=True,
                    timeout=(3, 0.2),
                )
                try:
                    chunks = response.iter_content(chunk_size=3)
                    assert_prefix(chunks, b"abc")
                    with pytest.raises(socket.timeout):
                        next(chunks)
                finally:
                    response.close()
        finally:
            release.set()


def test_http_incomplete_gzip_stream_reports_decoding_failure():
    compressor = zlib.compressobj(wbits=31)
    body = (compressor.compress(b"payload") + compressor.flush())[:-4]

    def serve(conn):
        read_headers(conn)
        conn.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n"
            + b"Content-Length: %d\r\n\r\n" % len(body)
            + body
        )

    with LocalServer(serve) as server:
        with Session(pool=ConnectionPool()) as session:
            response = session.get(
                "http://127.0.0.1:%d/stream" % server.port, stream=True, timeout=2
            )
            try:
                with pytest.raises(RequestException) as failure:
                    list(response.iter_content(chunk_size=3))
                assert type(failure.value).__name__ == "ContentDecodingError"
            finally:
                response.close()


def test_http_stream_iteration_does_not_silently_replay_or_cache_the_body():
    def serve(conn):
        read_headers(conn)
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabcdef")

    with LocalServer(serve) as server:
        with Session(pool=ConnectionPool()) as session:
            response = session.get(
                "http://127.0.0.1:%d/stream" % server.port, stream=True, timeout=2
            )
            try:
                chunks = response.iter_content(chunk_size=1)
                assert next(chunks) == b"a"
                with pytest.raises(RuntimeError) as failure:
                    _ = response.content
                assert isinstance(failure.value, RequestException)
                assert type(failure.value).__name__ == "StreamConsumedError"
                assert b"".join(chunks) == b"bcdef"
                with pytest.raises(RuntimeError):
                    _ = response.content
            finally:
                response.close()


def test_http_connect_proxy_preserves_incremental_body_delivery():
    gate = framed_gate("length")
    tunnels = []

    def serve(conn):
        tunnels.append(read_headers(conn))
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        gate.serve(conn)

    with LocalServer(serve) as server:
        with Session(pool=ConnectionPool()) as session:
            assert_gated_delivery(
                session,
                "http://stream.invalid/stream",
                gate,
                b"alphaomega",
                proxies={"http": "http://127.0.0.1:%d" % server.port},
            )
    assert tunnels[0].startswith(b"CONNECT stream.invalid:80 HTTP/1.1\r\n")


@pytest.mark.parametrize("version", [4, 5], ids=["socks4a", "socks5"])
def test_http_socks_proxy_preserves_incremental_body_delivery(version):
    gate = framed_gate("chunked")
    observed = {}

    def serve(conn):
        serve_socks(conn, observed, version=version, tunnel_handler=gate.serve)

    with LocalServer(serve) as server:
        with Session(pool=ConnectionPool()) as session:
            assert_gated_delivery(
                session,
                "http://stream.invalid/stream",
                gate,
                b"alphaomega",
                proxies={"http": "socks%d://127.0.0.1:%d" % (version, server.port)},
            )
    assert observed["host"] == b"stream.invalid"
    assert observed["port"] == 80
