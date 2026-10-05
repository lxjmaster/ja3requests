"""A failed full read must not turn an unread response into an empty cache."""

import socket
import threading

import pytest

from ja3requests import Session
from ja3requests.exceptions import StreamConsumedError
from ja3requests.pool import ConnectionPool
from test.mock_servers.local import LocalServer, read_headers


def assert_consumed(response):
    """Every public body entry point rejects replay after the original failure."""
    for read in (
        lambda: response.content,
        lambda: response.body,
        lambda: response.text,
        response.json,
        lambda: list(response.iter_content()),
        lambda: list(response.iter_lines()),
    ):
        with pytest.raises(StreamConsumedError):
            read()


@pytest.mark.parametrize(
    'wire',
    [
        b'Content-Length: 6\r\n\r\nabc',
        b'Transfer-Encoding: chunked\r\n\r\n6\r\nabc',
    ],
    ids=['length', 'chunked'],
)
def test_truncated_full_read_cannot_be_replayed_as_empty(wire):
    def serve(conn):
        read_headers(conn)
        conn.sendall(b'HTTP/1.1 200 OK\r\n' + wire)

    with LocalServer(serve) as server:
        with Session(pool=ConnectionPool()) as session:
            with session.get(
                'http://127.0.0.1:%d/' % server.port, stream=True, timeout=2
            ) as response:
                with pytest.raises(ConnectionError, match='Truncated'):
                    _ = response.content
                assert_consumed(response)


def test_timed_out_full_read_preserves_failure_and_rejects_replay():
    release = threading.Event()

    def serve(conn):
        read_headers(conn)
        conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc')
        assert release.wait(3), 'Client did not finish the failed response'

    with LocalServer(serve) as server:
        try:
            with Session(pool=ConnectionPool()) as session:
                with session.get(
                    'http://127.0.0.1:%d/' % server.port,
                    stream=True,
                    timeout=(2, 0.05),
                ) as response:
                    with pytest.raises(socket.timeout):
                        _ = response.content
                    assert_consumed(response)
        finally:
            release.set()
