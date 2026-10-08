"""Public synchronous uploads against independent, bounded loopback peers."""

import io
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

import ja3requests
from ja3requests import Session
from ja3requests.exceptions import InvalidData, StreamConsumedError
from ja3requests.pool import ConnectionPool
from ja3requests.retry import HTTPRetry
from ja3requests._upload import UploadSource
from ja3requests.sockets import _upload as upload_transport
from test.mock_servers.local import LocalServer, read_exact, read_headers, serve_socks


def read_upload(conn):
    raw = read_headers(conn)
    fields = dict(line.split(b':', 1) for line in raw.split(b'\r\n')[1:-2])
    fields = {key.lower(): value.strip() for key, value in fields.items()}
    if b'content-length' in fields:
        body = read_exact(conn, int(fields[b'content-length']))
    else:
        assert fields[b'transfer-encoding'] == b'chunked'
        chunks = []
        while True:
            line = b''
            while not line.endswith(b'\r\n'):
                line += read_exact(conn, 1)
            size = int(line, 16)
            if not size:
                assert read_exact(conn, 2) == b'\r\n'
                break
            chunks.append(read_exact(conn, size))
            assert read_exact(conn, 2) == b'\r\n'
        body = b''.join(chunks)
    return raw, body


def reply(conn, code=200):
    conn.sendall(('HTTP/1.1 %d Result\r\nContent-Length: 2\r\n\r\nok' % code).encode())


def slow_upload_source():
    """The whole body outlasts 250 ms while every source pull stays below it."""
    for _ in range(8):
        time.sleep(0.05)
        yield b'piece'


@pytest.mark.parametrize('route', ['direct', 'connect', 'socks5'])
def test_upload_progress_outlives_response_read_timeout(route):
    seen = []

    def application(conn):
        seen.append(read_upload(conn)[1])
        reply(conn)

    def serve(conn):
        if route == 'connect':
            assert read_headers(conn).startswith(b'CONNECT ')
            conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
        if route == 'socks5':
            serve_socks(conn, {}, tunnel_handler=application)
        else:
            application(conn)

    with LocalServer(serve) as peer, Session(use_pooling=False) as session:
        proxies = (
            None
            if route == 'direct'
            else {
                'http': '%s://127.0.0.1:%d'
                % ('http' if route == 'connect' else route, peer.port)
            }
        )
        response = session.put(
            'http://127.0.0.1:%d/' % peer.port,
            data=slow_upload_source(),
            proxies=proxies,
            timeout=(2, 0.25),
        )
        assert response.content == b'ok'
        assert not session._uploads
    assert seen == [b'piece' * 8]


def test_finished_upload_still_times_out_waiting_for_response():
    seen = []

    def serve(conn):
        seen.append(read_upload(conn)[1])
        while conn.recv(4096):
            pass

    with LocalServer(serve) as peer, Session(use_pooling=False) as session:
        with pytest.raises(TimeoutError):
            session.put(
                'http://127.0.0.1:%d/' % peer.port,
                data=iter([b'body']),
                timeout=(2, 0.2),
            )
        assert not session._uploads
    assert seen == [b'body']


@pytest.mark.parametrize('source_kind', ['file', 'iterator', 'declared'])
@pytest.mark.parametrize('route', ['direct', 'connect', 'socks5'])
def test_public_fixed_and_chunked_uploads_and_borrowed_ownership(source_kind, route):
    seen = []

    def application(conn):
        seen.append(read_upload(conn))
        reply(conn)

    def serve(conn):
        if route == 'connect':
            assert read_headers(conn).startswith(b'CONNECT ')
            conn.sendall(b'HTTP/1.1 200 Tunnel\r\n\r\n')
        if route == 'socks5':
            serve_socks(conn, {}, tunnel_handler=application)
        else:
            application(conn)

    source = (
        io.BytesIO(b'skip-payload')
        if source_kind == 'file'
        else iter([b'pay', b'', b'load'])
    )
    if source_kind == 'file':
        source.seek(5)
    with LocalServer(serve) as peer:
        proxies = (
            None
            if route == 'direct'
            else {
                'http': '%s://127.0.0.1:%d'
                % ('http' if route == 'connect' else route, peer.port)
            }
        )
        with Session(pool=ConnectionPool()) as session:
            response = session.put(
                'http://127.0.0.1:%d/upload' % peer.port,
                data=source,
                headers={'Content-Length': '7'} if source_kind == 'declared' else None,
                proxies=proxies,
                timeout=2,
            )
            assert response.content == b'ok'
            assert not session._uploads
            assert response.request.data._closed
    assert seen[0][1] == b'payload'
    assert b'application/x-www-form-urlencoded' not in seen[0][0]
    assert (b'Transfer-Encoding: chunked' in seen[0][0]) is (source_kind == 'iterator')
    if source_kind == 'file':
        assert not source.closed


def test_first_body_bytes_arrive_before_source_eof():
    received = threading.Event()
    pulled = []

    def source():
        yield b'prefix'
        assert received.wait(2), 'peer never saw the first piece'
        pulled.append('tail')
        yield b'tail'

    def serve(conn):
        assert b'Transfer-Encoding: chunked' in read_headers(conn)
        assert read_exact(conn, len(b'6\r\nprefix\r\n')) == b'6\r\nprefix\r\n'
        received.set()
        assert (
            read_exact(conn, len(b'4\r\ntail\r\n0\r\n\r\n'))
            == b'4\r\ntail\r\n0\r\n\r\n'
        )
        reply(conn)

    with LocalServer(serve) as peer, Session(use_pooling=False) as session:
        assert (
            session.post(
                'http://127.0.0.1:%d/' % peer.port, data=source(), timeout=2
            ).content
            == b'ok'
        )
    assert pulled == ['tail']


@pytest.mark.parametrize(
    'headers',
    [
        {'Content-Length': '-1'},
        {'Content-Length': 'x'},
        {'Content-Length': '1', 'content-length': '1'},
        {'Transfer-Encoding': 'chunked'},
        {'Content-Length': '1.0'},
        {1: 'invalid header name'},
    ],
)
def test_bad_framing_rejected_without_consuming_or_connecting(headers):
    pulled = []

    def source():
        pulled.append(True)
        yield b'x'

    with Session(use_pooling=False) as session:
        with pytest.raises(InvalidData):
            session.post('http://127.0.0.1:1/', data=source(), headers=headers)
    assert pulled == []


@pytest.mark.parametrize('kind', ['short', 'long', 'failure', 'text'])
def test_source_failures_keep_error_type_and_never_retry(kind):
    pulls = []

    def source():
        pulls.append(True)
        if kind == 'failure':
            raise OSError('source failed')
        yield 'text' if kind == 'text' else (b'x' if kind == 'short' else b'xxxx')

    def serve(conn):
        read_headers(conn)
        while conn.recv(1024):
            pass

    with LocalServer(serve) as peer, Session(
        use_pooling=False, retry=HTTPRetry(total=2)
    ) as session:
        with pytest.raises(InvalidData):
            session.put(
                'http://127.0.0.1:%d/' % peer.port,
                data=source(),
                headers={'Content-Length': '2'},
                timeout=2,
            )
        assert not session._uploads
    assert pulls == [True]


@pytest.mark.parametrize('replayable', [False, True])
def test_retry_rewinds_file_or_rejects_consumed_iterator(replayable):
    seen = []
    source = io.BytesIO(b'prefix-body') if replayable else iter([b'body'])
    if replayable:
        source.seek(7)

    def serve(conn):
        seen.append(read_upload(conn)[1])
        reply(conn, 503 if len(seen) == 1 else 200)

    with LocalServer(serve, connections=2 if replayable else 1) as peer:
        with Session(
            use_pooling=False, retry=HTTPRetry(total=1, backoff_factor=0)
        ) as session:
            call = lambda: session.put(
                'http://127.0.0.1:%d/' % peer.port, data=source, timeout=2
            )
            if replayable:
                assert call().content == b'ok'
            else:
                with pytest.raises(StreamConsumedError):
                    call()
    assert seen == [b'body'] * (2 if replayable else 1)


def test_early_response_returns_headers_and_close_joins_source_worker():
    entered, release, response_headers = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    pulls = []

    def source():
        yield b'prefix'
        entered.set()
        assert release.wait(3)
        pulls.append('late')
        yield b'discarded'
        pulls.append('must-not-pull')

    def serve(conn):
        read_headers(conn)
        assert read_exact(conn, 11) == b'6\r\nprefix\r\n'
        assert entered.wait(2)
        reply(conn, 413)
        response_headers.set()

    with LocalServer(serve) as peer, Session(use_pooling=False) as session:
        response = session.post(
            'http://127.0.0.1:%d/' % peer.port, data=source(), stream=True, timeout=2
        )
        assert response.status_code == 413 and response_headers.wait(1)
        with ThreadPoolExecutor(max_workers=1) as executor:
            closing = executor.submit(session.close)
            try:
                assert not closing.done()
            finally:
                release.set()
            closing.result(timeout=2)
        response.close()
        assert not session._uploads
        assert response.request.data._closed
    assert pulls == ['late']


@pytest.mark.parametrize('finish', ['consume', 'close', 'eager'])
def test_module_helper_keeps_session_until_stream_response_release(monkeypatch, finish):
    sessions = []

    class ObservedSession(Session):
        def __init__(self):
            super().__init__(use_pooling=False)
            self.close_calls = 0
            sessions.append(self)

        def close(self):
            self.close_calls += 1
            super().close()

    monkeypatch.setattr(ja3requests, 'Session', ObservedSession)
    source = io.BytesIO(b'upload')

    def serve(conn):
        assert read_upload(conn)[1] == b'upload'
        reply(conn)

    with LocalServer(serve) as peer:
        response = ja3requests.post(
            'http://127.0.0.1:%d/' % peer.port,
            data=source,
            stream=finish != 'eager',
            timeout=2,
        )
        session = sessions[0]
        if finish != 'eager':
            assert session.close_calls == 0
            assert session._uploads
        if finish == 'close':
            response.close()
        else:
            assert response.content == b'ok'
        assert session.close_calls == 1
        assert not session._uploads
        assert response.request.data._closed
        assert response.response._release is None
    assert not source.closed


def test_module_helper_closes_failed_session(monkeypatch):
    sessions = []

    class ObservedSession(Session):
        def close(self):
            sessions.append(self)
            super().close()

    monkeypatch.setattr(ja3requests, 'Session', ObservedSession)
    source = io.BytesIO(b'body')
    with pytest.raises(InvalidData, match='length'):
        ja3requests.post(
            'http://127.0.0.1:1/',
            data=source,
            headers={'Content-Length': '1'},
            stream=True,
        )
    assert len(sessions) == 1
    assert not source.closed and source.tell() == 0


@pytest.mark.parametrize('status', [307, 308])
def test_sync_body_preserving_status_keeps_existing_bodyless_get_policy(status):
    seen = []

    def serve(conn):
        if not seen:
            seen.append(read_upload(conn)[0])
            conn.sendall(
                (
                    'HTTP/1.1 %d Redirect\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n'
                    % status
                ).encode()
            )
        else:
            seen.append(read_headers(conn))
            reply(conn)

    with LocalServer(serve, connections=2) as peer, Session(
        use_pooling=False
    ) as session:
        response = session.post(
            'http://127.0.0.1:%d/upload' % peer.port,
            data=iter([b'body']),
            timeout=2,
        )
        assert response.content == b'ok'
        assert not session._uploads
    assert seen[0].startswith(b'POST /upload ')
    assert seen[1].startswith(b'GET /next ')
    assert b'Content-Length:' not in seen[1]
    assert b'Transfer-Encoding:' not in seen[1]


def test_before_request_hook_selects_source_before_preparation():
    borrowed = io.BytesIO(b'new body')
    old_pulls = []

    def old_source():
        old_pulls.append(True)
        yield b'old body'

    def replace(request):
        request.data = borrowed

    def serve(conn):
        assert read_upload(conn)[1] == b'new body'
        reply(conn)

    with LocalServer(serve) as peer, Session(
        use_pooling=False, hooks={'before_request': [replace]}
    ) as session:
        response = session.post(
            'http://127.0.0.1:%d/' % peer.port,
            data=old_source(),
            timeout=2,
        )
        assert response.content == b'ok'
        assert response.request.data._closed
    assert not old_pulls and not borrowed.closed


def test_explicit_file_length_mismatch_is_preconnect_and_unconsumed(monkeypatch):
    def reject_read(size=-1):
        raise AssertionError('length validation consumed file data')

    source = io.BytesIO(b'prefix-data')
    monkeypatch.setattr(source, 'read', reject_read)
    source.seek(7)
    with Session(use_pooling=False) as session:
        with pytest.raises(InvalidData, match='length'):
            session.put(
                'http://127.0.0.1:1/',
                data=source,
                headers={'Content-Length': '3'},
                timeout=1,
            )
    assert source.tell() == 7 and not source.closed


def test_generated_upload_python_memory_does_not_grow_with_total_size():
    def measure(pieces):
        length = pieces * 65536
        pulls = []

        def source():
            for _ in range(pieces):
                pulls.append(True)
                yield b'x' * 65536

        def serve(conn):
            assert ('Content-Length: %d\r\n' % length).encode() in read_headers(conn)
            remaining = length
            while remaining:
                size = min(65536, remaining)
                assert read_exact(conn, size) == b'x' * size
                remaining -= size
            reply(conn)

        tracemalloc.start()
        try:
            with LocalServer(serve) as peer, Session(use_pooling=False) as session:
                response = session.put(
                    'http://127.0.0.1:%d/' % peer.port,
                    data=source(),
                    headers={'Content-Length': str(length)},
                    timeout=2,
                )
                assert response.content == b'ok'
                assert response.request.data._pending is None
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        assert len(pulls) == pieces
        return peak

    small, large = measure(16), measure(128)
    # Eight times the generated upload size may add scheduler/test metadata,
    # but must not retain the additional seven MiB in library Python buffers.
    assert large < small + 512 * 1024


@pytest.mark.parametrize('early_response', [False, True])
def test_empty_chunks_stop_at_timeout_or_final_http1_response(early_response):
    entered, safety_stop = threading.Event(), threading.Event()
    owners, requests = [], []

    def source():
        while not safety_stop.is_set():
            entered.set()
            yield b''

    def serve(conn):
        read_headers(conn)
        assert entered.wait(2)
        if early_response:
            reply(conn, 413)
        else:
            while conn.recv(4096):
                pass

    with LocalServer(serve) as peer, Session(
        use_pooling=False,
        hooks={'before_request': [lambda request: requests.append(request)]},
    ) as session:
        original_register = session._register_upload

        def register(owner):
            owners.append(owner)
            return original_register(owner)

        session._register_upload = register
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(
                session.post,
                'http://127.0.0.1:%d/' % peer.port,
                data=source(),
                timeout=1 if early_response else 0.1,
            )
            try:
                if early_response:
                    response = result.result(timeout=2)
                    assert response.status_code == 413 and response.content == b'ok'
                else:
                    with pytest.raises(OSError):
                        result.result(timeout=2)
                assert result.done(), 'empty chunks prevented the worker from stopping'
                assert not owners[0].worker.is_alive()
                assert requests[0].data._closed
                assert not session._uploads
            finally:
                safety_stop.set()


def test_unspecified_source_timeout_adds_no_implicit_deadline(monkeypatch):
    def no_clock():
        raise AssertionError('unlimited source progress unexpectedly read a deadline')

    monkeypatch.setattr(
        upload_transport,
        'time',
        SimpleNamespace(
            monotonic=no_clock,
            sleep=lambda delay: None,
        ),
    )
    source = UploadSource(iter([b'', b'', b'body']))
    assert (
        upload_transport.read_upload_piece(source, threading.Event(), None) == b'body'
    )
    source.close_owned()


@pytest.mark.parametrize('stopped', [False, True])
def test_returned_source_piece_observes_elapsed_deadline_or_stop(monkeypatch, stopped):
    now = [0]
    stop = threading.Event()
    monkeypatch.setattr(
        upload_transport,
        'time',
        SimpleNamespace(
            monotonic=lambda: now[0],
            sleep=lambda delay: None,
        ),
    )

    def chunks():
        if stopped:
            stop.set()
        else:
            now[0] = 2
        yield b'late source result'

    source = UploadSource(chunks())
    with pytest.raises(StreamConsumedError if stopped else TimeoutError):
        upload_transport.read_upload_piece(source, stop, 1)
    source.close_owned()


def test_stop_while_yielding_control_prevents_next_source_pull(monkeypatch):
    stop = threading.Event()
    pulled = []
    monkeypatch.setattr(
        upload_transport,
        'time',
        SimpleNamespace(
            monotonic=lambda: 0,
            sleep=lambda delay: stop.set(),
        ),
    )

    def chunks():
        pulled.append(True)
        yield b'must-not-be-pulled'

    source = UploadSource(chunks())
    with pytest.raises(StreamConsumedError):
        upload_transport.read_upload_piece(source, stop, None)
    assert not pulled
    source.close_owned()
