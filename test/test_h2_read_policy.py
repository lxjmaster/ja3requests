"""Request-owned H2 budgets over real conditions, readers and socket writes."""

from concurrent.futures import Future
from contextlib import contextmanager
import queue
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from ja3requests import _sync_timeout
from ja3requests._sync_timeout import UNLIMITED_READ
from ja3requests._upload import UploadSource
from ja3requests.protocol.h2 import multiplex
from ja3requests.protocol.h2.frame import (
    CONNECTION_PREFACE,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_PING,
    FRAME_RST_STREAM,
    FRAME_SETTINGS,
    H2Frame,
    SETTINGS_INITIAL_WINDOW_SIZE,
    SETTINGS_MAX_CONCURRENT_STREAMS,
    build_data_frame,
    build_settings_frame,
    build_window_update_frame,
)
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection
from ja3requests.sockets import _upload
from ja3requests.sockets._upload import _H2WriteGuard
from test.test_h2_streaming import Wire, headers


class Clock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now


def start_call(threads, name, function, *args, **kwargs):
    result = Future()

    def run():
        try:
            result.set_result(function(*args, **kwargs))
        except BaseException as error:
            result.set_exception(error)

    thread = threading.Thread(target=run, name=name, daemon=True)
    threads.append(thread)
    thread.start()
    return result


@contextmanager
def connected(peer_settings=None, withhold_settings=False):
    wire, writes, threads = Wire(), [], []

    def send(data, timeout):
        writes.append((data, timeout))
        wire.send(data)

    conn = H2MultiplexConnection(wire.send, wire.recv, send_with_timeout=send)
    conn.initiate()
    if not withhold_settings:
        wire.feed(build_settings_frame(peer_settings or {}))
        wire.flush()
    try:
        yield conn, wire, writes, threads
    finally:
        for stream_id in list(conn._uploads):
            conn.cancel_stream(stream_id)
        wire.incoming.put(b'')
        conn._reader.join(2)
        assert not conn._reader.is_alive(), 'H2 reader survived cleanup'
        for thread in threads:
            thread.join(2)
            assert not thread.is_alive(), 'request wait survived transport EOF'


def observe_waits(monkeypatch, conn):
    waits = queue.Queue()
    original = conn._wait_event

    def wait(event, timeout):
        waits.put((threading.current_thread().name, timeout))
        return original(event, timeout)

    monkeypatch.setattr(conn, '_wait_event', wait)
    return waits


def next_wait(waits, name):
    while True:
        owner, timeout = waits.get(timeout=1)
        if owner == name:
            return timeout


@pytest.mark.parametrize('timeout, expected', [(UNLIMITED_READ, None), (None, 15)])
@pytest.mark.parametrize('boundary', ['settings', 'capacity'])
def test_request_admission_preserves_unlimited_and_legacy_waits(
    monkeypatch, timeout, expected, boundary
):
    monkeypatch.setattr(_sync_timeout, 'time', Clock())
    with connected(
        peer_settings={SETTINGS_MAX_CONCURRENT_STREAMS: 1},
        withhold_settings=boundary == 'settings',
    ) as (conn, wire, _, threads):
        occupied = None
        if boundary == 'capacity':
            occupied = conn.send_request('GET', 'example.test', '/', timeout=1)
        waits = observe_waits(monkeypatch, conn)
        result = start_call(
            threads,
            'admission',
            conn.send_request,
            'GET',
            'example.test',
            '/',
            timeout=timeout,
        )
        assert next_wait(waits, 'admission') == expected
        assert not result.done()
        if boundary == 'settings':
            wire.feed(build_settings_frame({}))
        else:
            conn.cancel_stream(occupied)
        assert result.result(timeout=1) == (1 if occupied is None else 3)


def test_other_stream_progress_does_not_extend_finite_body_wait(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(_sync_timeout, 'time', clock)
    with connected() as (conn, wire, _, threads):
        unlimited, limited, active = [
            conn.send_request('GET', 'example.test', '/', timeout=1) for _ in range(3)
        ]
        wire.feed(headers(unlimited), headers(limited), headers(active))
        wire.flush()
        waits = observe_waits(monkeypatch, conn)
        indefinite = start_call(
            threads,
            'unlimited',
            conn.read_stream,
            unlimited,
            8,
            timeout=UNLIMITED_READ,
        )
        finite = start_call(
            threads,
            'limited',
            conn.read_stream,
            limited,
            8,
            timeout=5,
        )
        initial = dict(waits.get(timeout=1) for _ in range(2))
        assert initial == {'unlimited': None, 'limited': 5}
        clock.now += 4
        wire.feed(build_data_frame(active, b'progress', end_stream=True))
        wire.flush()
        assert next_wait(waits, 'limited') == 1
        assert conn.read_stream(active, 8, timeout=0) == b'progress'
        clock.now += 2
        wire.flush()
        with pytest.raises(TimeoutError, match='stream timed out'):
            finite.result(timeout=1)
        assert not indefinite.done()
        assert not conn.failed
        wire.feed(build_data_frame(unlimited, b'finish', end_stream=True))
        assert indefinite.result(timeout=1) == b'finish'
        resets = [
            frame.stream_id for frame in wire.sent if frame.type == FRAME_RST_STREAM
        ]
        assert resets == [limited]


@pytest.mark.parametrize('streaming', [False, True])
def test_unlimited_upload_credit_wait_does_not_block_another_stream(
    monkeypatch, streaming
):
    clock = Clock()
    monkeypatch.setattr(_sync_timeout, 'time', clock)
    with connected(peer_settings={SETTINGS_INITIAL_WINDOW_SIZE: 0}) as (
        conn,
        wire,
        _,
        threads,
    ):
        waits = observe_waits(monkeypatch, conn)
        if streaming:
            stream = conn.begin_upload(
                'POST',
                'example.test',
                '/',
                body=UploadSource(iter([b'body'])),
                timeout=UNLIMITED_READ,
            )
            worker = conn._uploads[stream]
        else:
            result = start_call(
                threads,
                'buffered',
                conn.send_request,
                'POST',
                'example.test',
                '/',
                body=b'body',
                timeout=UNLIMITED_READ,
            )
            stream = 1
        assert waits.get(timeout=1)[1] is None
        clock.now += 100
        wire.flush()
        assert waits.get(timeout=1)[1] is None
        active = conn.send_request('GET', 'example.test', '/active', timeout=1)
        wire.feed(headers(active, end=True))
        assert conn.receive_response(active, timeout=1) == ([(':status', '200')], b'')
        wire.feed(build_window_update_frame(stream, 4))
        if streaming:
            worker.thread.join(1)
            assert not worker.thread.is_alive()
            assert conn._streams[stream].error is None
        else:
            assert result.result(timeout=1) == stream
        assert conn._streams[stream].send_done
        assert not conn.failed


@pytest.mark.parametrize(
    'timeout, expected', [(UNLIMITED_READ, None), (None, 15), (5, 5)]
)
def test_collector_keeps_its_original_budget_across_headers_and_body(
    monkeypatch, timeout, expected
):
    clock = Clock()
    monkeypatch.setattr(_sync_timeout, 'time', clock)
    with connected() as (conn, wire, _, threads):
        stream = conn.send_request('GET', 'example.test', '/', timeout=1)
        waits = observe_waits(monkeypatch, conn)
        result = start_call(
            threads,
            'collector',
            conn.receive_response,
            stream,
            timeout=timeout,
        )
        assert next_wait(waits, 'collector') == expected
        clock.now += 100 if expected is None else expected - 1
        wire.feed(headers(stream), build_data_frame(stream, b'first'))
        wire.flush()
        assert next_wait(waits, 'collector') == (None if expected is None else 1)
        clock.now += 2
        if expected is None:
            wire.feed(build_data_frame(stream, b'last', end_stream=True))
            assert result.result(timeout=1) == ([(':status', '200')], b'firstlast')
        else:
            wire.flush()
            with pytest.raises(TimeoutError, match='stream timed out'):
                result.result(timeout=1)
        assert not conn.failed


@pytest.mark.parametrize('timeout', [UNLIMITED_READ, None])
def test_upload_source_none_and_control_frames_keep_independent_budgets(
    monkeypatch, timeout
):
    def unexpected_deadline():
        raise AssertionError('unlimited source created an implicit deadline')

    monkeypatch.setattr(
        _upload,
        'time',
        SimpleNamespace(monotonic=unexpected_deadline, sleep=time.sleep),
    )
    original = multiplex.read_upload_piece
    source_budgets = []

    def read_piece(source, stopped, budget):
        source_budgets.append(budget)
        return original(source, stopped, budget)

    monkeypatch.setattr(multiplex, 'read_upload_piece', read_piece)
    with connected() as (conn, wire, writes, _):
        source = UploadSource(iter([b'body']))
        stream = conn.begin_upload(
            'POST',
            'example.test',
            '/',
            body=source,
            timeout=timeout,
        )
        worker = conn._uploads[stream]
        worker.thread.join(1)
        assert not worker.thread.is_alive()
        wire.flush()
        assert source_budgets == [None, None]
        frames = []
        for data, budget in writes:
            if data != CONNECTION_PREFACE:
                parsed, remaining = H2Frame.parse_all(data)
                assert not remaining
                frames.extend((frame, budget) for frame in parsed)
        application = [
            (frame, budget)
            for frame, budget in frames
            if frame.type in (FRAME_HEADERS, FRAME_DATA)
        ]
        controls = [
            (frame, budget)
            for frame, budget in frames
            if frame.type in (FRAME_SETTINGS, FRAME_PING)
        ]
        assert application and controls
        assert all(budget is timeout for _, budget in application)
        assert all(budget is None for _, budget in controls)
        assert [
            frame.payload for frame, _ in application if frame.type == FRAME_DATA
        ] == [b'body', b'']
        wire.feed(headers(stream, end=True))
        assert conn.receive_response(stream, timeout=1) == ([(':status', '200')], b'')


@pytest.mark.parametrize('unlimited', [False, True])
def test_real_blocked_write_keeps_unlimited_or_expires_and_closes(unlimited):
    writer, reader = socket.socketpair()
    writer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
    entered = threading.Event()

    class ObservedSocket:
        def sendall(self, data):
            entered.set()
            writer.sendall(data)

        def shutdown(self, how):
            writer.shutdown(how)

    guard = _H2WriteGuard(ObservedSocket())
    threads = []
    payload = b'x' * (1 << 20)
    result = start_call(
        threads,
        'writer',
        guard.sendall,
        payload,
        None if unlimited else time.monotonic() + 0.05,
    )
    try:
        assert entered.wait(1)
        if unlimited:
            assert not result.done()
            assert guard._deadline is None
            reader.settimeout(1)
            remaining = len(payload)
            while remaining:
                piece = reader.recv(min(65536, remaining))
                assert piece
                remaining -= len(piece)
            assert result.result(timeout=1) is None
            assert not guard._expired
        else:
            with pytest.raises(TimeoutError, match='write timed out'):
                result.result(timeout=1)
            assert guard._expired
        guard.close()
        with pytest.raises(TimeoutError if guard._expired else ConnectionError):
            guard.sendall(b'closed', None)
    finally:
        guard.close()
        writer.close()
        reader.close()
        for thread in threads:
            thread.join(1)
            assert not thread.is_alive()
        assert not guard.thread.is_alive()
