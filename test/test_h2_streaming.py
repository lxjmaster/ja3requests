"""Incremental HTTP/2 consumption, receive credit, and stream isolation."""

from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
import queue
import threading
import time

import pytest

from ja3requests.protocol.h2.frame import (
    CONNECTION_PREFACE,
    FLAG_ACK,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FLAG_PADDED,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_PING,
    FRAME_RST_STREAM,
    FRAME_WINDOW_UPDATE,
    H2Frame,
    SETTINGS_INITIAL_WINDOW_SIZE,
    build_data_frame,
    build_goaway_frame,
    build_rst_stream_frame,
    build_settings_frame,
    build_window_update_frame,
)
from ja3requests.protocol.h2.hpack import HPACKEncoder
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection, H2StreamError


class Wire:
    """Bounded fake transport using the real multiplex reader thread."""

    def __init__(self):
        self.incoming = queue.Queue()
        self.sent = []
        self.condition = threading.Condition()
        self.ping = 0

    def send(self, raw):
        if raw == CONNECTION_PREFACE:
            return
        frames, remaining = H2Frame.parse_all(raw)
        assert not remaining
        with self.condition:
            self.sent.extend(frames)
            self.condition.notify_all()

    def recv(self, _size):
        return self.incoming.get(timeout=2)

    def feed(self, *frames):
        for frame in frames:
            self.incoming.put(frame.serialize())

    def flush(self):
        self.ping += 1
        payload = self.ping.to_bytes(8, 'big')
        self.feed(H2Frame(FRAME_PING, 0, 0, payload))
        deadline = time.monotonic() + 2
        with self.condition:
            while not any(
                frame.type == FRAME_PING
                and frame.flags & FLAG_ACK
                and frame.payload == payload
                for frame in self.sent
            ):
                remaining = deadline - time.monotonic()
                assert remaining > 0, "Reader did not acknowledge the frame barrier"
                self.condition.wait(remaining)

    def updates(self, stream_id):
        with self.condition:
            return [
                int.from_bytes(frame.payload, 'big')
                for frame in self.sent
                if frame.type == FRAME_WINDOW_UPDATE and frame.stream_id == stream_id
            ]


@contextmanager
def connected(window=8, peer_settings=None):
    wire = Wire()
    conn = H2MultiplexConnection(
        wire.send, wire.recv, settings={SETTINGS_INITIAL_WINDOW_SIZE: window}
    )
    conn.initiate()
    wire.feed(build_settings_frame(peer_settings or {}))
    try:
        yield conn, wire
    finally:
        wire.incoming.put(b'')
        conn._reader.join(2)
        assert not conn._reader.is_alive(), "HTTP/2 reader did not terminate"


def request(conn):
    return conn.send_request('GET', 'example.test', '/', timeout=1)


def headers(stream_id, end=False):
    flags = FLAG_END_HEADERS | (FLAG_END_STREAM if end else 0)
    return H2Frame(FRAME_HEADERS, flags, stream_id, b'\x88')


def test_headers_and_available_bytes_do_not_wait_for_end_stream():
    with connected() as (conn, wire):
        stream = request(conn)
        wire.feed(headers(stream))
        assert conn.receive_headers(stream, timeout=1) == [(':status', '200')]
        assert not conn._streams[stream].done
        wire.feed(build_data_frame(stream, b'abcde'))
        wire.flush()
        assert wire.updates(stream) == []
        assert conn.read_stream(stream, 3, timeout=0) == b'abc'
        assert wire.updates(stream) == [3]
        assert conn.read_stream(stream, 100, timeout=0) == b'de'
        assert conn._buffered_bytes == 0
        wire.feed(build_data_frame(stream, b'end', end_stream=True))
        assert conn.read_stream(stream, 100, timeout=1) == b'end'
        assert conn.read_stream(stream, 100, timeout=0) == b''
        assert stream not in conn._streams


@pytest.mark.parametrize('finish_upload', ['credit', 'reset', 'cancel'])
def test_half_closed_upload_keeps_independent_send_state(finish_upload):
    with connected(peer_settings={SETTINGS_INITIAL_WINDOW_SIZE: 0}) as (conn, wire):
        with ThreadPoolExecutor(max_workers=1) as executor:
            upload = executor.submit(
                conn.send_request,
                'POST',
                'example.test',
                '/',
                body=b'upload',
                timeout=1,
            )
            with wire.condition:
                assert wire.condition.wait_for(
                    lambda: any(frame.type == FRAME_HEADERS for frame in wire.sent),
                    timeout=1,
                )
            wire.feed(headers(1), build_data_frame(1, b'result', end_stream=True))
            wire.flush()
            assert conn._streams[1].done and not conn._streams[1].send_done
            assert not upload.done()

            if finish_upload == 'credit':
                wire.feed(build_window_update_frame(1, 6))
            elif finish_upload == 'reset':
                wire.feed(build_rst_stream_frame(1, 0))
            else:
                conn.cancel_stream(1)
            if finish_upload == 'cancel':
                with pytest.raises(H2StreamError):
                    upload.result(timeout=1)
            else:
                assert upload.result(timeout=1) == 1
                assert conn.receive_response(1, timeout=1) == (
                    [(':status', '200')],
                    b'result',
                )
            sent_data = [frame for frame in wire.sent if frame.type == FRAME_DATA]
            assert [frame.payload for frame in sent_data] == (
                [b'upload'] if finish_upload == 'credit' else []
            )
            resets = [frame for frame in wire.sent if frame.type == FRAME_RST_STREAM]
            assert len(resets) == (1 if finish_upload == 'cancel' else 0)
            assert request(conn) == 3
            assert not conn.failed


def test_paused_stream_stays_bounded_while_other_stream_progresses():
    with connected() as (conn, wire):
        paused, active = request(conn), request(conn)
        wire.feed(headers(paused), headers(active), build_data_frame(paused, b'p' * 8))
        wire.flush()
        assert conn._streams[paused].receive_window == 0
        assert wire.updates(paused) == []
        for index in range(4):
            wire.feed(
                build_data_frame(active, bytes([index]) * 8, end_stream=index == 3)
            )
            assert conn.read_stream(active, 8, timeout=1) == bytes([index]) * 8
            assert len(conn._streams[paused].body) == 8
            assert conn._buffered_bytes <= 16
        assert conn.read_stream(active, 8, timeout=0) == b''
        assert wire.updates(active) == [8, 8, 8]
        assert wire.updates(paused) == []
        conn.cancel_stream(paused)
        assert conn._buffered_bytes == 0
        assert not conn.failed


def test_connection_budget_limits_credit_and_cancellation_releases_it():
    window = 65535
    with connected(window=window) as (conn, wire):
        first, second, active = request(conn), request(conn), request(conn)
        wire.feed(headers(first), headers(second), headers(active))
        for stream in (first, second):
            for offset in range(0, window, 16384):
                wire.feed(build_data_frame(stream, b'x' * min(16384, window - offset)))
        wire.flush()
        assert conn._buffered_bytes == conn.receive_buffer_limit == 2 * window
        assert conn._connection_receive_window == 0
        assert sum(wire.updates(0)) == window
        assert wire.updates(first) == wire.updates(second) == []

        conn.cancel_stream(first)
        assert conn._buffered_bytes == window
        assert conn._connection_receive_window == window
        assert sum(wire.updates(0)) == 2 * window
        wire.feed(build_data_frame(active, b'ok', end_stream=True))
        assert conn.receive_response(active, timeout=1) == ([(':status', '200')], b'ok')
        assert len(conn._streams[second].body) == window
        conn.cancel_stream(second)
        assert conn._buffered_bytes == 0


def test_exceeding_stream_credit_fails_without_growing_its_queue():
    with connected() as (conn, wire):
        stream = request(conn)
        wire.feed(headers(stream), build_data_frame(stream, b'x' * 8))
        wire.flush()
        wire.feed(build_data_frame(stream, b'y'))
        conn._wait_for(lambda: conn.failed, 1)
        assert conn._buffered_bytes == 8
        with pytest.raises(ConnectionError) as failure:
            conn.read_stream(stream, 8, timeout=0)
        assert 'stream receive window exceeded' in str(failure.value.__cause__)
        assert conn._buffered_bytes == 0


def test_padding_is_credited_before_body_consumption():
    with connected() as (conn, wire):
        stream = request(conn)
        wire.feed(
            headers(stream),
            H2Frame(FRAME_DATA, FLAG_PADDED, stream, b'\x04a' + b'\x00' * 4),
        )
        wire.flush()
        assert wire.updates(stream) == [5]
        assert conn._buffered_bytes == 1
        assert conn.read_stream(stream, 10, timeout=0) == b'a'
        assert conn._buffered_bytes == 0
        conn.cancel_stream(stream)


@pytest.mark.parametrize('window', [1, 2])
def test_small_windows_replenish_after_consumption(window):
    with connected(window=window) as (conn, wire):
        stream = request(conn)
        wire.feed(headers(stream), build_data_frame(stream, b'a' * window))
        assert conn.read_stream(stream, window, timeout=1) == b'a' * window
        assert wire.updates(stream) == [window]
        wire.feed(build_data_frame(stream, b'b', end_stream=True))
        assert conn.read_stream(stream, window, timeout=1) == b'b'
        assert conn.read_stream(stream, window, timeout=0) == b''


def test_header_only_eof_and_zero_reads_release_state_at_the_right_time():
    with connected() as (conn, wire):
        stream = request(conn)
        wire.feed(headers(stream, end=True))
        assert conn.receive_headers(stream, timeout=1) == [(':status', '200')]
        assert conn.read_stream(stream, 0, timeout=0) == b''
        assert stream in conn._streams
        assert conn.read_stream(stream, 10, timeout=0) == b''
        assert stream not in conn._streams
        conn.cancel_stream(stream)
        assert not any(frame.type == FRAME_RST_STREAM for frame in wire.sent)


def test_timeout_cancels_only_one_stream_and_keeps_connection_usable():
    with connected() as (conn, wire):
        slow, fast = request(conn), request(conn)
        wire.feed(headers(slow), headers(fast, end=True))
        conn.receive_headers(slow, timeout=1)
        with pytest.raises(TimeoutError):
            conn.read_stream(slow, 8, timeout=0)
        assert conn.receive_response(fast, timeout=1) == ([(':status', '200')], b'')
        assert not conn.failed
        resets = [
            frame.stream_id for frame in wire.sent if frame.type == FRAME_RST_STREAM
        ]
        assert resets == [slow]


def test_cancel_wakes_a_waiting_reader_and_is_idempotent():
    with connected() as (conn, wire):
        stream = request(conn)
        wire.feed(headers(stream))
        conn.receive_headers(stream, timeout=1)
        started = threading.Event()
        failures = []

        def consume():
            started.set()
            try:
                conn.read_stream(stream, 1, timeout=1)
            except H2StreamError as error:
                failures.append(error)

        reader = threading.Thread(target=consume, daemon=True)
        reader.start()
        assert started.wait(1)
        conn.cancel_stream(stream)
        conn.cancel_stream(stream)
        reader.join(1)
        assert not reader.is_alive()
        assert len(failures) == 1
        assert stream not in conn._streams
        resets = [frame for frame in wire.sent if frame.type == FRAME_RST_STREAM]
        assert len(resets) == 1


@pytest.mark.parametrize('failure', ['reset', 'goaway'])
def test_reset_or_goaway_discards_rejected_data_without_harming_accepted_stream(
    failure,
):
    with connected() as (conn, wire):
        accepted, rejected = request(conn), request(conn)
        wire.feed(
            headers(accepted), headers(rejected), build_data_frame(rejected, b'bad')
        )
        wire.feed(
            build_rst_stream_frame(rejected, 8)
            if failure == 'reset'
            else build_goaway_frame(accepted)
        )
        wire.flush()
        assert conn._buffered_bytes == 0
        with pytest.raises(H2StreamError):
            conn.read_stream(rejected, 8, timeout=0)
        wire.feed(build_data_frame(accepted, b'ok', end_stream=True))
        assert conn.receive_response(accepted, timeout=1) == (
            [(':status', '200')],
            b'ok',
        )
        assert not conn.failed


def test_interim_headers_and_trailers_keep_final_headers_and_body():
    with connected() as (conn, wire):
        stream = request(conn)
        encoder = HPACKEncoder()
        wire.feed(
            H2Frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS,
                stream,
                encoder.encode_headers([(':status', '103')]),
            ),
            headers(stream),
            build_data_frame(stream, b'abc'),
            H2Frame(
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                stream,
                encoder.encode_headers([('x-trailer', 'done')]),
            ),
        )
        assert conn.receive_response(stream, timeout=1) == (
            [(':status', '200')],
            b'abc',
        )
        assert stream not in conn._streams
        assert conn._buffered_bytes == 0
