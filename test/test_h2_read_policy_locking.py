"""A stalled unlimited writer must not own another stream's finite wait."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import queue
import threading

import pytest

from ja3requests._sync_timeout import UNLIMITED_READ
from ja3requests._upload import UploadSource
from ja3requests.exceptions import InvalidData
from ja3requests.protocol.h2.frame import (
    CONNECTION_PREFACE,
    FRAME_DATA,
    FRAME_RST_STREAM,
    H2Frame,
    build_data_frame,
)
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection
from test.integration.test_sync_redirect_replay import BorrowedFile


class BlockedWriter:
    """Exercise real multiplex send turns without a TLS/network timing race."""

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.armed = False
        self.block_kind = None
        self.failure = None
        self.frames = []
        self.closed = []
        self.pool = ThreadPoolExecutor(4)
        self.conn = H2MultiplexConnection(
            lambda data: None,
            lambda size: b'',
            send_with_timeout=self.send,
            close_transport=lambda: self.closed.append(True),
        )
        # Establishment/SETTINGS is outside this lock-ownership test.
        self.conn._peer_settings_received = True

    def send(self, data, timeout):
        if data == CONNECTION_PREFACE:
            return
        frames, remaining = H2Frame.parse_all(data)
        assert not remaining
        self.frames.extend(frames)
        if (
            self.armed
            and timeout is UNLIMITED_READ
            and (self.block_kind is None or frames[0].type == self.block_kind)
        ):
            self.armed = False
            self.entered.set()
            assert self.release.wait(3), 'test failed to release its writer'
            if self.failure is not None:
                raise self.failure

    def request(self, timeout=1):
        return self.conn.send_request('GET', 'example.test', '/', timeout=timeout)

    def block(self):
        self.armed = True
        result = self.pool.submit(self.request, UNLIMITED_READ)
        assert self.entered.wait(1)
        return result

    def resets(self):
        return [
            frame.stream_id for frame in self.frames if frame.type == FRAME_RST_STREAM
        ]

    def assert_writer_owned(self, writer):
        assert not writer.done()
        assert not self.conn.failed
        assert not self.closed


@contextmanager
def blocked_writer():
    wire = BlockedWriter()
    try:
        yield wire
    finally:
        wire.release.set()
        wire.pool.shutdown(wait=True)
        for stream_id in list(wire.conn._uploads):
            wire.conn.cancel_stream(stream_id)


def assert_owned_timeout(result):
    with pytest.raises(TimeoutError, match='HTTP/2.*timed out'):
        result.result(timeout=0.5)
    assert result.done(), 'caller is still waiting on the other writer'


@pytest.mark.parametrize('budget', [0, 0.03])
def test_finite_admission_expires_without_cancelling_unlimited_writer(budget):
    with blocked_writer() as wire:
        writer = wire.block()
        limited = wire.pool.submit(wire.request, budget)
        assert_owned_timeout(limited)
        wire.assert_writer_owned(writer)
        assert not wire.resets()
        wire.release.set()
        assert writer.result(timeout=1) == 1
        assert wire.request() == 3
        assert not wire.conn.failed


@pytest.mark.parametrize('operation', ['receive_headers', 'read_stream'])
@pytest.mark.parametrize('budget', [0, 0.03])
def test_existing_finite_wait_cancels_only_its_target_after_writer_turn(
    operation, budget
):
    with blocked_writer() as wire:
        target = wire.request()
        writer = wire.block()
        function = getattr(wire.conn, operation)
        arguments = (target,) if operation == 'receive_headers' else (target, 1)
        limited = wire.pool.submit(function, *arguments, timeout=budget)
        assert_owned_timeout(limited)
        wire.assert_writer_owned(writer)
        assert not wire.resets(), 'cancel attempted to interleave a TLS writer'
        wire.release.set()
        assert writer.result(timeout=1) == 3
        # A framing turn applies pending cancellation before further work.
        assert wire.request() == 5
        assert target not in wire.conn._streams
        assert wire.resets() == [target]
        assert not wire.conn.failed


@pytest.mark.parametrize('operation', ['receive_headers', 'read_stream'])
def test_finite_wait_already_asleep_can_expire_while_new_writer_owns_lock(
    monkeypatch, operation
):
    with blocked_writer() as wire:
        target = wire.request()
        waiting = threading.Event()
        original = wire.conn._wait_event

        def wait(event, timeout):
            waiting.set()
            return original(event, timeout)

        monkeypatch.setattr(wire.conn, '_wait_event', wait)
        function = getattr(wire.conn, operation)
        arguments = (target,) if operation == 'receive_headers' else (target, 1)
        limited = wire.pool.submit(function, *arguments, timeout=0.1)
        assert waiting.wait(1)
        writer = wire.block()
        assert_owned_timeout(limited)
        wire.assert_writer_owned(writer)
        wire.release.set()
        writer.result(timeout=1)
        wire.request()
        assert wire.resets() == [target]


def test_capacity_wait_already_asleep_expires_after_existing_writer_takes_lock(
    monkeypatch,
):
    with blocked_writer() as wire:
        target, _ = wire.conn._begin_request(
            'POST', 'example.test', '/', has_body=True, timeout=1
        )
        wire.conn._peer_settings[3] = 1
        waiting = threading.Event()
        original = wire.conn._wait_event

        def wait(event, timeout):
            waiting.set()
            return original(event, timeout)

        monkeypatch.setattr(wire.conn, '_wait_event', wait)
        limited = wire.pool.submit(wire.request, 0.1)
        assert waiting.wait(1)

        def write_existing_body():
            with wire.conn._framing(UNLIMITED_READ):
                wire.conn._send(
                    build_data_frame(target, b'active').serialize(),
                    timeout=UNLIMITED_READ,
                )

        wire.armed = True
        writer = wire.pool.submit(write_existing_body)
        assert wire.entered.wait(1)
        assert_owned_timeout(limited)
        wire.assert_writer_owned(writer)
        assert not wire.resets()
        wire.release.set()
        assert writer.result(timeout=1) is None


def test_cancel_queues_without_writer_interruption_then_discards_buffered_body():
    with blocked_writer() as wire:
        target = wire.request()
        stream = wire.conn._streams[target]
        stream.body.extend(b'queued')
        wire.conn._buffered_bytes += len(stream.body)
        writer = wire.block()
        cancelled = wire.pool.submit(wire.conn.cancel_stream, target)
        assert cancelled.result(timeout=0.5) is None
        wire.assert_writer_owned(writer)
        assert not wire.resets()
        assert bytes(stream.body) == b'queued'
        wire.release.set()
        assert writer.result(timeout=1) == 3
        wire.request()
        assert target not in wire.conn._streams
        assert not stream.body and wire.conn._buffered_bytes == 0
        assert wire.resets() == [target]


@pytest.mark.parametrize('timeout', [None, UNLIMITED_READ])
def test_unspecified_or_unlimited_admission_keeps_waiting_for_its_turn(timeout):
    with blocked_writer() as wire:
        writer = wire.block()
        waiting = wire.pool.submit(wire.request, timeout)
        # Once the actual writer is released, each waiter gets its own send.
        assert not waiting.done()
        wire.release.set()
        assert writer.result(timeout=1) == 1
        assert waiting.result(timeout=1) == 3
        assert not wire.conn.failed and not wire.resets()


def test_upload_waiting_for_another_writer_stops_and_joins_without_more_reads(
    monkeypatch,
):
    source_entered = threading.Event()
    release_source = threading.Event()
    source_returned = threading.Event()
    worker_turn = threading.Event()

    class GatedFile(BorrowedFile):
        active = False

        def read(self, size=-1):
            self.active = True
            source_entered.set()
            try:
                assert release_source.wait(3)
                return super().read(size)
            finally:
                self.active = False
                source_returned.set()

    source = GatedFile(b'body')
    with blocked_writer() as wire:
        try:
            stream = wire.conn.begin_upload(
                'POST',
                'example.test',
                '/',
                body=UploadSource(source),
                timeout=UNLIMITED_READ,
            )
            owner = wire.conn._uploads[stream]
            assert source_entered.wait(1)
            original = wire.conn._framing

            @contextmanager
            def framing(timeout, stopped=None):
                if threading.current_thread() is owner.thread:
                    worker_turn.set()
                with original(timeout, stopped=stopped):
                    yield

            monkeypatch.setattr(wire.conn, '_framing', framing)
            writer = wire.block()
            release_source.set()
            assert source_returned.wait(1)
            assert worker_turn.wait(1)
            cancelled = wire.pool.submit(wire.conn.cancel_stream, stream)
            assert cancelled.result(timeout=0.5) is None
            assert owner.stopped.is_set() and not owner.thread.is_alive()
            assert not source.active and source.reads == 1 and not source.closed
            wire.assert_writer_owned(writer)
            wire.release.set()
            writer.result(timeout=1)
            wire.request()
            assert wire.resets() == [stream]
            assert not wire.conn.failed
        finally:
            release_source.set()


def test_cancelling_the_active_unlimited_upload_writer_waits_for_its_own_cleanup():
    source = BorrowedFile(b'body')
    with blocked_writer() as wire:
        wire.armed = True
        wire.block_kind = FRAME_DATA
        stream = wire.conn.begin_upload(
            'POST',
            'example.test',
            '/',
            body=UploadSource(source),
            timeout=UNLIMITED_READ,
        )
        owner = wire.conn._uploads[stream]
        assert wire.entered.wait(1)
        cancelled = wire.pool.submit(wire.conn.cancel_stream, stream)
        assert owner.stopped.wait(1)
        assert (
            not cancelled.done()
        ), 'active source worker returned before its write completed'
        assert owner.thread.is_alive() and not source.closed
        assert not wire.conn.failed and not wire.closed
        wire.release.set()
        assert cancelled.result(timeout=1) is None
        assert not owner.thread.is_alive() and not source.closed
        assert source.reads == 1


def test_upload_already_waiting_for_credit_stops_when_another_writer_takes_lock(
    monkeypatch,
):
    source = BorrowedFile(b'body')
    with blocked_writer() as wire:
        wire.conn._peer_settings[4] = 0
        waiting = threading.Event()
        original = wire.conn._wait_event

        def wait(event, timeout):
            waiting.set()
            return original(event, timeout)

        monkeypatch.setattr(wire.conn, '_wait_event', wait)
        stream = wire.conn.begin_upload(
            'POST',
            'example.test',
            '/',
            body=UploadSource(source),
            timeout=UNLIMITED_READ,
        )
        owner = wire.conn._uploads[stream]
        assert waiting.wait(1)
        writer = wire.block()
        cancelled = wire.pool.submit(wire.conn.cancel_stream, stream)
        assert cancelled.result(timeout=0.5) is None
        assert owner.stopped.is_set() and not owner.thread.is_alive()
        assert source.reads == 1 and not source.closed
        wire.assert_writer_owned(writer)
        wire.release.set()
        writer.result(timeout=1)
        wire.request()
        assert wire.resets() == [stream]


def test_actual_writer_failure_still_fails_shared_transport_after_waiter_timeout():
    with blocked_writer() as wire:
        writer = wire.block()
        limited = wire.pool.submit(wire.request, 0.03)
        assert_owned_timeout(limited)
        wire.failure = OSError('owned TLS write failed')
        wire.release.set()
        with pytest.raises(OSError, match='owned TLS write failed'):
            writer.result(timeout=1)
        assert wire.conn.failed


def test_source_failure_wakes_its_waiter_without_acquiring_the_other_writer_lock(
    monkeypatch,
):
    source_entered = threading.Event()
    release_source = threading.Event()
    header_waiting = threading.Event()
    header_awakened = threading.Event()

    def broken_source():
        source_entered.set()
        assert release_source.wait(3)
        raise ValueError('owned source failed')
        yield b'unreachable'

    with blocked_writer() as wire:
        try:
            stream = wire.conn.begin_upload(
                'POST',
                'example.test',
                '/',
                body=UploadSource(broken_source()),
                timeout=UNLIMITED_READ,
            )
            owner = wire.conn._uploads[stream]
            assert source_entered.wait(1)
            original = wire.conn._wait_event

            def wait(event, timeout):
                header_waiting.set()
                original(event, timeout)
                header_awakened.set()

            monkeypatch.setattr(wire.conn, '_wait_event', wait)
            headers = wire.pool.submit(
                wire.conn.receive_headers, stream, timeout=UNLIMITED_READ
            )
            assert header_waiting.wait(1)
            writer = wire.block()
            release_source.set()
            owner.thread.join(0.5)
            assert not owner.thread.is_alive()
            assert header_awakened.wait(
                0.5
            ), 'source error notification waited for the writer lock'
            wire.assert_writer_owned(writer)
            wire.release.set()
            writer.result(timeout=1)
            with pytest.raises(
                InvalidData, match='Could not read the upload source'
            ) as failure:
                headers.result(timeout=1)
            assert isinstance(failure.value.__cause__, ValueError)
            assert str(failure.value.__cause__) == 'owned source failed'
            assert not wire.conn.failed
            assert wire.resets() == [stream]
        finally:
            release_source.set()


def test_reader_eof_closes_transport_before_waiting_for_unlimited_writer_lock():
    with blocked_writer() as wire:
        incoming = queue.Queue()
        wire.conn._recv = lambda size: incoming.get(timeout=2)

        def close():
            wire.closed.append(True)
            wire.release.set()

        wire.conn._close_transport = close
        wire.conn.initiate()
        writer = wire.block()
        try:
            incoming.put(b'')
            wire.conn._reader.join(0.5)
            assert (
                not wire.conn._reader.is_alive()
            ), 'EOF waited for a writer that only transport closure can wake'
            assert wire.closed
            writer.result(timeout=1)
            assert wire.conn.failed
        finally:
            wire.release.set()
            incoming.put(b'')
            wire.conn._reader.join(1)
            assert not wire.conn._reader.is_alive()
