"""Concurrent HTTP/2 streams over one TLS transport."""

import threading
import time
from contextlib import contextmanager

from ja3requests.protocol.h2.frame import (
    build_data_frame,
    build_rst_stream_frame,
)
from ja3requests.protocol.h2.stream_state import H2StreamError, H2StreamState, _Stream
from ja3requests.protocol.h2.connection import H2GoAwayError
from ja3requests.protocol.h2.hpack import HeaderLimitError
from ja3requests.protocol.h2.frame import normalize_headers_priority
from ja3requests._upload import UploadSource
from ja3requests._sync_timeout import (
    UNLIMITED_READ,
    read_deadline,
    read_remaining,
    source_timeout,
)
from ja3requests.sockets._upload import read_upload_piece


class _UploadStopped(Exception):
    """An upload cancelled while waiting for another stream's framing turn."""


class _UploadWorker:
    def __init__(self, connection, stream_id, source, timeout):
        self.connection = connection
        self.stream_id = stream_id
        self.source = source
        self.timeout = timeout
        self.stopped = threading.Event()
        self.unregister = None
        self._finished = False
        self._final_source = False
        self._finish_lock = threading.Lock()
        self.thread = threading.Thread(
            target=connection._produce_upload, args=(self,), daemon=True
        )

    def close(self):
        self.connection.cancel_stream(self.stream_id)
        self.finish()

    def finish(self):
        with self._finish_lock:
            if self._finished:
                return
            if (
                self.thread.ident is not None
                and self.thread is not threading.current_thread()
            ):
                self.thread.join()
            self._finished = True
            if self.unregister is not None:
                self.unregister()
                self.unregister = None
            if self._final_source:
                self.source.close_owned()

    def finalize_source(self):
        with self._finish_lock:
            self._final_source = True
            if self._finished:
                self.source.close_owned()


class H2MultiplexConnection(H2StreamState):
    """Serialize framing and demultiplex responses in one reader thread."""

    def __init__(
        self,
        send_func,
        recv_func,
        settings=None,
        send_with_timeout=None,
        close_transport=None,
        pseudo_header_order=None,
        priority_frames=None,
        huffman=False,
        indexing_exclusions=(),
    ):
        super().__init__(
            send_func,
            recv_func,
            settings=settings,
            pseudo_header_order=pseudo_header_order,
            priority_frames=priority_frames,
            huffman=huffman,
            indexing_exclusions=indexing_exclusions,
        )
        self._condition = threading.Condition(threading.RLock())
        self._reader = None
        self._transport_send = send_func
        self._transport_send_with_timeout = send_with_timeout
        self._close_transport = close_transport
        self._send = self._send_checked
        self._uploads = {}
        # Cancellation must remain visible while a different stream owns a
        # blocking TLS write under the framing lock. Never hold this small
        # bookkeeping lock while acquiring the framing lock or joining a worker.
        self._cancel_lock = threading.Lock()
        self._upload_workers = {}
        self._deferred_cancels = set()
        self._deferred_upload_errors = {}
        self._waiters = set()

    def _notify_all(self):
        self._condition.notify_all()
        with self._cancel_lock:
            for waiter in self._waiters:
                waiter.set()

    def _wait_event(self, event, timeout):
        event.wait(timeout)

    @contextmanager
    def _framing(self, timeout, stopped=None):
        """Bound acquisition too, without interrupting another stream's write."""
        deadline = read_deadline(timeout)
        while True:
            if stopped is not None and stopped.is_set():
                raise _UploadStopped()
            remaining = None if deadline is None else read_remaining(deadline)
            if remaining is not None and remaining <= 0:
                acquired = self._condition.acquire(False)
            elif stopped is not None:
                acquired = self._condition.acquire(
                    timeout=0.05 if remaining is None else min(0.05, remaining)
                )
            elif remaining is None:
                acquired = self._condition.acquire()
            else:
                acquired = self._condition.acquire(timeout=remaining)
            if acquired:
                break
            if deadline is not None and read_remaining(deadline) <= 0:
                raise TimeoutError('HTTP/2 stream timed out')
        try:
            self._drain_deferred()
            if stopped is not None and stopped.is_set():
                raise _UploadStopped()
            yield
        finally:
            try:
                self._drain_deferred()
            finally:
                self._condition.release()

    def _drain_deferred(self):
        """Apply queued changes only while the original framing lock is held."""
        with self._cancel_lock:
            cancelled = self._deferred_cancels
            errors = self._deferred_upload_errors
            self._deferred_cancels = set()
            self._deferred_upload_errors = {}
        for stream_id, error in errors.items():
            stream = self._streams.get(stream_id)
            if stream_id not in cancelled and stream is not None and not stream.done:
                stream.error = error
                if self._failed is None:
                    try:
                        self._send(build_rst_stream_frame(stream_id, 8).serialize())
                    except OSError:
                        pass
        for stream_id in cancelled:
            self._cancel_stream_locked(stream_id)
        if errors or cancelled:
            self._notify_all()

    def _send_checked(self, data, timeout=None):
        try:
            if self._transport_send_with_timeout is None:
                self._transport_send(data)
            else:
                self._transport_send_with_timeout(data, timeout)
        except Exception as error:  # pylint: disable=broad-exception-caught
            with self._condition:
                if self._failed is None:
                    self._failed = error
                self._notify_all()
            raise

    @property
    def failed(self):
        return self._failed is not None

    def set_pooled_connection(self, pooled):
        with self._condition:
            self._pooled_connection = pooled
            pooled.set_max_concurrent_streams(self._peer_settings[3])
            if self._goaway_received:
                pooled.mark_goaway()

    def initiate(self, window_update_increment=None):
        super().initiate(window_update_increment)
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        try:
            while True:
                frames = self._read_frames()
                with self._condition:
                    self._drain_deferred()
                    for frame in frames:
                        self._dispatch_frame(frame)
                    for stream_id, upload in self._uploads.items():
                        stream = self._streams.get(stream_id)
                        if stream is not None and stream.done:
                            upload.stopped.set()
                            if not stream.send_done:
                                self._send(
                                    build_rst_stream_frame(stream_id, 8).serialize()
                                )
                                stream.send_done = True
                    self._notify_all()
        except Exception as error:  # pylint: disable=broad-exception-caught
            # A failed shared reader owns transport shutdown. Interrupt an
            # unlimited write before waiting to record failure under its lock.
            if self._close_transport is not None:
                self._close_transport()
            with self._condition:
                if self._failed is None:
                    self._failed = error
                self._notify_all()
            if (
                isinstance(error, (HeaderLimitError, H2GoAwayError))
                and self._pooled_connection is not None
            ):
                self._pooled_connection.close()
        finally:
            if self._close_transport is not None:
                self._close_transport()

    def _wait_for(self, predicate, timeout, stopped=None, lock_timeout=UNLIMITED_READ):
        deadline = read_deadline(timeout)
        waiter = threading.Event()
        with self._cancel_lock:
            self._waiters.add(waiter)
        try:
            while True:
                # Event.wait does not reacquire the framing lock. Each return
                # takes a bounded turn, even if another writer started meanwhile.
                budget = read_remaining(deadline)
                if deadline is None:
                    budget = lock_timeout
                with self._framing(budget, stopped):
                    if predicate():
                        return
                    if self._failed is not None:
                        raise ConnectionError(
                            "HTTP/2 connection failed"
                        ) from self._failed
                    remaining = None if deadline is None else read_remaining(deadline)
                    if remaining is not None and remaining <= 0:
                        raise TimeoutError("HTTP/2 stream timed out")
                    waiter.clear()
                self._wait_event(waiter, remaining)
        finally:
            with self._cancel_lock:
                self._waiters.discard(waiter)

    def _begin_request(
        self,
        method,
        authority,
        path,
        headers=None,
        has_body=False,
        scheme="https",
        timeout=None,
        headers_priority=None,
    ):
        headers_priority = normalize_headers_priority(headers_priority)
        h2_headers = self._prepare_request_headers(
            method, authority, path, headers, scheme
        )
        deadline = read_deadline(timeout)
        while True:
            self._wait_for(
                lambda: self._goaway_received
                or (
                    self._peer_settings_received
                    and len(self._streams) < self._peer_settings[3]
                ),
                read_remaining(deadline),
            )
            with self._framing(read_remaining(deadline)):
                if self._failed is not None:
                    raise ConnectionError("HTTP/2 connection failed") from self._failed
                if self._goaway_received:
                    raise ConnectionError("HTTP/2 connection received GOAWAY")
                # Another request may have consumed the available turn between
                # the predicate and this reservation. Recheck under the lock.
                if len(self._streams) >= self._peer_settings[3]:
                    continue
                stream_id = self._next_stream_id
                self._next_stream_id += 2
                stream = _Stream(self._peer_settings[4], self._local_settings[4])
                self._streams[stream_id] = stream
                try:
                    block = self._encoder.encode_headers(h2_headers)
                    for frame in self._header_frames(
                        stream_id,
                        block,
                        end_stream=not has_body,
                        headers_priority=headers_priority,
                    ):
                        self._send(frame.serialize(), timeout=timeout)
                    stream.send_done = not has_body
                except Exception:
                    self._streams.pop(stream_id, None)
                    self._notify_all()
                    raise
                return stream_id, stream

    def send_request(
        self,
        method,
        authority,
        path,
        headers=None,
        body=None,
        scheme='https',
        timeout=None,
        headers_priority=None,
    ):
        if body is not None and not isinstance(body, bytes):
            raise TypeError('HTTP/2 request body must be bytes')
        stream_id, stream = self._begin_request(
            method,
            authority,
            path,
            headers,
            bool(body),
            scheme,
            timeout,
            headers_priority,
        )

        try:
            offset = 0
            while body and offset < len(body):
                with self._framing(timeout):
                    error = stream.error
                    if error is not None:
                        raise error
                    if stream.send_done:
                        break
                    size = min(
                        len(body) - offset,
                        self._peer_settings[5],
                        self._connection_send_window,
                        stream.send_window,
                    )
                    if size > 0:
                        end = offset + size
                        self._send(
                            build_data_frame(
                                stream_id, body[offset:end], end_stream=end == len(body)
                            ).serialize(),
                            timeout=timeout,
                        )
                        self._connection_send_window -= size
                        stream.send_window -= size
                        offset = end
                        stream.send_done = end == len(body)
                if size <= 0:
                    self._wait_for(
                        lambda: stream.error
                        or stream.send_done
                        or (
                            self._connection_send_window > 0 and stream.send_window > 0
                        ),
                        timeout,
                    )
            return stream_id
        except Exception:
            self.cancel_stream(stream_id)
            raise

    def begin_upload(
        self,
        method,
        authority,
        path,
        headers=None,
        body=None,
        scheme='https',
        timeout=None,
        register=None,
        headers_priority=None,
    ):
        """Reserve headers, then let one producer run beside response reading."""
        if not isinstance(body, UploadSource):
            raise TypeError('HTTP/2 streaming body requires an UploadSource')
        headers_priority = normalize_headers_priority(headers_priority)
        body.prepare()
        stream_id, _ = self._begin_request(
            method, authority, path, headers, True, scheme, timeout, headers_priority
        )
        upload = _UploadWorker(self, stream_id, body, timeout)
        try:
            with self._framing(timeout):
                self._uploads[stream_id] = upload
                with self._cancel_lock:
                    self._upload_workers[stream_id] = upload
                if register is not None:
                    upload.unregister = register(upload)
                upload.thread.start()
        except BaseException:
            self.cancel_stream(stream_id)
            raise
        return stream_id

    def _produce_upload(self, upload):
        stream_id = upload.stream_id
        try:
            while not upload.stopped.is_set():
                with self._framing(upload.timeout, upload.stopped):
                    stream = self._streams.get(stream_id)
                    if stream is None or stream.done or stream.send_done:
                        return
                    if stream.error is not None:
                        raise stream.error
                # Never advance application code under framing or TLS locks.
                piece = read_upload_piece(
                    upload.source, upload.stopped, source_timeout(upload.timeout)
                )
                offset = 0
                while not upload.stopped.is_set():
                    with self._framing(upload.timeout, upload.stopped):
                        stream = self._streams.get(stream_id)
                        if stream is None or stream.done or stream.send_done:
                            return
                        if stream.error is not None:
                            raise stream.error
                        if not piece:
                            self._send(
                                build_data_frame(
                                    stream_id, b'', end_stream=True
                                ).serialize(),
                                timeout=upload.timeout,
                            )
                            stream.send_done = True
                            self._notify_all()
                            return
                        size = min(
                            len(piece) - offset,
                            self._peer_settings[5],
                            self._connection_send_window,
                            stream.send_window,
                        )
                        if size > 0:
                            self._send(
                                build_data_frame(
                                    stream_id, piece[offset : offset + size]
                                ).serialize(),
                                timeout=upload.timeout,
                            )
                            self._connection_send_window -= size
                            stream.send_window -= size
                            offset += size
                    if size <= 0:
                        self._wait_for(
                            lambda: upload.stopped.is_set()
                            or stream.error
                            or stream.done
                            or stream.send_done
                            or (
                                self._connection_send_window > 0
                                and stream.send_window > 0
                            ),
                            upload.timeout,
                            stopped=upload.stopped,
                        )
                    else:
                        # Release the send turn after each bounded DATA frame.
                        time.sleep(0)
                    if offset == len(piece):
                        break
        except BaseException as error:
            with self._cancel_lock:
                if not upload.stopped.is_set():
                    self._deferred_upload_errors[stream_id] = error
                    for waiter in self._waiters:
                        waiter.set()
            if self._condition.acquire(False):
                try:
                    self._drain_deferred()
                finally:
                    self._condition.release()

    def receive_headers(self, stream_id, timeout=None):
        """Wait for final response headers without waiting for its DATA or EOF."""
        try:
            deadline = read_deadline(timeout)
            with self._framing(read_remaining(deadline)):
                stream = self._response_stream(stream_id)
                uploading = stream_id in self._uploads
            if uploading:
                # Upload duration is not capped by response waiting. Taking a
                # framing turn still uses this request's own progress budget.
                self._wait_for(
                    lambda: stream.headers is not None
                    or stream.error
                    or stream.send_done,
                    UNLIMITED_READ,
                    lock_timeout=timeout,
                )
                deadline = read_deadline(timeout)
            self._wait_for(
                lambda: stream.headers is not None or stream.error,
                read_remaining(deadline),
            )
            with self._framing(read_remaining(deadline)):
                stream = self._response_stream(stream_id)
                self._check_response_error(stream)
                return stream.headers
        except Exception:
            self.cancel_stream(stream_id)
            raise

    def read_stream(self, stream_id, size, timeout=None):
        """Return up to size available bytes; release stream state on empty EOF.

        The caller owns the stream until EOF or cancel_stream(). Reading zero
        bytes does not consume or finish the stream. After EOF the caller must
        cache that state instead of reading the removed stream again.
        """
        if not isinstance(size, int) or size < 0:
            raise ValueError("HTTP/2 read size must be a non-negative integer")
        if size == 0:
            return b""
        try:
            deadline = read_deadline(timeout)
            with self._framing(read_remaining(deadline)):
                stream = self._response_stream(stream_id)
            self._wait_for(
                lambda: stream.body or stream.done or stream.error,
                read_remaining(deadline),
            )
            with self._framing(read_remaining(deadline)):
                stream = self._response_stream(stream_id)
                self._check_response_error(stream)
                if not stream.body:
                    self._streams.pop(stream_id, None)
                    self._notify_all()
                    return b""
                data = bytes(memoryview(stream.body)[:size])
                del stream.body[: len(data)]
                self._buffered_bytes -= len(data)
                self._replenish_connection_window()
                self._replenish_stream_window(stream_id, stream)
                self._notify_all()
                return data
        except Exception:
            self.cancel_stream(stream_id)
            raise

    def receive_response(self, stream_id, timeout=None):
        """Compatibility collector over incremental reads, with one deadline."""
        deadline = read_deadline(timeout)
        chunks = []
        try:
            headers = self.receive_headers(stream_id, timeout=read_remaining(deadline))
            while True:
                chunk = self.read_stream(
                    stream_id, 65536, timeout=read_remaining(deadline)
                )
                if not chunk:
                    return headers, b"".join(chunks)
                chunks.append(chunk)
        finally:
            self.cancel_stream(stream_id)

    def cancel_stream(self, stream_id):
        with self._cancel_lock:
            upload = self._upload_workers.get(stream_id)
            if upload is not None:
                upload.stopped.set()
            self._deferred_cancels.add(stream_id)
            for waiter in self._waiters:
                waiter.set()
        if self._condition.acquire(False):
            try:
                self._drain_deferred()
            finally:
                self._condition.release()
        if upload is not None:
            upload.finish()

    def _cancel_stream_locked(self, stream_id):
        upload = self._uploads.pop(stream_id, None)
        with self._cancel_lock:
            self._upload_workers.pop(stream_id, None)
        if upload is not None:
            upload.stopped.set()
        stream = self._streams.pop(stream_id, None)
        if stream is not None and stream.header_open:
            self._ignored_header_block = stream.header_block
        if (
            stream is not None
            and not (stream.done and stream.send_done)
            and stream.error is None
            and self._failed is None
        ):
            try:
                self._send(build_rst_stream_frame(stream_id, 8).serialize())
            except OSError:
                pass
        if stream is not None:
            if not (stream.done and stream.send_done) and stream.error is None:
                stream.error = H2StreamError(f"HTTP/2 stream {stream_id} was cancelled")
            self._discard_body(stream)
        self._notify_all()
