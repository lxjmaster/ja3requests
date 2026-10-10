"""Synchronous request framing and one owned HTTP/1 upload worker."""

import io
import selectors
import socket
import threading
import time

from ja3requests.exceptions import InvalidData, StreamConsumedError
from ja3requests.utils import _encode_http1_headers


class _H2WriteGuard:
    """One socket write deadline watcher, independent of the shared reader."""

    def __init__(self, connection):
        self.connection = connection
        self._condition = threading.Condition()
        self._deadline = None
        self._closed = False
        self._expired = False
        self.thread = threading.Thread(target=self._watch, daemon=True)
        self.thread.start()

    def _shutdown(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _watch(self):
        with self._condition:
            while not self._closed:
                if self._deadline is None:
                    self._condition.wait()
                    continue
                remaining = self._deadline - time.monotonic()
                if remaining > 0:
                    self._condition.wait(remaining)
                    continue
                self._expired = True
                self._closed = True
        if self._expired:
            # A partially written TLS record cannot be cancelled per stream.
            # Abort the shared transport so neither framing nor reader locks
            # can remain held behind an unresponsive peer.
            self._shutdown()

    def sendall(self, data, deadline):
        if time.monotonic() >= deadline:
            self._shutdown()
            raise TimeoutError('HTTP/2 write timed out')
        with self._condition:
            if self._expired:
                raise TimeoutError('HTTP/2 write timed out')
            if self._closed:
                raise ConnectionError('HTTP/2 transport is closed')
            self._deadline = deadline
            self._condition.notify_all()
        try:
            self.connection.sendall(data)
        except OSError as error:
            if self._expired:
                raise TimeoutError('HTTP/2 write timed out') from error
            raise
        finally:
            with self._condition:
                self._deadline = None
                self._condition.notify_all()
        if self._expired or time.monotonic() >= deadline:
            self._shutdown()
            raise TimeoutError('HTTP/2 write timed out')

    def close(self):
        with self._condition:
            self._closed = True
            self._condition.notify_all()
        self._shutdown()
        if self.thread is not threading.current_thread():
            self.thread.join()


def upload_length(headers):
    """Validate new-source framing before case normalization loses duplicates."""
    values = []
    for name, value in (headers or {}).items():
        if not isinstance(name, str):
            raise InvalidData('Streaming upload header names must be text')
        if name.lower() == 'transfer-encoding':
            raise InvalidData('Streaming uploads generate Transfer-Encoding')
        if name.lower() == 'content-length':
            values.append(value)
    if len(values) > 1:
        raise InvalidData('Duplicate upload Content-Length')
    if not values:
        return None
    value = values[0]
    if isinstance(value, bytes):
        try:
            value = value.decode('ascii')
        except UnicodeError as error:
            raise InvalidData('Invalid upload Content-Length') from error
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise InvalidData('Invalid upload Content-Length')
    value = str(value)
    if not value or any(char not in '0123456789' for char in value):
        raise InvalidData('Invalid upload Content-Length')
    try:
        return int(value)
    except ValueError as error:
        raise InvalidData('Invalid upload Content-Length') from error


def upload_headers(context, h2=False):
    source = context.data
    source.prepare()
    headers = context.headers
    if source.length is None:
        headers.pop('Content-Length', None)
        if not h2:
            headers['Transfer-Encoding'] = 'chunked'
    else:
        headers['Content-Length'] = str(source.length)
    if h2:
        headers.pop('Transfer-Encoding', None)
    return (
        context.start_line.encode('utf-8')
        + b'\r\n'
        + _encode_http1_headers(headers)
        + b'\r\n\r\n'
    )


def read_upload_piece(source, stopped, timeout):
    """Empty chunks share one progress deadline and remain stoppable."""
    deadline = None if timeout is None else time.monotonic() + timeout
    checked = False

    def check_continue():
        nonlocal checked
        if checked:
            # An immediately yielding empty producer must also let the response
            # reader run, especially while it is parsing fragmented headers.
            time.sleep(0)
        checked = True
        if stopped.is_set():
            raise StreamConsumedError('Upload source was stopped')
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError('Upload source timed out')

    piece = source.read_piece(65536, check_continue=check_continue)
    check_continue()
    return piece


class _UploadFile:
    def __init__(self, file, owner):
        self.file = file
        self.owner = owner

    def _read(self, method, *args):
        self.owner.check_error()
        try:
            result = getattr(self.file, method)(*args)
        except Exception:
            self.owner.check_error()
            raise
        self.owner.check_error()
        return result

    def read(self, size=-1):
        return self._read('read', size)

    def read1(self, size=-1):
        return self._read('read1' if hasattr(self.file, 'read1') else 'read', size)

    def readline(self, size=-1):
        return self._read('readline', size)

    def close(self):
        self.file.close()


class _UploadReader(io.RawIOBase):
    """Use the exchange's receive deadline without changing socket write timeouts."""

    def __init__(self, exchange):
        super().__init__()
        self.exchange = exchange

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.exchange.recv(len(buffer))
        buffer[: len(data)] = data
        return len(data)


class UploadExchange:
    """Response reader and upload worker share exactly one transport release."""

    def __init__(self, context, connection, response, send, release):
        self.source = context.data
        self.timeout = getattr(context, 'read_timeout', None)
        self.connection = connection
        self.read_timeout = connection.gettimeout()
        self.response = response
        self.send = send
        self.release = release
        self.stopped = threading.Event()
        self.complete = False
        self.completed_at = None
        self._headers_received = False
        self._read_selector = None
        self.error = None
        self._finished = False
        self._finish_lock = threading.Lock()
        self._unregister = None
        self._final_source = False
        register = getattr(context, '_upload_register', None)
        if register is not None:
            self._unregister = register(self)
        self.worker = threading.Thread(target=self._write, daemon=True)

    def start(self, headers):
        try:
            self.send(headers)
            self.worker.start()
        except BaseException:
            self.close()
            raise
        return self

    def _shutdown(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except (OSError, AttributeError):
            pass

    def _write(self):
        try:
            while not self.stopped.is_set():
                piece = read_upload_piece(self.source, self.stopped, self.timeout)
                if self.stopped.is_set():
                    break
                if not piece:
                    if self.source.length is None:
                        self.send(b'0\r\n\r\n')
                    self.completed_at = time.monotonic()
                    self.complete = True
                    break
                if self.source.length is None:
                    piece = ('%x\r\n' % len(piece)).encode('ascii') + piece + b'\r\n'
                self.send(piece)
        except BaseException as error:
            if not self.stopped.is_set():
                self.error = error
                self._shutdown()

    def upload_headers_received(self):
        self._headers_received = True
        self.stopped.set()
        self.check_error()

    def recv(self, size):
        """Read early responses while upload progress owns the active timeout.

        A socket makefile cannot recover after a timed-out read. Wait for
        readability before recv instead, leaving the socket's finite sendall
        timeout intact. After the upload or response headers finish, each read
        again has the transport's normal read timeout.
        """
        if not size:
            return b''
        started = time.monotonic()
        if self._read_selector is None:
            self._read_selector = selectors.DefaultSelector()
            self._read_selector.register(self.connection, selectors.EVENT_READ)
        while True:
            self.check_error()
            remaining = None
            if self.read_timeout is not None:
                if self._headers_received:
                    remaining = started + self.read_timeout - time.monotonic()
                elif self.completed_at is not None:
                    remaining = (
                        max(started, self.completed_at)
                        + self.read_timeout
                        - time.monotonic()
                    )
            # Recheck upload completion without adding another watcher thread.
            wait = 0.05 if remaining is None else min(0.05, max(0, remaining))
            if self._read_selector.select(wait):
                return self.connection.recv(size)
            if remaining is not None and remaining <= 0:
                raise TimeoutError('timed out')

    def makefile(self, mode='rb'):
        file = (
            io.BufferedReader(_UploadReader(self))
            if self.response is self.connection
            else self.response.makefile(mode)
        )
        return _UploadFile(file, self)

    def check_error(self):
        if self.error is not None:
            raise self.error

    def release_response(self, reusable):
        with self._finish_lock:
            if self._finished:
                return
            self._finished = True
            self.stopped.set()
            if not self.complete:
                self._shutdown()
            if (
                self.worker.ident is not None
                and self.worker is not threading.current_thread()
            ):
                self.worker.join()
            try:
                self.release(reusable and self.complete and self.error is None)
            finally:
                if self._read_selector is not None:
                    self._read_selector.close()
                    self._read_selector = None
                if self._unregister is not None:
                    self._unregister()
                    self._unregister = None
                if self._final_source:
                    self.source.close_owned()
            self.check_error()

    def close(self):
        self.release_response(False)

    def finalize_source(self):
        with self._finish_lock:
            self._final_source = True
            if self._finished:
                self.source.close_owned()
