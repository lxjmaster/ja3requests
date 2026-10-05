"""Native asyncio TCP, proxy tunnels and the project's TLS record transport."""

import asyncio
from base64 import b64encode
import contextvars
import copy
import math
import socket
import ssl
from typing import Optional
from urllib.parse import unquote, urlsplit

from ja3requests._async_utils import owner_task
from ja3requests.exceptions import Timeout, TLSHandshakeError
from ja3requests.protocol.exceptions import ProxyError
from ja3requests.protocol.sockets import allowed_gai_family
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls._io import Call, Pause, Read, Write
from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.sockets.https import TLSRecordCodec


class _AsyncHandshakeSocket:
    """Legacy per-read timeouts never change the native socket's blocking mode."""

    @staticmethod
    def settimeout(_timeout):
        # The caller owns one monotonic connect budget, including the handshake.
        return None


def _prepare_certificates(config):
    """Read local trust/key files only; this worker never receives a socket."""
    roots = None
    if config.verify_cert:
        roots = tuple(ssl.create_default_context().get_ca_certs(binary_form=True))
    certificate = TLS._load_cert_data(config.client_cert)
    key = TLS._load_cert_data(config.client_key)
    return roots, certificate, key


class AsyncTransport:
    """One loop-bound connection with bounded record reads and ordered writes."""

    def __init__(self, conn: socket.socket):
        self._loop = asyncio.get_running_loop()
        self._socket = conn
        self._socket.setblocking(False)
        self._read_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._pending = b""
        self._plaintext = b""
        self._native_tasks = set()
        self._native_waiters = {}
        self._close_task = None
        self.tls = None  # type: Optional[TLS]
        self._codec = None  # type: Optional[TLSRecordCodec]
        self.closed = False

    @property
    def negotiated_protocol(self) -> Optional[str]:
        """The peer's authenticated ALPN choice, or None for plain TCP."""
        return getattr(self.tls, '_negotiated_protocol', None)

    def _check_loop(self):
        if asyncio.get_running_loop() is not self._loop:
            raise RuntimeError("AsyncTransport belongs to another event loop")

    def _native_done(self, task):
        self._native_tasks.discard(task)
        waiter = self._native_waiters.pop(task, None)
        try:
            result = task.result()
        except asyncio.CancelledError:
            if waiter is not None and not waiter.done():
                waiter.cancel()
        except Exception as error:
            if waiter is not None and not waiter.done():
                waiter.set_exception(error)
        else:
            if waiter is not None and not waiter.done():
                waiter.set_result(result)

    async def _socket_io(self, operation, *args):
        if self.closed:
            raise ConnectionError("Transport is closed")
        # Socket shutdown alone need not wake the selector's registered Future.
        # Own the native task separately so close can wake, but never cancel,
        # an application task which is awaiting this transport.
        waiter = self._loop.create_future()
        task = owner_task(operation(self._socket, *args))
        self._native_tasks.add(task)
        self._native_waiters[task] = waiter
        task.add_done_callback(self._native_done, context=contextvars.Context())
        try:
            return await waiter
        except asyncio.CancelledError:
            if not self.closed:
                task.cancel()
            raise
        finally:
            # close and caller cancellation may occur in the same loop turn.
            # Observe the close error even when cancellation wins the await.
            if waiter.done() and not waiter.cancelled():
                waiter.exception()

    async def _recv(self, size):
        if self._pending:
            result, self._pending = self._pending[:size], self._pending[size:]
            return result
        if self.closed:
            return b""
        # TLS headers and payloads often arrive together. Reuse one bounded
        # native read instead of scheduling a task for each small exact read.
        data = await self._socket_io(self._loop.sock_recv, 65536 if size > 0 else size)
        if not self.closed:
            self._pending = data[size:]
        # A completed read can resume after close; never restore its excess
        # bytes after close has already discarded the transport's buffers.
        return data[:size]

    async def _send(self, data):
        if self.closed:
            raise ConnectionError("Transport is closed")
        await self._socket_io(self._loop.sock_sendall, data)

    async def _exact(self, size):
        result = bytearray()
        while len(result) < size:
            part = await self._recv(size - len(result))
            if not part:
                break
            result.extend(part)
        return bytes(result)

    async def _handshake_steps(self, steps):
        result = None
        try:
            while True:
                try:
                    operation = steps.send(result)
                except StopIteration as completed:
                    return completed.value
                try:
                    if isinstance(operation, Read):
                        result = await self._recv(operation.size)
                    elif isinstance(operation, Write):
                        result = await self._send(operation.data)
                    elif isinstance(operation, Pause):
                        # Keep pause operations cooperative; handshake I/O waits
                        # for socket readiness rather than a fixed grace delay.
                        result = await asyncio.sleep(0)
                    elif isinstance(operation, Call):
                        method = operation.method
                        generator = method.handshake_steps(
                            method.__self__, *operation.args
                        )
                        result = await self._handshake_steps(generator)
                    else:
                        raise TypeError("Unknown TLS handshake operation")
                except asyncio.CancelledError:
                    # Python 3.7's cancellation must not enter the legacy TLS
                    # methods' broad Exception handlers, which return False.
                    raise
                # Native I/O errors propagate too: authentication failures still
                # originate in the shared state machine, but a reset is not a
                # certificate failure and must keep its transport error identity.
        finally:
            steps.close()

    async def _start_tls(self, host, port, config):
        prepared = copy.copy(config)
        roots, certificate, key = await self._loop.run_in_executor(
            None, _prepare_certificates, prepared
        )
        prepared.client_cert, prepared.client_key = certificate, key
        tls = TLS(
            _AsyncHandshakeSocket(),
            session_cache=prepared.session_cache,
            server_host=host,
            server_port=port,
        )
        tls._trust_roots = roots
        tls.set_payload(prepared)
        succeeded = await self._handshake_steps(
            getattr(TLS.handshake, 'handshake_steps')(tls)
        )
        if not succeeded:
            raise TLSHandshakeError("TLS handshake failed")
        pending_attr = (
            '_tls13_pending_record_data'
            if tls._is_tls13
            else '_tls12_pending_record_data'
        )
        self._pending = getattr(tls, pending_attr) + self._pending
        setattr(tls, pending_attr, b"")
        self.tls = tls
        self._codec = TLSRecordCodec(tls)

    async def read(self, size: int) -> bytes:
        """Return up to size plaintext bytes, skipping authenticated controls."""
        self._check_loop()
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("read size must be a non-negative integer")
        if not size:
            return b""
        async with self._read_lock:
            try:
                if self.tls is None:
                    result = await self._recv(size)
                    if not result:
                        self.close()
                    return result
                while not self._plaintext and not self.closed:
                    header = await self._exact(5)
                    if not header:
                        if self.tls._is_tls13:
                            self._codec.check_handshake_complete()
                        self.close()
                        return b""
                    length = self._codec.record_length(header)
                    payload = await self._exact(length)
                    kind, payload = self._codec.decode_record(header, payload)
                    if kind == 22:
                        # This lock covers key updates, encryption and writes,
                        # not merely sendall after key state has advanced.
                        async with self._write_lock:
                            for reply in self._codec.post_handshake(payload):
                                await self._send(reply)
                        continue
                    if kind == 21:
                        self.close()
                        return b""
                    self._plaintext = payload
                result, self._plaintext = (
                    self._plaintext[:size],
                    self._plaintext[size:],
                )
                return result
            except asyncio.CancelledError:
                self.close()
                raise
            except Exception:
                self.close()
                raise

    async def write(self, data: bytes) -> None:
        """Serialize encryption and bounded sends; failures discard key state."""
        self._check_loop()
        async with self._write_lock:
            try:
                if self.closed:
                    raise ConnectionError("Transport is closed")
                for offset in range(0, len(data), 16384):
                    fragment = data[offset : offset + 16384]
                    record = self._codec.encrypt(fragment) if self._codec else fragment
                    await self._send(record)
            except asyncio.CancelledError:
                self.close()
                raise
            except Exception:
                self.close()
                raise

    async def send_key_update(self, request_update=False):
        """Order a supported TLS 1.3 KeyUpdate with application/control writes."""
        self._check_loop()
        handshake = getattr(self.tls, '_tls13_handshake', None)
        if handshake is None:
            raise ValueError("TLS 1.3 application keys are not available")
        async with self._write_lock:
            try:
                await self._send(handshake.build_key_update(request_update))
            except asyncio.CancelledError:
                self.close()
                raise
            except Exception:
                self.close()
                raise

    def close(self) -> None:
        """Detach the socket and wake native I/O without cancelling callers."""
        if self.closed:
            return
        self.closed = True
        self._pending = b""
        self._plaintext = b""
        for waiter in tuple(self._native_waiters.values()):
            if not waiter.done():
                waiter.set_exception(ConnectionError("Transport is closed"))
        for task in tuple(self._native_tasks):
            task.cancel()
        # Python 3.7 socket operations unregister on readiness, not cancellation.
        # Detach registrations before close allows the descriptor to be reused.
        descriptor = self._socket.fileno()
        if descriptor >= 0:
            try:
                self._loop.remove_reader(descriptor)
                self._loop.remove_writer(descriptor)
            except NotImplementedError:
                # Proactor loops own completion-based I/O, not fd registrations.
                pass
        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._socket.close()

    async def aclose(self) -> None:
        """Finish one shielded cleanup even if a caller cancels its close wait."""
        self._check_loop()
        self.close()
        if self._close_task is None:
            self._close_task = owner_task(self._join_native())
        await asyncio.shield(self._close_task)

    async def _join_native(self):
        while self._native_tasks:
            pending = tuple(self._native_tasks)
            await asyncio.gather(*pending, return_exceptions=True)
            self._native_tasks.difference_update(pending)


async def _connect(host, port):
    loop = asyncio.get_running_loop()
    host = host.encode('idna').decode('ascii')
    addresses = await loop.getaddrinfo(
        host, port, family=allowed_gai_family(), type=socket.SOCK_STREAM
    )
    error = None
    for family, kind, protocol, _name, address in addresses:
        conn = socket.socket(family, kind, protocol)
        try:
            conn.setblocking(False)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            await loop.sock_connect(conn, address)
            return AsyncTransport(conn)
        except asyncio.CancelledError:
            conn.close()
            raise
        except OSError as failure:
            error = failure
            conn.close()
    if error is not None:
        raise error
    raise OSError("No addresses found for destination")


async def _proxy_exact(transport, size):
    result = await transport._exact(size)
    if len(result) != size:
        raise ProxyError("Proxy closed during tunnel establishment")
    return result


async def _http_tunnel(transport, host, port, proxy):
    hostname = host.encode('idna').decode('ascii')
    authority = (
        "[{}]:{}".format(hostname, port)
        if ':' in hostname
        else "{}:{}".format(hostname, port)
    )
    lines = ["CONNECT {} HTTP/1.1".format(authority), "Host: " + authority]
    if proxy.username is not None:
        credentials = unquote(proxy.username) + ':' + unquote(proxy.password or '')
        lines.append(
            "Proxy-Authorization: Basic "
            + b64encode(credentials.encode()).decode('ascii')
        )
    await transport._send(('\r\n'.join(lines) + '\r\n\r\n').encode('ascii'))
    response = b""
    while b'\r\n\r\n' not in response:
        if len(response) >= 65536:
            raise ProxyError("CONNECT response headers exceed 65536 bytes")
        part = await transport._recv(min(4096, 65536 - len(response)))
        if not part:
            raise ProxyError("Proxy closed before CONNECT response headers")
        response += part
    header, tail = response.split(b'\r\n\r\n', 1)
    status = header.split(b'\r\n', 1)[0].split(b' ', 2)
    if len(status) < 2 or not status[0].startswith(b'HTTP/') or status[1] != b'200':
        raise ProxyError("CONNECT tunnel was rejected")
    transport._pending = tail + transport._pending


async def _socks_tunnel(transport, host, port, proxy):
    hostname = host.encode('idna')
    username = unquote(proxy.username or '').encode('utf-8')
    password = unquote(proxy.password or '').encode('utf-8')
    if len(hostname) > 255 or len(username) > 255 or len(password) > 255:
        raise ProxyError("SOCKS host or credentials exceed 255 bytes")
    if proxy.scheme in ('socks4', 'socks4a'):
        if b'\x00' in username or b'\x00' in hostname:
            raise ProxyError("SOCKS4 fields cannot contain NUL")
        try:
            address = socket.inet_aton(host)
            domain = b''
        except OSError:
            address, domain = b'\x00\x00\x00\x01', hostname + b'\x00'
        await transport._send(
            b'\x04\x01'
            + port.to_bytes(2, 'big')
            + address
            + username
            + b'\x00'
            + domain
        )
        reply = await _proxy_exact(transport, 8)
        if reply[:2] != b'\x00\x5a':
            raise ProxyError("SOCKS4 tunnel was rejected")
        return
    await transport._send(b'\x05\x02\x00\x02' if username else b'\x05\x01\x00')
    reply = await _proxy_exact(transport, 2)
    if reply[0] != 5 or reply[1] not in (0, 2):
        raise ProxyError("SOCKS5 did not select an offered authentication method")
    if reply[1] == 2:
        if not username:
            raise ProxyError("SOCKS5 requires credentials")
        await transport._send(
            b'\x01'
            + bytes([len(username)])
            + username
            + bytes([len(password)])
            + password
        )
        if await _proxy_exact(transport, 2) != b'\x01\x00':
            raise ProxyError("SOCKS5 authentication failed")
    await transport._send(
        b'\x05\x01\x00\x03'
        + bytes([len(hostname)])
        + hostname
        + port.to_bytes(2, 'big')
    )
    reply = await _proxy_exact(transport, 4)
    if reply[:3] != b'\x05\x00\x00':
        raise ProxyError("SOCKS5 tunnel was rejected")
    if reply[3] == 1:
        length = 4
    elif reply[3] == 4:
        length = 16
    elif reply[3] == 3:
        length = (await _proxy_exact(transport, 1))[0]
    else:
        raise ProxyError("SOCKS5 returned an invalid address type")
    await _proxy_exact(transport, length + 2)


async def open_transport(
    host: str,
    port: int,
    *,
    tls_config: Optional[TlsConfig] = None,
    proxy: Optional[str] = None,
    timeout: Optional[float] = None,
) -> AsyncTransport:
    """Connect once, sharing one deadline across DNS, candidates, tunnel and TLS."""
    if timeout is not None and (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout < 0
    ):
        raise ValueError("connect timeout must be finite and non-negative or None")
    parsed_proxy = urlsplit(proxy) if proxy is not None else None
    if parsed_proxy is not None:
        if parsed_proxy.scheme not in (
            'http',
            'socks4',
            'socks4a',
            'socks5',
            'socks5h',
        ):
            raise ProxyError("Unsupported proxy scheme")
        if not parsed_proxy.hostname or not parsed_proxy.port:
            raise ProxyError("Proxy URL requires a host and port")

    async def establish():
        transport = await _connect(
            parsed_proxy.hostname if parsed_proxy else host,
            parsed_proxy.port if parsed_proxy else port,
        )
        try:
            if parsed_proxy:
                if parsed_proxy.scheme == 'http':
                    await _http_tunnel(transport, host, port, parsed_proxy)
                else:
                    await _socks_tunnel(transport, host, port, parsed_proxy)
            if tls_config is not None:
                await transport._start_tls(host, port, tls_config)
            return transport
        except asyncio.CancelledError:
            transport.close()
            raise
        except Exception:
            transport.close()
            raise

    try:
        if timeout is None:
            return await establish()
        return await asyncio.wait_for(establish(), timeout)
    except asyncio.TimeoutError as error:
        raise Timeout("Connection setup timed out (DNS/TCP/proxy/TLS)") from error
