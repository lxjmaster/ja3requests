"""
Ja3Requests.pool
~~~~~~~~~~~~~~~~

Thread-safe connection pooling for HTTP/HTTPS connections.
Supports HTTP/1.1 serial reuse and HTTP/2 stream multiplexing.
"""

from __future__ import annotations

import socket
import threading
import time
from collections import deque
from types import TracebackType
from typing import TYPE_CHECKING, Deque, Dict, List, Optional, Tuple, Any, Type

from ja3requests.protocol.tls.debug import debug

if TYPE_CHECKING:
    from typing_extensions import Literal
    from ja3requests._typing import PoolStats
    from ja3requests.protocol.h2.multiplex import H2MultiplexConnection
    from ja3requests.protocol.tls import TLS
    from ja3requests.sockets.https import HttpsSocket

PoolKey = Tuple[str, int, str]
PolicyKey = Optional[Tuple[object, ...]]
ReservationKey = Tuple[PoolKey, PolicyKey]


class PooledConnection:
    """Wrapper for pooled connections with metadata"""

    def __init__(
        self,
        conn: socket.socket,
        scheme: str,
        host: str = "",
        port: int = 0,
        *,
        created_at: Optional[float] = None,
    ) -> None:
        self.conn: Optional[socket.socket] = conn
        self.scheme = scheme
        self.host = host
        self.port = port
        self.created_at = created_at or time.time()
        self.last_used_at = self.created_at
        self.tls: Optional[TLS] = None  # TLS context for HTTPS connections
        self._pool_generation = None
        self.negotiated_protocol: Optional[str] = (
            None  # ALPN result ('h2', 'http/1.1', None)
        )

    def __repr__(self) -> str:
        return f"<PooledConnection {self.scheme}://{self.host}:{self.port} alive={self.is_alive()}>"

    def is_expired(self, idle_timeout: float) -> bool:
        """Check if connection has been idle too long"""
        return (time.time() - self.last_used_at) > idle_timeout

    def is_alive(self) -> bool:
        """Check if underlying socket is still connected"""
        try:
            if self.conn is None:
                return False
            self.conn.setblocking(False)
            try:
                data = self.conn.recv(1, socket.MSG_PEEK)
                if data == b'':
                    return False
            except BlockingIOError:
                pass
            except (OSError, ConnectionError) as e:
                debug(f"Connection check failed: {e}", level=2)
                return False
            finally:
                self.conn.setblocking(True)
            return True
        except (OSError, AttributeError, TypeError) as e:
            debug(f"Connection alive check error: {e}", level=2)
            return False

    def touch(self) -> None:
        """Update last used timestamp"""
        self.last_used_at = time.time()

    def close(self) -> None:
        """Close the underlying connection"""
        try:
            if self.conn:
                self.conn.close()
        except OSError as e:
            debug(f"Error closing connection: {e}", level=2)
        self.conn = None


class PooledH2Connection(PooledConnection):
    """
    Pooled HTTP/2 connection with stream multiplexing support.

    Unlike PooledConnection (one request at a time), a PooledH2Connection
    can serve multiple concurrent streams up to the server's
    SETTINGS_MAX_CONCURRENT_STREAMS.
    """

    def __init__(
        self,
        conn: socket.socket,
        scheme: str,
        host: str = "",
        port: int = 0,
        **kwargs: Any,
    ) -> None:
        super().__init__(conn, scheme, host, port, **kwargs)
        self.negotiated_protocol = "h2"
        self.h2_connection: Optional[H2MultiplexConnection] = None
        self.transport_owner: Optional[HttpsSocket] = None
        self._active_streams = 0
        self._max_concurrent_streams = 100  # Conservative default
        self._goaway_received = False
        self._stream_lock = threading.RLock()

    @property
    def active_streams(self) -> int:
        """Number of active streams on this connection."""
        with self._stream_lock:
            return self._active_streams

    def set_max_concurrent_streams(self, value: int) -> None:
        """Update max concurrent streams from server's SETTINGS frame."""
        with self._stream_lock:
            self._max_concurrent_streams = value

    def mark_goaway(self) -> None:
        """Mark this connection as no longer accepting new streams (GOAWAY received)."""
        with self._stream_lock:
            self._goaway_received = True

    def can_allocate_stream(self) -> bool:
        """Check if a new stream can be allocated on this connection."""
        with self._stream_lock:
            if self._goaway_received:
                return False
            return self._active_streams < self._max_concurrent_streams

    def acquire_stream(self) -> bool:
        """Reserve a stream slot. Returns True if successful."""
        with self._stream_lock:
            if not self.can_allocate_stream():
                return False
            self._active_streams += 1
            self.touch()
            return True

    def release_stream(self) -> None:
        """Release a stream slot after a request completes."""
        with self._stream_lock:
            if self._active_streams > 0:
                self._active_streams -= 1
            self.touch()

    def is_idle(self) -> bool:
        """Check if connection has no active streams."""
        with self._stream_lock:
            return self._active_streams == 0

    def __repr__(self) -> str:
        return (
            f"<PooledH2Connection {self.scheme}://{self.host}:{self.port} "
            f"streams={self._active_streams}/{self._max_concurrent_streams} "
            f"goaway={self._goaway_received}>"
        )

    def close(self) -> None:
        """Wake the reader thread before closing a multiplexed socket."""
        if self.conn is not None:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except (OSError, AttributeError):
                pass
        super().close()


class ConnectionPool:
    """
    Thread-safe connection pool for HTTP/HTTPS connections.

    Maintains separate pools for each (host, port, scheme) combination.
    Supports:
    - HTTP/1.1 serial reuse (one request per connection at a time)
    - HTTP/2 stream multiplexing (multiple concurrent requests per connection)
    - Connection reuse, idle timeout, maximum connections per host
    """

    def __init__(
        self,
        max_connections_per_host: int = 10,
        idle_timeout: float = 60.0,
        max_pool_size: int = 100,
    ) -> None:
        """
        Initialize connection pool.

        Args:
            max_connections_per_host: Maximum connections per (host, port, scheme)
            idle_timeout: Seconds before idle connection is closed
            max_pool_size: Maximum total connections across all hosts
        """
        self._pools: Dict[PoolKey, Deque[PooledConnection]] = {}
        # H2 connections kept separately (not popped on checkout)
        self._h2_pools: Dict[PoolKey, List[PooledH2Connection]] = {}
        self._lock = threading.RLock()
        self._max_per_host = max_connections_per_host
        self._idle_timeout = idle_timeout
        self._max_pool_size = max_pool_size
        self._total_connections = 0
        self._generation = object()
        self._h2_connecting = set()
        self._h2_condition = threading.Condition(self._lock)

    def __repr__(self) -> str:
        return f"<ConnectionPool connections={self._total_connections} pools={len(self._pools)}>"

    def _get_pool_key(self, host: str, port: int, scheme: str) -> Tuple[str, int, str]:
        """Generate pool key from connection parameters"""
        return (host.lower(), port, scheme.lower())

    def get_h2_connection(
        self,
        host: str,
        port: int,
        scheme: str = "https",
        *,
        policy_key: PolicyKey = None,
        verified_host: Optional[str] = None,
    ) -> Optional[PooledH2Connection]:
        """
        Get an HTTP/2 connection with available stream capacity.

        Does NOT remove the connection from the pool — H2 connections
        can serve multiple concurrent streams.

        Returns None if no H2 connection has capacity.
        """
        key = self._get_pool_key(host, port, scheme)

        with self._h2_condition:
            conns = self._h2_pools.get(key, [])
            # Prune dead/expired connections
            valid = []
            for c in conns:
                dead = (
                    c.conn is None
                    or getattr(c.h2_connection, "failed", False)
                    or (c.h2_connection is None and not c.is_alive())
                    or (c.active_streams == 0 and c.is_expired(self._idle_timeout))
                )
                if dead:
                    c.close()
                    self._total_connections -= 1
                    continue
                valid.append(c)
            self._h2_pools[key] = valid

            # Find connection with stream capacity
            for c in valid:
                if (
                    policy_key is not None
                    and getattr(c.tls, '_pool_policy_key', None) != policy_key
                ):
                    continue
                if verified_host is not None and (
                    getattr(c.tls, '_cert_verified', False) is not True
                    or getattr(c.tls, '_verified_hostname', None) != verified_host
                ):
                    continue
                if c.acquire_stream():
                    return c
            return None

    def get_h2_or_reserve(
        self,
        host: str,
        port: int,
        policy_key: PolicyKey,
        verified_host: Optional[str] = None,
        *,
        timeout: Optional[float] = None,
    ) -> Tuple[Optional[PooledH2Connection], Optional[ReservationKey]]:
        """Check out a stream or reserve the first connection handshake."""
        key = (self._get_pool_key(host, port, "https"), policy_key)
        deadline = time.monotonic() + (5.0 if timeout is None else timeout)
        with self._h2_condition:
            while True:
                pooled = self.get_h2_connection(
                    host, port, policy_key=policy_key, verified_host=verified_host
                )
                if pooled is not None:
                    return pooled, None
                if key not in self._h2_connecting:
                    self._h2_connecting.add(key)
                    return None, key
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Timed out waiting for HTTP/2 connection")
                self._h2_condition.wait(remaining)

    def release_h2_reservation(self, key: Optional[ReservationKey]) -> None:
        if key is None:
            return
        with self._h2_condition:
            self._h2_connecting.discard(key)
            self._h2_condition.notify_all()

    def put_h2_connection(
        self,
        host: str,
        port: int,
        scheme: str,
        conn: socket.socket,
        *,
        tls: Optional[TLS] = None,
        h2_connection: Optional[H2MultiplexConnection] = None,
        transport_owner: Optional[HttpsSocket] = None,
        acquire_initial: bool = False,
    ) -> Optional[PooledH2Connection]:
        """
        Register a new HTTP/2 connection in the pool.

        Returns the PooledH2Connection wrapper, or None if pool is full.
        The caller should call `acquire_stream()` before using.
        """
        key = self._get_pool_key(host, port, scheme)

        with self._h2_condition:
            if self._total_connections >= self._max_pool_size:
                debug(f"Pool full ({self._total_connections}/{self._max_pool_size})")
                return None

            if key not in self._h2_pools:
                self._h2_pools[key] = []

            pooled = PooledH2Connection(conn, scheme, host, port)
            pooled.tls = tls
            pooled.h2_connection = h2_connection
            pooled.transport_owner = transport_owner
            pooled._pool_generation = self._generation
            if acquire_initial:
                pooled.acquire_stream()
            self._h2_pools[key].append(pooled)
            self._total_connections += 1
            self._h2_condition.notify_all()
            return pooled

    def release_h2_stream(self, pooled_conn: PooledH2Connection) -> None:
        """Release a stream on an H2 connection. Connection stays in pool."""
        with self._h2_condition:
            pooled_conn.release_stream()
            if pooled_conn.is_idle() and (
                pooled_conn._goaway_received
                or getattr(pooled_conn.h2_connection, "failed", False)
            ):
                self.discard_h2_connection(pooled_conn)
            self._h2_condition.notify_all()

    def discard_h2_connection(self, pooled_conn: PooledH2Connection) -> None:
        """Remove one multiplexed connection without affecting its peers."""
        with self._h2_condition:
            key = self._get_pool_key(
                pooled_conn.host, pooled_conn.port, pooled_conn.scheme
            )
            conns = self._h2_pools.get(key, [])
            if pooled_conn in conns:
                conns.remove(pooled_conn)
                self._total_connections -= 1
                if not conns:
                    self._h2_pools.pop(key, None)
            pooled_conn.close()
            self._h2_condition.notify_all()

    def get_connection(
        self, host: str, port: int, scheme: str = "https"
    ) -> Optional[PooledConnection]:
        """
        Get an HTTP/1.1 connection from the pool if available.
        Removes the connection (serial reuse).
        """
        key = self._get_pool_key(host, port, scheme)

        with self._lock:
            if key not in self._pools:
                return None

            pool = self._pools[key]

            while pool:
                pooled_conn = pool.popleft()

                if pooled_conn.is_expired(self._idle_timeout):
                    pooled_conn.close()
                    self._total_connections -= 1
                    continue

                if not pooled_conn.is_alive():
                    pooled_conn.close()
                    self._total_connections -= 1
                    continue

                pooled_conn.touch()
                return pooled_conn

            return None

    def discard_connection(self, pooled_conn: PooledConnection) -> None:
        """Close a checked-out HTTP/1 connection without counting an old pool."""
        with self._lock:
            if pooled_conn.conn is not None:
                pooled_conn.close()
                if pooled_conn._pool_generation is self._generation:
                    self._total_connections -= 1

    def put_connection(
        self,
        host: str,
        port: int,
        scheme: str,
        conn: socket.socket,
        *,
        tls: Optional[TLS] = None,
        pooled_conn: Optional['PooledConnection'] = None,
    ) -> bool:
        """
        Return an HTTP/1.1 connection to the pool for reuse.

        Returns:
            True if connection was pooled, False if pool is full
        """
        key = self._get_pool_key(host, port, scheme)

        with self._lock:
            if key not in self._pools:
                self._pools[key] = deque()

            pool = self._pools[key]

            if (
                pooled_conn is not None
                and pooled_conn._pool_generation is self._generation
            ):
                pooled_conn.touch()
                pool.append(pooled_conn)
                return True

            if self._total_connections >= self._max_pool_size:
                debug(
                    f"Pool full ({self._total_connections}/{self._max_pool_size}), rejecting connection"
                )
                return False

            if len(pool) >= self._max_per_host:
                debug(
                    f"Host pool full ({len(pool)}/{self._max_per_host}), rejecting connection"
                )
                return False

            new_pooled_conn = PooledConnection(conn, scheme, host, port)
            new_pooled_conn._pool_generation = self._generation
            new_pooled_conn.tls = tls
            new_pooled_conn.touch()

            pool.append(new_pooled_conn)
            self._total_connections += 1

            return True

    def close_idle_connections(self) -> None:
        """Close all connections that have exceeded idle timeout"""
        with self._lock:
            for key, pool in list(self._pools.items()):
                active_conns = deque()

                while pool:
                    pooled_conn = pool.popleft()

                    if pooled_conn.is_expired(self._idle_timeout):
                        pooled_conn.close()
                        self._total_connections -= 1
                    else:
                        active_conns.append(pooled_conn)

                if active_conns:
                    self._pools[key] = active_conns
                else:
                    del self._pools[key]

            # Also close idle H2 connections (only if no active streams)
            for key, conns in list(self._h2_pools.items()):
                kept = []
                for c in conns:
                    if c.is_expired(self._idle_timeout) and c.is_idle():
                        c.close()
                        self._total_connections -= 1
                    else:
                        kept.append(c)
                if kept:
                    self._h2_pools[key] = kept
                else:
                    del self._h2_pools[key]

    def close_host_connections(self, host: str, port: int, scheme: str) -> None:
        """Close all connections to a specific host"""
        key = self._get_pool_key(host, port, scheme)

        with self._lock:
            if key in self._pools:
                pool = self._pools.pop(key)
                for pooled_conn in pool:
                    pooled_conn.close()
                    self._total_connections -= 1
            if key in self._h2_pools:
                conns = self._h2_pools.pop(key)
                for c in conns:
                    c.close()
                    self._total_connections -= 1

    def close_all(self) -> None:
        """Close all pooled connections"""
        with self._h2_condition:
            for pool in self._pools.values():
                for pooled_conn in pool:
                    pooled_conn.close()
            for conns in self._h2_pools.values():
                for c in conns:
                    c.close()

            self._pools.clear()
            self._h2_pools.clear()
            self._total_connections = 0
            self._generation = object()
            self._h2_connecting.clear()
            self._h2_condition.notify_all()

    def get_stats(self) -> PoolStats:
        """Get pool statistics"""
        with self._lock:
            stats: PoolStats = {
                "total_connections": self._total_connections,
                "pools": len(self._pools),
                "h2_pools": len(self._h2_pools),
                "max_per_host": self._max_per_host,
                "idle_timeout": self._idle_timeout,
                "hosts": {},
                "h2_hosts": {},
            }

            for key, pool in self._pools.items():
                host, port, scheme = key
                stats["hosts"][f"{scheme}://{host}:{port}"] = len(pool)

            for key, conns in self._h2_pools.items():
                host, port, scheme = key
                stats["h2_hosts"][f"{scheme}://{host}:{port}"] = {
                    "connections": len(conns),
                    "active_streams": sum(c.active_streams for c in conns),
                }

            return stats

    def __enter__(self) -> ConnectionPool:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Literal[False]:
        self.close_all()
        return False

    def __del__(self) -> None:
        self.close_all()


# Global default connection pool
_default_pool: Optional[ConnectionPool] = None
_pool_lock = threading.Lock()


def get_default_pool() -> ConnectionPool:
    """Get or create the default connection pool"""
    global _default_pool  # pylint: disable=global-statement

    with _pool_lock:
        if _default_pool is None:
            _default_pool = ConnectionPool()
        return _default_pool


def set_default_pool(pool: ConnectionPool) -> None:
    """Set a custom default connection pool"""
    global _default_pool  # pylint: disable=global-statement

    with _pool_lock:
        if _default_pool is not None:
            _default_pool.close_all()
        _default_pool = pool
