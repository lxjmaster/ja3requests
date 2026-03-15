"""
Ja3Requests.pool
~~~~~~~~~~~~~~~~

Thread-safe connection pooling for HTTP/HTTPS connections.
"""

import threading
import time
from collections import deque
from typing import Dict, Optional, Tuple, Any


class PooledConnection:
    """Wrapper for pooled connections with metadata"""

    def __init__(self, conn: Any, scheme: str, created_at: float = None):
        self.conn = conn
        self.scheme = scheme
        self.created_at = created_at or time.time()
        self.last_used_at = self.created_at
        self.tls = None  # TLS context for HTTPS connections

    def is_expired(self, idle_timeout: float) -> bool:
        """Check if connection has been idle too long"""
        return (time.time() - self.last_used_at) > idle_timeout

    def is_alive(self) -> bool:
        """Check if underlying socket is still connected"""
        try:
            if self.conn is None:
                return False
            # Try to check socket state without consuming data
            self.conn.setblocking(False)
            try:
                # Peek at socket - if recv returns empty, connection is closed
                data = self.conn.recv(1, 0x02)  # MSG_PEEK
                if data == b'':
                    return False
            except BlockingIOError:
                # No data available but connection is alive
                pass
            except (OSError, ConnectionError):
                return False
            finally:
                self.conn.setblocking(True)
            return True
        except Exception:
            return False

    def touch(self):
        """Update last used timestamp"""
        self.last_used_at = time.time()

    def close(self):
        """Close the underlying connection"""
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        self.conn = None


class ConnectionPool:
    """
    Thread-safe connection pool for HTTP/HTTPS connections.

    Maintains separate pools for each (host, port, scheme) combination.
    Supports connection reuse, idle timeout, and maximum connections per host.
    """

    def __init__(
        self,
        max_connections_per_host: int = 10,
        idle_timeout: float = 60.0,
        max_pool_size: int = 100,
    ):
        """
        Initialize connection pool.

        Args:
            max_connections_per_host: Maximum connections per (host, port, scheme)
            idle_timeout: Seconds before idle connection is closed
            max_pool_size: Maximum total connections across all hosts
        """
        self._pools: Dict[Tuple[str, int, str], deque] = {}
        self._lock = threading.RLock()
        self._max_per_host = max_connections_per_host
        self._idle_timeout = idle_timeout
        self._max_pool_size = max_pool_size
        self._total_connections = 0

        # Start cleanup thread
        self._cleanup_thread = None
        self._shutdown = False

    def _get_pool_key(self, host: str, port: int, scheme: str) -> Tuple[str, int, str]:
        """Generate pool key from connection parameters"""
        return (host.lower(), port, scheme.lower())

    def get_connection(
        self,
        host: str,
        port: int,
        scheme: str = "https"
    ) -> Optional[PooledConnection]:
        """
        Get a connection from the pool if available.

        Args:
            host: Target hostname
            port: Target port
            scheme: Connection scheme (http/https)

        Returns:
            PooledConnection if available, None otherwise
        """
        key = self._get_pool_key(host, port, scheme)

        with self._lock:
            if key not in self._pools:
                return None

            pool = self._pools[key]

            # Try to find a valid connection
            while pool:
                pooled_conn = pool.popleft()

                # Check if connection is still usable
                if pooled_conn.is_expired(self._idle_timeout):
                    pooled_conn.close()
                    self._total_connections -= 1
                    continue

                if not pooled_conn.is_alive():
                    pooled_conn.close()
                    self._total_connections -= 1
                    continue

                # Found a valid connection
                pooled_conn.touch()
                return pooled_conn

            return None

    def put_connection(
        self,
        host: str,
        port: int,
        scheme: str,
        conn: Any,
        tls: Any = None,
        pooled_conn: 'PooledConnection' = None
    ) -> bool:
        """
        Return a connection to the pool for reuse.

        Args:
            host: Target hostname
            port: Target port
            scheme: Connection scheme
            conn: Socket connection object
            tls: TLS context (for HTTPS connections)
            pooled_conn: Existing PooledConnection wrapper (for reused connections)

        Returns:
            True if connection was pooled, False if pool is full
        """
        key = self._get_pool_key(host, port, scheme)

        with self._lock:
            if key not in self._pools:
                self._pools[key] = deque()

            pool = self._pools[key]

            # If returning an existing pooled connection, just add it back
            if pooled_conn is not None:
                pooled_conn.touch()
                pool.append(pooled_conn)
                return True

            # Check pool limits for new connections
            if self._total_connections >= self._max_pool_size:
                return False

            if len(pool) >= self._max_per_host:
                return False

            # Create new pooled connection wrapper
            new_pooled_conn = PooledConnection(conn, scheme)
            new_pooled_conn.tls = tls
            new_pooled_conn.touch()

            pool.append(new_pooled_conn)
            self._total_connections += 1

            return True

    def close_idle_connections(self):
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

    def close_host_connections(self, host: str, port: int, scheme: str):
        """Close all connections to a specific host"""
        key = self._get_pool_key(host, port, scheme)

        with self._lock:
            if key in self._pools:
                pool = self._pools.pop(key)
                for pooled_conn in pool:
                    pooled_conn.close()
                    self._total_connections -= 1

    def close_all(self):
        """Close all pooled connections"""
        with self._lock:
            for pool in self._pools.values():
                for pooled_conn in pool:
                    pooled_conn.close()

            self._pools.clear()
            self._total_connections = 0

    def get_stats(self) -> Dict:
        """Get pool statistics"""
        with self._lock:
            stats = {
                "total_connections": self._total_connections,
                "pools": len(self._pools),
                "max_per_host": self._max_per_host,
                "idle_timeout": self._idle_timeout,
                "hosts": {}
            }

            for key, pool in self._pools.items():
                host, port, scheme = key
                stats["hosts"][f"{scheme}://{host}:{port}"] = len(pool)

            return stats

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_all()
        return False

    def __del__(self):
        self.close_all()


# Global default connection pool
_default_pool: Optional[ConnectionPool] = None
_pool_lock = threading.Lock()


def get_default_pool() -> ConnectionPool:
    """Get or create the default connection pool"""
    global _default_pool

    with _pool_lock:
        if _default_pool is None:
            _default_pool = ConnectionPool()
        return _default_pool


def set_default_pool(pool: ConnectionPool):
    """Set a custom default connection pool"""
    global _default_pool

    with _pool_lock:
        if _default_pool is not None:
            _default_pool.close_all()
        _default_pool = pool
