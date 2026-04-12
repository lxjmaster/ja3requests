"""
ja3requests.protocol.tls.session_cache
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Thread-safe TLS session cache for session resumption.
Stores session IDs and master secrets keyed by (host, port).
"""

import threading
import time
from typing import Dict, Optional, Tuple


class TLSSessionEntry:
    """A cached TLS session for resumption."""

    def __init__(self, session_id, master_secret, cipher_suite, tls_version=None):
        self.session_id = session_id
        self.master_secret = master_secret
        self.cipher_suite = cipher_suite
        self.tls_version = tls_version
        self.created_at = time.time()

    def is_expired(self, ttl):
        """Check if this session entry has expired."""
        return (time.time() - self.created_at) > ttl

    def __repr__(self):
        return (
            f"<TLSSessionEntry id={self.session_id[:8].hex()}... "
            f"cipher=0x{self.cipher_suite:04X}>"
        )


class TLSSessionCache:
    """
    Thread-safe cache for TLS session resumption data.

    Stores session ID and master secret for each (host, port) pair
    to enable abbreviated TLS handshakes on reconnection.
    """

    def __init__(self, max_size=100, ttl=3600.0):
        """
        :param max_size: Maximum number of cached sessions.
        :param ttl: Time-to-live for each session entry in seconds (default: 1 hour).
        """
        self._cache: Dict[Tuple[str, int], TLSSessionEntry] = {}
        self._lock = threading.RLock()
        self._max_size = max_size
        self._ttl = ttl

    def get(self, host, port) -> Optional[TLSSessionEntry]:
        """
        Retrieve a cached session for the given host and port.
        Returns None if no valid session is cached.
        """
        key = (host.lower(), port)
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.is_expired(self._ttl):
                del self._cache[key]
                return None
            return entry

    def put(self, host, port, session_id, master_secret, cipher_suite, tls_version=None):
        """
        Store a TLS session for later resumption.
        """
        if not session_id or len(session_id) == 0:
            return

        key = (host.lower(), port)
        entry = TLSSessionEntry(session_id, master_secret, cipher_suite, tls_version)

        with self._lock:
            # Evict oldest entry if cache is full
            if len(self._cache) >= self._max_size and key not in self._cache:
                oldest_key = min(self._cache, key=lambda k: self._cache[k].created_at)
                del self._cache[oldest_key]

            self._cache[key] = entry

    def remove(self, host, port):
        """Remove a cached session."""
        key = (host.lower(), port)
        with self._lock:
            self._cache.pop(key, None)

    def clear(self):
        """Clear all cached sessions."""
        with self._lock:
            self._cache.clear()

    def cleanup_expired(self):
        """Remove all expired entries."""
        with self._lock:
            expired = [k for k, v in self._cache.items() if v.is_expired(self._ttl)]
            for k in expired:
                del self._cache[k]

    def __len__(self):
        with self._lock:
            return len(self._cache)

    def __repr__(self):
        return f"<TLSSessionCache entries={len(self)} max={self._max_size} ttl={self._ttl}>"
