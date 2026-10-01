"""
ja3requests.protocol.tls.session_cache
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Thread-safe TLS session cache for session resumption.
Stores TLS 1.2 sessions and TLS 1.3 tickets keyed by (host, port).
"""

import threading
import time
from typing import Dict, Optional, Tuple


class TLSSessionEntry:
    """A cached TLS session for resumption."""

    def __init__(
        self,
        session_id,
        master_secret,
        cipher_suite,
        tls_version=None,
        *,
        extended_master_secret=False,
        verified=False,
        verified_hostname=None,
        certificate_expires_at=None,
        sni=None,
        is_ticket=False,
    ):
        self.session_id = session_id
        self.master_secret = master_secret
        self.cipher_suite = cipher_suite
        self.tls_version = tls_version
        self.extended_master_secret = extended_master_secret
        self.verified = verified
        self.verified_hostname = verified_hostname
        self.certificate_expires_at = certificate_expires_at
        self.sni = sni
        self.is_ticket = is_ticket
        self.created_at = time.time()

    def is_expired(self, ttl):
        """Check if this session entry has expired."""
        return (time.time() - self.created_at) > ttl or (
            self.certificate_expires_at is not None
            and time.time() >= self.certificate_expires_at
        )

    def __repr__(self):
        return (
            f"<TLSSessionEntry id={self.session_id[:8].hex()}... "
            f"cipher=0x{self.cipher_suite:04X}>"
        )


class TLS12Ticket(TLSSessionEntry):
    """TLS 1.2 ticket and the authenticated session state it resumes."""

    def __init__(self, ticket, master_secret, cipher_suite, lifetime, **kwargs):
        super().__init__(b"", master_secret, cipher_suite, is_ticket=True, **kwargs)
        self.ticket = ticket
        self.lifetime = lifetime
        self.received_at = time.monotonic()

    def is_expired(self, ttl):
        return time.monotonic() - self.received_at >= min(
            self.lifetime, ttl
        ) or super().is_expired(ttl)


class TLS13Ticket:
    """An in-memory TLS 1.3 resumption identity and its derived PSK."""

    def __init__(
        self,
        ticket,
        psk,
        cipher_suite,
        lifetime,
        age_add,
        sni,
        verified=False,
        verified_hostname=None,
        certificate_expires_at=None,
    ):
        self.ticket = ticket
        self.psk = psk
        self.cipher_suite = cipher_suite
        self.lifetime = lifetime
        self.age_add = age_add
        self.sni = sni
        self.verified = verified
        self.verified_hostname = verified_hostname
        self.certificate_expires_at = certificate_expires_at
        self.received_at = time.monotonic()
        self.created_at = time.time()

    def is_expired(self, ttl):
        return time.monotonic() - self.received_at >= min(
            self.lifetime, ttl, 604800
        ) or (
            self.certificate_expires_at is not None
            and time.time() >= self.certificate_expires_at
        )

    def obfuscated_age(self):
        age_ms = int((time.monotonic() - self.received_at) * 1000)
        return (age_ms + self.age_add) & 0xFFFFFFFF


class TLSSessionCache:
    """
    Thread-safe cache for TLS session resumption data.

    Stores TLS 1.2 sessions and TLS 1.3 tickets for each (host, port).
    """

    def __init__(self, max_size=100, ttl=3600.0):
        """
        :param max_size: Maximum number of cached sessions.
        :param ttl: Time-to-live for each session entry in seconds (default: 1 hour).
        """
        self._cache: Dict[Tuple[str, int], TLSSessionEntry] = {}
        self._tls12_tickets: Dict[Tuple[str, int], TLS12Ticket] = {}
        self._tls13_tickets: Dict[Tuple[str, int], TLS13Ticket] = {}
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

    def put(
        self,
        host,
        port,
        session_id,
        master_secret,
        cipher_suite,
        tls_version=None,
        *,
        extended_master_secret=False,
        verified=False,
        verified_hostname=None,
        certificate_expires_at=None,
        sni=None,
        is_ticket=False,
    ):
        """
        Store a TLS session for later resumption.
        """
        if not session_id or self._max_size <= 0:
            return

        key = (host.lower(), port)
        entry = TLSSessionEntry(
            session_id,
            master_secret,
            cipher_suite,
            tls_version,
            extended_master_secret=extended_master_secret,
            verified=verified,
            verified_hostname=verified_hostname,
            certificate_expires_at=certificate_expires_at,
            sni=sni,
            is_ticket=is_ticket,
        )

        with self._lock:
            self._evict_if_full(self._cache, key)
            self._cache[key] = entry

    def _evict_if_full(self, target, key):
        """Evict the oldest entry across all session stores under the cache lock."""
        if (
            key in target
            or len(self._cache) + len(self._tls12_tickets) + len(self._tls13_tickets)
            < self._max_size
        ):
            return
        candidates = [
            (entry.created_at, store, stored_key)
            for store in (self._cache, self._tls12_tickets, self._tls13_tickets)
            for stored_key, entry in store.items()
        ]
        _, store, oldest_key = min(candidates, key=lambda candidate: candidate[0])
        del store[oldest_key]

    def get_tls12_ticket(self, host, port) -> Optional[TLS12Ticket]:
        """Return a live TLS 1.2 ticket for this destination."""
        key = (host.lower(), port)
        with self._lock:
            entry = self._tls12_tickets.get(key)
            if entry is not None and entry.is_expired(self._ttl):
                del self._tls12_tickets[key]
                return None
            return entry

    def put_tls12_ticket(
        self,
        host,
        port,
        ticket,
        master_secret,
        cipher_suite,
        lifetime,
        *,
        tls_version=None,
        extended_master_secret=False,
        verified=False,
        verified_hostname=None,
        certificate_expires_at=None,
        sni=None,
    ):
        """Store a TLS 1.2 ticket separately from its Session ID."""
        if not ticket or not master_secret or lifetime <= 0 or self._max_size <= 0:
            return
        key = (host.lower(), port)
        entry = TLS12Ticket(
            ticket,
            master_secret,
            cipher_suite,
            lifetime,
            tls_version=tls_version,
            extended_master_secret=extended_master_secret,
            verified=verified,
            verified_hostname=verified_hostname,
            certificate_expires_at=certificate_expires_at,
            sni=sni,
        )
        with self._lock:
            self._evict_if_full(self._tls12_tickets, key)
            self._tls12_tickets[key] = entry

    def remove_tls12_ticket(self, host, port, ticket=None):
        """Discard a particular TLS 1.2 ticket without touching Session IDs."""
        with self._lock:
            key = (host.lower(), port)
            entry = self._tls12_tickets.get(key)
            if entry is not None and (ticket is None or entry.ticket == ticket):
                del self._tls12_tickets[key]

    def get_tls13(self, host, port) -> Optional[TLS13Ticket]:
        """Return a live ticket for this destination, if one exists."""
        key = (host.lower(), port)
        with self._lock:
            entry = self._tls13_tickets.get(key)
            if entry is not None and entry.is_expired(self._ttl):
                del self._tls13_tickets[key]
                return None
            return entry

    def put_tls13(
        self,
        host,
        port,
        ticket,
        psk,
        cipher_suite,
        lifetime,
        age_add,
        sni,
        verified=False,
        verified_hostname=None,
        certificate_expires_at=None,
    ):
        """Store the latest usable ticket independently of TLS 1.2 sessions."""
        if not ticket or not psk or not 0 < lifetime <= 604800 or self._max_size <= 0:
            return
        key = (host.lower(), port)
        entry = TLS13Ticket(
            ticket,
            psk,
            cipher_suite,
            lifetime,
            age_add,
            sni,
            verified,
            verified_hostname,
            certificate_expires_at,
        )
        with self._lock:
            self._evict_if_full(self._tls13_tickets, key)
            self._tls13_tickets[key] = entry

    def remove_tls13(self, host, port, ticket=None):
        """Discard an offered ticket after successful use."""
        with self._lock:
            key = (host.lower(), port)
            entry = self._tls13_tickets.get(key)
            if entry is not None and (ticket is None or entry.ticket == ticket):
                del self._tls13_tickets[key]

    def remove_tls12(self, host, port, session_id=None):
        """Discard an offered TLS 1.2 session without affecting TLS 1.3 tickets."""
        with self._lock:
            key = (host.lower(), port)
            entry = self._cache.get(key)
            if entry is not None and (
                session_id is None or entry.session_id == session_id
            ):
                del self._cache[key]

    def remove(self, host, port):
        """Remove both TLS versions' cached state for this destination."""
        key = (host.lower(), port)
        with self._lock:
            self._cache.pop(key, None)
            self._tls12_tickets.pop(key, None)
            self._tls13_tickets.pop(key, None)

    def clear(self):
        """Clear all cached sessions."""
        with self._lock:
            self._cache.clear()
            self._tls12_tickets.clear()
            self._tls13_tickets.clear()

    def cleanup_expired(self):
        """Remove all expired entries."""
        with self._lock:
            expired = [k for k, v in self._cache.items() if v.is_expired(self._ttl)]
            for k in expired:
                del self._cache[k]
            expired = [
                k for k, v in self._tls12_tickets.items() if v.is_expired(self._ttl)
            ]
            for k in expired:
                del self._tls12_tickets[k]
            expired = [
                k for k, v in self._tls13_tickets.items() if v.is_expired(self._ttl)
            ]
            for k in expired:
                del self._tls13_tickets[k]

    def __len__(self):
        with self._lock:
            return (
                len(self._cache) + len(self._tls12_tickets) + len(self._tls13_tickets)
            )

    def __repr__(self):
        return f"<TLSSessionCache entries={len(self)} max={self._max_size} ttl={self._ttl}>"
