"""TLS session resumption: session ID caching for faster reconnections."""

from ja3requests import Session, TlsConfig
from ja3requests.protocol.tls.session_cache import TLSSessionCache

# Sessions auto-create a TLSSessionCache
session = Session(use_pooling=False)
print(f"Session cache: {session.tls_config.session_cache}")

# Custom cache with specific TTL and size
cache = TLSSessionCache(max_size=50, ttl=1800)  # 50 entries, 30 min TTL
config = TlsConfig()
config.session_cache = cache

session = Session(tls_config=config, use_pooling=False)

# First request: full TLS handshake
# resp = session.get("https://example.com/api")

# Second request to same host: abbreviated handshake (session ID reuse)
# resp = session.get("https://example.com/api/data")

# Check cache stats
print(f"Cache entries: {len(cache)}")
# cache.cleanup_expired()  # Remove stale entries
# cache.clear()  # Clear all

# Server may also send NewSessionTicket → automatically cached
