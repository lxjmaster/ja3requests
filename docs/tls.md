# TLS trust, mTLS, and resumption

The client performs TLS itself; changing configuration does not switch to an
OpenSSL client or a Python SSL socket. Cryptographic primitives still come from
`cryptography`. The [wire-control guide](tls_wire_control.md) covers exact
ClientHello choices separately from certificate policy.

## Server trust

`TlsConfig()` and `TlsConfig.secure()` verify the server by default and offer
TLS 1.3 with authenticated TLS 1.2 ECDHE/AES-GCM fallback. A trusted chain, valid
certificate dates and a Subject Alternative Name matching the URL destination
are required. Custom SNI changes routing, not certificate identity.

The high-level request `verify` argument is boolean. To use private trust, set
`SSL_CERT_FILE` to the intended PEM root bundle before requests begin. There is
no Requests-style `verify='/path/ca.pem'` or `REQUESTS_CA_BUNDLE` API.

```python
import os
from pathlib import Path

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

os.environ["SSL_CERT_FILE"] = str(Path("/path/to/roots.pem").resolve(strict=True))
with Session(tls_config=TlsConfig.secure(), pool=ConnectionPool()) as session:
    response = session.get("https://service.internal/", timeout=5)
```

This requires a real CA bundle and service. The setting is process-wide. Use a
combined public/private root bundle if both are required and keep trust stable
for the lifetime of connections/caches. The [secure-defaults migration guide](tls_defaults_migration.md)
details tested private-CA layouts, wrong-host behavior, request overrides and
legacy opt-in. `verify=False` disables checks; it does not supply custom trust.

## Mutual TLS

Set the client certificate and private key on the TLS configuration:

```python
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

config = TlsConfig.secure()
config.client_cert = "/path/to/client-chain.pem"
config.client_key = "/path/to/client-key.pem"
with Session(tls_config=config, pool=ConnectionPool()) as session:
    response = session.get("https://mtls.internal/", timeout=5)
```

The implementation accepts PEM bytes, PEM strings, or string file paths.
Convert a `Path` to `str` explicitly. It loads the private key without a password;
encrypted-key passwords are not a supported config argument. The server must
request a compatible client certificate and trust its issuer. Client
authentication does not replace verification of the server's certificate.
The project has TLS1.2 and TLS1.3 client-authentication paths; the tested matrix,
rather than an advertised numeric algorithm ID alone, defines verified coverage.

## Session resumption

A Session initializes an in-memory `TLSSessionCache` if its config has none.
Defaults are `max_size=100` and `ttl=3600`. It retains TLS1.2 Session IDs/tickets
and TLS1.3 tickets, constrained by ticket/certificate lifetime and authentication
compatibility. Server support determines whether an offer actually resumes.

```python
from ja3requests import Session, TlsConfig
from ja3requests.protocol.tls.session_cache import TLSSessionCache

config = TlsConfig.secure()
config.session_cache = TLSSessionCache(max_size=32, ttl=600)
with Session(tls_config=config, use_pooling=False) as session:
    first = session.get("https://example.com/", timeout=5)
    second = session.get("https://example.com/", timeout=5)
```

Disabling pooling here ensures separate connections, but does not prove the
server accepted resumption. A pooled connection avoids a new handshake entirely.
TLS1.3 uses PSK with fresh Diffie-Hellman exchange (`psk_dhe_ke`), not PSK-only
mode or 0-RTT. TLS1.2 sessions lacking extended master secret and client-auth
sessions are excluded from the corresponding cache/resume paths. Configuring a
client certificate disables TLS1.3 ticket resumption, preserving authentication
behavior on new connections.

TLS tickets can arrive after the handshake and are processed while reading
records. Finishing response reads is therefore relevant to ticket availability.
Neither Cookie files nor Session close save TLS secrets to disk. Avoid exposing
cache contents or raw ClientHello records, which may contain resumption identities.
