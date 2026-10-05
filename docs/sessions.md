# Sessions and pools

This page covers synchronous `Session` and `ConnectionPool`. See
[native async](async.md#pools-concurrent-tasks-and-close) for async admission,
private default pools and borrowed explicit pools.

A `Session` keeps response Cookies, TLS configuration/session cache, hooks and
an optional retry policy. HTTP/1.1 reuses an idle connection serially; HTTP/2
can run multiple streams on one negotiated connection.

```python
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

pool = ConnectionPool(max_connections_per_host=10, idle_timeout=60, max_pool_size=100)
with Session(tls_config=TlsConfig.secure(), pool=pool) as session:
    first = session.get("https://example.com/", timeout=5)
    second = session.get("https://example.com/account", timeout=5)
```

`ConnectionPool` defaults are 10 retained connections per host, a 60-second idle
timeout and 100 total retained connections. These settings govern retained
connections; they are not an application concurrency queue or a guarantee of
waiting for a free HTTP/1 slot.

An explicitly supplied pool takes precedence over `use_pooling=False`. To use
per-request connections, set `use_pooling=False` and omit `pool`.

## Ownership and close

| Resource | Ownership and release |
| --- | --- |
| Default shared pool | Used by Sessions with no explicit pool; closing one Session does not close it |
| Explicit dedicated pool | `Session.close()` closes it, including remaining pooled connections |
| Unpooled request | Its response owns the connection until body completion or close |
| HTTP/1 streaming response | Valid EOF returns a reusable connection; early close discards it |
| HTTP/2 streaming response | EOF releases its stream; early close cancels that stream |

If several Sessions are given the same explicit pool, closing any of them
closes that pool. A Session context should therefore outlive the responses using
its dedicated pool. Use a response context manager whenever iteration can stop
early. A module-level streaming request also requires consuming or closing its
returned Response.

Connection reuse avoids a handshake entirely. TLS session resumption opens a
new TCP connection and performs an abbreviated handshake using in-memory state;
these are separate optimizations. [TLS resumption](tls.md#session-resumption)
explains the cache boundary. Cookie persistence is separate from both.

## Cookies

Response Cookies are retained in the Session; request Cookies are merged for
that request. The jar applies domain/path/secure/expiry filtering and preserves
same-name Cookies at different paths in the outgoing header. Response
`Set-Cookie` fields update existing jars directly, including deletion through
`Max-Age=0` or an expired `Expires` value. For explicit initial state, assign a
`Ja3RequestsCookieJar`:

```python
from ja3requests import Session
from ja3requests.cookies import Ja3RequestsCookieJar

jar = Ja3RequestsCookieJar()
jar.set("language", "en", domain="example.com", path="/", secure=True)
with Session(use_pooling=False) as session:
    session.cookies = jar
    response = session.get("https://example.com/", timeout=5)
```

`session.cookies` returns a detached compatibility snapshot, including the latest
request's Cookies. Modifying it does not update future requests, and request-only
values in that view are not persisted. Use explicit assignment or `load_cookies()`
for stored state. [Cookie-file persistence](cookie_persistence.md) documents opt-in
disk storage, session-Cookie handling, merge rules, limits and file permissions.

## Concurrency boundary

Pool and TLS cache operations are synchronized, and HTTP/2 supports multiplexed
requests. This does not make every mutable Session property or user hook
thread-safe. Set configuration before concurrent use, synchronize application
hook state, and use each call's returned Response rather than treating
`session.response` as a per-thread result store.
