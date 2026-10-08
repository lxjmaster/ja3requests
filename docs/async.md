# Native asynchronous requests

Version 2.1.0 introduces `AsyncSession`, `AsyncResponse` and
`AsyncConnectionPool`. The existing synchronous APIs remain available.

Async requests use native `asyncio` socket waits with the project's TLS
handshake, authentication, record protection and HTTP/2 state. The live HTTP/TLS
connection does not run inside a worker wrapping the synchronous client. DNS
and certificate/key preparation may use narrowly scoped workers; cryptographic
and parser work still runs on the event loop and is not promised to be free of
CPU cost. Async support alone does not establish a performance improvement.

## Make and stream a request

```python
import asyncio
from ja3requests import AsyncSession

async def download(url):
    async with AsyncSession() as session:
        async with await session.get(url, stream=True, timeout=(3, 10)) as response:
            response.raise_for_status()
            async for chunk in response.aiter_content(65536):
                print(len(chunk))

if __name__ == "__main__":
    asyncio.run(download("https://example.com/data"))
```

`stream=True` returns after headers and request policy/hooks. With `stream=False`
(the default), the request awaits the complete decoded body before returning.
Use `async with response` or `await response.aclose()` when stopping early;
`break` from an async iterator alone does not guarantee immediate cleanup.
Keep the session open until its responses finish.

## Body consumption

| Operation | Behavior |
| --- | --- |
| `await response.read()` | Collect and cache bytes; later reads use the cache |
| `await response.text()` | Read/cache, then decode using Content-Type's charset or the assignable `encoding` override |
| `await response.json()` | Read/cache, then parse JSON |
| `response.content` | Cached bytes only; unread content raises `RuntimeError` directing the caller to `await read()` |
| `response.aiter_content(chunk_size)` | One uncached consumer, no hidden replay copy; positive integer sizes, short chunks allowed |
| `response.aiter_lines(chunk_size, delimiter)` | Byte lines with LF/CRLF handling; a bytes delimiter is optional |
| `await response.aclose()` | Release ownership once; cached bytes remain readable |

Creating an iterator does not claim the body until its first advancement. Once
uncached iteration or a collection operation starts, a competing consumer is
rejected. An uncached body cannot be replayed: another iteration or full read
raises `StreamConsumedError`. Cached bodies can be read or iterated repeatedly,
including after close. Metadata, Cookies, `location`, `is_redirected` and
`raise_for_status()` do not perform body I/O. Headers are a regular dictionary;
`raw_headers` preserves separate fields, including repeated `Set-Cookie`.

Both async eager and streaming modes strictly decode gzip, zlib/raw deflate and
Brotli. Corrupt or incomplete compressed content raises `ContentDecodingError`.
This deliberately differs from the synchronous eager raw-bytes fallback.
Length/chunked truncation is also an error; close-delimited HTTP/1 bodies end
only when their transport reaches EOF.

`chunk_size` bounds returned chunks, not total memory. TLS records, HTTP/2
receive credit, framing and decompressor state are additional; `aiter_lines()`
may retain one arbitrarily long unfinished line. `read()`, joining chunks or
collecting them into a list intentionally buffers the whole body.

## Pools, concurrent tasks and close

Construction performs no network I/O. Sessions and pools bind to the event loop
at first use and reject cross-loop use. Close is terminal: create a new session
or pool after closing it. Configure policy before starting concurrent tasks;
request state is separate for each task, with snapshots of configuration,
hooks, retry policy and Cookies. There is no shared `session.response` result.

Each default async session owns a private pool. An explicit pool is **borrowed**:
closing one session releases its own work without closing another session's
responses. The caller closes the shared pool after all borrowers finish.

A response returned by an `after_request` hook transfers to the receiving
session, including when the sessions have separate private pools. Closing its
original session stops new pool admissions but preserves transferred responses
until they are consumed or closed. Their connections stay in the original pool
and close after the last active lease is released. An explicit `pool.aclose()`
still closes all of that pool's connections immediately.

```python
import asyncio
from ja3requests import AsyncConnectionPool, AsyncSession

async def fetch_pair(first_url, second_url):
    async with AsyncConnectionPool(max_connections_per_host=4) as pool:
        async with AsyncSession(pool=pool) as first, AsyncSession(pool=pool) as second:
            responses = await asyncio.gather(
                first.get(first_url, timeout=5),
                second.get(second_url, timeout=5),
            )
            return [await response.json() for response in responses]
```

Pool defaults are 10 connections per host, 100 total and a 60-second idle timeout.
Capacity includes pending connections; callers wait asynchronously for available
capacity. HTTP/1 leases are exclusive; eligible HTTP/2 streams share a connection
within peer limits. `use_pooling=False` owns per-request connections and cannot
be combined with an explicit pool.

| Completion or cancellation | Owned resources |
| --- | --- |
| Complete, reusable HTTP/1 body | Return its lease once, after chunked trailers and decoder validation |
| HTTP/1 early close, failure or cancellation | Discard that connection without draining an unlimited body |
| Pooled HTTP/2 complete/early close | Release its stream; early close resets only that stream and preserves other healthy streams |
| Unpooled HTTP/2 close | Close its exclusive connection and join its internal tasks |
| Session close | Stop its in-flight request work and close its remaining responses; stop its owned pool while transferred responses finish |
| Explicit pool close | Close owned transports, wake affected waiters and join internal tasks |

HTTP/2 readers and writers belong to the connection. Response cancellation and
timeouts do not cancel those shared tasks. Flow-control credit follows actual
consumption; a paused stream cannot accumulate an unlimited DATA queue. Several
paused streams can exhaust the aggregate connection budget. Basic DATA fairness
does not add legacy PRIORITY scheduling or server push.
Incoming header blocks and decoded header lists have separate limits, including
after stream cancellation; see [header memory limits](streaming.md#framing-compression-and-memory).

## Timeout, cancellation and request policy

Pass seconds as a scalar or `(connect, read)` tuple. Each value must be finite
and non-negative, or `None`; `None` means no deadline for that phase.

- The connect budget covers pool admission, DNS, TCP, proxy negotiation and TLS
  setup for one attempt, including address candidates.
- The read-side value bounds pending request writes/flow-control waits and this
  response's next awaited read progress. Time spent processing a chunk in your
  application is excluded; another H2 stream does not reset this deadline.
  Streaming uploads apply this value to each source/read-write progress wait;
  the separate response-header wait starts when upload completes. Early responses
  remain observable while the request is still being sent.
- Each retry or redirect hop gets new phase budgets. Backoff uses cancellable
  async waits. Hooks have caller cancellation, without a separate network timer.

Owned phase expiry raises `ja3requests.Timeout`. External
`asyncio.CancelledError` remains cancellation and does not trigger a retry.
Cancellation detaches the owned lease and finishes scoped cleanup. For an overall
deadline, wrap the complete request and body operation in `asyncio.wait_for`;
it also waits for cancellation cleanup, so the deadline is not an exact
wall-clock cutoff. There is no separate total-timeout option.

Reuse `HTTPRetry` for eligible methods, statuses and transient transport failures.
No automatic retry follows TLS authentication/protocol failure, decoding failure,
hook failure, cancellation or any later consumption of a returned response.
Partial sends do not establish that a request ran exactly once. Exhaustion with
`raise_on_status=True` raises `MaxRetriedException` with the final response
attached as `error.response`; it does not create `session.response`.
An HTTP/2 `GOAWAY` with a nonzero error code is a connection failure and is not
automatically retried. A graceful `GOAWAY(NO_ERROR)` still lets accepted streams
finish; rejected streams remain subject to the configured retry policy.

Response `Set-Cookie` fields update both the Session jar and the request's
snapshot, including expiry and deletion. Status retries rebuild automatically
generated Cookie headers from that updated snapshot; explicit or hook-modified
Cookie headers retain their precedence. Cookies passed to one request are not
persisted in the Session unless the server sets them in a response.

Async redirects preserve method/body for 307/308, change POST to GET for 301/302,
and use GET for 303 except HEAD. The limit is eight redirects. Cross-origin hops
strip authorization, proxy authorization and manually supplied Cookie headers.
`head()` defaults to `allow_redirects=False`. This redirect behavior differs
from the current synchronous GET-based follow-up path.

Hooks use `before_request` and `after_request`, with session registrations before
request registrations. Callbacks may return synchronously or return an awaitable.
`before_request` runs once per prepared hop, before its retries; `after_request`
runs once for the final policy-selected response. An async response replacement
must belong to the same loop. Replacements and failures close only responses
still owned by that session. If another session has already adopted a response,
cancelling its original request, failing its hook or replacing its response does
not close the transferred response. Awaiting `read()` in a response hook
deliberately buffers it. Synchronous callbacks run on the loop and must avoid
blocking it.

Hook coroutines retain their request's context. Cancelling a request asks its
hook coroutine to stop, while session resource cleanup proceeds without waiting
for user-defined `finally` blocks or hooks that suppress cancellation. If a
synchronous callback returns an existing `asyncio.Task` or `Future`, that object
remains application-owned: request cancellation stops waiting for it without
cancelling it. The application remains responsible for that task's lifetime.

## TLS, HTTP/2, proxies and first-version scope

The same `TlsConfig` controls verification, ClientHello/JA3 fields, in-memory TLS
resumption and client certificates. Default ALPN remains HTTP/1.1. To offer H2,
set `config.alpn_protocols = ["h2", "http/1.1"]` before creating the session; a
request's `h1=True` forces HTTP/1.1. The fingerprint and secure-profile limitations
in the [TLS](tls.md) and [wire-control](tls_wire_control.md) guides still apply.

The implementation covers direct HTTP/HTTPS, project TLS1.2/1.3, negotiated H2,
HTTP CONNECT and SOCKS4a/5, in-memory Cookies, hooks, retry/redirect policy and
compressed response streaming. Proxy routes are explicit request arguments;
environment proxy discovery and an HTTPS connection to the proxy are outside
the first scope. Unlike the synchronous simple parser, async accepts `http`,
`socks4`, `socks4a`, `socks5` and `socks5h` URLs with an explicit host and port,
percent-decodes credentials, and includes the proxy URL in its connection-pool
key. See the [API-specific proxy contracts](proxies.md#native-asyncsession).

Request bodies support in-memory bytes/text, form fields and JSON. Streaming
uploads add binary files, byte iterators and async byte iterators as
`data=`, and streaming multipart paths/handles as `files=`. See the
[upload contract](streaming.md#streaming-request-bodies) for length,
replay, cancellation and caller ownership. Pre-encoded multipart bytes can still
be supplied as `data` with their matching Content-Type.
Awaited `save_cookies()` and `load_cookies()` reuse the synchronous
file format with detached snapshots, serial file operations and owned cancellation
cleanup. See [async Cookie files](cookie_persistence.md#native-async-files).

Deferred interfaces are a public prepared-request/`send()` API and async module-level
convenience functions. HTTP/3, QUIC, ECH/PQ, 0-RTT, server push, Trio/AnyIO and
cross-loop pools are not added by this implementation.

Use the [self-contained local async example](examples.md#native-async-loopback-example)
to exercise the public API without external services. The
[generated async reference](api/async.md) reads the current source signatures.
Local examples and syntax checks do not replace installed-package and actual
supported-Python/OS runtime evidence.
