# Native async API design (#37)

Status: implemented for version 2.1.0; design selected on 2026-10-04.
`AsyncSession`, `AsyncResponse` and `AsyncConnectionPool` are exported. Dated
verification and completion state are recorded in [async execution](async_execution.md).
The implementation builds on the synchronous work including #41. This document
remains the design contract; the dated development acceptance is not a claim
about a later release's CI. See the [2.1.0 release](https://github.com/lxjmaster/ja3requests/releases/tag/v2.1.0)
for publication evidence.

## Decision and boundary

Recommend native `asyncio` socket I/O for `AsyncSession`/`AsyncResponse` while
retaining the project's ClientHello, TLS 1.2/1.3 handshake, authentication,
record protection, resumption and H2 state. Share existing codecs/crypto and
separate their state transitions from blocking I/O. Do not introduce an SSL
client backend, `start_tls`, another HTTP client or a generic backend framework.
Independent SSL/OpenSSL test servers remain valid oracles.

| Approach | Benefit | Actual limitation |
| --- | --- | --- |
| Native async using project TLS | Cooperative waits, explicit ownership, stream cancellation and backpressure | Requires I/O/state separation; crypto still occupies the loop while executing |
| Executor bridge around `Session` and iteration | Smaller initial patch; can preserve existing wire behavior | Cancelling an await does not stop a running worker's socket operation; response ownership survives the waiter and H2 retains its reader thread |

A bridge is an application migration option, not this native API. Performance
improvement is a measurement question, not an assumption of the design.

## Grounding in the synchronous source

| Current source/symbols | Reuse or split |
| --- | --- |
| [sessions.py](../ja3requests/sessions.py): `Session.request`, `send`, `resolve_redirects`, hook dispatch | Replace blocking orchestration and `threading.local`; `BaseSession.response` is also shared, not task-local. |
| [requests/request.py](../ja3requests/requests/request.py): `Request.request`; [base/__contexts.py](../ja3requests/base/__contexts.py): `message`, `body` | Reuse normalization/serialization after detaching synchronous request factories; freeze payloads because serialization mutates state. |
| [protocol/sockets.py](../ja3requests/protocol/sockets.py): `create_connection`; [base/__sockets.py](../ja3requests/base/__sockets.py): `_new_conn` | Replace blocking DNS/connect and synchronous `Retry.do`; retain address validation/socket options. |
| [protocol/tls/__init__.py](../ja3requests/protocol/tls/__init__.py): `TLS.handshake`, `_handshake_tls12`, `_handshake_tls13`, `_receive_server_hello`, `_parse_server_handshake_messages`, `_send_client_finishing_messages`, `_read_server_handshake_record` | Separate transcript/protocol transitions from direct `recv`, `sendall`, `settimeout`; preserve pending records at handoff. |
| [client_hello.py](../ja3requests/protocol/tls/layers/client_hello.py), [extensions](../ja3requests/protocol/tls/extensions/__init__.py), [config.py](../ja3requests/protocol/tls/config.py), [client_hello_info.py](../ja3requests/protocol/tls/client_hello_info.py) | Reuse validation/serialization/inspection and configured ordering, GREASE, key shares, record version and identity. |
| [crypto.py](../ja3requests/protocol/tls/crypto.py), [tls13.py](../ja3requests/protocol/tls/tls13.py): `TLS13Handshake`, `TLS13KeySchedule`, `TLS13RecordProtection` | Reuse byte-driven state and crypto per connection; separate ordered outbound post-handshake effects. |
| [certificate_verify.py](../ja3requests/protocol/tls/certificate_verify.py), [session_cache.py](../ja3requests/protocol/tls/session_cache.py) | Reuse authentication, expiry and identity policy; separate blocking CA/key file reads and keep cache locks outside I/O/awaits. |
| [sockets/https.py](../ja3requests/sockets/https.py): `_TLSRecordReader`, `_ResponseConnection`, `_recv_exact`, `_decrypt_single_record`, `_send_h1`, `_send_h2` | Replace `RawIOBase`/`BufferedReader` and socket waits; preserve authenticated record/pending-byte rules. [record_layer.py](../ja3requests/protocol/tls/record_layer.py)'s `TLSSocket` is not the active request adapter. |
| [response.py](../ja3requests/response.py): `HTTPResponse.handle`, `_iter_raw_body`, `iter_body`, `_finish` | Extract framing/decoding from `fp.read/readline/read1`; retain single release, incremental decoding and consumed-body rules. Current eager decoding tolerates errors. |
| [H2 frames](../ja3requests/protocol/h2/frame.py), [HPACK](../ja3requests/protocol/h2/hpack.py), [Huffman](../ja3requests/protocol/h2/huffman.py) | Reuse codecs; HPACK state belongs to the connection. |
| [connection.py](../ja3requests/protocol/h2/connection.py): `_read_frames`; [multiplex.py](../ja3requests/protocol/h2/multiplex.py): `H2MultiplexConnection` | Replace `_recv`, `threading.Condition`, `_wait_for` and reader thread; retain validation, windows, buffer accounting and discarded-header state. |
| [pool.py](../ja3requests/pool.py): `get_h2_or_reserve`, reservation/stream release, `close_all` | Reuse identity/generation invariants; replace condition waits/global ownership with loop-bound admission. |
| [retry.py](../ja3requests/retry.py): `HTTPRetry`; [proxy.py](../ja3requests/sockets/proxy.py), [socks.py](../ja3requests/sockets/socks.py) | Reuse policy/encodings; replace sleeps and proxy handshake I/O. Consume complete CONNECT headers and preserve trailing bytes. |

## Implemented API and response contract

The following names are exported locally. Preserve Python >=3.7 and sync APIs;
distinguish metadata/syntax compatibility from actual tested runtimes.

| Surface | Contract |
| --- | --- |
| `AsyncSession(tls_config=None, pool=None, use_pooling=True, hooks=None, retry=None)` | Construction performs no I/O. `async with` and `await aclose()` manage session lifetime. |
| `await session.request(method, url, *, ...)` | Support current in-memory params/data/json/headers/cookies/auth/proxies/timeout/verify/tls_config plus stream/allow_redirects/hooks/h1 options. Return `AsyncResponse`. Verb methods await the same path; HEAD defaults redirects off. |
| `await response.read()` | Collect/cache decoded bytes. `await text()` decodes using assignable `encoding`; `await json()` parses JSON. |
| `response.aiter_content(chunk_size=1024)` | Async iterator, one uncached consumer, no replay buffer; positive integer sizes only, excluding bool; short chunks allowed. |
| `response.aiter_lines(chunk_size=512, delimiter=None)` | Async byte-line iterator with current LF/CRLF semantics; may retain one arbitrarily long incomplete line. |
| `await response.aclose()` / `async with response` | Idempotent local resource release; no hidden task-scheduling synchronous close method. |
| Metadata / `raise_for_status()` | Immediate status, headers, cookies, request, encoding, location and redirect information; status check performs no I/O. |
| `.content` | Cached bytes only. Before a full read: `RuntimeError` directing the caller to await `read()`; after uncached iteration begins: `StreamConsumedError`. |

`stream=False` reads/caches before return; `stream=True` returns after headers
and policy/hooks. First iterator advancement claims an uncached body; competing
consumption or replay raises `StreamConsumedError`. Cached content remains
readable after close. Both async modes use strict incremental decoding and raise
`ContentDecodingError` for corrupt/incomplete data. This deliberately differs
from sync eager fallback to raw bytes; the sync compatibility behavior is unchanged.

Usage in the development checkout:

```python
async with AsyncSession(tls_config=config) as session:
    async with await session.get(url, stream=True, timeout=(3, 10)) as response:
        response.raise_for_status()
        async for chunk in response.aiter_content(65536):
            consume(chunk)
```

Breaking from `async for` alone does not guarantee immediate generator cleanup;
use the response context or `aclose()`. Initially expose request/verb methods,
not `send()` accepting synchronous transport objects or a new public prepared
request type. Hooks receive normalized request metadata, never a blocking sender.

## Ownership, pool and task context

Bind sessions/pools at first use to one loop; reject cross-loop use before I/O.
A new `AsyncConnectionPool` uses existing capacity/idle settings plus `aclose()`.
Default pools belong to their session; explicit async pools are borrowed.
Reject a supplied pool with `use_pooling=False`. Session close is terminal.

| Action | Exact resource scope |
| --- | --- |
| HTTP/1 valid framing EOF | Return its reusable lease once, after chunked trailers; close-delimited EOF cannot reuse the transport. |
| HTTP/1 early close/cancel | Discard its connection without draining an unbounded body. |
| Pooled H2 finish/close/cancel | Release/reset its stream only; preserve healthy TLS and unrelated streams. |
| Unpooled H2 close | Close its exclusive transport and join its internal tasks. |
| Session close | Stop its requests/responses; close its owned pool, or release only its leases in a borrowed pool. Do not close another session's streams. |
| Explicit pool close | Close all transports it owns, wake affected borrowers and join its tasks. |

Leases carry pool/generation, connection and stream identity. Detach once before
reuse; late close/decoder errors cannot harm a new owner, and late releases
cannot revive a closed generation. Admission counts active leases/streams and
pending connects, enforcing peer stream limits and GOAWAY. Cancellation removes
only that waiter's state; cancelling a connection creator closes its candidate
and releases the creation reservation. Never let one waiter cancel a shared Future.

Pass request/attempt/redirect state explicitly; do not expose shared
`session.Request`/`session.response` fields. Diagnostic `ContextVar` values must
be immutable and reset in `finally`, including nested hooks. Connection tasks
must not retain their creator's request context. Snapshot configuration, hooks,
retry policy and cookies before awaits, preserving cache identity. Cookie merges
are short loop-local updates; processing order resolves conflicts. Do not await
I/O/hooks under locks or promise cross-thread configuration/cache sharing.

## Cancellation and timeout policy

Always re-raise `asyncio.CancelledError` after scoped cleanup, before broad
handlers; never map it to a retry, empty body, `False` or timeout. Copied
`TLS.handshake()` exception handling would catch cancellation on Python 3.7;
its base class changed in 3.8. [Python exception change](https://github.com/python/cpython/blob/v3.8.20/Doc/library/asyncio-exceptions.rst)

| Cancellation point | Required behavior |
| --- | --- |
| Admission / pool / H2 slot wait | Remove only its waiter/reservation; no request sent. |
| DNS/TCP/proxy/TLS setup | Close its candidate; ignore late DNS/preparation results; discard partial handshake. |
| HTTP/1 write/header/body read | Discard that connection; uncertain partial-send receipt does not authorize replay. |
| H2 queued, uncommitted work | Withdraw plaintext work and reservation without changing HPACK/TLS state. |
| H2 committed work / response wait or read | Mark only that stream cancelled, discard its queue and order RST_STREAM(CANCEL) after committed frames. |
| Hook / backoff / redirect gap | Close owned response and stop; no next request. |
| Repeated/cancelled `aclose()` | Finish one owner-supervised cleanup; propagate caller cancellation and release exactly once. |

Detach local ownership before the next await. Retain/observe cleanup tasks and
join them at owner shutdown. Shield only cleanup or connection-owned operations,
not a cancelled request. Shared H2 close need not await a reset acknowledgement;
exclusive close wakes its tasks without peer EOF. Shutdown cannot depend on body
draining or user hook completion and must not cancel arbitrary application tasks.

Keep scalar or `(connect, read)` timeout inputs with finite non-negative values
or `None`; validate before admission and use monotonic remaining budgets.

| Phase | Async budget |
| --- | --- |
| Admission, DNS, TCP, proxy, TLS | One connect budget per HTTP attempt, including address candidates and reused-connection admission. |
| Request writes | Read-side value bounds pending bounded writes/window waits per request; never cancel the shared H2 writer on stream expiry. |
| Headers / body progress | Read-side value bounds this response's next awaited progress; other streams do not reset it. Application time between reads is excluded. |
| Retry / redirect / hooks | Each attempt/hop gets new phase budgets; backoff stays cancellable. Hooks have caller cancellation, not network phase timers. |

`None` means no phase deadline, unlike current incidental 15-second TLS/H2 and
5-second pool fallbacks. Defer a total-deadline API; callers may wrap complete
request/body consumption in `asyncio.wait_for`. That waits for cancellation
cleanup, so it is not an exact wall-clock cutoff. Only client-owned phase expiry
maps to `ja3requests.Timeout` with phase information; external cancellation stays
cancellation. Time individual waiters, never shared reader/creation tasks, and
avoid assuming Python 3.7 exception aliases. [Python 3.7 task semantics](https://github.com/python/cpython/blob/v3.7.17/Doc/library/asyncio-task.rst)

## Native TLS/H2 implementation boundary

Use non-blocking `loop.sock_connect/sock_recv/sock_sendall` with bounded input.
`loop.getaddrinfo` may use an executor; ignore late results after cancellation.
CA/key preparation may likewise use a narrow worker returning immutable data,
never a live network socket. Keep bounded crypto/parser work on the loop first;
measure before adding CPU offloading. [Socket APIs](https://github.com/python/cpython/blob/v3.7.17/Doc/library/asyncio-eventloop.rst), [resolver source](https://github.com/python/cpython/blob/v3.7.17/Lib/asyncio/base_events.py)

Extract byte-fed handshake/framing/decoder state for sync and async drivers,
without duplicating TLS engines. Transfer pending bytes and record state once
after authentication. Preserve Finished, certificate, HRR/key-share, resumption,
ALPN, KeyUpdate and supported post-handshake authentication; non-body records are
not EOF. HTTP/1 reads on demand; one H2 reader drives all connection input.

One bounded H2 writer serializes committed output and fairly schedules DATA:

- Cancel uncommitted plaintext. Once HPACK/TLS sequence state advances, send its
  bytes or fail the connection; never silently remove encoded work.
- Keep HEADERS/CONTINUATION contiguous and put resets after committed frames.
- Serialize outbound keys, post-handshake replies and application records; split
  `TLS13Handshake.process_post_handshake` outbound effects accordingly.
- Reserve bounded control capacity so DATA credit waits cannot block reader
  dispatch of WINDOW_UPDATE, SETTINGS/PING acknowledgements or resets.

A stream's cancellation must not interrupt shared `sock_sendall`. A real write
failure fails the connection; a stalled committed write stops new commitments
with bounded output until recovery/pool closure. A connection-wide stall policy
is separate from stream deadlines, never implicit permission to resend.

Reuse current H2 `receive_headers`/`read_stream` separation and cached terminal
EOF. Stream DATA plus unspent credit stays within its configured window;
consumption/discarded padding grants credit. Aggregate DATA plus connection
credit shares `receive_buffer_limit` (connection target plus one stream window).
Preserve initial SETTINGS/WINDOW_UPDATE fingerprints. One paused stream permits
a fast stream to progress; several can exhaust aggregate capacity. TLS/frame/
HPACK/decoder/application memory is additional to that DATA budget.

After cancellation, decode required discarded HEADERS/CONTINUATION to preserve
HPACK, and account for discarded DATA without reopening streams. RST targets
one stream; GOAWAY stops admission while eligible streams finish. Connection
framing/authentication/I/O failure wakes its waiters, not other connections.
Drain gzip/deflate/Brotli 1.2+ decoded output before new input; decoder/native
memory is not a chunk-size/RSS bound. Only `read()` collects the whole body.

## Retries, redirects and hooks

Reuse `HTTPRetry` with frozen replayable body bytes and `asyncio.sleep`. Require
allowed method, remaining count, eligible status/transient transport failure and
no returned response. Never retry cancellation, hooks, TLS authentication/protocol
errors, decoding failure or later consumption of a returned stream, even before
its first byte. GOAWAY/refused-stream errors follow this same policy. Do not
copy the hidden low-level three-connect-attempt loop; address fallback shares
the attempt's connect budget. Partial sends never imply exactly-once execution.

Close intermediates and merge their cookies before retry/redirect. Retain
`total` meaning, numeric Retry-After, jitter and `raise_on_status`. Final status
hooks run before exhaustion; close a raised final response and attach it to the
exception instead of a shared session field. Hook errors cannot trigger retries.

Use an explicit redirect loop and `DEFAULT_REDIRECT_LIMIT`, resolving relative
URLs against the current hop with a retry budget per hop. Follow Location only
for 301/302/303/307/308: rewrite POST to GET for 301/302, use GET except HEAD for
303, preserve method/body for 307/308. Remove body headers when dropping body;
recompute Host/cookies and strip Authorization/Proxy-Authorization/manual Cookie
on origin change without restoring original credentials later. This differs
from current sync redirects, which build GET requests. [HTTP redirect semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4)

Hooks keep existing event names and session-before-request registration order;
accept synchronous callbacks or awaitable results without automatic offloading.
Run `before_request` once per prepared hop before retries, validate/freeze any
replacement, and run `after_request` once for the final policy-selected response
(headers for streams, cached body otherwise, including exhaustion). This removes
current recursive redirect hook-count ambiguity. Awaiting `read()` in a hook
intentionally buffers. On hook failure/cancel close the currently owned response;
a same-loop `AsyncResponse` replacement transfers ownership and closes the
superseded response once. Never call hooks under protocol/pool guards.

## First scope, sequence and acceptance

First release covers existing direct HTTP/HTTPS, project TLS 1.2/1.3, ALPN H2,
CONNECT/SOCKS4a/5, verification/fingerprints/resumption/client authentication,
cookies, policy/hooks, pooling and compressed response streaming. Accept in-memory
data/forms/JSON and encoded multipart bytes. Defer file-object/path uploads,
cookie-file helpers, streaming uploads, public prepared-request APIs and module
convenience functions. Also excluded: new TLS/browser features, HTTP/3, push,
0-RTT, other backends, Trio/AnyIO abstraction and cross-loop pooling.

| Stage | Work | Required exit |
| --- | --- | --- |
| A1. I/O and TLS seam | Extract shared byte-driven state and native socket/TLS driver | Sync wire/authentication tests unchanged; full/resumed TLS, fragmented records and pending-byte handoff verified |
| A2. HTTP/1 lifecycle | Async response framing/decoding, iterators, deadlines, cancellation and close | Headers/prefix before tail, correct EOF/trailer handling and exact resource release |
| A3. Pool, policy and proxies | Async admission/task context, retries/redirects/hooks/cookies and existing tunnels | Creator/waiter isolation, borrowed-pool scope, no implicit replay and proxy/TLS evidence |
| A4. HTTP/2 | Reader/writer scheduling, stream admission/windows and cancellation | Slow/fast isolation, target-only RST, committed-write/HPACK/TLS ordering and GOAWAY tests |
| A5. Integration acceptance | Typing, docs, installed wheel, sync regression and existing Python/OS matrix | Failure matrix below plus retained environment/source and responsiveness/memory evidence |

Dependencies: stabilized #41 contracts, existing protocol fixtures, public typing/
package workflow, `brotli>=1.2.0` and `cryptography`. No new runtime dependency.
Use Python 3.7 `asyncio`/`contextvars`, not TaskGroup/asyncio.timeout/to_thread or
newer cancellation APIs. API availability alone does not prove runtime-matrix
support. Existing test tooling can drive async cases with `asyncio.run`.

These are acceptance requirements, not test results. The execution record names
the actual runtimes, limits and evidence. Use independent event-controlled peers,
request/wire counts and bounded joins; preserve existing sync test oracles.

| Acceptance area / reuse | Required failure evidence |
| --- | --- |
| [HTTP streaming](../test/test_network_streaming.py), [TLS streaming](../test/integration/test_tls_streaming.py) | Headers/prefix before tail for HTTP/TLS/tunnels; length/chunked/close framing, trailers, no-body and truncation outcomes |
| [Decoding/policy](../test/test_streaming_policy.py) | gzip/zlib/raw deflate/br incremental integrity, no replay cache, explicit consumed errors, strict async collector |
| Cancellation at every phase | Admission/DNS/connect/proxy/TLS/write/headers/body/hooks/backoff cancellation propagates unchanged, sends no follow-up and leaks no lease/socket/waiter; Python 3.7 plus current supported Python |
| EOF/close/consumer race | One body consumer, one release; old responses cannot close reused transports; unpooled H2 tasks exit without peer EOF |
| [Pool generation](../test/test_pool_generation.py), [context](../test/test_session_concurrency.py), [timeouts](../test/test_delivery_timeouts.py) | Generation accounting, creator/waiter isolation, redirect task context, loop affinity, borrowed-pool closure and per-response deadlines |
| [H2 streaming](../test/integration/test_h2_streaming_network.py) | Paused stream gains no unconsumed credit; target-only RST leaves active stream 3 and subsequent stream 5 usable on the same TLS connection |
| H2 write pressure / discarded frames | Cancel before/after commitment without skipped TLS sequence, truncated header block or HPACK desync; preserve [discarded headers](../test/integration/test_h2_discarded_headers.py), [padding](../test/integration/test_h2_padded_data.py), [disconnect](../test/integration/test_h2_disconnect.py) and GOAWAY behavior |
| [Wire control](../test/test_wire_control.py), [secure profiles](../test/integration/test_secure_profile_matrix.py), [KeyUpdate](../test/test_tls13_key_update.py), [post-handshake auth](../test/integration/test_tls13_post_handshake_auth.py) | Independent captures/authentication, verified cache identity and record/key ordering; cancelled handshakes publish no reusable connection |
| Retry/redirect/hook counts | No replay after cancellation/returned streams/hook errors; cookies and origin stripping correct; 307/308 body retained and hooks run at specified boundary |
| Responsiveness/memory/shutdown | Loop heartbeat progresses during gated I/O; queues stay within configured budgets; distinguish Python/native/RSS memory; owner exit leaves no internal tasks/test sockets |
| Distribution | Sync regression, supported Python/OS CI, external typed installed-wheel consumer and docs pass before advertising the API |

The selected implementation applies the visible differences described here:
borrowed pools, awaited body/cache-only content, strict decoding, timeout budgets,
hook counts, redirect methods and deferred files. The project-owned TLS boundary
remains fixed. Remote CI, source delivery and publication require their own
selected delivery scope; a local implementation is not published-runtime proof.
