# Streaming upload design and implementation map

Prepared: 2026-10-08. This is the U0 design for the selected streaming upload
work. It does not claim that any runtime slice has been implemented or accepted.
Implementation status and evidence belong to the
[delivery plan](next_delivery_and_client_plan.md); this document is its design
artifact, not a second execution workline.

## 1. Outcome and boundaries

Deliver streaming request bodies through synchronous and asynchronous HTTP/1.1
and negotiated HTTP/2, then provide asynchronous streaming `files=` convenience.
Retain Python >=3.7, the project's TLS/H2 engines, certificate authentication,
existing session defaults, hooks, proxy routing and retry policy. S1 design and
F1 Cookie-file helpers are not technical prerequisites for this work.

Use these independently acceptable slices:

| Slice | Delivered capability | Technical dependency |
| --- | --- | --- |
| U1a | Async HTTP/1.1 streaming over direct HTTP, project TLS, and existing proxy routes | This body and policy contract |
| U1b | Async negotiated H2 streaming with bounded producers and stream isolation | U1a source/policy adapter; existing H2 engine |
| U1c | Sync HTTP/1.1 streaming through the existing public request entrypoints and routes | Shared source/framing rules; U1a evidence can guide tests |
| U1d | Sync negotiated H2 streaming through `H2MultiplexConnection` | U1c preparation; existing sync H2 engine |
| U2 | Async streaming multipart `files=` | U1a and U1b for its advertised async transport coverage |

Recommended integration order is U1a -> U1b -> U1c -> U1d. U2 can be integrated
after U1b without waiting for synchronous uploads. The complete U1 target still
requires all four slices. A partial slice must state its transport support and
reject an unsupported negotiated path before consuming a source or sending
request headers. In particular, U1a must not silently force HTTP/1.1 when the user
selected an H2 fingerprint; its examples can use the existing `h1=True` option.

No buffering fallback replaces streaming in these slices. Existing in-memory
bytes, text, forms and JSON remain valid and keep their current public behavior.
Do not add a public prepared-request API, arbitrary source factory registry,
upload scheduler, separate timeout options, automatic authentication challenge
retries, request trailers, or a new transport implementation.

## 2. Selected public API

Extend the existing `data=` argument instead of adding a wrapper class or a new
request option:

| Input | Session | AsyncSession | Interpretation |
| --- | --- | --- | --- |
| Existing `str`, `bytes`, `dict`, `list`, `tuple` | Existing behavior | Existing behavior | Existing in-memory encoding branches take precedence |
| Binary file object with `read(size)` | Stream | Stream; file operations run off-loop | Read from its current position |
| `Iterator[bytes]` | Stream | Stream; `next()` runs off-loop | One-shot chunk source |
| `AsyncIterator[bytes]` | Reject | Stream | Await `__anext__()` on the owning loop |

Accept actual iterators, not arbitrary iterables. Use `iter(chunks)` when chunks
are stored in a list: a list remains a form input. Reject text file objects and
non-byte yielded values; do not implicitly encode producer output. Raw upload
sources do not receive an inferred form or JSON Content-Type. A caller can set
Content-Type through the existing headers argument.

Examples of the intended API after the relevant slice is implemented:

```python
with open("payload.bin", "rb") as source:
    response = session.put(url, data=source)

async def chunks():
    yield b"first"
    yield b"second"

async def upload(url):
    async with AsyncSession() as session:
        first = await session.post(
            url,
            data=iter((b"first", b"second")),
            headers={"Content-Type": "application/octet-stream"},
            h1=True,
        )
        second = await session.post(url, data=chunks())
        return first, second
```

Use separate static aliases: keep `Params` unchanged; extend synchronous `Data`
with `BinaryIO` and `Iterator[bytes]`, and define `AsyncData` to add
`AsyncIterator[bytes]`. Update async helpers and `AsyncRequestOptions` to use
`AsyncData`. Do not allow an async source in synchronous signatures. Update the
public hook metadata annotation when it can contain an upload source; existing
in-memory metadata bodies remain bytes. All new typing names must be compatible
with the project's Python 3.7 runtime import policy.

### Length and framing inputs

Use `Content-Length` as the existing explicit length input; add no separate
`length=` argument. For a seekable binary file, snapshot the current offset and
remaining byte length without reading its contents. Prefer regular-file metadata
or a seek-to-end-and-restore sequence where supported. If length discovery cannot
restore the original offset, fail before sending. Non-seekable files and
iterators have unknown length unless the caller supplies Content-Length.

For a new streaming input, validate the caller's framing headers before the
existing header normalizer can collapse duplicate case variants. Accept one
non-negative decimal Content-Length value, reject ambiguous duplicates and
invalid values, and compare it with a discovered file length. Reject user-set
Transfer-Encoding for streaming inputs: the selected transport generates
framing. Do not combine Content-Length and Transfer-Encoding. Existing buffered
input compatibility decisions remain outside this change.

The declared length describes the entire selected source, not a request to send
a prefix of a longer file or iterator. Count produced bytes. Reject premature
EOF or excess output with `InvalidData`; never send excess bytes. If exact EOF
requires one additional source read, perform that read before declaring upload
completion, under the same source timeout. Do not buffer the source to verify
length. Skip empty iterator chunks; empty `read(size)` on a file means EOF.

## 3. Small internal source adapter

Add a private `ja3requests/_upload.py` implementation, using a small concrete
adapter rather than a public inheritance hierarchy. It records source kind,
optional length, initial file offset, whether a source pull has begun, current
byte count, one pending chunk/offset, and ownership. Its operations are:

- `read_piece(limit)`: return at most `limit` bytes, with EOF distinct from an
  empty iterator chunk. Retain at most the unconsumed part of one yielded chunk.
- `rewind()`: restore the captured file offset, or reject a consumed one-shot
  source. Rewind includes resetting byte counts and pending chunk state.
- `close_owned()`: release resources created by the library; detach borrowed
  resources without closing them.
- `afinish_producer()`: on the async producer task, finalize a native async
  generator that this request has started, preserving its original Context.

An async facade drives these operations with awaited async iteration or an
owned executor job. The adapter does not own retry, redirect, authentication,
HTTP framing or connection policy. Buffered bodies can use a trivial bytes
adapter where useful without changing their public metadata representation.

Start with an internal 64 KiB file-read/piece limit. HTTP/2 DATA pieces are also
bounded by the peer's frame size and both send windows; TLS plaintext records
keep their existing 16 KiB bound. These are internal implementation constants,
not a new public tuning surface.

### Ownership and blocking I/O

Borrowed files, synchronous generators and custom async iterators remain
caller-owned: do not call their `close()` or `aclose()` automatically. They may
be consumed on success, failure or cancellation; the caller must not read, seek,
close, reuse or mutate them concurrently with an upload. A borrowed source used
in a second independent request starts from its then-current state.

The second review refines native async-generator ownership: require a fresh
generator per request. Once the request starts advancing it, that producer must
also finalize it before exiting, in the same task and Context. This includes
early responses and stops between yields. Unstarted generators remain untouched;
generators already advanced in a different task/context are outside this
contract. A producer's first stop request begins cleanup; subsequent library
cancellation paths join it without interrupting its finalizer. A source-raised
CancelledError terminates and cleans up only its request, without network retry.

Use Python 3.7's `loop.run_in_executor()` for synchronous file operations and
iterator pulls in AsyncSession. Catch StopIteration inside the worker and return
an EOF sentinel instead of setting StopIteration as an asyncio Future exception.
Keep at most one such job per source and do not invoke two operations on a
borrowed handle concurrently. Async iterators must be cooperative; the library
cannot make a blocking `__anext__()` implementation responsive.

Cancellation or a timeout stops further pulls and discards late results. Stop
network work promptly, then join the current worker before returning control of
the borrowed source or closing a library-owned handle. Cancellation may therefore
wait for one already-running blocking file/iterator call. A thread cannot be
safely force-stopped, so neither request cancellation nor session close promises
a wall-clock bound for an unresponsive user source. This wait must not block the
event loop or unrelated H2 streams. Observe each worker result/exception once;
do not leave fire-and-forget jobs reading a handle after cleanup was reported.

### Memory claim

For fixed-size file reads, library upload buffering is independent of total file
size. For an iterator, it also includes the largest source-owned yielded chunk:
splitting a huge chunk does not make that original allocation disappear.

Document the measured bound as source chunk retention + one pending piece +
framing/TLS overhead, multiplied by the active upload count, plus the existing
bounded H2 control/receive state. Caller-owned payloads, multipart field metadata,
OS socket buffers and executor internals are separate contributors. Do not claim
a process-memory bound equal to 64 KiB or a bound independent of stream count.

## 4. Request policy and errors

Prepare an adapter after before-request hooks have chosen the source and before
the first attempt sends headers. Header/body validation does not consume a
source. Repeated async `_freeze()` calls must not reread a file, restart an
iterator, deep-copy a handle or allocate a fresh replay state for the same body.
Keep one replay state across attempts and body-preserving redirect hops. A hook
that selects a different body gets a new source state; dispose of library-owned
resources for the replaced source first.

Preserve existing hook ordering: sync invokes before-request hooks before its
attempt loop; async invokes them per redirect hop. Neither gains implicit
per-attempt hook calls. Preserve current cross-origin removal of Authorization,
Proxy-Authorization and explicit Cookies, and current per-request Cookie views.
Auth remains the existing Basic-auth tuple; source support does not add a 401/407
challenge engine.

| Situation | Selected outcome |
| --- | --- |
| Retry is not allowed by existing method/status/error policy | Preserve existing outcome; source replayability grants no new retry authority |
| Existing policy allows retry before any source pull began | The same unconsumed source may be used |
| Allowed retry after a seekable file was pulled | Rewind to the captured initial offset, then retry |
| Allowed retry after an iterator or non-seekable file was pulled | Raise `StreamConsumedError`, preserving the response/cause where available |
| Rewind fails | Raise `StreamConsumedError`; do not send another request |
| Invalid chunk, source read failure, or length mismatch | Raise `InvalidData` with original cause; do not treat it as a retryable network error |
| Async 307/308 or another existing body-preserving redirect | Reuse the logical source with the same replay checks |
| Existing redirect policy changes to a bodyless GET | Stop/dispose the old upload and remove entity headers as today |

Caller-owned replayable files must remain byte-stable for the logical request.
Seeking or reopening enables replay but cannot prove that an external writer
has left the content unchanged. Do not add full-file hashing, disk snapshots or
locks as prerequisites. Detect observable length mismatches; document the
caller-stability requirement.

Keep synchronous redirect behavior unchanged: it currently constructs bodyless
GETs, including on 307/308. The upload work must document that difference instead
of silently fixing it. `allow_redirects=False` remains available. In contrast,
async already preserves the body on 307/308 and must enforce the replay check.

`RequestException` derives from IOError. Consequently the sync broad OSError
retry handler must explicitly exclude `InvalidData` and `StreamConsumedError`;
HTTPS wrappers must preserve these exception types instead of converting every
source failure into ConnectionError. Async already excludes most non-Timeout
RequestException instances from transport retries; retain that distinction.

Use the existing read/write timeout budget for source progress, credit waits and
socket writes; add no public timeout fields. Empty chunks are not progress and
must not repeatedly reset the deadline. Yield control during empty async output.
For sync borrowed blocking reads/iteration, the caller remains responsible for
the source returning: socket timeouts cannot interrupt arbitrary local code.

## 5. HTTP/1.1, TLS and early responses

Known-length sources emit raw content with Content-Length. Unknown-length sources
emit HTTP/1.1 chunks and a final zero chunk, with no Content-Length. Chunking is
transport framing; do not expose encoded chunk bytes as the application body.
The selected streaming API assumes an HTTP/1.1-capable endpoint; a 411 response
does not authorize automatic buffering or an unsafe replay. The framing and
concurrent response observation requirements follow
[RFC 9112 sections 6.2, 6.3, 7.1 and 9.5](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.2).

Separate request headers from body writes. Do not build `wire + request.body` or
use `BaseContext.message` to materialize a streaming request. Continue to use
the existing encrypted record writer and certificate-authenticated transport.
Preserve TLS write/key-update serialization; source reads must occur outside
transport locks. A source exception must not bypass transport/lease cleanup.

Observe responses while a streaming body is being sent. Async HTTP/1.1 uses a
single response-reading task and a separately owned upload task, with bounded
source pulls. Reuse the current response parser for interim/final responses;
there must never be two consumers of the same transport read stream. Do not add
`Expect: 100-continue` automatically or wait for it before starting the body.

On final response headers, stop new source pulls and new body pieces. Let an
already-started bounded write finish while the response remains readable, under
its existing write timeout. Do not cancel `AsyncTransport.write()` merely to
signal this stop: cancellation currently closes the transport and can destroy
the response being returned. If a partially sent write cannot finish or the
response ends first, close the connection after preserving any complete response
already obtained; never reuse an incompletely transmitted HTTP/1.1 request.

Do not await a blocked writer before consuming the early response. For eager
responses, complete the existing response collector concurrently; if a valid
complete response is observed first, retain it and close the unfinished upload's
connection to wake the writer. If the write timeout/error wins before response
completion, close and fail the request rather than return a truncated success.
For `stream=True`, keep normal bounded response buffering; do not secretly collect
the entire response. A late write failure closes the connection and is surfaced
by the response reader/close owner. Response EOF or explicit close ends any stuck
write. Finite configured write/read deadlines remain effective; an explicit
unlimited timeout does not introduce a new hidden deadline.

The response and upload share one private exchange/lease owner. `stream=True`
may return final headers while the stopping upload still has cleanup to finish;
response consumption/close and session close must observe that cleanup. Release
the lease once, after the required sides have finished. A normal complete upload
and complete reusable response can return the connection; early-stopped uploads
discard it. A write error before a valid response remains a request error. Do
not suppress malformed/truncated response errors just because an early status
line was available.

For sync HTTP/1.1, retain the synchronous public API and use one owned upload
worker per streaming exchange while the calling thread drives the response
parser. Apply the same stop flag, source ownership, bounded writes and lease
rule. Join that worker at request/response cleanup boundaries. The worker must
not read the response or mutate session Cookies/hooks. Buffered requests retain
their existing path. This is a transport adaptation, not a general task pool.

Route plaintext HTTP proxy/SOCKS writes through the same streaming writer. The
HTTP CONNECT and SOCKS TLS wrappers already reuse HttpsSocket; remove any eager
`message` property access when adapting those wrappers. In particular, the
current proxy TunnelContext copies attributes with `getattr()`, which evaluates
properties: copying a streaming source must not assemble or consume its body.

## 6. HTTP/2 producer and writer integration

Keep one connection writer and existing connection-wide HPACK serialization.
For async streams, a per-stream producer task makes the next source chunk ready;
the connection writer only chooses ready work and never awaits a source read or
`__anext__()`. Maintain at most one pending source operation and one retained
chunk per stream; do not start the next pull while retained bytes remain. A
single lookahead chunk is permitted while credit is zero, allowing EOF to be
discovered without accumulating more body data.

Keep control frames ahead of eligible DATA and rotate among ready streams after
each DATA piece. Pending/slow sources are skipped. Source exceptions terminate
only their stream; they must not escape the shared writer into its `_fail()`
connection path. Finish a committed HEADERS/CONTINUATION block before processing
that stream's cancellation, preserving existing HPACK atomicity.

Add a private begin-upload operation which returns the stream ID after local
validation/reservation, so AsyncSession can await response headers independently
of upload completion. Keep the existing bytes `send_request()` contract and its
tests; it can remain a wrapper waiting for send completion. Track upload and
response completion separately and retain state until lease cleanup is safe.

DATA respects stream and connection windows; frame headers are not charged as
content. Unknown-length EOF can emit empty DATA with END_STREAM even without
positive DATA credit. Do not send HTTP/1.1 chunk syntax or Transfer-Encoding in
H2. Response END_STREAM alone does not mean request transmission has ended; a
complete response followed by peer RST_STREAM/NO_ERROR must remain usable.
These rules follow
[RFC 9113 sections 6.1, 6.9 and 8.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.1).

For the new streaming exchange, allow response consumption while uploading. If
the response completes before the request source is exhausted, stop the producer
and cancel the unfinished stream direction through the existing reset mechanism,
preserving the complete response. Do not send a false successful request
END_STREAM with a mismatching Content-Length. If only final headers arrived,
response/body progress and upload progress can continue concurrently; response
close cancels remaining work. Existing buffered half-close behavior remains
covered separately. Cancellation while waiting for source data or credit must
not close the shared connection or cancel another stream's producer.

Adapt the actual sync public path in `H2MultiplexConnection`, not only the older
base `H2Connection._send_body()`. Read/advance sources outside `_condition` and
TLS locks. Ready streams should release the send turn after a bounded DATA piece;
one stalled producer must not prevent WINDOW_UPDATE, responses, or ready peers
from progressing. Reuse the sync reader thread; preserve independent send/receive
completion and the same early-response/reset and ownership contracts. No HTTP/2
priority-tree implementation is required for this fairness guarantee.

## 7. U2 streaming multipart convenience

Add `files=` to AsyncSession and its helper/type signatures. Use the synchronous
API's mapping convention: a field maps to a path, binary file, or a list of those
values; the new async path also accepts `os.PathLike[str]`. Preserve the existing
meaning of byte paths; bytes are not an implicit inline file payload. Do not add
Requests-style file tuples in this slice. Use binary handles for inline bytes,
for example `io.BytesIO`, when a multipart file part is needed.

With files, `data` may supply ordinary form mappings or ordered field pairs.
Reject raw streaming `data`/raw bytes and files together, and reject JSON with
files. File parts stream through the U1 source adapter. Path handles are opened
in `rb` by the library, one active part at a time, and closed on success/failure/
cancellation. Borrowed binary handles remain open. Reopen paths on an allowed
retry and rewind borrowed seekable files to their original offsets. Any consumed
non-replayable part makes the whole multipart body non-replayable.

Generate a high-entropy boundary once per logical request and reuse it on retry;
do not scan or buffer files to choose it. Freeze form fields, ordering and part
metadata before sending. Use basename only for path filenames; use a supplied
file's basename when meaningful, otherwise its field name. Infer Content-Type
from the filename with an application/octet-stream fallback. Validate names and
filenames before headers are sent: reject CR/LF/NUL, escape quote/backslash in
quoted parameters, and encode non-ASCII parameter text as UTF-8. Do not emit
`filename*`. Multiple files under one field become separate parts with that same
field name. End boundaries and part separators use exact CRLF framing. See
[RFC 7578 sections 4.1-4.4](https://www.rfc-editor.org/rfc/rfc7578.html#section-4).

The encoder owns the top-level Content-Type boundary. An explicitly conflicting
Content-Type is an input error, not permission to emit a header/body mismatch.
Compute total Content-Length from encoded metadata plus known part lengths when
all are available; otherwise use the already selected unknown-length transport
framing. Path stat/read/reopen and synchronous handle operations run off-loop.
File contents must remain stable for the logical request; the replay rule does
not imply cross-process locking or file snapshots.

## 8. Concrete change map

The following new filenames are proposed implementation targets, not existing
files or completed work.

| Area | Files | Required change |
| --- | --- | --- |
| Source adapter | New `ja3requests/_upload.py` | Source classification, bounded pieces, lengths, replay and resource ownership; async facade |
| Public types and exceptions | `ja3requests/_typing.py`, `ja3requests/exceptions.py`, `ja3requests/__init__.py` | Sync/async input aliases; retain existing precise errors and exports; annotate facade |
| Async preparation/policy | `ja3requests/async_sessions.py` | Preserve stream sources through preparation/hooks; replay checks; body/response exchange ownership; U2 signatures |
| Async H1 response/lease integration | `ja3requests/async_response.py`, `ja3requests/async_transport.py`, `ja3requests/async_pool.py` only where ownership requires it | Concurrent response observation; bounded writes; no early lease return or destructive stop cancellation |
| Async H2 | `ja3requests/protocol/h2/async_connection.py`, shared `stream_state.py` as needed | Ready producer state, begin-upload seam, EOF-at-zero-credit, source isolation and completion/cleanup |
| Sync request preparation | `ja3requests/requests/request.py`, `ja3requests/base/__requests.py`, `ja3requests/base/__contexts.py`, `ja3requests/sessions.py` | Accept raw sources without text/form conversion or full message assembly; retry exclusions; preserve existing redirects |
| Sync transport | `ja3requests/requests/http.py`, `https.py`, `ja3requests/sockets/http.py`, `https.py`, `proxy.py`, `socks.py` | Header/body separation, streaming exchange worker, actual H2 multiplex path and proxy context adaptation |
| Sync H2 | `ja3requests/protocol/h2/multiplex.py`, shared `stream_state.py` as needed | Bounded source reads outside locks, send turns, separate response/upload ownership |
| Multipart | New `ja3requests/_multipart.py` | Deterministic metadata/boundary per request; lazy file parts; total length and replay composition |
| Acceptance | New focused upload tests under `test/` and `test/integration/`; `typecheck/valid.py`, `invalid.py`, `README.md` | Independent framing/peer/ownership tests and installed public type coverage for each slice |
| Documentation | `docs/async.md`, `docs/api/async.md`, `docs/api/client.md`, `docs/streaming.md`, runnable upload examples and their existing verifier registration | Input/support matrix, examples, replay/cancellation/memory limitations and async multipart |

Inspect current signatures and concurrent edits immediately before applying each
change. The map is not authority for unrelated refactoring or moving all
transport logic into a new framework. The main integrator owns overlapping
session/type/protocol changes; independent tests/design work may run in parallel.

## 9. Acceptance for every delivered slice

Each slice requires installed positive/negative typing consumers and executable
docs for its newly supported entrypoints. Do not defer U1 public acceptance until
U2. Build/install evidence must identify the actual selected candidate; historical
test counts do not validate new code. Use the existing verifier and docs guides
for command details and source-inventory checks.

| Slice | Minimum independent behavior checks |
| --- | --- |
| U1a | Raw HTTP and trusted project TLS peers verify fixed/chunked bodies, source prefix before EOF, exact payload, EOF/excess errors, early response before producer completion, close/disconnect, retries and async 307/308, cancellation during source/write, pool release, and existing proxy-route payloads |
| U1b | Independently framed H2 peer verifies frame bytes/windows, zero-credit EOF, reduced/zero windows, ready/slow streams plus PING, target-only producer failure/cancellation, HPACK continuity, GOAWAY/reset/early-response interactions, and subsequent same-connection success |
| U1c | Sync direct HTTP/TLS and supported proxy routes verify the U1a source/framing/error cases, worker cleanup, source reads outside TLS locks, and unchanged sync redirect behavior |
| U1d | Actual Session->HttpsSocket->H2MultiplexConnection path verifies fairness and response/control progress under slow sources, source error isolation, credit waits, response completion and resource release |
| U2 | Independent multipart parser/peer verifies fields, repeated files, binary and non-ASCII metadata, exact lengths/separators, unknown-length parts, large files, borrowed-handle ownership, owned-path cleanup, replay and failure on a later part |

Use events/barriers to control source, write and peer progress instead of relying
only on sleeps. Tests must prove that reading the full source is unnecessary
before the peer sees the first body bytes, and that the producer stops advancing
under backpressure. Run memory comparisons with generated fixed-size chunks and
increasing total sizes; count retained chunks/queued work in addition to measuring
peak allocations. Include multiple concurrent H2 uploads to test the per-stream
bound. Do not put a giant prebuilt input buffer into a test and call its total
allocation a library streaming failure.

Maintain library syntax/import/runtime compatibility with Python 3.7 and the
existing Python 3.7-3.13 test matrix. New upload tests must themselves use 3.7-safe
APIs, or use established narrowly justified fixture skips for independent peers.
Run the selected upload tests on locally available supported interpreters,
including 3.7 when available; distinguish actual runs from grammar checks and
unrun CI targets. No new Python-3.9+ runtime helpers such as `asyncio.to_thread`,
TaskGroup or built-in generic annotations may enter the library import path.

For an independently delivered slice, run its focused behavior tests, installed
type consumers, changed runnable docs and relevant existing retry/redirect/
transport regressions. Run full installed-suite acceptance and the existing
>=85% coverage gate at each selected integrated delivery boundary, reusing
unchanged accepted evidence rather than repeating unrelated tools tests for
every internal edit. Keep source manifests, commands and observed outcomes in
the main plan's fresh evidence root. Retain the design, source, tests and evidence;
clean only verified task-owned temporary servers, handles and staging.

## 10. Repository evidence behind these decisions

- [Async request preparation and policy](../ja3requests/async_sessions.py)
  currently enforce replayable bytes, reject Transfer-Encoding, regenerate
  Content-Length, and send the complete HTTP/1 body before reading a response.
- [Async transport](../ja3requests/async_transport.py) already bounds TLS writes
  but closes the transport when an active write is cancelled. Its cancellation
  rule must be respected by the early-response stop path.
- [Async H2](../ja3requests/protocol/h2/async_connection.py) already has a single
  connection writer, control priority, rotating streams and flow control. Source
  reads must not be inserted as blocking awaits inside that writer.
- [Sync source setters](../ja3requests/base/__requests.py) currently eagerly read
  files; [context encoding](../ja3requests/base/__contexts.py) builds full bodies
  and full messages. Both must be bypassed for new raw stream inputs.
- [Sync HTTPS](../ja3requests/sockets/https.py) constructs
  [H2MultiplexConnection](../ja3requests/protocol/h2/multiplex.py) for the actual
  public H2 path. The base H2Connection writer alone is not that delivery target.
- [Shared H2 state](../ja3requests/protocol/h2/stream_state.py) and
  [half-closed upload tests](../test/test_h2_streaming.py) distinguish upload
  completion from response completion and preserve a complete response on reset.
- [Independent async H2 network tests](../test/integration/test_async_h2_network.py)
  already verify control and another request progressing while upload credit is
  zero. Extend that evidence to slow/failing producers instead of replacing it.

This design is ready for implementation selection within the authorized local
work. Runtime completion remains dependent on the observed acceptance above.
