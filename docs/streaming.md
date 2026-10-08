# Streaming responses and uploads

This describes the streaming behavior introduced in 2.1.0. Version 2.0.1 returned
buffered bodies even with `stream=True`.

The examples and eager-compatibility rules below concern synchronous `Response`.
[AsyncResponse](async.md#body-consumption) uses awaited body methods and strict
decoding in both eager and streaming modes.

## Incremental consumption and ownership

```python
from ja3requests import Session
from ja3requests.pool import ConnectionPool

with Session(pool=ConnectionPool()) as session:
    with session.get("https://example.com/data", stream=True, timeout=(3, 10)) as response:
        response.raise_for_status()
        for chunk in response.iter_content(chunk_size=65536):
            print(len(chunk))
```

The request returns after response headers. Iteration receives, frames and
decodes subsequent body bytes incrementally for HTTP/1.1, project TLS1.2/1.3
and negotiated HTTP/2. `iter_content()` yields bytes; `chunk_size` must be a
positive integer. A server delay or read timeout can be observed during iteration.

Valid body EOF returns a reusable HTTP/1 connection to its pool once. Closing
an unread HTTP/1 body discards that connection because the next response boundary
is not available for safe reuse. For HTTP/2, closing one response cancels its
stream and releases its stream slot without closing unrelated streams on a
healthy connection. Intermediate retry and redirect responses are closed too.

Always close a response when stopping early, preferably with `with response:`.
Keep a Session with a dedicated pool alive until its responses finish.

## Replay and full-body properties

| First body operation | Later operations |
| --- | --- |
| Eager request (`stream=False`) | Body is cached; `.content`, `.text`, `.json()` and iteration read the cache |
| `.content` / `.body` / `.text` / `.json()` before streaming iteration | Loads and caches the full body; later iteration reads that cache |
| Begin `iter_content()` or `iter_lines()` on an uncached stream | One consumption only; replay or full-body access raises `StreamConsumedError` |
| Close an unread, uncached response | Further full-body access/iteration raises `StreamConsumedError` |

Iteration does not accumulate a hidden copy of the body. Calling `list()` or
joining all chunks in application code does allocate the full response. A single
iteration generator can be advanced repeatedly; creating a second iterator is
not replay support. Do not run competing consumers on the same Response.

A full-body read that fails, for example because of truncation or a timeout,
also consumes the stream. The first read raises its original error; later body
access or iteration raises `StreamConsumedError` instead of returning empty bytes.

`iter_lines(chunk_size=512, delimiter=None)` yields byte strings, splits on LF
by default, and strips an immediately preceding CR. It can retain one incomplete
line, so a server sending one enormous line still requires memory for that line.
Pass a bytes delimiter for another separator. Decode text explicitly using the
response's encoding when appropriate.

## Framing, compression, and memory

HTTP/1 handles Content-Length, chunked framing and close-delimited bodies, along
with no-body responses such as HEAD/204/304. A truncated length/chunked body is
an error; socket closure is valid EOF only when the framing permits it.
Incremental gzip, deflate and Brotli decoding occurs before chunks reach the
caller. Invalid or incomplete compressed content raises `ContentDecodingError`
rather than silently returning the encoded bytes. Text/JSON decoding can add
its own errors after the body is read.

That strict error contract belongs to incremental iteration. The eager
compatibility path, including accessing `.content` before iteration, still
returns the original bytes when its decompressor rejects a body.

Memory is not specified as `<= chunk_size`: framing buffers, TLS records,
HTTP/2 receive windows, compression state and application buffers also matter.
The Brotli path requires version 1.2 or later and calls its output-limited
incremental API, draining pending output before reading more network input.
With the selected limit, Brotli 1.2 uses its initial 32 KiB native output block;
that is a bound on one decoder output block, not the decoder's history window,
all Python/native allocations, or process RSS. Each H2 stream has a bounded
receive buffer under its negotiated/configured flow-control window, and stream
credit advances with consumption. A slow stream therefore does not grant itself
unbounded credit while other streams continue.

Both synchronous and async HTTP/2 clients also bound incoming response headers,
trailers and discarded headers from cancelled streams. The decoded header-list
limit is the client's configured `SETTINGS_MAX_HEADER_LIST_SIZE` (16 KiB by
default), counting name/value bytes plus 32 bytes per field. Compressed header
blocks have a separate local limit of `max(64 KiB, 4 * header-list limit)`.
Exceeding either limit fails the connection rather than retaining an incomplete
block or reusing uncertain HPACK state. These checks do not change the advertised
SETTINGS or request fingerprint.

The [local example](examples.md) demonstrates the first chunk arriving while a
loopback server deliberately holds the remainder. The performance suite records
first-chunk/body timing and Python allocation measurements separately; it does
not equate `tracemalloc` with total process/native memory.

## Streaming request bodies

Pass a binary file or a byte iterator as `data=`. `AsyncSession` also accepts
an async byte iterator. This works over HTTP/1.1, project TLS1.2/1.3, negotiated
HTTP/2 and the existing supported proxy routes. `stream=True` controls the
**response**; an upload source streams with either response mode.

| Input | Synchronous API | AsyncSession |
| --- | --- | --- |
| `bytes`, text, form mappings/pairs, JSON | Existing buffered encoding | Existing buffered encoding |
| Binary file opened in `rb` | Stream from its current offset | Stream; file operations run in a worker |
| `Iterator[bytes]` | Stream | Stream; `next()` runs in a worker |
| `AsyncIterator[bytes]` | Unsupported | Stream on the owning event loop |
| A list/tuple of chunks | Existing form interpretation; use `iter(chunks)` | Same |

```python
from ja3requests import Session

with Session() as session:
    with open("payload.bin", "rb") as source:
        with session.put("https://example.com/upload", data=source, timeout=10) as response:
            response.raise_for_status()
```

```python
from ja3requests import AsyncSession

async def chunks():
    yield b"first"
    yield b"second"

async def upload(url):
    async with AsyncSession() as session:
        response = await session.post(
            url, data=chunks(), headers={"Content-Type": "application/octet-stream"}, timeout=10
        )
        response.raise_for_status()
        return await response.text()
```

Text files and non-byte chunks are invalid. Raw streaming sources do not receive
an inferred Content-Type. Empty iterator chunks are skipped; a file's empty
`read()` means EOF. Ordinary binary files and standard `io.BytesIO` have their
remaining lengths discovered without reading their contents. Other wrappers,
including `gzip.open(..., "rb")`, retain an unknown length unless Content-Length
is supplied; their underlying file size may differ from their output size. They
are not scanned in advance. Unknown lengths use HTTP/1.1 chunked framing or H2
DATA; H2 never receives HTTP/1 chunk syntax.

An explicit Content-Length must be one non-negative decimal integer and match
the entire selected source. Duplicate case variants, premature EOF, excess bytes
and user-supplied Transfer-Encoding are rejected for streaming inputs. Excess
bytes are never sent. Confirming exact EOF may require one final source read.

### Upload replay and ownership

Files, synchronous generators and custom async iterators remain caller-owned
and are not automatically closed. Do not read, seek, close or mutate a source
concurrently with the request; keep file contents stable through any retries.
A separate new request starts from a borrowed source's then-current position.

Pass a fresh native async generator (an `async def` function containing `yield`)
to each request. Once the request starts advancing it, the upload task also owns
its finalization: normal completion, an early response, failure or cancellation
runs its `finally` in that same task and context. A generator never advanced by
the request is left untouched. This makes `ContextVar` token cleanup safe even
when transmission stops between yields. A generator already advanced in another
task/context is outside this contract; custom async iterators keep their own
resource-management contract and are not automatically passed to `aclose()`.

Only the existing retry policy authorizes a retry. A consumed seekable file is
rewound to its captured initial offset. A consumed iterator or non-seekable file
raises `StreamConsumedError` when replay is required. Invalid chunks, read failures
and length errors raise `InvalidData` and are not network retry triggers.
Async 307/308 redirects preserve the body with these replay rules. The synchronous
client retains its existing bodyless GET follow-up, including for 307/308.

The response can arrive before the source finishes. Final HTTP/1 headers stop
new body pulls; an unfinished upload makes that connection non-reusable. H2
allows upload progress after response headers and stops the source when the
response completes or is closed. A failure/cancellation affects its own stream
on a healthy H2 connection. Complete early responses remain readable.

During upload, source reads, socket writes and H2 flow-control waits each retain
their progress deadline. Waiting for response headers gets its own budget after
the upload finishes; a peer may consume the whole request before replying.
Continuous upload progress can therefore outlast one read-timeout interval.
Async byte iterators execute in one producer task that inherits the request's
context, preserving `ContextVar` scopes across successive yields.
If the source itself raises `CancelledError`, the request propagates cancellation
and releases its stream; it does not turn that cancellation into a network retry.

For `stream=True`, keep the Session and source alive until response consumption
or close finishes. Response/session cleanup joins the owned upload work. Async
timeouts and cancellation stop new pulls, then wait for an already-running
blocking worker call or a started native generator's finalizer. Repeated request
cancellation still waits for that cleanup. An unresponsive source or finalizer
can therefore delay cleanup; threads cannot be force-stopped safely. Sync source
code must return on its own, and async iterators/finalizers must cooperate with
the event loop. Empty chunks do not refresh source progress deadlines.

### Upload memory

File reads and pending pieces are limited to 64 KiB, and H2 splits DATA by frame
and flow-control credit. Each H2 source has at most one outstanding pull and one
pending piece; a slow producer does not occupy the shared connection writer.

This is not a 64 KiB process-memory bound. An iterator retains its largest yielded
chunk until its pieces are consumed. Total upload state includes that chunk,
one pending piece, framing/TLS overhead and every concurrent upload, plus existing
bounded H2 control/receive state. Application buffers, multipart field metadata,
OS socket buffers and executor internals contribute separately. Increasing total
file size does not increase library body buffering for fixed-size source chunks.

## Async multipart files

`AsyncSession` accepts a `files=` mapping. Each field maps to a path (`str`, byte
path or `PathLike[str]`), a binary file, or a list of those values. Repeated files
become separate parts with the same field name. Bytes mean a path; wrap inline
binary content in `io.BytesIO`. Filename/file tuples are unsupported.

```python
from pathlib import Path
from ja3requests import AsyncSession

async def send_form(url):
    async with AsyncSession() as session:
        return await session.post(
            url,
            data=[("label", "first"), ("label", "second")],
            files={"attachment": [Path("first.bin"), Path("second.bin")]},
            timeout=10,
        )
```

With files, `data` must contain ordinary form fields; raw bodies and JSON cannot
be combined with files. The encoder owns Content-Type and its boundary and rejects
a conflicting explicit value. Part names/filenames reject CR, LF and NUL; quoted
parameters escape quotes/backslashes and encode non-ASCII text as UTF-8.
Only basenames appear in filenames. Media types are inferred with an
`application/octet-stream` fallback.

Path files are opened in binary mode one part at a time and closed by the library
on success, failure or cancellation. Borrowed handles remain open. Allowed retries
reuse the boundary, reopen paths and rewind seekable handles. Any consumed part
that cannot be replayed prevents replay of the whole form. Length is known when
all parts have known lengths; otherwise normal unknown-length framing applies.
The existing synchronous `files=` encoder retains its buffered behavior; raw
synchronous `data=file` is the streaming option.

The [upload loopback example](examples.md#streaming-upload-example) exercises the
public sync/async interfaces and multipart without an external service.
