# Streaming responses

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
