# Retry, timeout, and hooks

This page covers synchronous `Session`. See [async request policy](async.md#timeout-cancellation-and-request-policy)
for cancellable waits, phase budgets, awaitable hooks and async redirect methods.

## Timeouts

```python
from ja3requests import Session

with Session(use_pooling=False) as session:
    response = session.get("https://example.com/", timeout=(3, 10))
```

A scalar applies to connect and read operations. A two-item tuple supplies
`(connect_timeout, read_timeout)` in seconds. `None` supplies no explicit limit.
These are operation limits, not a single end-to-end deadline across DNS,
handshake, redirects, retries, backoff and body consumption. In streaming mode,
read limits apply while waiting for the next network data; application processing
between reads is not a total-response timer. A timeout can therefore occur
inside `iter_content()` after the request call returned.

## HTTP retries

```python
from ja3requests import HTTPRetry, Session

retry = HTTPRetry(
    total=2,
    backoff_factor=0.25,
    status_forcelist={502, 503, 504},
    allowed_methods={"GET", "HEAD"},
    raise_on_status=False,
)
with Session(retry=retry, use_pooling=False) as session:
    response = session.get("https://example.com/", timeout=5)
    response.raise_for_status()
```

`total` counts retries **after** the first attempt. `HTTPRetry()` defaults to
three retries, a 0.5-second backoff factor, statuses 502/503/504, methods
GET/HEAD/OPTIONS/PUT/DELETE, `raise_on_status=True`, and respect for `Retry-After`.
The backoff is `factor * 2 ** (retry_number - 1)` plus up to 10% random jitter.
`Retry-After` supports numeric seconds; HTTP-date parsing is not implemented.

With `raise_on_status=True`, the final retryable status raises
`MaxRetriedException`, including when `total=0`. Response hooks run first and
the final response remains available as `session.response`; its transport is
closed on that exception path. `raise_on_status=False` returns that response so
the caller can inspect it or use `raise_for_status()`. Passing an empty set for
`allowed_methods` or `status_forcelist` currently selects the defaults rather
than disabling them. Use `total=0, raise_on_status=False` when no additional
HTTP attempts or exhaustion exception is wanted.

`Session(retry=None)` does not install an HTTP retry policy. Separately, the
low-level connection helper can make up to three socket connection attempts;
the HTTP policy is not the only possible source of multiple connection attempts.
Its retry loop handles connection/OS errors raised during request execution.
Each redirect destination uses its own HTTP retry budget. An exhausted
destination error propagates without retrying a completed earlier hop or
reusing an upload source that the redirect chain has already finalized.
Status exhaustion also belongs to the current hop: the method selected by its
request hooks determines whether retry and `raise_on_status` apply there.
Failures while consuming a returned streaming response are not retried behind
the caller's back. Application retries must account for method semantics and
already delivered bytes.

Final header names and control characters are validated after `before_request`
hooks and before connection or streaming-source preparation. Invalid fields
raise `ValueError` and do not enter the HTTP retry loop. HTTP2 byte values retain
their UTF-8 input contract; malformed UTF-8 is also an input error and is not
retried. An existing shared H2 connection remains usable after rejecting such
a local field value.

Before retrying a response status, automatically generated Cookie headers are
rebuilt from that request's jar after applying the response's `Set-Cookie`
updates, including deletions. Explicit Cookie headers and Cookie choices made
by `before_request` hooks keep their precedence. Request-only Cookies remain
local to the request; they are not added to stored Session state.
Every automatic Cookie refresh is validated. An invalid refreshed field raises
`ValueError` before retry backoff, source replay or the next connection attempt.

## Hooks

```python
from ja3requests import Session

events = []

def before_request(request):
    events.append(("request", request.method))

def after_request(response):
    events.append(("response", response.status_code))

with Session(
    use_pooling=False,
    hooks={"before_request": [before_request], "after_request": [after_request]},
) as session:
    response = session.get("https://example.com/", timeout=5)
```

The event names are `before_request` and `after_request`. Each callback receives
one object. Returning `None` preserves it; returning a value replaces the object
passed onward. Session callbacks run before any request-level callbacks for the
same event. Request hooks use the same dictionary shape via `hooks=...`.

Synchronous hooks may edit a prepared request's method and URL, but its URL
scheme must match its transport type. Changing an `HttpRequest` URL to `https://`
in place (or the reverse) raises `NotAllowedScheme` before source or connection
work. To change scheme, return a newly prepared `Request(...).request()` from
the hook, with the desired TLS/proxy/timeout settings. Native async hooks use
metadata and select their transport from the final URL.
The synchronous client revalidates the supported method set after hooks and
on direct prepared sends; an invalid method raises `NotAllowedRequestMethod`
before sending. Valid method changes and replacements remain supported.

An `after_request` replacement must be a `Response` (or `None` to retain the
current response). Replacing it closes the previous independent response. A
new wrapper around the same underlying body takes ownership instead; the old
wrapper is detached and cannot close that body later. If a later hook raises,
the currently owned response is closed, including any earlier replacement.

`before_request` runs on the prepared transport request before its HTTP retry
loop. `after_request` sees the response available under the requested loading
mode: headers for `stream=True`, the loaded body for eager requests. Reading
`.content` inside a streaming hook consumes and caches the entire body and
therefore removes its streaming benefit. Hooks execute synchronously, and their
exceptions propagate. Redirects involve additional request processing; do not
use callback counts as an application transaction count.

Synchronous redirects inherit proxy routes, timeout and TLS configuration from
the current prepared transport request, including replacements returned by hooks.
This also applies to direct `Session.send()` calls without a prior high-level
`request()` call. Both destination schemes in the proxy mapping are retained
when a redirect changes the URL scheme.

For synchronous HTTPS, `Session.send()` fills an omitted `tls_config` from the
Session policy after `before_request` hooks and before upload preparation or
connection work. This covers newly prepared requests and hooks that clear the
configuration. An explicit request configuration retains precedence. Calling
the prepared transport's `send()` directly without a configuration uses the
verified `TlsConfig()` defaults; direct and proxy HTTPS still perform TLS.

Both clients use this redirect method/body policy. The 301/302/303 correction
for synchronous requests ships in **2.5.0**; 307/308 preservation shipped in 2.4.0.

| Status | Follow-up |
| --- | --- |
| 301/302 | POST becomes GET with no body; other methods retain method/body |
| 303 | HEAD retains method/body; other methods become GET with no body |
| 307/308 | Retain method/body |

For example, synchronous PUT -> 302 now resends PUT and its body, and HEAD ->
303 retains HEAD and its body. Previously both became empty-body GET requests.
Rewritten GET follow-ups remove Content-Length, Content-Type and Transfer-Encoding.
To keep the previous behavior, use `allow_redirects=False` and follow explicitly
with a GET. A newly preserved one-shot body can now raise `StreamConsumedError`
rather than silently dropping its data.

Preserved synchronous redirects reuse the actual prepared body, matching the
async replay contract.
Buffered form/JSON/multipart bodies reuse their encoded bytes while the body
inputs remain unchanged. Next-hop hook edits invalidate that replay; clearing
or replacing a buffered body removes inherited length framing and computes
framing for the new body or upload source, including through CONNECT tunnels.
The inherited length reflects the encoded byte count, including UTF-8 text set
by first-hop hooks. Different lengths declared for replacement uploads survive.
In-place JSON edits use the serialized representation, including numeric types,
nested values and dictionary order.
Multipart file-field order also participates in replay validation. Removing
files while retaining form fields produces a multipart body with those remaining
fields, including empty values. Removing form data while retaining files produces
a file-only multipart body; clearing both sends an empty body. Prepared file
contents are reused without rereading or closing caller files.
On synchronous POST/PUT, a final non-empty `files` mapping selects multipart
encoding and its Content-Type. First-hop hooks can edit `data` and `files` in
either order; an earlier form Content-Type does not discard those files.
Multipart field names and filenames reject CR, LF and NUL with `InvalidData`,
including edits made by next-hop hooks. Quoted part parameters escape quotes and
backslashes and encode non-ASCII text as UTF-8.
When hooks replace or clear a streaming source, inherited length headers are
removed regardless of casing or whether the old length was declared explicitly.
Different lengths set by hooks and explicit lengths on replacement request
objects remain available for the new source.
Consumed seekable upload sources rewind to their initial offset after the prior
producer stops;
consumed non-replayable sources raise `StreamConsumedError` before destination I/O.
Next-hop hooks select the source before replay. Matching method/body policy does
not imply identical response-history, timeout or pool-ownership APIs.
