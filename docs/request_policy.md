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
