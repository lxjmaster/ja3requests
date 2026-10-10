# Session defaults: current behavior and opt-in design

Prepared: 2026-10-08. S1 / C17 design deliverable only. This document adds no
runtime behavior, public attribute, constructor argument or release commitment.
`request_defaults` below is a **proposed API**, not an available feature.

## 1. Decision and implementation boundary

Recommend a later, separately selected increment that adds one explicit
`session.request_defaults` assignment for **headers and query parameters only**,
with the same contract on `Session` and `AsyncSession`. Its initial value is
`None` (disabled); assigning a validated nonempty configuration opts in, and
assigning `None` or `{}` disables it. Add no constructor argument and no mode flag
to every request. Existing calls on an unconfigured session retain their behavior.

Do not interpret existing `Session.headers`, `.params`, `.auth` or `.proxies` as
defaults. Their getters can cache values from the most recent `Request`; enabling
merging through them would change both existing assignments and observational
reads. The proposed configuration has separate storage and never reads those
properties or `Session.Request`. It does not create those properties on async.

| Approach | Compatibility and cost | Decision |
| --- | --- | --- |
| Start consuming existing Session properties automatically | Short surface, but cached request observations become future defaults; assignments that currently do not affect sending change meaning | Reject for this increment |
| Separate, explicitly assigned headers/params configuration | One additive opt-in surface; leaves legacy observations and all unselected fields alone | Recommend |

This is deliberately smaller than complete Requests compatibility. Authentication,
proxy routes, timeout defaults, TLS defaults beyond the existing `tls_config`,
Cookie replacement/removal APIs, new deletion sentinels, prepared requests,
environment proxy discovery and sync redirect corrections are not selected.
An implementation must be separately authorized; U0 upload design can retain
today's request preparation and does not depend on this proposal being implemented.

## 2. Current implementation anchors

Line references describe the inspected source; symbols are the stable anchors.

| Evidence | Relevant behavior |
| --- | --- |
| [Session](../ja3requests/sessions.py), `__init__`, `request` (72-100, 183-261) | Constructor accepts TLS/pool/hooks/retry only; request uses its arguments directly except stored Cookies and TLS fallback |
| [BaseSession](../ja3requests/base/__sessions.py), `headers`, `auth`, `proxies`, `params` (66-85, 136-198) | Falsy stored values may be populated by reading the latest `Request`; those fields are not consumed by `Session.request` |
| [AsyncSession](../ja3requests/async_sessions.py), `__init__`, `request` (191-218, 289-360) | No declared headers/params/auth/proxies/timeout defaults; per-call Cookie, TLS, hooks, retry and proxy snapshots |
| [Sync preparation](../ja3requests/requests/request.py), `request`, `__ready_headers`, `__ready_auth` (78-127, 194-217, 283-308) | Header mapping copied; Basic auth prepared before constructing the ready request |
| [BaseRequest](../ja3requests/base/__requests.py), `params`, `headers`, `proxy` (154-184, 273-296, 417-430) | Query encoding, default headers for falsy mappings, title-case normalization and route selection |
| [Async preparation](../ja3requests/async_sessions.py), `_headers`, `_prepare`, `_freeze` (80-181) | `None` headers differ from `{}`; query `doseq=True`; validation and request framing |
| [Cookie operations](../ja3requests/cookies.py), `get_cookie_header`, `_refresh_cookie_header`, `merge_cookies` (215-249, 722-747) | Scope filtering, explicit-header precedence and input-dependent merge behavior |
| [Sync policy](../ja3requests/sessions.py), `send`, `resolve_redirects` (419-627) | Hook/retry order, response Cookie extraction and GET-based redirects |
| [Async policy](../ja3requests/async_sessions.py), `_request` (375-506) | Per-hop hooks, per-attempt retry, cross-origin stripping and final response hooks |
| [Public types](../ja3requests/_typing.py) and [async timeout validation](../ja3requests/_async_utils.py), `timeout_pair` | Supported input types; no default/deletion sentinel; async timeout validation |

Both request signatures currently use `None` as the default for every field in
the following matrix. Omission and an explicit `None` cannot be distinguished
inside these methods. S1 does not require adding a sentinel to distinguish them.

## 3. Current request semantics matrix

“Empty” means a supported empty container/string where one exists, not `False`
for a boolean. “No supported empty value” is a definite type boundary, not a
missing design decision. These are preparation/selection rules; generated Host,
body framing, auth and Cookie headers can still be added later.

| Field/API | Omitted | Explicit `None` | Empty value | Explicit nonempty value |
| --- | --- | --- | --- | --- |
| headers, sync | Library `default_headers()` | Same as omitted | `{}` also selects library defaults | Replaces library header set; case normalized, request auth/Cookies/body can add fields |
| headers, async | Library `default_headers()` | Same as omitted | `{}` supplies no library convenience headers | Replaces library header set; case normalized, preparation adds required/generated fields |
| params, both | Keep the URL's query; append nothing | Same as omitted | `{}`, `[]`, `()`, `''`, `b''` append nothing | Append supplied query to existing URL query; do not merge with Session properties |
| auth, both | Do not generate Basic auth; an explicit Authorization header can remain | Same as omitted | No supported empty tuple; sync currently ignores `()`, async rejects it | A `(username, password)` pair generates Basic auth and takes precedence over the supplied Authorization header |
| proxies, both | Direct route | Same as omitted | `{}` selects direct route | Choose the entry for the destination scheme; no Session-property or environment merge |
| cookies, both | Start from stored Session Cookies | Same as omitted | Empty dict/jar/text adds nothing; does not clear stored Cookies | Add request-only Cookies using the merge rules below |
| timeout, both | Pass `None` to existing timeout policy | Same as omitted | No supported empty value | Scalar or pair passed to the existing transport policy; no Session timeout default |
| tls_config, both | Use Session TLS configuration | Same as omitted | No supported empty value | Select the supplied configuration as a whole, not a field merge |
| verify, both | Use the selected TLS configuration's value | Same as omitted | No supported empty value; `False` is explicit | `True`/`False` overrides certificate verification for this request |

### Header and query details

- Both APIs normalize header names using `str.title()` and collapse differently
  cased duplicates with the last encountered value. Sync preparation warns about
  duplicate case-insensitive input names. Async validates names and CR/LF in
  values, decodes byte values as Latin-1, and stringifies other supported values.
  `None` header values are not a deletion API and are outside `Headers` typing.
- Explicit request headers replace the library header set today. They are not
  merged with `session.headers`. `default_headers()` returns a new mapping.
- Query pair sequences can retain repeated keys. Sync uses `urlencode(params)`;
  async uses `urlencode(params, doseq=True)`. A mapping containing list values
  therefore does not have identical sync/async encoding. Raw text/bytes queries
  use the existing per-client handling. S1 does not normalize these differences.

### Cookies, routing and TLS details

- A request dict or Cookie string is merged with `overwrite=False` by Cookie
  name: an existing name in the destination jar wins, even if its domain/path
  differs. A request `CookieJar` replaces matching `(domain, path, name)` entries.
  Do not describe both forms as uniform “request overrides Session”. Explicit
  Cookie headers, including a hook replacement/removal, take precedence over
  generated Cookie headers. Empty `cookies` does not suppress the Session jar.
- Stored response Cookies persist; request-only Cookies do not persist unless
  the server sets them. Sync's `session.cookies` getter returns a compatibility
  snapshot; async's `cookies` attribute is the live jar. Sync can normalize its
  broader setter inputs before a request; the documented async store is a jar.
  Cookie copies are not promises of deep isolation for arbitrary application
  mutation of Cookie extension metadata or policy objects.
- Async copies the supplied proxy mapping and rejects keys other than `http` and
  `https`. Sync selects a route through its existing preparation. Proxy URL
  parsing and pooling deliberately remain API-specific; see
  [proxy contracts](../docs/proxies.md). Neither reads environment proxy settings.
- Sync normally reuses the selected TLS object and copies it only when `verify`
  changes its value. Async copies the selected object for every request. Both
  preserve the TLS session-cache object when copying. Configure TLS before
  concurrent use; do not promise identical live-mutation behavior.
- `timeout=None` is not a new uniform “unlimited” contract for sync: for example,
  [the direct HTTPS HTTP/1 path](../ja3requests/sockets/https.py) uses a 15-second
  read fallback when no read timeout is supplied (around line 360). Async `None`
  means no deadline for the phase; its finite nonnegative scalar/pair validation
  remains unchanged. S1 selects no timeout correction or default.

## 4. Proposed opt-in contract

The proposed configuration accepts only `headers` and `params` keys. Unknown
keys raise `TypeError` before replacing the previous configuration. Each field
may be omitted or `None` to remain unconfigured. Empty fields also remain
unconfigured. The setter validates the entire configuration before one storage
replacement; failed assignment leaves the previous configuration intact.
Invalid configuration/container/value types raise `TypeError`; duplicate or
forbidden default header names raise `ValueError`. Header syntax follows the
existing async header validator's name/CRLF checks in this new configuration
boundary, with invalid syntax raising `ValueError` for both clients.

- Default headers accept the existing string-name/`HeaderValue` mapping. Reject
  case-insensitive duplicate names in this new configuration so its stored value
  is unambiguous. Reject `Authorization`, `Proxy-Authorization`, `Cookie`, `Host`,
  `Content-Length` and `Transfer-Encoding` in **default configuration only**:
  origin credentials, Cookie policy and transport framing remain explicit
  existing request operations. This adds no restriction to current request
  headers. Arbitrary custom header values are still application-managed; these
  names do not constitute a general secret detector or origin-access policy.
- Default params accept a string-to-string mapping or ordered sequence of
  `(str, str)` pairs. Retain duplicate keys in sequences. Store copied immutable
  pairs; do not add nested defaults, raw query parsing or arbitrary-object
  freezing. Broader values remain available as explicit request parameters.
- The getter returns a detached snapshot. Mutating that snapshot or the original
  assigned mapping has no effect; assign the complete configuration to change it.
  Clear the configuration with `None` or `{}`. Do not overload legacy getters.

For a field with no configured defaults, preserve its complete current behavior.
For a configured field, use this matrix:

| Request input | headers with configured defaults | params with configured defaults |
| --- | --- | --- |
| Omitted | Start from library defaults and overlay configured headers | Use the configured ordered pairs |
| `None` | Same as omitted | Same as omitted |
| Empty supported value | `{}` bypasses configured headers and follows that API's existing `{}` behavior | Any supported empty value bypasses configured params; retain the URL's existing query |
| Nonempty structured value | Overlay case-insensitively onto library + configured headers; explicit value wins | Remove every default pair whose key appears in the request input, then append all request pairs in their original order |
| Nonempty raw text/bytes | Not a supported header mapping | Bypass configured params and use the existing raw request query path |

For structured query overlays, preserve the request's existing key/value types
and client-specific encoding. Compare keys by their actual equality; a `bytes`
key is distinct from a string key. Mapping iteration order determines pair order;
mapping list values retain native sync/async encoding, while explicit repeated
pair sequences retain repeats. URL query keys are not removed by this operation:
only configured default pairs are replaced. A default `tag=a&tag=b&page=1` plus
request pairs `[('tag', 'x'), ('tag', 'y')]` produces appended pairs
`[('page', '1'), ('tag', 'x'), ('tag', 'y')]` in both clients.

Header omission does not remove an inherited field. Remove one default header for
one request using the existing `before_request` hook, after preparation, e.g.
`request.headers.pop('X-Default', None)`. The merger runs only before initial
preparation and does not reinsert that field during retries or redirects. There
is no `None`-as-deletion sentinel and no new per-call removal argument. Protocol
headers regenerated by existing preparation remain governed by that preparation.
In async, `_freeze()` calls `_headers(request.headers)` with a non-`None` mapping,
so it does not refill library defaults after a hook removes a header, even if the
mapping becomes empty. It can restore `Host` and recompute `Content-Length`.
Sync's `BaseRequest.headers` getter falls back to library defaults when its whole
mapping is empty. The supported removal scenario is an optional default header
such as `X-Default` from an otherwise prepared request; removing every header or
managed framing/Host fields has no new guarantee under this proposal.

| Unselected field | Proposed omitted / `None` / empty / explicit handling |
| --- | --- |
| auth, proxies, timeout | Exactly the current matrix; no storage slot in `request_defaults`; configuring these keys fails |
| cookies | Existing Session jar + request overlay; no second Cookie-default store; configuring the key fails |
| tls_config, verify | Existing TLS object selection and verification override; configuring these keys fails |
| hooks, retry, redirect options, body/files | Existing APIs only; configuring these keys fails |

No omitted/`None` distinction is needed. No new constructor arguments, global
mode, context variable, inheritance tree or general configuration engine is
needed. The proposed feature can be implemented as a small validated assignment
boundary and a merge step feeding existing preparation.

## 5. Snapshot, hooks, retries and origin boundaries

### Snapshot and mutation timing

At the beginning of each request's **execution**, capture the assigned defaults
once and build private header/parameter containers. Creating an async coroutine
object alone does not capture them. The async merge and preparation complete
before the first await. Sync callers must synchronize configuration assignments
with concurrent use, following the existing Session concurrency contract.

Do not mutate caller mappings, the stored defaults, legacy observation fields,
or another request's prepared state. Stored default values have the limited
immutable types above. Encode explicit request parameters during ordinary
preparation; do not introduce a promise to deep-copy arbitrary values allowed
by the existing `Params` annotation. A hook or later configuration assignment
can affect future calls, but cannot change the captured defaults of a pending
request. Hook code remains responsible for its own shared state.

### Existing policy sequence to preserve

| Point | Sync | Async |
| --- | --- | --- |
| Before preparation | Select TLS; combine stored/request Cookies; construct request | Validate timeout; snapshot TLS/Cookies/hooks/retry/proxies; construct metadata |
| Before sending a hop | Session `before_request`, then per-request hooks; refresh generated Cookie header | Session `before_request`, then per-request hooks; freeze/validate; refresh generated Cookie header |
| Retry | Reuse the prepared request; do not rerun before hooks; apply response Cookies before status retry and refresh generated Cookie header | Same preparation boundary; use captured retry policy; apply response Cookies to shared and request jars; refresh before status retry |
| Redirect | Re-enters `send`; bodyless GET for all followed statuses; session hooks run for each hop | Re-enters the hop loop; 307/308 retain method/body, 301/302 change POST, 303 changes non-HEAD to GET; per-request hooks remain in the captured list |
| After hooks | Nested redirected `send` calls run session after hooks; outer `send` runs session and original per-request after hooks. Original per-request hooks are popped before redirect kwargs are passed | Once for the final policy-selected response, session registrations then request registrations |

Sync retry configuration is referenced rather than snapshotted, and sync hook
lists are copied when dispatched. These differ from async snapshots and remain
unchanged. The new defaults merge happens once before this existing policy
sequence. Do not unify hook invocation counts, cancellation, stream ownership or
retry eligibility as part of default merging.

Cross-origin means a change of scheme, hostname or effective port. Both existing
redirect paths strip explicit Authorization, Proxy-Authorization and Cookie
headers on such a change and regenerate/select appropriate routing/headers.
Sync follows redirects with a fresh snapshot of stored Session Cookies; async
uses its request-local Session snapshot plus that request's response updates,
dropping request-only Cookies on cross-origin hops. Preserve those differences.
Never reapply configured defaults after redirect stripping. Proxy routing remains
the explicitly selected request mapping indexed by each destination's scheme;
proxy authentication belongs to that proxy route, not to a new origin default.

For **independent** requests, only explicitly configured defaults may carry
forward. Request A's auth, header observations, params and proxy route must never
be inferred as defaults for request B. Reading `session.auth` after A may still
populate the legacy observation field, but the new merger cannot read that field.
Default custom headers/params are session-wide for new initial requests; callers
needing origin-specific custom values must use separate configurations/sessions
or explicit per-request values. No automatic origin registry is selected.

## 6. Acceptance cases and migration advice

The following are exact future assertions, not a claim that the proposal exists
or its tests have passed. Use captured preparation for merge tests, existing
local peers for policy tests, and no public network endpoints. Reuse
[Cookie policy tests](../test/test_cookie_policy_review.py),
[async Session tests](../test/test_async_session.py),
[hook tests](../test/test_hooks.py) and
[retry exhaustion tests](../test/test_retry_exhaustion.py) for established behavior.

| Case | Setup/action | Required assertion |
| --- | --- | --- |
| Disabled mode | Do not configure; repeat each row of the current matrix | Same prepared values and exceptions as baseline, including sync/async empty-header difference |
| Observation isolation | Request A to `https://a.example/` with `auth=('u', 'p')`; read sync `.auth`, `.headers`, `.params`, `.proxies`; make independent B to `https://b.example/` with only configured `X-Default` | B has no Authorization, Cookie or route inferred from A; B's auth is `None`; configured header is present |
| Explicit legacy assignment | Assign sync `.headers`, `.auth`, `.params`, `.proxies`; make a request without corresponding arguments | No newly effective defaults, exactly as before |
| Header precedence | Configure `X-Default: a`; request `x-default: b` | One case-insensitive field with value `b`; configuration still contains `a` |
| Empty/None headers | Configure `X-Default: a`; compare omitted, `None`, `{}` | First two contain `a`; `{}` bypasses it and retains each API's native empty-header behavior |
| Per-call removal | Same defaults; before hook removes `X-Default`; trigger one retry and one redirect | Removed field stays absent; next independent unmodified request again gets `a` |
| Repeated query keys | Configure the `tag/tag/page` example; supply the repeated request pairs above | Ordered appended pairs are exactly `page=1`, `tag=x`, `tag=y`; URL query remains before them |
| Raw and empty query | Configure `page=1`; pass `params=''`, `{}`, then `'q=%2F'` | First two append no defaults; third follows native raw query handling with no `page` injection |
| Assignment atomicity | Store valid defaults; assign an unknown key, duplicate header name or forbidden default header | Unknown key raises `TypeError`; duplicate/forbidden name raises `ValueError`; previous valid configuration unchanged |
| Copy boundary | Assign caller dictionaries; mutate originals and a getter snapshot | Following request uses the original stored values until explicit reassignment |
| Async execution boundary | Create a coroutine, replace defaults, await it; then block an in-flight request and replace defaults again | First uses the configuration at execution; in-flight prepared state stays unchanged; next request sees the latest assignment |
| Independent async calls | Concurrent calls override the same default with different values | Each peer sees only that call's value; stored defaults unchanged |
| Cookie compatibility | Store scoped Cookie `sid=stored`; request dict `sid=local`, then a matching-identity jar `sid=local`, then `{}` | Existing dict-vs-jar precedence and empty no-clear behavior unchanged; scope and explicit header rules still pass |
| Origin and hook policy | Local cross-origin redirect with explicit auth/Cookie/proxy inputs | Existing stripping, route selection and the table's API-specific hook counts remain unchanged; default merge is not repeated |
| TLS/timeout non-expansion | Attempt to configure unselected keys; separately pass valid request overrides | Configuration rejected; existing request override behavior and Session TLS state preserved |

An implementation can express the header cases directly against captured
prepared requests. This example is **future acceptance pseudocode**: `capture`
is a test fixture returning the initial prepared request without network I/O.

```python
session.request_defaults = {"headers": {"X-Default": "a"}}
assert capture(session).headers["X-Default"] == "a"
assert capture(session, headers=None).headers["X-Default"] == "a"
assert "X-Default" not in capture(session, headers={}).headers
assert capture(session, headers={"x-default": "b"}).headers["X-Default"] == "b"
session.request_defaults = None
assert "X-Default" not in capture(session).headers
```

For the current source, a runnable, network-free regression check for the
observation hazard uses existing APIs only (no new feature required):

```python
from unittest.mock import patch
from ja3requests import Session

with Session(use_pooling=False) as session:
    with patch.object(session, "send", side_effect=lambda request, **kw: request):
        first = session.get("https://a.example/", auth=("u", "p"))
        assert first.headers["Authorization"].startswith("Basic ")
        assert session.auth == ("u", "p")  # A legacy observation is now cached.
        second = session.get("https://b.example/")
        assert second.auth is None
        assert "Authorization" not in second.headers
```

Migration recommendation: retain existing behavior by default and document the
new configuration as additive opt-in if implementation is selected. No release
version is selected here. Do not describe this as full Requests parity, uniform
sync/async semantics or a fix to existing observation properties. A later change
to legacy getters, empty-header behavior, Cookie precedence, timeout policy or
sync 307/308 semantics needs its own compatibility decision and migration notes.

## 7. Design acceptance boundary

This deliverable is complete when the current behavior is supported by the code
anchors, every proposed precedence cell has a definite result, the auth
observation case is covered, and the implementation exclusions remain explicit.
Only this design document is changed by S1. Future runtime tests, typing consumers,
documentation examples and installed acceptance belong to the separately selected
implementation; static review of this document does not establish runtime support.

Verification for this design delivery: the current-source, network-free auth
observation snippet above passed under `python3 -B`. All 17 relative file links
resolved and the document had no trailing whitespace. No feature tests or
installed-package acceptance are claimed for the proposed API.
