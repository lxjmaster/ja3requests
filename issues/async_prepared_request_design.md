# Buffered async prepared request design

Selected workflow: prepare the encoded URL, headers and bytes body without
network I/O, inspect them or add a signature, then send explicitly. Preparation
binds to the current Session and loop, consistent with native async ownership.

## API and snapshots

- `await session.prepare_request(method, url, ...) -> AsyncPreparedRequest`:
  same buffered encoding, query, auth and Cookie selection as `request()`.
  No hooks, source reads, connections or sends. It snapshots TLS and proxy
  settings and Cookie jars at coroutine execution, not coroutine creation.
  The destination URL uses the transport's lower-case scheme/host, IDNA/IPv6
  authority and numeric non-default port. Empty paths become `/`; empty query
  delimiters and fragments are omitted. Existing percent encoding, leading slash
  counts, query order and repeated parameters are preserved. Generated Cookies
  are selected again
  for this normalized destination before inspection/signing. Explicit Host
  overrides remain headers and do not rewrite the destination URL.
- `method`, `url`, `headers` and `body` are read-only inspection properties.
  Headers are `Mapping[str, Union[str, bytes]]`: bytes are preserved, text stays
  text and numeric values become strings. Body is bytes. HTTP1 sends byte-valued
  fields unchanged; H2 requires UTF-8 bytes. Shared field syntax is validated
  during preparation and after automatic Cookie refreshes; protocol-specific
  encoding is validated at send after negotiation. Objects are created by the
  Session factory, not by application construction.
- `prepared.with_headers(headers)` creates a new prepared snapshot with a
  replacement header mapping. Use `dict(prepared.headers, Authorization=...)`
  to add a signature. Existing normalization/Host/Content-Length validation
  runs again; method/URL/body and transport context are retained. A supplied
  Cookie is explicit even when identical to a generated value; omission removes
  a previously generated Cookie. Explicit headers do not refresh on retry.
- `await session.send(prepared, timeout=None, stream=False,
  allow_redirects=True, hooks=None)` clones all per-send mutable state. Sequential
  and concurrent sends reuse bytes; policy never promises exactly-once effects.

| State | Snapshot / send policy |
| --- | --- |
| URL, encoded body, auth and explicit headers | Encoded at preparation; header copy only through `with_headers()` |
| Cookie jars and generated Cookie metadata | Snapshotted at preparation; expiry filtering remains active; private per-send copies receive response/retry/redirect updates, while responses still update the live Session jar |
| TLS, verify, ALPN, client certificate configuration | Deep copied at preparation and each send; configured cache identity retained; later caller/Session mutation cannot change this prepared request |
| Certificate or trust file contents | Paths/configuration are snapshotted, files are read during transport setup; preparation makes no persistent credential copies or frozen filesystem claim |
| Proxy mapping | Copied at preparation and send; no environment discovery |
| Retry policy and Session hooks | Snapshotted at each send, in existing order; per-send hooks appended |
| Pool and Session/loop ownership | Sending Session must be the preparing Session, on the same loop and still open; no pool or transport in public metadata |

## Body and error decisions

| Input / operation | Outcome |
| --- | --- |
| `data=None`, bytes/text, form dict/list/tuple; `json` dict/text/bytes | Existing `_prepare()` encoding; owned immutable bytes |
| File handle, sync/async iterator, UploadSource | `InvalidData` before pull/read/seek; no implicit buffering or automatic close |
| `files=` | Unsupported keyword: `TypeError` |
| Conflicting data/json; invalid method/URL/header | Existing preparation errors; no network effects |
| Direct `AsyncPreparedRequest()` construction | `TypeError`, use the Session factory |
| Wrong request type / another Session / another loop / closed Session | `TypeError` / `ValueError` / `RuntimeError` / `RuntimeError`, before transport I/O |
| Sequential/concurrent resend | Independent metadata, TLS/proxy and Cookie copies; prepared snapshot stays unchanged |
| Hook supplies a streaming body on prepared send | `InvalidData` before source I/O; high-level `request()` retains existing streaming support |

## Hooks, retries, redirects and responses

Preparation and `with_headers()` run no hooks. Send preserves the current mutable
`_RequestMetadata` hook type, once before each redirect hop, with no per-attempt
hook. Hooks may alter signed fields; signatures for those changes or new redirect
origins must be recomputed by the caller's policy. Signed callers can disable
redirects. Cookie signatures use an explicit Cookie in `with_headers()`;
automatically changed signed fields need caller-managed retry policy since before
hooks do not run per retry. Existing cross-origin auth/Cookie stripping remains in the shared
dispatcher, and configured defaults are not introduced.

Buffered send reuses the current retry/redirect/response implementation, including
307/308 body preservation, final response hooks, target cancellation, response
adoption across Sessions, and borrowed-pool cleanup. Each invocation creates the
same tracked request task as `request()`. `stream=True` returns a live Session-
owned response, to be read/closed or released by Session close. Preparation owns
no live connection or upload source and needs no close API.

## Acceptance matrix

1. No connection or hook during preparation/header derivation; exact bytes/query
   normalization, immutable inspection and detached original input mappings.
2. Unsupported files/iterators rejected without any source pull, rewind or close.
3. Signature survives HTTP1/TLS/H2 send; server observes the inspected body/URL;
   two sends and concurrent hook changes never mutate the prepared object.
4. Same-origin 307/308 byte replay; status retry with Cookie response updates;
   cross-origin credentials stripped and current hook order preserved.
5. TLS/verify/client certificate/proxy/Cookie snapshot isolation and cache identity;
   closed Session, wrong owner and loop rejected before network activity.
6. Caller cancellation, timeout, Session close, streaming response early close and
   borrowed pool; existing response-hook transfer tests exercise the shared path.
7. Installed positive/negative consumers, strict facade, syntax, docs and exact
   artifact acceptance. No new release/runtime support claim follows local checks.

This design is reviewed within the authorized local execution. Streaming prepared
sources, module helpers, C17 defaults and synchronous API changes are deferred.
