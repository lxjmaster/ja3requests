# Release Notes

## 2.2.0 — streaming request bodies and async file APIs

- Stream binary `data=` files and byte iterators over synchronous/asynchronous
  HTTP/1.1 and H2; async sources also accept async byte iterators. Bound source
  reads/pending pieces, honor flow control, preserve complete early responses
  and isolate H2 producer failures. Borrowed files and ordinary iterators remain open;
  retries require an unconsumed or replayable source, and length/read failures
  raise `InvalidData`. Sync redirect behavior remains unchanged.
- Keep streaming upload progress deadlines separate from the subsequent response
  wait, so continuous uploads can exceed one timeout interval. Preserve async
  generator context across body chunks, including ContextVar cleanup. Infer body
  length only for plain binary files/BytesIO; wrapped streams such as gzip use
  unknown-length framing unless the caller declares their output length.
- Propagate cancellation raised by an async upload source without a network
  retry or a stranded H2 response waiter. Finalize a started native async
  generator in its upload task, including an early response or cancellation
  between yields; repeated cancellation waits for its finalizer. Supply a fresh
  native async generator per request. Custom async iterators remain borrowed.
- Add async streaming `files=` multipart for paths, binary files and repeated
  parts, with deterministic metadata per request, lazy owned file handles and
  replay checks. PathLike inputs are accepted; filename/file tuples are not.
  Existing synchronous multipart remains buffered.

- Add awaited `AsyncSession.save_cookies()` and `load_cookies()` with the existing
  interoperable Cookie format, detached snapshots and atomic writes. Helpers on
  one Session are serialized; cancellation and close join active file work, and
  a cancelled load cannot mutate the jar afterward. A save may finish its atomic
  replacement after cancellation. File I/O runs outside the event loop.

- Count HPACK encoder dynamic-table entries using UTF-8 wire bytes, including
  insertion, eviction and resizing. Reject invalid text header inputs before
  changing compression state; async H2 validates before admitting a stream, so
  a local input error does not fail unrelated requests.
- Compatibility: byte header names/values must now decode as UTF-8 and string
  inputs must be UTF-8 encodable. Previously accepted arbitrary header bytes can
  raise `ValueError`. This is a text-API restriction, not an HPACK wire requirement.
  Raw `encode_string`/`decode_string` codecs still preserve arbitrary bytes.
  Supply valid UTF-8 text to the header API; raw codecs do not bypass its contract.
- Add local artifact verification and a full-history documentation CI gate.
  These changes and the HPACK follow-up are not part of published 2.1.1.

## 2.1.1 — transport performance and maintenance

- Remove the fixed 300 ms wait from full TLS1.2 handshakes. Continue waiting for
  authenticated server Finished with the existing receive timeout and failure
  behavior; resumed handshakes and secure/wire defaults are unchanged.
- Reuse bounded 64 KiB native-async socket read-ahead across small TLS reads,
  retaining cancellation, close wakeups and native-task cleanup. Local controlled
  comparisons show higher throughput with increased Python allocation peaks;
  this is not a whole-connection memory or latency guarantee. See the
  [measurement report](bench/POST_2_1_0_RESULTS.md) for samples and limits.
- Add strict internal types for HTTP/2 frames, HPACK Huffman values and
  ClientHello inspection, with installed-consumer acceptance. This is an
  incremental migration, not a claim that every protocol module is type-clean.
- Remove obsolete setuptools test-command integration. Runtime dependencies,
  package contents, `py.typed` and Python >=3.7 support remain unchanged.

## 2.1.0 — native async, incremental streaming and typed APIs

- Read streaming HTTP/1.1 and HTTP/2 responses incrementally, including project
  TLS1.2/1.3 record processing and gzip/deflate/Brotli decoding. Brotli now
  requires >=1.2.0 for output-limited decoding; Python remains >=3.7.
- Keep connections owned by their responses until completion or close. Early
  HTTP/1 close discards the connection; HTTP/2 close cancels only that stream
  on a healthy shared connection. HTTP/2 DATA queues use consumption-driven
  flow control without changing configured SETTINGS or initial window values.
- Add response context management and explicit `StreamConsumedError` and
  `ContentDecodingError` exceptions. Streaming iteration does not cache a replay
  copy; reading synchronous `.content` before iteration still caches the full body.
  Synchronous eager decoding retains its existing invalid-content fallback. Intermediate retry
  and redirect responses and failed response hooks release their resources.
  Response-hook replacement chains close superseded independent bodies; a new
  wrapper sharing the same body takes ownership without prematurely closing it.
- Add public API annotations and packaged `py.typed` support, an installed
  consumer type check, a locally buildable MkDocs API/user guide, and synchronous
  TLS/HTTP/component benchmarks with retained raw measurement evidence.
- Add native `AsyncSession`, `AsyncResponse` and `AsyncConnectionPool` using
  asyncio socket waits with project-owned TLS1.2/1.3 and HTTP/2 protocol state.
  Async response bodies support awaited read/text/json and single-consumer
  streaming; `.content` is cache-only, and eager/streaming decode errors are strict.
- Give async sessions private default pools and borrow explicit pools. Scope
  cancellation, read deadlines and early close to the owned response/stream;
  shared H2 connections retain other streams. Support awaitable hooks, cancellable
  retries and 307/308 method/body-preserving redirects, with public typing and
  a local runnable async guide/example. Async file uploads, Cookie-file helpers,
  prepared-request APIs and module-level convenience functions remain deferred.
- Remove native socket event registrations before async close, including on
  Python 3.7, so cancelled reads/writes cannot poison a reused file descriptor.
- Honor `HTTPRetry.raise_on_status` after the final retryable response. With
  the default `True`, exhaustion now raises `MaxRetriedException` instead of
  silently returning the failed response; `False` still returns it. The retry
  count excludes the initial request, so `total=0` applies the same policy to
  the first response. Successful and non-retryable requests are unchanged.
  Final response hooks and `session.response` remain available, response cookies
  are retained, and a successful redirect after a configured retryable redirect
  status still returns normally.
- Validate complete TLS 1.2 CBC padding and record authentication in both
  handshake and application-data paths. Bound inbound HTTP/2 header blocks and
  decoded header lists, including cancelled streams and trailers; retire failed
  connections. Nonzero GOAWAY errors do not trigger automatic async retries.
- Preserve scoped Cookie selection, expiry/deletion, explicit header precedence
  and string/bytes Cookie inputs. Async cross-origin redirects keep request
  snapshot isolation while incorporating that request's response updates.
  Synchronous GET redirects discard stale body framing headers, while retaining
  the existing synchronous redirect method policy.

## 2.0.1 — explicit TLS wire control

- Honor configured Session IDs, reject unsupported compression and conflicting
  extension declarations before sending TLS bytes, and support exact extension
  ordering and inspection of the actual sent ClientHello/JA3.
- Add opt-in TLS 1.3 P-384, including HelloRetryRequest and fragmented reads.
  Secure defaults and historical preset initial key shares remain unchanged.
- Add an explicitly selected Chrome 154 supported-subset profile, calibrated
  against a retained browser capture. It has a different JA3 and does not claim
  complete browser impersonation; ECH and post-quantum groups are not implemented.
- Validate TLS 1.3 Session ID echoes on direct and retried handshakes, require
  record version 0x0303 on retry, and reject unimplemented PSK exchange modes.
- Keep the client TLS protocol project-owned. Cryptography supplies primitive
  operations; OpenSSL is used only as the independent TLS test server.

Compatibility: invalid custom configurations that were previously ignored or
accepted now fail early. TLS 1.3 initial record versions are 0x0301/0x0303;
TLS 1.2 also permits 0x0302. Custom PSK exchange modes must be `[1]`.
See [the wire-control contract](docs/tls_wire_control.md) for supported fields,
protocol constraints and browser-profile differences.

## 2.0.0 — secure TLS defaults

Released on 2026-10-03. See the
[published release](https://github.com/lxjmaster/ja3requests/releases/tag/v2.0.0).

### Breaking changes

- `TlsConfig()`, implicit Sessions, factory Sessions and module-level requests
  now verify server certificates. They prefer TLS 1.3, allow TLS 1.2
  ECDHE/AES-GCM fallback and offer HTTP/1.1 ALPN by default.
- Untrusted, expired and wrong-host certificates fail before HTTP is sent.
  Trust private services through `SSL_CERT_FILE`; disabling verification does
  not establish private trust. There is no automatic insecure retry.
- Cipher, group, ALPN and extension defaults change ClientHello/JA3 fingerprints.
  The default profile is not a browser impersonation preset.
- `from_browser()` retains preset wire settings but now verifies certificates.
  Mutating browser/custom builders retain their source configuration's
  verification and extensions; a default source now inherits secure settings.
- Direct protocol handshakes without an explicit configuration also select
  secure defaults. Low-level `ClientHello` remains a wire encoder.

### Compatibility

- `TlsConfig.secure()` explicitly selects the new default profile.
- `TlsConfig.legacy()` pins the 1.x TLS 1.2 RSA/AES-CBC offer, empty group/ALPN
  lists and disabled certificate verification. Verification can be enabled
  independently on that profile.
- Explicit request `verify=True`/`False` still overrides the selected profile
  for that request and its redirects, without changing Session defaults.
- Cookie persistence and protocol features delivered by T01–T04 are retained.
  TLS session persistence, server push and 0-RTT remain unsupported.

See [the migration guide](docs/tls_defaults_migration.md) for trust setup,
hostname/SNI rules, legacy services and fingerprint compatibility.
