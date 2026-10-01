# Local protocol integration tests

The `integration/` suite exercises the existing `Session -> Request -> Socket ->
TLS/H2` architecture without changing its public interfaces. Independent peers in
`mock_servers/` implement only the wire exchanges needed by these tests; they do
not import the library's protocol encoders or decoders.

## Run

Install the project and its development dependencies in your virtual environment,
then run from the repository root:

```sh
python -m pytest test/integration -q
python -m pytest test --ignore=test/test_session.py --cov=ja3requests --cov-report=term
```

`test_session.py` contains legacy manual scenarios that depend on external sites,
fixed local services/proxies and machine-specific files. It is explicitly excluded
from the second command, not silently skipped by test configuration. An unfiltered
baseline run on this development machine had 850 passing tests and three failures
in that file before this change.

## Continuous integration

GitHub Actions runs the same explicit test selection on Python 3.7–3.13 using
Ubuntu 22.04 (which supplies the Python 3.7 runtime). A separate job installs
the built wheel and checks HTTP/2 request framing outside the source directory.
Coverage runs on Python 3.12 and fails below 85%. The coverage table is available
in the job summary and a 14-day artifact; same-repository PRs also receive an
updated coverage comment.
Fork PRs run the checks without attempting a write-permission comment.

The suite includes three portability regressions for Python 3.7/OpenSSL's ragged
EOF reporting, three pool-reset regressions, and four regressions for certificate
verification inheritance and redirects. Only the local test peer normalizes that
EOF; authentication errors and timeouts still propagate, and incomplete protocol
reads still raise `EOFError`.

Coverage comments use a dedicated marker and bot ownership check, so reruns do
not overwrite unrelated automation comments. Two Node tests exercise this selection.

The source-format gate uses Black 25.1.0, and pylint checks errors across the
package. Existing style/refactoring warnings are not silently reported as clean;
they are outside this error-level gate. Legacy manual tests remain explicitly
excluded rather than made to pass using a developer's external services.

For local hooks, use an activated Python 3.12+ development environment, install
`requirements.txt` and `requirements-dev.txt`, then run:

```sh
pre-commit install
pre-commit run --all-files
```

The hook configuration checks package formatting, pylint errors, YAML syntax,
merge-conflict markers and package whitespace. CI does not publish packages or
deploy the repository.

## Covered behavior

- Complete TLS 1.2 RSA/AES-CBC handshake and encrypted HTTP/1.1 request/response.
- Two requests on the same TLS connection through an isolated existing pool.
- ALPN selection of HTTP/1.1 and HTTP/2, custom H2 SETTINGS and WINDOW_UPDATE values,
  and response assembly across multiple DATA frames.
- TLS handshake rejection when no cipher is shared.
- SOCKS4, SOCKS4a and SOCKS5 connection negotiation, user/password fields, rejection,
  and data exchange with a simulated tunnel endpoint (no outbound forwarding).
- H2 frame fragmentation, early EOF, truncated frames, and receive frame-size
  limits checked as soon as a complete frame header arrives. Response DATA before
  HEADERS fails both receive paths and discards a pooled TLS connection. The
  server's first frame must be non-ACK SETTINGS, including on fragmented reads.
- HTTP/2 responses require one valid `:status`; interim responses and trailers
  do not replace the final response headers. Missing status fails both local TLS
  connection paths, including the pooled path.
- Extra DATA or HEADERS in the same receive batch after END_STREAM fails the
  response, while late WINDOW_UPDATE and RST_STREAM do not alter its result.
- Truncated TLS records and malformed encrypted records propagating errors.
- TLS 1.3 HTTP/1.1 connection reuse and HTTP/2 ALPN routing against OpenSSL,
  using AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305. Each case also runs with
  socket reads limited to seven bytes.
- TLS 1.3 handshake transcript reassembly, server Finished validation and
  application-key derivation at the server Finished boundary.
- TLS 1.3 session tickets preceding application data, and rejection of tampered
  application records in both HTTP/1.1 and HTTP/2 readers.
- TLS 1.3 KeyUpdate from either peer against OpenSSL, plus record-level checks
  for both HTTP/1.1 and HTTP/2 readers across AES-128-GCM, AES-256-GCM and
  ChaCha20-Poly1305. Fragmented updates, invalid values, premature updates and
  continued use of an old traffic key are rejected.
- TLS 1.3 PSK-DHE ticket resumption against OpenSSL with certificate verification,
  three cipher suites and HelloRetryRequest. Unknown tickets fall back to a full
  verified handshake; unverified or expired tickets are not offered for verified
  requests.
- TLS 1.3 browser presets offering supported cipher suites; the Chrome 120 preset
  negotiates verified TLS 1.3 or TLS 1.2 ECDHE-RSA/AES-GCM with extended master
  secret against local OpenSSL peers, including seven-byte reads and rejection
  of a bad certificate.
- TLS 1.2 RSA/AES-CBC with extended master secret, and rejection of invalid
  ServerHello versions, unoffered cipher suites and downgrade markers.
- TLS 1.2 ECDHE-RSA and ECDHE-ECDSA AES-256-GCM/SHA-384 with and without
  extended master secret, seven-byte reads, and rejection of a tampered Finished
  before HTTP or pool insertion.
- The opt-in secure profile with certificate verification enabled by default:
  TLS 1.3 and TLS 1.2 ECDHE/AES-GCM against RSA and ECDSA certificate peers,
  including seven-byte reads and rejection of incorrect host identities. The
  [secure-profile matrix](secure_profile_matrix.md) records explicit cipher/group,
  HTTP/2 connection-path and resumption evidence, plus unverified environments.
- TLS 1.3 against an OpenSSL peer limited to P-256, with normal and seven-byte
  reads; the selected server group uses its matching private key, while an
  unoffered group is rejected. Rebuilding a ClientHello creates fresh shares.
- TLS 1.3 HelloRetryRequest from a P-256-only OpenSSL peer when the initial
  ClientHello offers only X25519; verified AES-128-GCM and AES-256-GCM handshakes
  pass with normal and seven-byte reads. Invalid groups, suites, versions and
  repeated retry requests are rejected.
- Verified TLS 1.2 RSA/AES-CBC, TLS 1.2 ECDHE-RSA/AES-GCM and TLS 1.3 requests
  and connection reuse, using an ephemeral CA trusted only by the test process.
- Rejection of incorrect DNS/IP identities, expired certificates, invalid chain
  signatures, untrusted self-signed peers and peer-supplied untrusted roots.
- TLS 1.2 ServerKeyExchange and TLS 1.3 CertificateVerify signatures, including
  tampering, unsupported scheme/key combinations and missing authentication.
- Verification upgrades cannot reuse previously unverified pooled connections.
- HTTP CONNECT and SOCKS5 tunnels authenticate the destination, even when the
  configured SNI differs from the request hostname.
- Per-request verification overrides isolate mutable configuration while sharing
  the Session's existing thread-safe cache, without copying its lock.
- Requests without a verification override inherit the Session's TLS setting;
  redirects retain an explicit request-level override.
- Cross-origin redirects strip authentication, raw Cookie and Host headers;
  same-origin redirects retain Basic Auth, and both retain the request timeout.
  Session cookies are filtered by the target domain.
- Response cookies retain their source host, path, Secure and HttpOnly attributes;
  outbound requests respect those limits even with a custom Host header. Multiple
  Set-Cookie headers remain distinct, and Session.send persists scoped cookies.
- TLS 1.2 handshakes reassemble messages across records, reject unoffered
  server cipher suites, and authenticate RSA/ECDSA client certificates through
  CertificateVerify. A mismatched or missing client key cannot send HTTP.
- TLS 1.3 main-handshake client authentication against OpenSSL with RSA and ECDSA
  certificates, two cipher suites and fragmented reads. An optional request
  accepts an empty client certificate; a mismatched private key sends no HTTP.
  Configured client certificates do not offer cached PSK tickets.
- Opt-in TLS 1.3 post-handshake client authentication against OpenSSL with RSA
  and ECDSA certificates, empty certificates, two cipher suites and fragmented
  reads. Tests reject missing extension, duplicate request context and mismatched
  private keys, and check independent transcripts after a client KeyUpdate.
- TLS 1.2 Session ID and ticket resumption with extended master secret against OpenSSL,
  including RSA/AES-CBC, ECDHE/AES-GCM, fragmented reads and TLS 1.3 profile
  fallback. Rejected IDs or tickets return to a verified full handshake; a bad
  resumed server Finished cannot send HTTP. Unverified and expired cache entries
  are not offered to verified requests.
- Pooled HTTPS connections require matching TLS configuration and certificate
  policy; cross-host requests use the current destination for SNI without
  modifying the Session's TLS configuration.
- Concurrent HTTP/2 requests, including POST bodies and JSON, can share one
  pooled TLS connection. Interleaved responses are matched by stream ID, and
  request DATA obeys peer stream and connection windows, including mid-send
  updates; early response DATA replenishes the receive window, and peer table-size
  changes reach the next header block. GOAWAY prevents new streams, while a reset
  stream does not interrupt other active streams. JA3 reporting follows the
  prepared ClientHello, with optional destination SNI, and validation rejects
  TLS 1.3 configurations without an implemented key share group.
- HTTP/2 advertises disabled server push by default. A local TLS peer that sends
  PUSH_PROMISE after acknowledging that setting fails concurrent requests; the
  failed pooled connection is discarded and the next request reconnects.
- Legacy HTTP/2 PRIORITY frames and priority fields in padded, fragmented
  response HEADERS are accepted without scheduling changes. An invalid PRIORITY
  frame resets only its stream, and the pooled connection remains usable.
- Padded HTTP/2 DATA contributes its full payload to flow control while only
  application bytes enter the response body. Invalid padding fails the pooled
  connection; the next request establishes a new one.
- Headers received after a locally reset HTTP/2 stream are decoded and discarded
  so later streams can use dynamic HPACK entries from those header blocks. Frames
  on unopened client or unpromised server streams fail both TLS receive paths;
  idle PRIORITY and unknown extension frames remain allowed.
- HTTP/2 frame tests reject invalid stream IDs and fixed payload lengths
  on both connection paths. A local TLS peer confirms HEADERS on stream 0 fails
  the pooled connection.
- TLS 1.2 server Finished authentication for the tested CBC and GCM suites:
  record MAC/AEAD checks, CBC padding, sequence numbers, the transcript through
  client Finished, and constant-time verify_data comparison. Invalid Finished
  messages cannot send HTTP or enter the pool, regardless of certificate settings.
- Fragmented TLS 1.2 Finished messages and pre-CCS session tickets contribute to
  the correct transcript; subsequent application records remain unread. Tickets
  are cached only after server Finished verification and require the server's
  SessionTicket extension.

All servers bind to `127.0.0.1` on OS-assigned ports. Socket operations and thread
joins are bounded. TLS certificates and private keys are generated in pytest's
temporary directory and deleted at fixture teardown. Tests use dedicated
`ConnectionPool` instances to avoid modifying or retaining the global pool.

The TLS 1.2 fixture enables a legacy cipher only on the test server to exercise
the library's current default. It does not change application security settings.
The separate trusted-certificate fixtures exercise the verification paths without
installing a CA on the host or contacting an external service.

## TLS 1.3 configuration and limitations

The integration tests explicitly configure the existing API:

```python
config = TlsConfig()
config.tls_version = 0x0304
config.cipher_suites = [0x1301]  # Or 0x1302 / 0x1303.
config.supported_groups = [29]  # X25519, matching the existing generated key share.
config.signature_algorithms = [0x0804]
config.alpn_protocols = ["h2", "http/1.1"]
```

The normal defaults are unchanged; pass `verify=True` to the request to enable
certificate validation. Both TLS versions now route through `CertificateVerifier`,
which uses the existing `cryptography>=42` dependency's certificate-path verifier.
It checks the destination DNS/IP identity, validity, signatures and CA constraints
against independently trusted roots. TLS 1.3 also verifies the server's
CertificateVerify signature before accepting Finished. The earlier temporary
rejection of all verified TLS 1.3 handshakes has been removed.

Trust roots come from Python's default `ssl` context (including `SSL_CERT_FILE` /
`SSL_CERT_DIR`). The lower-level `CertificateVerifier(ca_certs=...)` continues to
accept a PEM CA bundle. A server-provided root never extends the trust store.
The legacy `check_hostname` / `check_expiry` arguments control preliminary checks;
when verification is enabled the full path policy always enforces both checks.

Request-level `verify` overrides now copy configuration using a memo entry for
the shared TLS session cache, so its `RLock` is neither copied nor replaced.
Verified requests do not offer session IDs from the legacy unauthenticated cache.

Transcript and application-key boundaries follow
[RFC 8446 sections 4.4.1, 4.4.4 and 7.1](https://www.rfc-editor.org/rfc/rfc8446.html).
Session tickets are consumed without breaking response reads and can resume
TLS 1.3 connections in the same process. This does not claim 0-RTT support.

## Issue #34 progress

T04 added [opt-in Cookie file persistence](../docs/cookie_persistence.md) and
63 [file tests](test_cookie_files.py). The installed-wheel selected full run
passed 1362 tests with 88.86% statement coverage on the local Python 3.13.3/macOS
environment. All 58 package modules matched the source snapshot, including the
new file codec. Black, error-level Pylint and diff checks passed. The wheel and
reports are retained in `dist/t04/`; other environments and remote CI remain
unverified for this candidate.

The integration work exceeded the issue's 85% coverage target in a recorded run.
That Python 3.13.3/macOS run with cryptography 45.0.5 passed 955 tests (including
114 new cases), with 87% total statement coverage. TLS orchestration was at 84%,
HTTPS socket handling at 79%, and H2 connection handling at 95%. The T01 full
selected run passed 1247 tests locally with 89% statement coverage. T02 added
52 passing secure-profile/fragmented-resumption cases while reusing that full
baseline for unchanged library code; see the matrix for the separate run results.
The suite covers the issue's local TLS/H2/SOCKS server, handshake, failure, pool-reuse and
ALPN scenarios. A sequential HTTP/2 reset test keeps its peer open and verifies
that a later stream reuses the connection. No remote issue or PR state is changed
by these tests.

HPACK decoder tests cover bounded dynamic-table eviction, table-size updates,
invalid indexes, truncated and oversized integers, truncated strings, and invalid
Huffman padding or EOS. A local TLS HTTP/2 peer reuses indexes across responses
and verifies malformed header blocks fail the connection.

TLS 1.2 Finished tests cover RSA/AES-CBC and ECDHE-RSA/AES-GCM with SHA-256,
plus ECDHE-RSA/ECDHE-ECDSA AES-256-GCM with the SHA-384 PRF. Other SHA-384
TLS 1.2 suites are not established by these tests. TLS 1.3 post-handshake
client authentication is covered by local OpenSSL cases. This is not a complete
protocol audit.
