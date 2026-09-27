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
- H2 frame fragmentation, early EOF and truncated frames.
- Truncated TLS records and malformed encrypted records propagating errors.
- TLS 1.3 HTTP/1.1 connection reuse and HTTP/2 ALPN routing against OpenSSL,
  using AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305. Each case also runs with
  socket reads limited to seven bytes.
- TLS 1.3 handshake transcript reassembly, server Finished validation and
  application-key derivation at the server Finished boundary.
- TLS 1.3 session tickets preceding application data, and rejection of tampered
  application records in both HTTP/1.1 and HTTP/2 readers.
- TLS 1.3 browser presets offering supported cipher suites; the Chrome 120 preset
  negotiates verified TLS 1.3 or TLS 1.2 ECDHE-RSA/AES-GCM with extended master
  secret against local OpenSSL peers, including seven-byte reads and rejection
  of a bad certificate.
- TLS 1.2 RSA/AES-CBC with extended master secret, and rejection of invalid
  ServerHello versions, unoffered cipher suites and downgrade markers.
- The opt-in secure profile with certificate verification enabled by default:
  TLS 1.3 and TLS 1.2 ECDHE/AES-GCM against RSA and ECDSA certificate peers,
  including seven-byte reads and rejection of incorrect host identities.
- TLS 1.3 against an OpenSSL peer limited to P-256, with normal and seven-byte
  reads; the selected server group uses its matching private key, while an
  unoffered group is rejected. Rebuilding a ClientHello creates fresh shares.
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
- TLS 1.2 server Finished authentication for the tested CBC and GCM suites:
  record MAC/AEAD checks, CBC padding, sequence numbers, the transcript through
  client Finished, and constant-time verify_data comparison. Invalid Finished
  messages cannot send HTTP or enter the pool, regardless of certificate settings.
- Fragmented TLS 1.2 Finished messages and pre-CCS session tickets contribute to
  the correct transcript; subsequent application records remain unread. Ticket
  processing here does not add new resumption/cache behavior.

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
Session tickets are consumed without breaking response reads; this does not claim
TLS 1.3 PSK resumption or 0-RTT support.

## Issue #34 progress

The integration work exceeded the issue's 85% coverage target in a recorded run.
That Python 3.13.3/macOS run with cryptography 45.0.5 passed 955 tests (including
114 new cases), with 87% total statement coverage. TLS orchestration was at 84%,
HTTPS socket handling at 79%, and H2 connection handling at 95%. The current
selected suite passes 1001 tests locally with 87.37% statement coverage. The suite
covers the issue's local TLS/H2/SOCKS
server, handshake, failure, pool-reuse and ALPN scenarios. No remote issue or PR
state is changed by these tests.

The TLS 1.2 Finished tests use TLS_RSA_WITH_AES_128_CBC_SHA and
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, both with the SHA-256 PRF. The existing
TLSCrypto key schedule still uses SHA-256 unconditionally; SHA-384 PRF suite
support is not established by these tests. TLS 1.3 HelloRetryRequest, KeyUpdate
and resumption also remain outside these integration cases. This is not a complete
protocol audit.
