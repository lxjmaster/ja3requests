# Secure Profile Interoperability Matrix

Recorded: 2026-10-01. T02 local verification is complete for the selected cases.

## Scope and evidence

This matrix describes `TlsConfig.secure()` and explicit supported adjustments
to its cipher selection and ALPN. Tests use the public `Session` request API and
independent Python/OpenSSL loopback servers, with an ephemeral trusted CA.
Requests inherit certificate verification from the profile; the new positive
and negative cases do not pass a request-level `verify` override.

T02 added 40 explicit profile cases and 12 fragmented-read resumption cases.
All 52 added cases passed. The 40-case run took 17.60 seconds; the 12-case run
took 7.79 seconds. During T02, no library source was changed. Its 57 module hashes
matched the [T01 installed-wheel record](../issues/delivery_readiness.md), whose
1247 selected tests passed with 88.68% coverage. That full run was reused,
not repeated or reported as a new 1299-test full run.

The new matrix cases are defined in
[test_secure_profile_matrix.py](integration/test_secure_profile_matrix.py).
Ordinary and seven-byte socket reads use the existing `fragmented_reads` fixture
in [test_local_tls13.py](integration/test_local_tls13.py). Each row below records
selected combinations, not every possible combination of its dimensions.

## Explicit HTTP/1.1 cases

Each row passes with ordinary and seven-byte reads, validates the selected TLS
version, cipher and ALPN at the peer, and serves two requests on one connection.
The peer is restricted to the listed key exchange group. Certificate key type
and ephemeral key exchange group are distinct dimensions.

| TLS version | Cipher ID / peer name | Server certificate | Peer group | Reads / reuse |
| --- | --- | --- | --- | --- |
| 1.3 | `0x1301` / TLS_AES_128_GCM_SHA256 | RSA | X25519 | Both / same connection |
| 1.3 | `0x1301` / TLS_AES_128_GCM_SHA256 | ECDSA | P-256 | Both / same connection |
| 1.3 | `0x1302` / TLS_AES_256_GCM_SHA384 | RSA | P-256 | Both / same connection |
| 1.3 | `0x1302` / TLS_AES_256_GCM_SHA384 | ECDSA | X25519 | Both / same connection |
| 1.3 | `0x1303` / TLS_CHACHA20_POLY1305_SHA256 | RSA | X25519 | Both / same connection |
| 1.3 | `0x1303` / TLS_CHACHA20_POLY1305_SHA256 | ECDSA | P-256 | Both / same connection |
| 1.2 | `0xC02F` / ECDHE-RSA-AES128-GCM-SHA256 | RSA | X25519 | Both / same connection |
| 1.2 | `0xC030` / ECDHE-RSA-AES256-GCM-SHA384 | RSA | P-256 | Both / same connection |
| 1.2 | `0xC02B` / ECDHE-ECDSA-AES128-GCM-SHA256 | ECDSA | X25519 | Both / same connection |
| 1.2 | `0xC02C` / ECDHE-ECDSA-AES256-GCM-SHA384 | ECDSA | P-256 | Both / same connection |

Evidence: `test_secure_explicit_suite_and_group_reuses_http1_connection`,
20 passed cases. TLS 1.2 rows keep the client profile's TLS 1.3 version setting
and offer TLS 1.3 plus the selected TLS 1.2 suite; a TLS-1.2-only peer proves
authenticated fallback instead of forcing the client to TLS 1.2.

The unmodified profile and the P-256-only default-share path retain their existing
evidence in `test_secure_profile_verified_interop` and
`test_secure_profile_p256_only_peer` in `test_local_tls13.py` (T01 run).

## Explicit HTTP/2 cases

HTTP/2 is opt-in through `config.alpn_protocols = ["h2"]`. Each row passes on
both connection paths and with both ordinary and seven-byte socket reads.

| TLS version | Cipher | Server certificate | Peer group | Connection paths |
| --- | --- | --- | --- | --- |
| 1.3 | `0x1301` / AES-128-GCM | RSA | X25519 | Non-pooled and pooled |
| 1.3 | `0x1303` / ChaCha20-Poly1305 | ECDSA | P-256 | Non-pooled and pooled |
| 1.2 | `0xC030` / ECDHE-RSA AES-256-GCM | RSA | P-256 | Non-pooled and pooled |
| 1.2 | `0xC02B` / ECDHE-ECDSA AES-128-GCM | ECDSA | X25519 | Non-pooled and pooled |

Evidence: `test_secure_explicit_http2_paths`, 16 passed cases. A pooled peer
observes streams 1 and 3 on one connection; a non-pooled peer observes stream 1
on each of two connections. Successful responses assert status 200 and the
expected body; peer-side assertions confirm version, cipher and ALPN.

The new test peer waits for its initial SETTINGS acknowledgement before finishing
the expected requests. Closing immediately with an unread acknowledgement caused
a TCP reset in the initial test implementation; waiting for transport EOF instead
blocked acceptance of the next non-pooled connection. The final peer terminates
on the explicit frame condition, without retries or sleep-based synchronization.

## Authentication, retry, and session evidence

| Claim and tested boundary | Evidence | Coverage recorded |
| --- | --- | --- |
| Wrong destination identity fails before HTTP/2, using inherited verification; failed connections cannot enter a dedicated pool | `test_secure_http2_rejects_wrong_identity_before_request` in the new matrix file | T02: TLS 1.2/1.3, RSA peer, non-pooled/pooled, 4 cases |
| Secure-profile wrong identity fails before HTTP/1.1 | `test_secure_profile_rejects_bad_certificate` in `test_local_tls13.py` | T01: TLS 1.2/1.3 |
| Certificate identity, expiry, bad signatures, and self-signed trust rejection | [test_certificate_verification.py](integration/test_certificate_verification.py) | T01: chain checks and representative verified TLS 1.2/1.3 paths; not every cipher/group |
| A verification upgrade cannot reuse an unverified connection | `test_verify_upgrade_cannot_reuse_unverified_connection` in the certificate file | T01: TLS 1.2/1.3 |
| Per-request verification inherits/overrides configuration and stays isolated across redirects/pools | [test_verify_config.py](test_verify_config.py) | T01: configuration/request regressions |
| P-256 HelloRetryRequest with X25519-only initial shares, authenticated handshake | `test_tls13_hello_retry_request_with_p256_peer` in `test_local_tls13.py` | T01: RSA peer, AES-128/256-GCM, ordinary/seven-byte reads |
| TLS 1.3 PSK-DHE ticket resumption and rejected-ticket full-handshake fallback, with and without HelloRetryRequest | [test_tls13_resumption.py](integration/test_tls13_resumption.py) | T01: 12 ordinary-read cases; T02: 12 seven-byte-read cases; RSA peer and all 3 TLS 1.3 suites |
| TLS 1.2 Session ID and ticket resumption with extended master secret; unknown identity/ticket fallback and bad resumed Finished rejection | [test_tls12_resumption.py](integration/test_tls12_resumption.py) | T01: RSA peer, AES-128/256-GCM, ordinary/seven-byte reads where parametrized; TLS 1.3-profile fallback also covered |
| Authentication policy and expiry constrain offered cache entries | [TLS 1.2 cache tests](test_tls12_resumption.py), [TLS 1.3 cache tests](test_tls13_resumption.py) | T01: incompatible/expired/unverified entries and configured-client-certificate restrictions |
| Main-handshake client authentication and mismatched private-key rejection | `test_tls12_client_certificate_authentication`, `test_tls13_client_certificate_authentication` and mismatched-key cases in the certificate file | T01: RSA/ECDSA client keys; TLS 1.3 AES-128/256-GCM; fragmented TLS 1.3 reads |
| Opt-in post-handshake client authentication | [test_tls13_post_handshake_auth.py](integration/test_tls13_post_handshake_auth.py) | T01: RSA/ECDSA/empty client certificate, AES-128/256-GCM, ordinary/seven-byte reads |
| KeyUpdate from either endpoint | [test_tls13_key_update.py](integration/test_tls13_key_update.py) and record-level cases | T01: independent OpenSSL CLI peer and key/record failure boundaries |
| Invalid selections and missing authentication are rejected | [version selection](test_tls_version_selection.py), [TLS 1.3 handshake](test_tls13_handshake.py), [transcript](test_tls13_transcript.py), [configuration](test_config_validation.py) | T01: unoffered suites/groups, malformed retries, missing CertificateVerify, invalid Finished and configuration rejection |

The TLS 1.3 resumption fixture was extended using the existing scenarios; no
second resumption implementation or duplicate server was added for T02.

## Environment matrix

| Environment | Status | Evidence or remaining condition |
| --- | --- | --- |
| macOS 15.7.7 arm64; Python 3.13.3; Python ssl/OpenSSL 3.0.16; cryptography 45.0.5; brotli 1.1.0; pytest 8.4.1 | Locally verified | T01 installed-wheel full run and T02's 52 added cases |
| Python 3.7-3.12 on Ubuntu 22.04 | Configured, unverified for this candidate | Versions appear in [the CI workflow](../.github/workflows/test.yml); no matching local runtime was found on PATH, and no remote run is claimed |
| Python 3.13 on Ubuntu 22.04 | Configured, unverified for this candidate | Local macOS results do not establish Linux/OpenSSL results |
| Other OpenSSL versions, TLS implementations or operating systems | Unverified | Require a selected environment and independent-peer execution |

The CI workflow already selects all tests under `test/`, so it will collect the
new cases after the candidate is committed and pushed. This work does not start
remote CI or change the supported Python range.

## Unsupported or unverified cells

- TLS 1.3 key shares outside X25519 and P-256 and 0-RTT are not implemented.
- Other TLS 1.2 SHA-384 CBC/static-RSA suites have no established secure-profile
  end-to-end evidence and are not part of that profile.
- The explicit secure HTTP/2 matrix covers the four rows above. Other cipher,
  certificate and group permutations, including TLS 1.3 AES-256-GCM secure HTTP/2,
  are not claimed to have passed this explicit matrix.
- ECDSA-server ticket/Session ID resumption has no independent-peer result in
  the selected resumption tests. ECDSA full handshakes and connection reuse are
  verified separately and must not be presented as resumption evidence.
- HelloRetryRequest with ChaCha20-Poly1305 is covered for RSA ticket resumption;
  other certificate/mode combinations are not claimed as a complete retry matrix.
- Resumption with configured client certificates remains disabled by current
  policy. TLS 1.2 resumption without extended master secret is also excluded.
- This matrix establishes selected interoperability and failure boundaries. It
  does not change `TlsConfig()` defaults or constitute a full protocol audit.

## Reproduce and retained evidence

```sh
.venv/bin/python -m pytest test/integration/test_secure_profile_matrix.py -q
.venv/bin/python -m pytest test/integration/test_tls13_resumption.py -q -k fragmented-reads
.venv/bin/black --check test/integration/test_secure_profile_matrix.py test/integration/test_tls13_resumption.py
```

Passing JUnit reports and a summary are retained in the ignored `dist/t02/`
directory. The temporary workspace, including generated certificate keys, is
removed after report readback. T02 reused T01's wheel as the snapshot of library
code tested at that point. Subsequent library changes require new installed-wheel
verification; [T04 Cookie persistence](../docs/cookie_persistence.md) records the
newer full-suite result.

Task lifecycle remains UNREGISTERED because the installed task CLI cannot obtain
an official session binding. The completed checklist is maintained in
[the development plan](../issues/next_development_plan.md). Next: T03, the TLS
defaults migration guide using the verified and unverified boundaries above.
