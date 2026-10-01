# T01 Delivery Readiness Record

Date: 2026-10-01
Status: T01 complete; candidate changes remain uncommitted.

## Outcome and boundary

Prepare the existing uncommitted implementation for review and local delivery.
The deliverables are a classified change inventory, candidate commit groups,
release-note draft, and an installed-wheel verification record.

The user requested sequential execution of the development plan. This record
covers T01. No commit, push, merge, version change, or package publication is part
of this batch. Existing source edits, debug scripts, IDE metadata, and older
build artifacts are retained.

Lifecycle: UNREGISTERED. The task CLI is installed but could not resolve its
official session binding. The file checklist in the development plan is the
execution record until registration is available.

## Change inventory

The inventory below was captured before adding this record. Git's expanded
untracked listing counts individual IDE files rather than one directory entry.

| Classification | Files | Disposition |
| --- | ---: | --- |
| Runtime source | 19 | Required candidate deliverables |
| Automated tests and fixtures | 33 | Required candidate verification |
| Documentation and examples | 7 | Candidate documentation |
| Root-level manual scripts | 12 | Retain locally; not selected for delivery |
| Local metadata | 8 | Retain locally; not selected for delivery |

The runtime inventory contains 18 modified tracked files and one untracked
module, `ja3requests/protocol/h2/multiplex.py`. The automated test inventory
contains 19 modified tracked files and 14 untracked tests. Those new files are
needed for the current implementation and its regressions.

The existing `test/test_cookie_persistence.py` exercises cookies within a
Session. It does not implement the planned T04 cross-process file interface.
Several root-level scripts use external services; they are not part of the
bounded selected test suite.

## Candidate commit groups

### Candidate A: Runtime behavior with its tests

Suggested title: `feat: extend TLS sessions and harden HTTP/2 and request handling`

Include every path in the runtime and automated-test inventories below as one
coherent implementation candidate. Source and tests belong together.

Review the candidate in these logical sections:

1. TLS 1.2/1.3 authentication, transcript handling, key update, and resumption.
2. HTTP/2 parsing, HPACK, pooled stream multiplexing, and flow control.
3. Cookie scope, redirects, request isolation, and shared Session behavior.

The TLS and HTTP/2 paths share `sockets/https.py`; HTTP/2 and Cookie/request
behavior share `sessions.py`. A file-only split into separate feature commits
would cross these dependencies. This two-candidate delivery sequence avoids
inventing intermediate versions. If a reviewer requires smaller implementation
commits, reconcile the shared hunks and verify each resulting revision before
staging; no such partial staging has been performed here.

### Candidate B: Documentation, examples, and execution records

Suggested title: `docs: record protocol support and the next development plan`

Include the documentation/example inventory, this record, and its plan updates.
Keep the existing compatibility limits and distinguish tested behavior from
future features. Both candidates are prepared for review, not committed.

## Release-note draft

### Added or extended

- TLS 1.3 HelloRetryRequest with selective initial X25519/P-256 key shares,
  bidirectional KeyUpdate, and in-memory PSK-DHE ticket resumption.
- TLS 1.3 main-handshake client-certificate authentication and explicit opt-in
  post-handshake client authentication.
- TLS 1.2 authenticated Session ID and ticket resumption for the covered extended
  master secret paths, plus client CertificateVerify handling.
- Pooled HTTP/2 concurrent requests, including request bodies and interleaved
  responses, with retained compression and stream state.

### Correctness and failure handling

- HTTP/2 send/receive flow control, padded DATA accounting, header continuation,
  dynamic HPACK state, frame envelopes, server SETTINGS preface order, and
  rejection of response frames on unopened streams.
- Connection failure propagation, GOAWAY handling, stream-reset isolation, and
  decoding of late headers on locally cancelled streams.
- Cookie extraction retains destination scope and raw Set-Cookie fields.
  Requests respect Cookie scope despite a Host override; cross-origin redirects
  remove sensitive headers and retain the request timeout.
- Request-local TLS configuration and Session state support concurrent use
  without temporarily replacing the Session-wide TLS configuration.

### Compatibility and limits

- Constructor defaults still select the legacy TLS configuration and disable
  certificate verification. Callers can explicitly choose `TlsConfig.secure()`.
- Session caches remain in memory. No cross-process Cookie/TLS persistence or
  TLS 1.3 early-data support is claimed.
- Server push remains disabled. Legacy PRIORITY frames are accepted without
  priority-based request scheduling.
- Protocol support claims apply to the tested suites, groups and authentication
  paths described in `test/README.md`; they are not a complete security audit.
- This draft proposes no new version number or publication date.

## Package verification

An isolated copy of the build inputs was created in a task-owned temporary
directory. It omitted package bytecode caches and reused neither the existing
`build/` directory nor the existing `dist/` packages.

- Wheel build: passed using `pip wheel . --no-deps` with isolated build dependencies.
- Wheel: `ja3requests-1.2.0-py3-none-any.whl`.
- SHA-256: `aeca12bf8853dddafef739f6bc8693d3c62137f8f604fb9e9e8ef803d087ccd7`.
- All 57 package Python modules matched the source snapshot byte for byte,
  including the previously untracked HTTP/2 multiplex module.
- Installation into a fresh target directory outside the repository: passed.
- Import origin was asserted to be the installed target rather than the source
  checkout or its editable installation.
- Installed-wheel smoke: passed for secure/legacy profiles, TLS extension and
  cache APIs, sequential HTTP/2 response handling, and interleaved multiplexed
  POST/GET response routing.
- Installed-wheel selected full suite: 1247 passed, zero failures/errors/skips,
  with one existing TestContext collection warning. Coverage: 88.68% (89% in
  the rounded statement table), above the configured 85% floor.
- Black 25.1.0: passed for all 57 package files.
- Pylint 3.3.8, errors only: passed.
- Final source and copied-test readback: unchanged during verification.

Local environment: Python 3.13.3, macOS 15.7.7 arm64, OpenSSL 3.0.16,
cryptography 45.0.5, brotli 1.1.0, pytest 8.4.1 and pytest-cov 7.1.0.
Remote CI and the other declared Python/OpenSSL environments are unverified
for this candidate; T02 records the interoperability matrix.

The selected test command is run from the temporary installation workspace:

```sh
PYTHONPATH=installed /path/to/project/.venv/bin/python -m pytest test --ignore=test/test_session.py --cov=ja3requests --cov-report=term --cov-report=json:coverage.json --cov-fail-under=85 --junitxml=verification.xml -q
```

## Retention and next step

The wheel, source manifest, coverage JSON, JUnit XML and verification summary
were retained under the ignored `dist/t01/` directory. Copied artifact checksums
and report contents were verified. The task-owned temporary build/install/test
workspace was removed. The older `dist/ja3requests-1.1.1*` packages, existing
`build/`, manual scripts and IDE files were preserved.

After T01 acceptance, the next development batch is T02, secure-profile
interoperability evidence, followed by T03 migration documentation and T04 Cookie
file persistence.

## Runtime source candidates

- `ja3requests/base/__requests.py` (modified)
- `ja3requests/cookies.py` (modified)
- `ja3requests/pool.py` (modified)
- `ja3requests/protocol/h2/connection.py` (modified)
- `ja3requests/protocol/h2/frame.py` (modified)
- `ja3requests/protocol/h2/hpack.py` (modified)
- `ja3requests/protocol/h2/huffman.py` (modified)
- `ja3requests/protocol/tls/__init__.py` (modified)
- `ja3requests/protocol/tls/config.py` (modified)
- `ja3requests/protocol/tls/extensions/__init__.py` (modified)
- `ja3requests/protocol/tls/layers/client_hello.py` (modified)
- `ja3requests/protocol/tls/session_cache.py` (modified)
- `ja3requests/protocol/tls/tls13.py` (modified)
- `ja3requests/requests/request.py` (modified)
- `ja3requests/response.py` (modified)
- `ja3requests/sessions.py` (modified)
- `ja3requests/sockets/https.py` (modified)
- `ja3requests/utils.py` (modified)
- `ja3requests/protocol/h2/multiplex.py` (untracked)

## Automated test and fixture candidates

- `test/integration/conftest.py` (modified)
- `test/integration/test_certificate_verification.py` (modified)
- `test/integration/test_local_tls.py` (modified)
- `test/integration/test_local_tls13.py` (modified)
- `test/mock_servers/local.py` (modified)
- `test/test_config_validation.py` (modified)
- `test/test_cookie_persistence.py` (modified)
- `test/test_coverage_extra.py` (modified)
- `test/test_coverage_utils.py` (modified)
- `test/test_h2.py` (modified)
- `test/test_h2_huffman.py` (modified)
- `test/test_pool.py` (modified)
- `test/test_remaining.py` (modified)
- `test/test_session_cache.py` (modified)
- `test/test_tls12_finished.py` (modified)
- `test/test_tls13_handshake.py` (modified)
- `test/test_tls13_transcript.py` (modified)
- `test/test_tls_version_selection.py` (modified)
- `test/test_verify_config.py` (modified)
- `test/integration/test_h2_discarded_headers.py` (untracked)
- `test/integration/test_h2_hpack_table.py` (untracked)
- `test/integration/test_h2_invalid_frames.py` (untracked)
- `test/integration/test_h2_padded_data.py` (untracked)
- `test/integration/test_h2_priority.py` (untracked)
- `test/integration/test_h2_push_disabled.py` (untracked)
- `test/integration/test_tls12_resumption.py` (untracked)
- `test/integration/test_tls13_key_update.py` (untracked)
- `test/integration/test_tls13_post_handshake_auth.py` (untracked)
- `test/integration/test_tls13_resumption.py` (untracked)
- `test/test_session_concurrency.py` (untracked)
- `test/test_tls12_resumption.py` (untracked)
- `test/test_tls13_key_update.py` (untracked)
- `test/test_tls13_resumption.py` (untracked)

## Documentation and example candidates

- `IMPROVEMENTS.md` (modified)
- `README-zh.md` (modified)
- `README.md` (modified)
- `examples/09_mutual_tls.py` (modified)
- `issues/https_feature_development.md` (modified)
- `test/README.md` (modified)
- `issues/next_development_plan.md` (untracked)

## Manual scripts retained outside the candidate change set

- `compare_hello.py` (untracked)
- `test_client_hello.py` (untracked)
- `test_crypto.py` (untracked)
- `test_final_https.py` (untracked)
- `test_google_https.py` (untracked)
- `test_handshake_only.py` (untracked)
- `test_hex_debug.py` (untracked)
- `test_simple_https.py` (untracked)
- `test_simple_tls.py` (untracked)
- `test_ssl_comparison.py` (untracked)
- `test_tls_debug.py` (untracked)
- `test_ultra_simple.py` (untracked)

## Local metadata retained outside the candidate change set

- `.DS_Store` (untracked)
- `.idea/.gitignore` (untracked)
- `.idea/inspectionProfiles/profiles_settings.xml` (untracked)
- `.idea/ja3requests.iml` (untracked)
- `.idea/material_theme_project_new.xml` (untracked)
- `.idea/misc.xml` (untracked)
- `.idea/modules.xml` (untracked)
- `.idea/vcs.xml` (untracked)
