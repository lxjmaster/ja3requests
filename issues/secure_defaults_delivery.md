# T05 Secure Defaults Delivery

Recorded: 2026-10-02. Candidate version: 2.0.0.

## Outcome and scope

The user requested the next development task after T01–T04 delivery. T05
switches implicit TLS configuration to the existing secure profile, retains
explicit legacy compatibility, and updates version/migration documentation.
The recommended major version 2.0.0 is used for this development candidate.
Package publication, deployment and merging are separate outcomes.

The migration branch is `feature/secure-defaults-migration`, based on the
verified `feature/protocol-delivery` branch (PR #52). The migration is reviewed
as a dependent draft pull request. Manual scripts and IDE files are retained
outside the candidate commits. Execution is serial because construction and
protocol tests overlap. Lifecycle remains UNREGISTERED: the task CLI cannot
resolve an official session binding; this record and the roadmap are the local
execution evidence.

## Behavior and compatibility

- `TlsConfig()` and `secure()` select the same verified TLS 1.3 profile with
  TLS 1.2 ECDHE/GCM fallback and HTTP/1.1 ALPN. Per-instance lists/extensions
  remain independent.
- Session/factory/module-level requests inherit that profile. Direct TLS
  preparation or handshake without configuration uses it too, even after
  inspecting the lazy ClientHello body.
- `legacy()` retains TLS 1.2 RSA/AES-CBC, empty group/ALPN/extension lists and
  disabled verification. Old protocol fixtures select it explicitly.
- Browser preset factories preserve their explicit wire fields and now verify
  certificates. Mutating browser/custom builders inherit verification and
  extensions from their source configuration; this distinction is documented.
- Explicit verification overrides retain their request/redirect scope. An
  unverified pooled connection cannot satisfy the next implicit verified request.
- Certificate rejection never causes an automatic insecure retry. Default
  cipher/group/extension/ALPN changes affect ClientHello and JA3 fingerprints.

## Local acceptance evidence

- 53 default-policy integration cases passed against independent loopback TLS
  peers: all public entry points, TLS 1.3 and verified TLS 1.2 fallback,
  HTTP/1.1 and HTTP/2 certificate rejection, untrusted CA, verification override
  isolation, pool upgrades, RSA-only peer rejection/legacy opt-in, and direct
  protocol configuration/ClientHello-preview paths.
- The earlier updated-source full run passed 1400 tests. The final selected
  suite from the installed 2.0.0 wheel passed **1415 tests**, zero failures,
  errors or skips, with **89.03% statement coverage** and the existing
  `TestContext` collection warning.
- A separate installation of the retained 1.2.0 wheel confirmed its old
  constructor/version/cipher/verification baseline before installing 2.0.0.
- All 58 wheel modules matched the build source snapshot; original source and
  copied test hashes matched after verification. Import origin was asserted to
  be the installed target outside the repository.
- All nine browser presets retained explicit wire settings and verified
  certificates; legacy/default mutating builders retained their respective
  verification and extension policy in installed-package checks.
- Black and error-level package Pylint passed. Markdown file links, 30 Python
  snippets using the Python 3.7 grammar, and diff whitespace checks passed.
  Syntax parsing is not a Python 3.7 runtime result.

Local environment: macOS arm64, Python 3.13.3, OpenSSL 3.0.16. Remote results for
this candidate are tracked on its migration pull request; the earlier PR #52
results do not establish T05 results. Older peer APIs can explicitly skip the
18 X25519-only matrix cases described in `test/secure_profile_matrix.md`.

## Retention and completion boundary

The 2.0.0 wheel, coverage JSON, JUnit XML, module/test manifests and verification
summary are retained under ignored `dist/t05/`. Their copied checksums and
report contents were read back. Task-owned build/install/test staging, including
its generated certificate keys, was removed. Earlier delivery artifacts remain.

Local T05 acceptance is complete. Delivery CI results belong to the migration
pull request. T06 requires selecting a concrete target group/peer before its
implementation; it is not an automatic extension of this migration.
