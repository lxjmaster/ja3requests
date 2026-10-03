# R01: 2.0.0 Release Preparation

Date: 2026-10-03. Selected outcome: verified local release artifacts and remote
delivery of necessary packaging fixes, the revised roadmap and this handoff.
No package index upload, tag creation, GitHub Release or T06-T10 implementation.

## Candidate identity

- Starting master: `bfe12639308418c82fb9bcdbb74de2993cc154a8`.
- Pinned release source: `2cffc275ab6d67229274d34909b5a67daa2c78eb`.
- Version: `2.0.0`; retain candidate wording until R02 publication.
- Output directory: `dist/r01/artifacts/` (local retained deliverables).
- Build and verification evidence: `dist/r01/verification_summary.json`,
  `verification.xml`, `coverage.json`, command logs and `verify_release.py`.
  Original T05 and delivery-review artifacts remain unchanged.

Follow-up documentation commits need not rebuild the candidate: they do not
change its package inputs. Any later package-input change requires a newly
pinned candidate and relevant validation before publication.

## Proven packaging defects and minimal fixes

The original clean Git snapshot produced an sdist without `requirements.txt`
or `requirements-dev.txt`, even though setup.py reads both during a build.
Building a wheel from that sdist failed with FileNotFoundError for
`requirements.txt`. A direct checkout-to-wheel build had not exercised this
boundary. The original sdist also contained an incomplete test tree.

`MANIFEST.in` now includes the two dependency files, the translated README,
changelog, documentation and complete Python/Markdown test tree. The source
comes from a clean Git archive, excluding user debug scripts and IDE files.
The package's Python requirement now explicitly declares `>=3.7`, matching
the existing README claim. Library runtime code is unchanged.

The existing CI wheel job now builds an sdist and then builds its wheel from
that sdist before running the installed-package smoke check. It also checks
the Python metadata. This closes the observed gap without adding another
workflow or a packaging-system migration.

## Verification and limitations

Both artifacts pass strict Twine metadata checks. Each installs successfully
in a separate clean environment outside the source tree, passes dependency
consistency and secure/default/legacy smoke checks, and contains all 58 package
modules byte-for-byte identical to the pinned source and prior verified runtime.

The selected full suite is run using tests from the sdist against the installed
wheel, outside both source trees. Its final results and hashes are recorded in
the machine-readable summary and the acceptance section below.

Retain the project's Python 3.7-3.13 support claim and explicit older-peer
limitations. The selected suite excludes the manual `test/test_session.py`.
Old Python/OpenSSL X25519 peer limitations account for 18 matrix skips; skips
are not evidence that those cells passed.

Setuptools currently warns about the deprecated setup.py test command and
`tests_require`; both artifact builds succeed. Removing that legacy interface
is not necessary for this release-preparation outcome and was not bundled in.
The build log records the actual backend version used.

## Release notes for the selected candidate

Use [CHANGELOG.md](../CHANGELOG.md) and the
[migration guide](../docs/tls_defaults_migration.md). The public announcement
must prominently state that implicit requests now verify certificates and use
TLS 1.3 with TLS 1.2 ECDHE/GCM fallback, changing default ClientHello/JA3 behavior.
Use explicit trust configuration for private certificates; there is no automatic
insecure retry. `legacy()` remains explicit compatibility behavior with disabled
verification, and `from_browser()` retains preset wire settings but verifies.

TLS in-memory resumption, HTTP/2 multiplexing and Cookie JSON persistence are
included. TLS session persistence, service push, additional TLS 1.3 groups and
0-RTT are not included. No new functionality is added by R01.

## R02 handoff

R02 must select the package registry and whether publication includes a tag and
GitHub Release. No registry has been selected for upload in R01. GitHub's latest
release was v1.2.0 at inspection; this does not establish PyPI version availability.
Before uploading, query the selected registry for 2.0.0 and resolve any existing
version rather than overwriting or silently changing it.

Publish only these two reviewed paths, never `dist/*` or `make upload`:

- `dist/r01/artifacts/ja3requests-2.0.0-py3-none-any.whl`
- `dist/r01/artifacts/ja3requests-2.0.0.tar.gz`

Before publication, verify their hashes against this handoff and run:

```sh
python -m twine check --strict dist/r01/artifacts/ja3requests-2.0.0-py3-none-any.whl dist/r01/artifacts/ja3requests-2.0.0.tar.gz
```

The upload command and tag/release actions are finalized only for the selected
destination and action set; credentials are not needed for R01. After upload,
verify remote artifact identity and install from the target registry. A failed
or ambiguous upload requires readback before retrying.

## Acceptance and retention

Local acceptance passed: 1427 tests and 107 subtests passed, zero failures,
errors or skips; statement coverage is 89.05%. JUnit reports 1534 entries
because this pytest version counts the 107 subtests separately. Environment:
macOS arm64, Python 3.13.3, OpenSSL 3.0.16; clean runtime installations selected
brotli 1.2.0 and cryptography 50.0.2. The isolated build used build 1.6.1 and
setuptools 84.0.0. Exact dependency snapshots are retained in the freeze logs.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| ja3requests-2.0.0-py3-none-any.whl | 153294 | 3eaf03ccbdca957a253860cbb8ae9bf08ff31149a92667555a7fc19167f4a397 |
| ja3requests-2.0.0.tar.gz | 255655 | bd1d900b1de3679e1a7b053e059fd8d7991bbb1c60596bf661550c4373997ccb |

The R01 remote-delivery gate is
the merged PR containing the packaging fix, roadmap and this final record,
successful checks on that candidate, and remote file readback. The PR itself
records its eventual merge SHA; no post-merge local-only status edit is needed.

Keep reviewed artifacts/reports and the existing worktrees. Remove only the
task-owned `/tmp/ja3requests-r01.8jWorW` staging after artifact readback; never use
a broad dist cleanup. Preserve all user debug scripts, `.idea/` and `.DS_Store`.
