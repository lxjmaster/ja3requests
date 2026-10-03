# Next Development Plan

Revised: 2026-10-03 after live state readback. R01 remains incomplete; later
batches remain reference. This revision plans the remaining work; it does not
report remote delivery or publication as completed.

## Outcome and scope

Replace the completed delivery sequence with bounded next outcomes, explicit
entry conditions and observable acceptance. The follow-up execution request
selects recommended R01: prepare and verify the 2.0.0 artifacts and deliver the
roadmap, necessary packaging fixes and final handoff through a PR to master.
No package upload, release/tag creation or T06-T10 development is included.

When a batch is selected, fix its outcome and action scope once and execute it
without repeatedly requesting authority already supplied. Register only the
selected execution outcome when supported; this roadmap is reference context,
not a gating workline for deferred batches. The user's R01 goal is active.
File-plan registration remains UNREGISTERED: the supported CLI cannot obtain
an official session binding. Continue independent work without inventing one.

## Current baseline

- Master at inspection: `bfe12639308418c82fb9bcdbb74de2993cc154a8`.
- T01-T05 and E1-E3 are complete. PR #52, #53 and documentation closeout #54
  are merged. There is no pending protocol-delivery merge.
- Final master CI has ten successful checks, including Python 3.7-3.13,
  installed-wheel smoke, formatting, error-level lint and coverage.
- The final protocol candidate passed 1427 installed-wheel tests with 89.04%
  coverage. Python 3.7-3.10 remote runs each passed 1409 with 18 explicit skips.
  The suite excludes `test/test_session.py`; skips are not passing evidence.
- Secure TLS defaults, TLS 1.2/1.3 authentication and in-memory resumption,
  HTTP/2 multiplexing and opt-in Cookie file persistence are implemented.
- TLS 1.3 key shares implement X25519/P-256. P-384 is not supported end to end
  merely because TLS 1.2 or a browser preset contains that group identifier.
- This work has not published 2.0.0. GitHub's latest release at inspection is
  v1.2.0. Check the selected package index separately before publication; this
  is not a PyPI status claim.
- Historical failed CI runs remain visible after fixes. Do not rerun old
  commits to erase red history. Explicit older-peer limitations remain.

Completed evidence, not new tasks:
[delivery review](protocol_delivery_review.md),
[execution record](protocol_delivery_execution_plan.md),
[T05 acceptance](secure_defaults_delivery.md),
[interoperability matrix](../test/secure_profile_matrix.md),
[migration guide](../docs/tls_defaults_migration.md),
[Cookie persistence](../docs/cookie_persistence.md).
Retain existing `dist/t01/` through `dist/t05/` and `dist/delivery_review/`.

## Recommended sequence

### Immediate remaining work: R01 closeout

Verified at this revision: remote master is `bfe1263`; the release-preparation
branch is pushed at `9a6977e9d1cf887b8dc77d71e5673497513ffe41`. No PR exists for
that branch and no candidate CI run is shown in the latest runs. Master Tests,
Lint and Coverage workflows succeeded. Those successes do not validate the new
packaging workflow. The task-owned staging directory still exists.

- [ ] Finalize and deliver this revised plan together with the existing five-file
  R01 change through one PR from `release/2.0.0-preparation` to `master`.
  Inspect the final diff; preserve user files. Do not add runtime features.
- [ ] Validate the exact PR head with the existing CI gates, particularly the
  changed sdist-to-wheel build and installed-package smoke check. Investigate
  any new failure by commit, job and failing step; fix only required defects.
  Historical failed runs are not current failures and need no cosmetic reruns.
- [ ] Under the established R01 delivery scope, merge the green PR server-side,
  read back master and confirm all five deliverables. Check automatically
  triggered master CI; do not manually duplicate unchanged successful tests.
- [ ] Read back retained artifact hashes/reports, then remove only validated
  task-owned `/tmp/ja3requests-r01.8jWorW` staging. Retain `dist/r01/`, prior
  evidence, existing worktrees, user debug scripts and IDE files.
- [ ] Reconcile local acceptance, remote delivery, CI and cleanup evidence.
  Only then complete the active R01 goal. A finished plan or local test run
  alone must not complete it. Record remote evidence without creating an
  uncommitted tracked-document tail after merging.

The existing 1427 tests plus 107 subtests and 89.05% coverage are retained
local acceptance evidence, not a new test task. Rebuild only if package inputs
change; rerun affected checks for a new relevant failure. Documentation-only
revisions need content, relative-link and diff checks.

If CI fails, keep R01 open and return to its closeout after the scoped fix.
An unavailable plan-session binding does not prevent repository work. Registry
credentials or a release destination are inputs to R02, not blockers for R01.
Execute serially without subagents; this coupled closeout needs no parallel
workstreams or new automation framework.

| Batch | Status | Entry condition | Deliverable |
| --- | --- | --- | --- |
| R01: Prepare 2.0.0 release candidate | Local acceptance passed; remote delivery through the containing PR | Selected by follow-up execution request | Pinned source, checked artifacts and publication handoff |
| R02: Publish 2.0.0 | Independent; not started | R01 passes; destination and publication authorized | Selected package/tag/release, verified by readback |
| T06: One additional TLS 1.3 group | Proposed next feature; not started | Select group/peer and configuration policy | End-to-end explicit opt-in support |
| T07: Additional TLS 1.2 SHA-384 compatibility | Deferred | Exact suite and target system/peer | Supported/unsupported result for that target |
| T08: Cross-process TLS sessions | Deferred | Restart-resumption need and storage constraints | Bounded design first |
| T09: HTTP/2 extension | Deferred | Select scheduling OR push and a use case | One defined API and behavior |
| T10: TLS 1.3 0-RTT | Deferred | Eligible requests and replay/retry policy | Design before implementation |

Recommendation: prepare the existing 2.0.0 candidate without adding features to
it. R02 need not block T06 on a separate branch; T06 does not depend on package
publication. If development is the priority, selecting T06 directly is valid.
Do not silently include T06 in the frozen release or change version numbers
before selecting that release boundary. Do not execute all candidates in order.
No calendar promises precede target and scope selection.

## R01: Release preparation without publication

Outcome: a concrete release candidate and reviewable publication handoff.
R01 does not require credentials, tag pushes, uploads or release creation.

- [✅] Pin the source commit; reconcile version, package metadata, changelog,
  migration examples and declared Python support. Check version availability
  read-only if the target package index has been selected.
- [✅] Build only the intended wheel and source distribution in an isolated
  task directory. Inspect metadata, archive contents and required modules;
  exclude debug scripts, IDE files, local reports and secrets.
- [✅] Check wheel/source-distribution consistency and installation/imports
  outside the checkout, plus secure/legacy entry points. Reuse behavioral
  evidence when source/dependencies match; rerun the installed-wheel suite
  only for changed inputs or a specific unresolved artifact concern.
- [✅] Record source SHA, exact artifact names/hashes, tool/runtime versions,
  validation results and known skips. Prepare release notes and commands for
  the chosen destination, or clearly leave destination selection to R02.
- [✅] Fix only proven release blockers, verify affected paths, and document
  their delivery scope. Do not turn this into packaging migration, dependency
  modernization or CI redesign without a concrete release need.

Acceptance: every intended artifact maps to a source commit and validation;
the handoff explains breaking defaults and known limits. R01 may finish while
R02 remains unselected; never equate artifact readiness with publication.

Result: [R01 release handoff](release_2_0_0_preparation.md), source
`2cffc275ab6d67229274d34909b5a67daa2c78eb`. Fixed missing sdist build inputs and
Python metadata, and made the existing CI wheel job build through the sdist.
Both artifacts install cleanly; 1427 tests plus 107 subtests passed with 89.05%
coverage. The containing PR must merge with successful checks and remote file
readback before remote delivery is reported complete; its state supplies that
final evidence without a post-merge uncommitted status edit.

Read local-development rules before builds/installs. Do not use broad
`make clean` or `make upload`: current targets cover prior dist artifacts.
Use task-owned output paths and explicit reviewed artifact arguments.

## R02: Publication when selected

- [ ] Confirm candidate, destination and exact artifact list, including whether
  the outcome includes index upload, repository tag and GitHub Release.
  One explicit instruction covers unchanged normal publication steps.
- [ ] Recheck source/artifact identity and version availability immediately
  before upload. Use existing credentials without exposing secrets.
- [ ] Publish only selected artifacts. Never upload a wildcard covering old
  reports; after an ambiguous result, inspect remote state before retrying.
- [ ] Read back version/artifact identity and install from the destination in
  an isolated environment. Record package, tag and release links as applicable.

Acceptance: selected external outputs exist and correspond to the verified
candidate. No unrequested TestPyPI stage, signing service or release automation
framework is required. Do not overwrite published artifacts; use the selected
registry's actual recovery/version policy if a correction is needed.

## T06: Proposed minimal P-384 batch

Pending selection: TLS 1.3 P-384 (`secp384r1`) through explicit configuration,
verified against an independent OpenSSL peer. Keep default and secure-profile
group lists, browser preset wire settings and default JA3 behavior unchanged.
Do not alter TLS 1.2 policy or build a generic curve-plugin framework.

- [ ] Confirm the peer can force P-384 and HelloRetryRequest. Inspect existing
  key generation/shared-secret dispatch, ClientHello share selection,
  configuration validation and retry reconstruction.
- [ ] Add P-384 key generation, public-key encoding and shared-secret derivation
  through the existing handshake and validation paths.
- [ ] Handle HelloRetryRequest (a request for another key share) with a fresh
  share and existing transcript rules. Preserve advertised-group validation
  and rejection of invalid/repeated retry behavior.
- [ ] Verify independent full handshake, forced retry and fragmented reads.
  Force retry by advertising P-384 while initially offering another share.
  Cover malformed public keys and server selection of an unadvertised group.
- [ ] Reuse X25519/P-256 and resumption regressions; add only meaningful gaps.
  Check actual ClientHello fields for unchanged default/preset behavior,
  rather than inferring wire compatibility from configuration lists alone.
- [ ] Update capability/configuration docs and the interoperability matrix.
  After changes stabilize, verify installed wheel, relevant selected full
  suite and final CI, then synchronize code/tests/docs within selected scope.

Acceptance: explicit P-384 works end to end, including retry and failure
boundaries; default wire behavior remains unchanged. At least one independent
peer exercises every claimed success/retry path. Older-peer skips must be
explicit; an entirely skipped P-384 matrix is not acceptance.

## Deferred tasks: entry requirements

- **T07:** select exact suite IDs and a real legacy system or reproducible peer.
  Verify negotiation, PRF/key derivation, Finished and record integrity.
  Existing ECDHE AES-256-GCM/SHA-384 evidence does not prove CBC/static-RSA
  support. Do not add legacy suites to secure defaults.
- **T08:** establish why Cookie persistence and in-memory TLS caches are
  insufficient. First design caller-controlled secret protection, record
  versioning, expiry reconstruction, trust-policy binding and concurrent writes.
  Do not directly serialize caches or treat monotonic ages as portable.
  Implementation is a separately selected outcome.
- **T09:** select scheduling OR push. Scheduling needs fairness/backpressure
  behavior; push needs a consumer API, cancellation and resource bounds.
  No concrete use case means no development, not an incomplete release.
- **T10:** select eligible requests, explicit opt-in and replay/retry behavior.
  Rejected early data must not duplicate application effects. Depend on T08
  only if persisted tickets are required; in-memory tickets do not impose
  that dependency. Finish the design before protocol implementation.

## Verification, delivery and retention

Execute serially without subagents. No speculative refactoring, unrelated
compatibility expansion, historical CI reruns or coverage-only tests. Diagnose
actual failures; after two attempts without narrowing the cause, use a safe
alternative or identify the real dependency rather than looping.

For code batches, start with affected tests. At the final candidate boundary
use existing gates: selected suite excluding `test/test_session.py`,
installed-wheel origin checks, coverage >=85%, package Black/error-level
Pylint and applicable remote checks. Reuse unchanged successful evidence.
Docs-only edits require links/content/diff checks, not manual protocol reruns.
Existing CI may trigger automatically on PR/push events.

Name the required completion level before each batch: implementation, verified
local artifact, remote delivery or publication. If remote delivery is selected,
code, tests AND final status documents must be committed, pushed and merged as
applicable, with remote readback. Uncommitted final documents do not complete a
remote handoff. Do not extend a finished batch with an unselected candidate.

Retain wheels/reports/manifests in a batch-specific directory with source
identity. Remove only task-owned build/install staging and generated test keys.
Preserve prior artifacts, debug scripts, `.idea/`, `.DS_Store`, unrelated source
edits and credentials. Never retain publication credentials or TLS session
secrets in reports.

## Planning handoff

This revision replaces the old sequential T01-T10 queue. Completed history is
available in the linked records and Git history. R01 is now selected with remote
delivery of its fixes and final records; artifact files remain retained locally.
R02 publication and T06-T10 remain independently selected future outcomes.
