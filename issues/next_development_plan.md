# Next Development Plan

## Published baseline and next plan (2026-10-05)

The selected commit, push and publication are complete: `master` and `v2.1.0`
resolve to `2175105016f83dfe24fcb340e986719bd05ed04d`. This includes native async,
incremental response streaming, public typing,
local documentation and performance tooling, plus the reviewed correctness fixes.
See [release notes](../CHANGELOG.md), [GitHub v2.1.0](https://github.com/lxjmaster/ja3requests/releases/tag/v2.1.0)
and [PyPI 2.1.0](https://pypi.org/project/ja3requests/2.1.0/) for the versioned
delivery. Final installed acceptance passed 2135 tests and 112 subtests with
91.06% coverage; all 11 configured CI jobs passed on this exact revision,
including Python 3.7-3.13. Published artifacts and official-index installation
were verified. Read-only inspection found five open Issues and zero open PRs.

The [post-2.1.0 plan](post_2_1_0_plan.md) maps all 17 remaining candidates and
four deferred async convenience categories to proposed batches, dependencies
and acceptance. Its subsequently selected P1-P4 sequence is **complete locally**:
minimal packaging maintenance, frozen performance baselines, removal of the
full-TLS1.2 fixed wait, bounded async read-ahead and three shared-value typing
modules. Final acceptance passes 2151 tests / 91.06% coverage, independent
sdist-to-wheel installation, all 39 typing negative markers and strict docs.
Six modules are now in the strict gate; the internal backlog is 1786 diagnostics
in 53 files, so full internal typing is not claimed complete. See the
[execution record](post_2_1_0_execution.md) and
[performance report](../bench/POST_2_1_0_RESULTS.md) for evidence and tradeoffs.
The maintenance measurements used source snapshots retaining version 2.1.0.
A subsequent release request selects this work for the 2.1.1 patch release;
see [release notes](../CHANGELOG.md). Historical measurements below are unchanged.
Public documentation hosting and optional feature branches
remain unselected. This does not authorize closing remote issues or another capability
batch. The 2026-10-04 local acceptance below remains historical evidence, not
the final 2.1.0 release test count.

## Completed local roadmap (2026-10-04 snapshot)

The latest selected outcome, **#37 native async A1-A5, is complete locally**.
It exports `AsyncSession`, `AsyncResponse` and `AsyncConnectionPool`, retaining
the project's TLS and HTTP/2 engines. Final acceptance and runtime limits are in
[async execution](async_execution.md): 1847 tests and 112 subtests passed against
the installed wheel, with 90.45% statement coverage; all 223 async tests also
passed on Python 3.11. The APIs were not yet released at that inspection.

The preceding [client roadmap execution](client_roadmap_execution.md) completed
incremental responses (#41), synchronous performance measurements (#40), public
typing (#36), a buildable documentation site (#42), and #37's design stage.
The project must continue to own TLS handshake/record state and wire/fingerprint
control. No OpenSSL client wrapper or replacement TLS backend is part of this plan.
Keep Python >=3.7; use modern tooling in a separate development environment.

The preceding [maintenance batch](post_2_0_1_maintenance.md) is complete locally:
19 retry regressions, 1536 passing selected tests, 89.57% coverage, documentation
alignment and the preserved [pre-streaming baseline](../bench/RESULTS.md). These
are historical results, not acceptance for the new streaming implementation.

Read-only GitHub issue inspection on 2026-10-04 found exactly five open issues:
[#36](https://github.com/lxjmaster/ja3requests/issues/36),
[#37](https://github.com/lxjmaster/ja3requests/issues/37),
[#40](https://github.com/lxjmaster/ja3requests/issues/40),
[#41](https://github.com/lxjmaster/ja3requests/issues/41), and
[#42](https://github.com/lxjmaster/ja3requests/issues/42).
Local completion does not close these issues, commit/push changes, merge a PR,
deploy a website, or publish a package.

### Published baseline

- `master` and `v2.0.1` resolve to
  `a291ef30bb6ae53cf38b3d79604c8f34e1865547` at the 2026-10-04 readback.
- R01 release preparation merged in [PR #55](https://github.com/lxjmaster/ja3requests/pull/55).
  Both [2.0.0](https://github.com/lxjmaster/ja3requests/releases/tag/v2.0.0)
  and [2.0.1](https://github.com/lxjmaster/ja3requests/releases/tag/v2.0.1)
  are published. The latest version at this inspection is
  [PyPI 2.0.1](https://pypi.org/project/ja3requests/2.0.1/).
- TLS wire-control A-E, including explicit P-384 (the former T06), merged in
  [PR #56](https://github.com/lxjmaster/ja3requests/pull/56). Ten checks passed
  on the merged source. This work does not need another implementation or merge.
- The 2.0.1 installed-wheel baseline passed 1517 tests and 112 subtests with
  89.09% statement coverage. Reports and artifact hashes are retained in
  `dist/release-2.0.1/verification.json` and `publication.json`. Ubuntu CI covers
  Python 3.7-3.13; Python 3.7-3.10 each skip 18 older-peer cases. Manual
  `test/test_session.py` scenarios are excluded. Neither skips nor package
  metadata establish support in untested environments.
- Secure defaults, authenticated TLS 1.2/1.3, in-memory session resumption,
  HTTP/2 multiplexing and Cookie file persistence are delivered. The
  [wire-control contract](../docs/tls_wire_control.md) distinguishes supported
  handshakes from encoded fields and capture-backed browser subsets.

### Completed prerequisite batch: sync client and async design

All eight steps below are complete at their local-delivery boundary. This table
preserves the prerequisite batch; the subsequent async implementation is recorded
below. Remote delivery and publication were separate, unselected actions at
that inspection; the subsequent release selection is recorded above.

| Order | Completed work and acceptance scope | Dependency satisfied |
| --- | --- | --- |
| 1 | #41: incremental HTTP/1 framing and project TLS1.2/1.3 record reading; gzip/deflate/Brotli decoding; content/replay/error semantics; ownership through EOF, failure and early close | Existing pre-streaming baseline and protocol gates |
| 2 | #41: bounded H2 DATA queues, consumption-driven flow control, slow/fast stream isolation, cancellation, timeout, reset, GOAWAY and HPACK/trailer handling | Stable response ownership; preserve configured initial fingerprint values |
| 3 | #41: real event-controlled HTTP/TLS/H2 tests, retry/redirect/hook/proxy integration, large-response first-chunk and memory evidence | Items 1-2; do not claim total memory is bounded by `chunk_size` alone |
| 4 | #40: measure full/resumed TLS, pool reuse, HTTP1/H2 sequential/concurrent workloads, HPACK, cookies, pools and JA3; compare requests only on shared H1 scenarios | Frozen production source; verify payload and observed protocol/connection paths; retain raw samples and hashes |
| 5 | #36: public API annotations, `py.typed` in both package formats, mypy configuration/CI, strict valid/invalid installed consumers | Stable sync API; distinguish public consumer checks from remaining internal diagnostics |
| 6 | #42: local MkDocs site, generated API, all feature/configuration/exception guides, requests migration, architecture and runnable examples | Final public signatures and streaming contract; strict build, links and actual examples |
| 7 | #37 design: async API/ownership/cancellation/timeouts/hooks, native I/O adaptation map, implementation stages and failure matrix | Completed synchronous ownership and H2 backpressure; [design](async_api_design.md) only in this batch |
| 8 | Local acceptance and handoff: selected complete suite, >=85% coverage, Black/error-level Pylint, installed artifacts, typing, docs and measurements | Reconcile all lanes; preserve prior evidence and clean only task-owned staging |

Final installed-wheel acceptance: **1624 passed, zero failures/errors/skips,
90.04% statement coverage**, excluding `test/test_session.py`. Final package
source aggregate SHA-256 is
`5963161b9673c2004d7c551501265f0cd2c5b151bbe64b512facf7dbe65ca3dd`.
The [execution record](client_roadmap_execution.md#final-local-acceptance-2026-10-04)
links package hashes, installed tests/coverage, typing, strict docs build and
performance evidence under `dist/client-roadmap/final/`. Valid installed type
consumers and all 23 negative cases passed. The performance suite passed 26
tests with 76 measurement records; the [report](../bench/PERFORMANCE_RESULTS.md)
retains successful large-body streaming evidence and observed limitations.

This is local acceptance, not new remote CI or Python 3.7 runtime evidence.
New behavior was unreleased at that inspection; published 2.0.1 keeps its previous buffering behavior.
Do not repeat already delivered T01-T06, release preparation, or 2.0.1 publication
as new tasks. All current local acceptance items are checked in the execution
record; retained historical unchecked items below are not current obligations.

### Completed latest batch: #37 native async implementation

The follow-up implementation request selected and completed A1-A5 after the
synchronous prerequisite batch. Use the [implemented design](async_api_design.md)
for API differences, protocol scope, cancellation ownership and failure matrix;
the [execution record](async_execution.md) provides actual evidence and limits.

| Stage | Completed implementation | Verified boundaries |
| --- | --- | --- |
| A1 | Native TCP/proxy waits and shared TLS handshake/record state | Independent full/resumed TLS1.2/1.3, authentication, configured wire identity, fragmented input, native close wakeup and external cancellation |
| A2 | AsyncResponse framing, incremental decoding and awaited body APIs | Prefix before EOF, strict decoding, one consumer/cache semantics, trailers, early close and timeouts |
| A3 | AsyncSession, loop-bound pool admission and request policy | Borrowed-pool isolation, retained live responses, hook ownership/reentrancy, task isolation, retries/redirects/Cookies and no late-body replay |
| A4 | Native H2 reader/writer with bounded queues and consumption-driven credit | Concurrent/paused streams, target-only reset, peer admission, committed-write ordering, GOAWAY and shutdown without peer EOF |
| A5 | Installed typing, runnable docs, compatibility probes and fair measurements | 1847 tests +112 subtests / 90.45% coverage; 36 negative type markers; strict docs; 16 comparisons +4 large-body tests with 72 records |

Final package source SHA-256 is
`7c6ccaa85405c9f8e8444f2aa83dc190e394aade8669c64c2535c87ade17dca6`
across 68 modules. The [async guide](../docs/async.md) and
[performance report](../bench/ASYNC_PERFORMANCE.md) are usable locally.
Python 3.11/3.13 have actual async acceptance; system Python 3.9's final transport
tests pass but its LibreSSL TLS-peer/trust environment is not fully validated.
Python 3.7 syntax passes, while its actual runtime and new remote CI were not run.
Security-sensitive TLS transitions remain in project code.

The first async scope defers file-object/path uploads, Cookie file helpers,
public prepared-request APIs and module-level convenience functions. Add these
only when a concrete async usage requires them, with cancellation, ownership,
typing and documentation acceptance appropriate to that API. Streaming uploads
remain the separately listed request-body candidate below. These deferred
conveniences do not gate A1-A5; the design records the complete first-scope matrix.

### Other future tasks: explicit entry conditions

The list below is the complete set of currently identified follow-ups. Candidates
are independent; listing them does not select or authorize their implementation.

| Candidate | Entry condition | Work and acceptance |
| --- | --- | --- |
| Remote source delivery | Completed on 2026-10-05 at `2175105` | Scoped source committed/pushed; exact-revision CI passed and remote commit read back; unrelated local changes preserved |
| Next package release | Completed on 2026-10-05: 2.1.0 on PyPI and GitHub | sdist-to-wheel and independent installed acceptance passed; tag, both published files and official-index installation verified |
| Public documentation deployment (#42 optional) | Select hosting and deployment target | Build the accepted source, publish, verify public routes/assets and version labeling |
| Performance automation (#40 optional) | Reproducible baseline and useful comparison policy established | Isolated optional CI run, retained samples and variability; no arbitrary speed threshold |
| Measured TLS1.2 handshake latency | Select a performance follow-up backed by the new baseline | Investigate the existing 300 ms sleep in `TLS._handshake_tls12`; remove or replace it only with independent full/resumed/fragmented-handshake evidence, preserving authentication and wire behavior |
| Measured request throughput investigation | Select a controlled follow-up to retained sync/async samples | Investigate the 1 KiB shared-H1 4503.21 to 2809.04 requests/s observation or the 17.5–46.7% async throughput decrease and 100 MiB duration increase observed between the pre-close-fix and final runs. Separate scheduler/runtime variation from implementation cost; preserve cancellation/ownership, payload and connection checks. The measurements do not authorize optimization in this completed batch |
| Legacy packaging configuration | Select a small packaging maintenance batch | Replace deprecated `setuptools.command.test` / `tests_require` usage and recheck sdist-to-wheel installation; the current build succeeds with warnings |
| Internal typing cleanup (#36 continuation) | Concrete checker diagnostics after public consumer support | Incrementally resolve real findings; do not suppress entire modules or alter runtime semantics merely to reduce counts |
| T07: additional TLS1.2 SHA-384 suites | Exact CBC/static-RSA suite IDs and real target or reproducible peer | Verify negotiation, PRF, Finished and records; do not add unproven legacy suites to secure defaults |
| T08: cross-process TLS session persistence | Restart-resumption requirement, storage and secret-protection choices | Design versioning, expiry, trust binding and concurrent writes before implementation; Cookie persistence is already delivered |
| T09a: H2 priority scheduling | A concrete fairness/latency workload | Define scheduling API, starvation bounds and interaction with backpressure; received PRIORITY signals currently do not schedule requests |
| T09b: H2 server push | An actual push consumer use case | Define consumer API, cancellation and resource bounds; do not enable push before support exists; select separately from scheduling |
| T10: TLS1.3 0-RTT | Eligible operations, explicit opt-in and replay/retry policy | Design first; rejection cannot duplicate application effects; persisted tickets are needed only if cross-process use is selected |
| Browser profile updates | Exact browser/version, retained fresh capture and supported wire fields | Reproduce and inspect actual ClientHello/H2 settings; report unsupported ECH/post-quantum fields and fingerprint differences |
| ECH or post-quantum groups | Named peer/browser requirement and cryptographic primitive availability | Separate design and independent interoperability/security evidence; no algorithm rewrite or implicit scope expansion |
| Request-body streaming | Concrete large upload need and retry/replay rules | Streaming upload framing and H2 send credit, cancellation and non-replayable-body policy; response streaming does not provide it |
| HTTP/3 | Concrete QUIC/HTTP3 target and acceptable ownership/dependency boundary | Separate feasibility/design stage; not an H2 incremental extension and not required for the current delivery |
| Additional support environments | Named Python/OS/architecture or external peer required by a user | Extend the actual installed-package/interop matrix; metadata or skipped tests alone are not proof |
| Session-default merging parity | A selected compatibility need with requests | Existing headers/auth/params/proxies are not all automatically merged by Session.request; specify precedence and add targeted behavior tests before changing it |

The native async batch is complete at its local boundary. Of the 19 candidates,
source delivery and the 2.1.0 package release were subsequently completed; the
other 17 form the proposal inventory. The P1-P4 follow-up selected packaging,
performance investigation and incremental typing; other candidates remain
unselected. Capability or performance work should follow a
concrete need and its acceptance criteria. Package publication does not select
public documentation-site deployment.

## Historical roadmap snapshot (2026-10-03)

The text below preserves the original R01/R02/T06 planning context. Its pending
states and then-current release references are historical; use the current
roadmap above for task selection and the linked release evidence for completion.

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
