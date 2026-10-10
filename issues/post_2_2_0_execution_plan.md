# Post-2.2.0 execution plan

Prepared: 2026-10-08

Status: **COMPLETE LOCALLY / UNREGISTERED**. The user authorized execution and selected
the workflow "prepare, inspect or sign, then send". This is the sole execution
status record; the follow-up plan is a candidate roadmap. The supported
`codex-plan --json status` still cannot obtain an official session binding.

The user authorized the latest three findings: reject malformed H2 response
fields without losing shared HPACK state, process every received SETTINGS pair
in order, and allow an extension-free legacy ClientHello to complete a real
handshake. Work is serial within the existing TLS/H2 engines. Existing edits
and historical evidence are preserved; this outcome has no remote writes.
Task-owned temporary artifacts are removed after verification and acceptance
reports are retained. Registration remains UNREGISTERED as recorded above.

- [✅] Add meaningful failing regressions for all three defects and valid controls.
- [✅] Implement stream-isolated response validation, ordered peer SETTINGS and
  empty-extension ALPN extraction; verify actual TLS and reuse/cleanup boundaries.
- [✅] Complete focused and installed acceptance, types/lint/docs, frozen source
  and artifact readback, temporary cleanup and section 20 of this record.

Section 20 records current acceptance; section 19 is retained previous evidence.

The user authorized the subsequent review's two findings: keep a local decoded
H2 response-header budget when exact SETTINGS omit ID 6, and reject application
protocols that the HTTP client does not implement. Work remains serial; the
existing TLS/H2 engines, source edits and historical evidence are preserved.
The scope is local fixes, documentation and acceptance, without remote writes.
Task-owned temporary staging is removed after verification; acceptance evidence
is retained. No official session binding is available, so registration remains
UNREGISTERED without a fabricated identity.

- [✅] Reproduce omitted decoded limits and unsupported ALPN with meaningful
  regressions, preserving exact wire SETTINGS and raw ClientHello encoding.
- [✅] Enforce local HPACK budgets and HTTP ALPN configuration/dispatch guards;
  verify real TLS 1.2/1.3, connection/pool failure and source ownership boundaries.
- [✅] Complete focused and installed acceptance, formatting/types/lint/docs,
  source/artifact identity, temporary cleanup and this execution record.

That batch's acceptance is recorded in section 19; section 18 is retained history.

The user authorized the TLS/H2 review fixes: exact ordered SETTINGS, usable
ordered-list inputs, H2 configuration validation, independent preset state,
offered-ALPN enforcement and valid H2 request fields. The identified H2 goal gap
also includes configurable pseudo-header order and initial PRIORITY signals.
The existing project-owned TLS/H2 engines remain the implementation boundary.
Work is serial because configuration, wire output and pool identity are shared;
existing source edits and historical artifacts remain intact. This outcome is
local fixes/types/docs/acceptance, without commit, push or publication.

- [✅] Reproduce the six defects and H2 control gap with independent request
  frames and TLS negotiation checks, preserving the previous accepted baseline.
- [✅] Separate emitted SETTINGS from effective defaults, validate ordered
  settings/windows, copy presets and connect pseudo/PRIORITY controls to pools.
- [✅] Enforce actual offered ALPN and share valid H2 request-field preparation
  across serial, multiplexed and native async senders.
- [✅] Complete relevant and installed acceptance, types/docs/lint, source and
  artifact readback, task-owned temporary cleanup and this execution record.

Current TLS/H2 acceptance is recorded in section 18; section 17 is retained history.

The user authorized fixes for the latest comprehensive review's five findings:
validate automatic Cookie refreshes, isolate async proxy authentication, preserve
raw header bytes across transports, read complete synchronous CONNECT responses
and close failed tunnels. Work remains serial because these paths share field
and ownership boundaries. Existing edits and acceptance evidence are retained;
commit, push and release are not part of this local outcome.

- [✅] Add regressions for Cookie refresh/retry rejection before source/network
  work and async CONNECT authentication isolation and pool identity.
- [✅] Preserve byte-valued fields in inspection and HTTP1/H2 wire output;
  verify UTF-8 H2 rejection and framing/multipart compatibility.
- [✅] Verify fragmented/bounded CONNECT parsing, preserved tunnel data and
  deterministic cleanup on rejection, malformed input and timeout.
- [✅] Complete focused and installed acceptance, docs/types/lint, frozen source
  and artifact identity, temporary cleanup and this execution record.

The current acceptance is recorded in section 17; section 16 is retained history.

The user authorized fixes for the subsequent review's two findings: preserve
synchronous HTTP2 byte-header encoding and avoid retrying local header input
errors as connection failures. Work remains serial because field validation,
proxy snapshots and HTTP2 encoding share the same boundary. Existing source
edits and prior acceptance evidence are retained; no remote action is selected.

- [✅] Preserve raw destination header values while validating fields and
  isolating proxy authentication; verify UTF-8 byte/text controls at wire peers.
- [✅] Reject invalid sync fields before network/source work and retain input
  error types through direct HTTPS/H2 send cleanup, without a network retry.
- [✅] Verify failure isolation, focused cases, installed acceptance, docs/types/
  lint, source identity and task-owned temporary cleanup; update this record.

That batch's acceptance is recorded in section 16; section 15 is retained history.

The user authorized fixes for the comprehensive review's five wire-boundary
defects and roadmap status drift. Work remains serial because the shared header
contract and its transport consumers are coupled. No delegation or remote
delivery is selected. The completed buffered A3 contract remains the baseline.

- [✅] Share final header validation across sync, async and CONNECT; keep proxy
  credentials out of destination requests without mutating retry metadata.
- [✅] Preserve semicolon path components and use final Host for sync HTTP2
  authority; add independent wire and invalid-input regressions.
- [✅] Reconcile current roadmap/evidence references and verify focused tests,
  installed acceptance, docs/types/lint, source identity and temporary cleanup.

That batch's acceptance is recorded in section 15. The preceding synchronous
maintenance acceptance in section 14 is retained history.

The user authorized the third review fix: preserve leading slashes in the shared
async HTTP1/H2 request target. This corrects an existing dispatcher defect that
affects both prepared sends and ordinary requests. Work remains serial with no
delegation. Earlier acceptances are retained history; the current candidate
passed its frozen-snapshot acceptance recorded in section 13 (retained history).

- [✅] Reproduce leading-slash signing failures at a real HTTP1 peer and add
  HTTP1/H2 plus ordinary-request path regressions.
- [✅] Correct the shared request-target construction and document preservation
  of leading slashes, encoded paths and query contents.
- [✅] Verify focused behavior, installed acceptance, docs/types/lint, snapshot
  identity and task-owned temporary cleanup.

The user authorized the second review fix: normalize all prepared destination
URLs to the effective scheme, authority and request target before signing.
Runtime work remains serial. The preceding acceptances are retained history;
that candidate passed installed acceptance recorded in section 12.

- [✅] Reproduce all three reported HTTP1 failures: empty query delimiter,
  upper-case scheme and port leading zeros; six existing controls pass.
- [✅] Implement shared authority formatting, prepared URL normalization and
  Cookie reselection; add HTTP1/H2 and authority regression cases and docs.
- [✅] Verify focused behavior, installed acceptance, docs/types/lint, snapshot
  identity and task-owned temporary cleanup.

The 2026-10-09 review fix is authorized: normalize empty prepared URL paths to
the actual `/` request target and verify signatures independently at local peers.
The earlier installed snapshot below is retained history and is superseded for
the current candidate. Runtime work remains serial; no delegation is needed.

- [✅] Reproduce the finding: four HTTP1 cases return 401 before the correction;
  existing slash/encoded-path controls pass.
- [✅] Add the bounded prepared-URL correction and independent HTTP1/H2 signature
  regression tests, with matching documentation.
- [✅] Verify focused behavior, required installed acceptance, docs/types/lint,
  snapshot identity and task-owned temporary cleanup.

## 1. Outcome and authorization boundary

Prepare one bounded next engineering batch while keeping 2.2.0 behavior stable.
The recommended product track is **A3 async prepared request/send**, beginning
with a contract and a buffered-body slice. Session-default merging (C17) is an
alternative track, not parallel work.

The selected local outcome includes A3 contract design, buffered-body
implementation, types/docs, regression tests and installed acceptance. Contract
review is an engineering check within this authorization. Commit/push, remote
Issue changes, site deployment and a new release are outside this local outcome.

Baseline:

- `master`, `origin/master`, and `v2.2.0` point to
  `83132c84547b6f7bbcf740b961b6d06a7121b058`.
- The published 2.2.0 wheel/sdist and official-index installation have already
  been verified. Retained evidence is under `dist/release-2.2.0/`.
- Streaming request bodies, async multipart/files, async Cookie files, HPACK
  validation and their ownership/cancellation fixes are released. They are
  dependencies and regression boundaries, not new implementation targets.
- Python `>=3.7`, project-owned TLS/HTTP2 state, secure certificate defaults,
  response ownership, cancellation, deadlines and flow-control bounds remain
  unchanged constraints.

## 2. Ordered workline

| Phase | Work | Dependency | Exit condition |
| --- | --- | --- | --- |
| E0 | Intake and exact-baseline readback | A concrete user workflow or reproducible defect | Use case, affected API, compatibility goal and baseline commit are recorded; without a real need, stop here |
| E1 | Candidate decision gate | E0 | Route confirmed defects through M0; otherwise select A3 or C17; wrappers/docs are evaluated |
| E2 | A3 contract design | E1 selects A3 | Freeze, body, hook, loop/session, response and cancellation matrices are complete and internally consistent |
| E3 | A3 minimal implementation | E2 accepted | Buffered-body preparation/send works with focused tests and no unresolved ownership rule |
| E4 | A3 boundary review | E3 | Streaming-body extension, if needed, is separately justified; otherwise it remains deferred |
| E5 | Exact-snapshot acceptance | E3/E4 | Installed tests, typing, docs, syntax and cleanup pass on one frozen source snapshot |
| E6 | Delivery decision | E5 | Reviewable commit/push/release handoff exists only if those action sets are selected |

The phases are serial for runtime code. Documentation examples and type-consumer
fixtures may proceed after E2's contract is frozen, but they cannot define API
semantics independently.

## 3. E0-E1: intake and candidate decision

- [✅] Record the concrete workflow: request reuse, middleware composition,
      explicit send control, or a reproducible compatibility defect.
- [✅] Reproduce the workflow against the 2.2.0 public API and check whether a
      small caller wrapper or documentation change already solves it.
- [✅] Identify affected synchronous/async methods, body kinds, redirect/retry
      paths and response ownership boundaries.
- [✅] Select one track. Do not combine A3 prepared-send work with C17 default
      merging in the same batch.

Decision rule:

- Select **A3** when the missing capability is explicit async preparation or
  controlled sending. The current private `_RequestMetadata` and `_freeze()`
  implementation are evidence that a public API needs a deliberate contract.
- Select **C17** only when a compatibility need justifies changing the current
  documented non-merging behavior. Prefer an additive opt-in defaults object;
  do not silently change legacy `Session.headers`, `auth`, `params` or
  `proxies` observations.
- If neither condition is met, retain the 2.2.0 maintenance posture and do not
  create runtime work to fill the roadmap.

## 4. E2: A3 contract design

Produce a small design record before changing public code. It must settle:

1. Candidate public names and whether the object is immutable after freeze.
2. Which inputs are supported in the first slice. Recommended first slice:
   buffered bytes/form/JSON bodies; streaming files and iterators remain a
   separately selected extension.
3. Whether repeated send creates a fresh replay state, and the exact outcomes
   for consumed iterators, non-seekable files and length mismatches.
4. How before/after hooks see metadata, how hook replacement transfers
   ownership, and which fields are snapshots rather than live Session state.
5. Session and event-loop ownership, cross-loop rejection, close behavior and
   response lease transfer when `stream=True`.
6. Retry and redirect policy, including 307/308 body preservation and the
   existing non-replayable-body rules.
7. Cancellation timing, source cleanup and the error types exposed to callers.
8. Public typing, migration notes and the minimum runnable example.
9. TLS configuration and `verify` snapshots, client certificate paths versus
   bytes, shared session-cache identity, and rejection across Sessions/loops.

The first prepared API accepts `None`, bytes/text, form mappings/pairs and JSON
using existing encoding. Binary handles, synchronous/async iterators and private
upload adapters raise `InvalidData` before source I/O. `files=` is absent and
raises `TypeError`; it is never buffered implicitly. Existing `request()` upload
support remains available. Before-request hooks on `send()` must also leave a
bytes body. The full contract is in
[the design record](async_prepared_request_design.md).

Required design artifacts:

- [✅] API and ownership matrix.
- [✅] Body/replay/error decision table.
- [✅] Hook and response-transfer matrix.
- [✅] Focused acceptance test list mapped to each decision.
- [✅] Explicit exclusions for streaming sources, module-level helpers and
      synchronous API changes unless separately selected.

Stop E2 if any body or ownership rule is unresolved. Do not expose a partial
prepared object merely to preserve a schedule.

## 5. E3-E4: minimal A3 implementation path

Implement in this order after E2 is accepted:

1. Add the smallest public metadata/prepared type and freeze logic for the
   buffered-body slice. Keep transport handles and private pools out of the
   public object.
2. Add `AsyncSession` preparation and send entry points with explicit Session
   and loop checks. Preserve existing hook order, Cookie snapshots, retry and
   redirect policy.
3. Add response ownership transfer, close/cancel paths and repeated-send tests.
4. Add public typing, API docs and one local loopback example.
5. Reassess streaming files/iterators using measured demand. Add them only as a
   separate follow-up with the already released upload ownership contract.

The implementation must not change synchronous redirect behavior, TLS wire
defaults, pool sharing, Cookie-file semantics or existing high-level methods.

## 6. C17 alternative path

This alternative remains unselected reference. A future C17 selection would
replace E2-E4 with this sequence; it is outside the completed A3 outcome:

- Choose additive opt-in configuration and its exact setter/getter shape.
- Implement header case-insensitive override/removal and ordered query
      append semantics from `issues/session_defaults_design.md`.
- Preserve explicit Cookie/auth/proxy precedence, cross-origin stripping,
      hook ordering and sync/async empty-header differences.
- Add network-free preparation tests before local peer redirect/retry tests.
- Document migration and reject unknown or forbidden default keys without
      mutating the previous valid configuration.

Do not implement C17 by making existing legacy properties magically merge.

## 7. E5 acceptance and evidence

Run the smallest affected checks first, then the required installed acceptance on
one frozen candidate:

- focused unit and loopback tests for the selected matrix;
- `pytest test --ignore=test/test_session.py --cov=ja3requests
  --cov-fail-under=85` through the installed artifact verifier;
- installed valid/invalid typing consumers and strict modules affected;
- documentation site build, links, API objects, snippets and runnable examples;
- Python 3.7 grammar compatibility plus actual runtime results only where run;
- mandatory sdist-to-wheel build, independent install, `pip check`, source/module
  origin and hashes for the runtime candidate, using
  `python tools/verify_release.py --repo . --worktree-snapshot
  --include test/test_async_prepared_request.py
  --output dist/post-2.2.0/final-acceptance`;
- `python -m mypy`, `python -m black --check ja3requests` and
  `python -m pylint --errors-only ja3requests`;
- `python -m mkdocs build --strict` and `python docs/verify.py` from this
  full-history checkout. The verifier performs installed typing and Python 3.7
  grammar checks; grammar is distinct from runtime-matrix evidence.

Record source identity, commands, counts, skips, warnings, logs, cleanup and
unverified environments. Do not label a candidate accepted when a required step
was skipped or failed.

## 8. Recovery, cleanup and stop conditions

- Preserve pre-existing untracked issue/debug files and all 2.2.0 evidence.
- Clean only staging and temporary files owned by this batch after reports are
  retained.
- After two attempts that do not narrow the cause or advance the selected
  phase, choose an in-scope mitigation, return to the design gate, or report
  the real dependency. Do not broaden into another candidate.
- Stop after E0 when no concrete need exists. Stop after E2 when ownership or
  replay semantics remain ambiguous. Optional documentation or automation does
  not block the selected product path.

## 9. Selected local execution checklist

- [✅] Concrete inspection/signing use case recorded from the user's reply.
- [✅] A3 selected; other candidate lanes retained as references.
- [✅] Baseline and acceptance boundary frozen.
- [✅] Contract/design record reviewed before runtime edits.
- [✅] Focused implementation and regression checks complete.
- [✅] Installed acceptance and documentation evidence reconciled.
- [✅] Delivery boundary reconciled: local implementation only; no new remote
      delivery selected or performed.

## 10. Initial execution evidence (2026-10-08; superseded)

- [✅] E0/E1: baseline `83132c84547b6f7bbcf740b961b6d06a7121b058` read back;
  user selected preparation for inspection/signing. There is no confirmed M0
  defect in this planning review. Hooks alone execute within request dispatch
  and cannot return a reusable public prepared snapshot without sending.
- [✅] E2: design and focused acceptance matrix reconciled. Preparation snapshots
  settings without network I/O; public metadata is read-only; header derivation
  is explicit; send uses the existing dispatcher and separate mutable state.
- [✅] E3/E4: public API, buffered body boundaries, types and docs implemented.
  Initial focused acceptance: 32 tests passed, including independent local
  TLS1.2/TLS1.3 client-auth peers, H2 resends, signature observations and
  cancellation/ownership. These initial checks are superseded by the final
  36 prepared-request tests in installed acceptance below.
- [✅] Review regression: Cookie supplied in `with_headers()` must be explicit
  even if equal to the previously generated value. A real status-retry test
  failed before the correction; header-copy semantics and guidance now match.
  The initial installed pass in `dist/post-2.2.0/acceptance/` is superseded.
- [✅] E5: exact-candidate artifact, typing, runtime, documentation and lint checks.
- [✅] Local handoff and cleanup reconciled; remote delivery is not selected.

Final evidence: `dist/post-2.2.0/final-acceptance/verification.json` and
`dist/post-2.2.0/local-checks.json`. The former records the accepted worktree
snapshot, 293 file hashes, artifact hashes, installed source identities,
command logs and actual staging/temporary-directory cleanup. No base-commit
acceptance or new published release is claimed for this snapshot.

- Installed runtime: Python 3.13.3 on macOS; **2,563 passed + 118 subtests**, no
  failures/errors/skips, **91.6188% statement coverage**. The single warning is
  the existing `TestContext` helper's collection warning, not a failing test.
  All 36 new cases were independently read back from installed JUnit evidence.
- Installed consumer typing: valid consumer plus **70 negative markers**.
  Strict configured mypy gate: seven modules; Black and error-level Pylint pass.
- Documentation: strict build and three actual local examples pass, including
  server verification of a prepared request signature. **23 pages, 1,539 local
  links/assets, 24 API objects, 39 snippets, 12 pinned source paths**.
- Python 3.7 package grammar passes. No new Python 3.7 runtime, remote CI or
  additional platform result was produced by this local batch.
- Final wheel SHA-256:
  `4de74f40bedfc60eeda6db8e922cbdf4744a15a3dfc2857c18e945485253b558`.
  Final sdist SHA-256:
  `4ecb067ba802321fd5dfd4f22e239f6efa4dc8522704066a1434a206eb650caa`.
  Version remains 2.2.0 in this unreleased candidate; these bytes are not the
  previously published 2.2.0 artifacts.
- Diff review reconciled buffer restrictions, public immutability, TLS/verify
  snapshots, Cookie header precedence and shared dispatcher behavior. Actual
  temporary cleanup was read back for both verifier runs. Retain their evidence
  and the built local site; preserve pre-existing environment/issue/debug files.

Only roadmap/completion records are updated after the final candidate freeze;
package, tests, typing, design and documentation bytes match the accepted
manifest. Plan registration remains UNREGISTERED because the supported CLI
cannot establish official session binding; no registry close is claimed.

## 11. First review-fix acceptance (2026-10-09; superseded)

The user's `fix findings` request covers the confirmed empty-path signing defect.
`prepare_request()` now exposes `/` before a caller signs a root URL, including
when it has query parameters or a fragment. The correction is confined to the
prepared API; existing high-level request metadata is not rewritten. The design
and public guide document the normalization.

Regression evidence:

- Four HTTP1 empty-path cases failed with independently verified 401 responses
  before the correction; slash/encoded-path controls passed.
- After correction, **110 focused/related tests passed**, including **44 prepared
  cases**. Local HTTP1 and HTTP2 peers independently compute signatures from the
  received method, scheme/authority/path and body, rather than trusting a client
  signature. Root URLs, query/fragment handling, encoded-path preservation and
  repeated sends are covered; H2 runs with TLS1.2 and TLS1.3.

The new acceptance supersedes `dist/post-2.2.0/final-acceptance/` for the current
candidate. Historical reports/artifacts are retained without rewriting them.
Command:

```sh
python tools/verify_release.py --repo . --worktree-snapshot \
  --include test/test_async_prepared_request.py \
  --include issues/async_prepared_request_design.md \
  --output dist/post-2.2.0/review-fixes-2026-10-09
```

- `verification.json`: **2,571 passed + 118 subtests**, no failures/errors/skips,
  **91.6289% statement coverage**, 70 installed negative typing markers.
  All 44 prepared cases were read back from installed JUnit evidence. Python
  3.13.3/macOS was tested; Python 3.7 grammar passed, with no new 3.7 runtime or
  remote CI claim. The existing `TestContext` collection warning remains.
- New sdist-to-wheel build, fresh independent installation, dependency/origin
  checks and 291-file source snapshot passed. Only completion records changed
  after the freeze; runtime/test/type/design/docs bytes were read back unchanged.
- Strict mypy: seven modules; Black: 73 files including the new tests; error-level
  Pylint: passed. Strict docs build and all three real local examples passed:
  23 pages, 1,539 links/assets, 24 API objects, 39 snippets, 12 pinned paths.
- Wheel SHA-256:
  `797cddb55cc252c21c0e2eb02ca4bb12b21edf47de86446408e8dc1972042816`.
  Sdist SHA-256:
  `0f287ce8766b9d1370d3f4c1db42896180f8016d78b580e4af95f6a0d1aeabf3`.
- Actual staging and all command-owned temporary paths were independently read
  back as absent. Retain reports, artifacts and the rebuilt local docs site as
  delivery evidence; preserve pre-existing issue/debug/environment files.

Local check evidence:
`dist/post-2.2.0/review-fix-local-checks-2026-10-09.json`. This remains an
uncommitted/unpublished local candidate; package version is unchanged at 2.2.0.

## 12. Second review-fix acceptance (2026-10-09; superseded)

The user's second `fix findings` request covers URL normalization beyond empty
paths. Prepared URLs now use the transport's effective lower-case scheme,
IDNA/IPv6 destination authority and numeric non-default port, plus its path/query
target. Empty paths become `/`; empty query delimiters and fragments are omitted.
Shared authority formatting keeps generated Host and destination URLs consistent.
Existing percent encoding and repeated query order are retained. Explicit Host
overrides remain header choices, and Cookie selection uses the normalized
destination before inspection/signing.

- Three HTTP1 cases failed with 401 before the correction: `/signed?`, upper-case
  scheme and port leading zeros. Six existing controls passed.
- After correction, **125 focused/related cases passed**, including **59 prepared
  cases**. HTTP1 and TLS1.2/TLS1.3 HTTP2 peers independently verify signatures for
  all three cases and repeated sends. Preparation checks cover default ports,
  case/IDNA/IPv6 authority, encoded paths/query preservation, explicit Host
  overrides and destination Cookie reselection, without network activity.
- The installed acceptance in
  `dist/post-2.2.0/review-fixes-2-2026-10-09/verification.json` supersedes both
  earlier A3 acceptances. It records **2,586 passed + 118 subtests**, no
  failures/errors/skips, **91.6066% statement coverage**, 70 negative typing
  markers, source identities and artifact hashes. All 59 prepared cases were
  read back from installed JUnit evidence. The only warning is the existing
  `TestContext` collection warning.
- The sdist-to-wheel build, independent installation, dependency/origin checks
  and 291-file snapshot passed. Strict mypy (seven modules), Black (73 files),
  and error-level Pylint passed. Strict docs build and three real local examples
  passed: 23 pages, 1,539 links/assets, 24 API objects, 39 snippets, 12 pinned paths.
- Runtime verification used Python 3.13.3/macOS. Python 3.7 grammar passed; this
  does not add a 3.7 runtime, additional-platform or remote CI claim.
- Wheel SHA-256:
  `cff663b8e0b7f7d406e034910058d8147186213c18a95976b0c4c0027f695c55`.
  Sdist SHA-256:
  `3006eb6364fa81e2788c7f172d179a34b5559dccb6ac6297a6e6340f2ff7fc04`.
- Source hashes and actual absence of staging/all command-owned temporary paths
  were independently read back. Only completion records changed after the
  freeze; runtime/tests/types/design/docs remain the accepted bytes. Retain
  reports, artifacts and the rebuilt local docs site as evidence, and preserve
  pre-existing issue/debug/environment files.

Acceptance command:

```sh
python tools/verify_release.py --repo . --worktree-snapshot \
  --include test/test_async_prepared_request.py \
  --include issues/async_prepared_request_design.md \
  --output dist/post-2.2.0/review-fixes-2-2026-10-09
```

Local check evidence:
`dist/post-2.2.0/review-fix-2-local-checks-2026-10-09.json`. The candidate is
complete locally, uncommitted/unpublished and still versioned 2.2.0. Historical
reports remain intact; no new remote action is selected or performed.

## 13. Current third review-fix acceptance (2026-10-09)

The user's third `fix findings` request covers the shared async request-target
construction. Serializing a path without an authority through `urlunsplit()`
added two leading slashes when the path began with `//`. The dispatcher now
combines the original path and nonempty query directly, retaining `/` for empty
paths. This corrects prepared sends and ordinary requests over HTTP1 and H2;
percent encoding, dot segments and repeated query order remain intact.

- Before correction, three independent HTTP1 signing cases returned 401 and
  three ordinary-request cases received two additional slashes. Ten existing
  or single-slash controls passed.
- After correction, **138 focused/related cases passed**, including **68 prepared
  cases**. Real HTTP1 and TLS1.2/TLS1.3 HTTP2 peers independently verify signatures
  and repeated sends for double/triple leading slashes and encoded path/query
  contents. Ordinary `request()` regression cases check the received target.
- The installed acceptance in
  `dist/post-2.2.0/review-fixes-3-2026-10-09/verification.json` supersedes all earlier
  A3 acceptances. It records **2,599 passed + 118 subtests**, no failures/errors/
  skips, **91.6242% statement coverage** and 70 negative typing markers. All 68
  prepared cases were read back from installed JUnit evidence. The only warning
  is the existing `TestContext` collection warning.
- The sdist-to-wheel build, independent installation, dependency/origin checks
  and 291-file source snapshot passed. Strict mypy (seven modules), Black (74
  files including both affected test files) and error-level Pylint passed.
  Strict docs build and three actual local examples passed: 23 pages, 1,539
  links/assets, 24 API objects, 39 snippets and 12 pinned source paths.
- Runtime verification used Python 3.13.3/macOS. Python 3.7 grammar passed;
  no new Python 3.7 runtime, additional-platform or remote CI result is claimed.
- Wheel SHA-256:
  `ba201c7e2145faee68e8ec42d75308c689f1dd0cf7e026197fbce2c504e7ed04`.
  Sdist SHA-256:
  `cb583c53cdf1f96a1249ab9ca58a5f68fb33a23e9ab1e522e3849d1a65565aa7`.
- All frozen source hashes matched before completion-record updates. Actual
  absence of staging and every command-owned temporary path was independently
  read back. Only completion records changed after acceptance; runtime/tests/
  types/design/docs retain the accepted bytes. Reports, artifacts and the local
  docs site remain delivery evidence; unrelated issue/debug/environment files
  are preserved.

Acceptance command:

```sh
python tools/verify_release.py --repo . --worktree-snapshot \
  --include test/test_async_prepared_request.py \
  --include issues/async_prepared_request_design.md \
  --output dist/post-2.2.0/review-fixes-3-2026-10-09
```

Local check evidence:
`dist/post-2.2.0/review-fix-3-local-checks-2026-10-09.json`. The candidate is
complete locally, uncommitted/unpublished and still versioned 2.2.0. Historical
reports remain intact. Plan registration remains UNREGISTERED because the
supported CLI cannot establish an official session binding; no registry close
is claimed. No new remote action is selected or performed.

## 14. Synchronous wire-boundary review fixes (2026-10-09)

The subsequent architecture review found bounded synchronous transport defects:
header control characters could reach HTTP/1 serialization after hook edits,
query parameters could be appended after a URL fragment, bracketed IPv6 URLs
were parsed by splitting colons, and generated `Host` omitted non-default
ports. The same final header validation now covers buffered messages and
streaming upload framing. Make cleanup retains `dist/` evidence, and the
release target requires an explicit version and uploads only its wheel and
sdist.

The focused regression suite covers fragment/query request targets, non-default
ports, IPv6 authority formatting, explicit header precedence and final header
validation. Documentation and the follow-up roadmap now describe buffered versus
streaming bodies, the current 70 typing markers, and the completed buffered A3
boundary. The local acceptance is recorded below; commit, push and release
remain outside this outcome.

Verification completed in `dist/post-2.2.0/review-fixes-4-2026-10-09/`:

- `verification.json.status` is **passed**: **2,604 tests + 118 subtests**, no
  failures/errors/skips, one existing `TestContext` collection warning, and
  **91.6357% statement coverage**.
- The installed wheel acceptance passed build, metadata, independent install,
  dependencies, smoke, source freeze, typing, full suite and Python 3.7 grammar;
  the installed consumer check recorded **70 negative markers**.
- Wheel SHA-256:
  `4213d77a8e34de5af17dbfe0dd5f8c0a0a00ec267430115653b10080e1cf961e`.
  Sdist SHA-256:
  `f223f0cb6fe09ae71184207efe592dfeb1ebda2533d8612012a31cb8143f3567`.
- The verifier read back the installed source hashes and removed its staging and
  command-owned temporary directories. The report and artifacts are retained;
  unrelated local files remain untouched.

This maintenance batch is complete locally and remains uncommitted,
unpushed and unreleased. The published package version remains 2.2.0.

## 15. Comprehensive request wire-boundary review fixes (2026-10-09)

The user authorized fixes for all five confirmed behavior findings and the
roadmap's outdated status references. The implementation shares one pure final
header validator across sync contexts, async preparation/dispatch and HTTP
CONNECT. Invalid names, C0 controls other than HTAB and DEL are rejected;
CONNECT validation runs before proxy connection I/O. Proxy authentication uses
case-insensitive fields, accepts complete values and legacy bare Basic tokens,
and stays out of the destination's buffered and streaming HTTP1/H2 requests.
The proxy copies its context and clears its message cache, preserving caller
metadata so retries authenticate again.

Synchronous HTTP2 uses the validated final Host, including explicit overrides,
IPv6 brackets and non-default ports. URL parsing and query assembly now retain
complete semicolon path components. The first focused run exposed an additional
instance of the same path defect: an empty trailing semicolon disappeared while
adding params. Using `urlsplit`/`urlunsplit` in query assembly corrected that
case as well. The roadmap now records buffered A3 as complete and links to this
execution record for current acceptance counts and paths rather than copying
them across plans.

Verification completed in `dist/post-2.2.0/review-fixes-5-2026-10-09/`:

- **2,683 installed tests + 118 subtests passed**, no failures/errors/skips,
  **91.6956% statement coverage** and 70 negative typing markers. The only
  warning is the existing `TestContext` collection warning.
- Added **79 regression cases**: CONNECT pre-I/O rejection, authentication
  isolation over plain/TLS HTTP1 and TLS HTTP2 with buffered/streaming bodies,
  retry and mixed-case hook credentials, final HTTP2 authority/path over pooled
  and unpooled requests, all async preparation/derivation/hook entry points,
  positive HTAB/token controls and rejection on an existing reusable H2 connection.
- The related local suite passed 273 cases; after the additional mixed-case
  retry case, all 39 dedicated transport cases passed. Installed acceptance
  includes every final test case.
- Strict configured mypy (seven modules), Black (75 files), error-level Pylint,
  strict MkDocs and three actual local examples passed. Documentation checks
  covered 23 HTML pages, 1,539 local links/assets, 24 API objects, 39 snippets and
  12 pinned source paths. The new site is retained at
  `dist/post-2.2.0/review-fix-5-docs-site-2026-10-09/`.
- The 292-file frozen source matched the worktree before completion-record
  updates. The explicit untracked inputs are the prepared-request design/test
  and the new `test/integration/test_request_wire_review.py`; unrelated local
  issue/debug files were excluded and preserved. Only execution/roadmap
  completion text changed after acceptance; package/test/type/docs bytes retain
  their accepted identities.
- Wheel SHA-256:
  `d88b326de2e4aacf26497753dcd320d198ef2117fea5faac638881216900374e`.
  Sdist SHA-256:
  `300526c47e049555136c213cf65edbddc3ee56c84d168f1e90137a71ba38d157`.
- Staging and all command-owned temporary directories were removed and their
  actual absence read back. Reports, artifacts and the docs site are retained
  acceptance evidence. Runtime verification used Python 3.13.3/macOS; Python
  3.7 grammar passed, without a new Python 3.7 runtime or remote CI claim.

Acceptance command:

```sh
.venv/bin/python tools/verify_release.py --repo . --worktree-snapshot \
  --include test/test_async_prepared_request.py \
  --include issues/async_prepared_request_design.md \
  --include test/integration/test_request_wire_review.py \
  --output dist/post-2.2.0/review-fixes-5-2026-10-09
```

Local checks and final source/artifact/cleanup readback are retained in
`dist/post-2.2.0/review-fix-5-local-checks-2026-10-09.json`. This maintenance batch
is complete locally, uncommitted, unpushed and unreleased; the published package
version remains 2.2.0. Plan registration remains UNREGISTERED because no official
session binding was established; no registry transition is claimed. Earlier
acceptances remain intact.

## 16. Synchronous byte-header and input-error review fixes (2026-10-09)

The user authorized fixes for the two confirmed P2 findings. Synchronous HTTP2
now validates field syntax while passing original header bytes to HPACK. The
CONNECT route copies original destination fields and removes proxy credentials
from the destination copy, preserving the caller's retry metadata. UTF-8 byte
values therefore retain their original wire encoding for buffered and streaming
requests over direct and proxy connections; final Host authority handling is
preserved.

Synchronous Session validates final field names and control characters after
`before_request` hooks and Cookie refresh, before connection or streaming-source
preparation. Local HTTPS/H2 field input errors retain `ValueError` through cleanup
and do not enter network retries. Rejecting malformed UTF-8 on an existing shared
H2 connection leaves that connection usable for a subsequent valid request.

Verification completed in `dist/post-2.2.0/review-fixes-6-2026-10-09/`:

- Added **36 regression cases**, all read back from installed JUnit evidence:
  eight direct/CONNECT buffered/upload UTF-8 byte/text wire controls, 24 invalid
  input/hook field cases across HTTP/HTTPS/CONNECT with no connection calls,
  two direct TLS HTTP1/H2 error-preservation cases and two shared-H2 malformed
  UTF-8 isolation cases. Before the correction, 24 of these cases failed.
- The focused suite passed **269 tests**. Installed acceptance passed **2,719
  tests + 118 subtests**, with no failures/errors/skips and **91.7797% statement
  coverage**. The only warning is the existing `TestContext` collection warning.
- Build, metadata, independent installation, dependencies, smoke, freeze and
  installed-consumer typing passed, including **70 negative typing markers**.
  Strict configured mypy (seven modules), Black (75 files), error-level Pylint
  and strict MkDocs passed. Three actual local documentation examples and checks
  passed: 23 pages, 1,539 links/assets, 24 API objects, 39 snippets and 12 pinned
  source paths. The local site is retained at
  `dist/post-2.2.0/review-fix-6-docs-site-2026-10-09/`.
- The 292-file frozen source and all 72 package source hashes matched the
  worktree. Only this untracked execution record changed after acceptance;
  accepted package/test/type/design/docs bytes retain their identities.
- Wheel SHA-256:
  `63f0c5f1f7c4440ca4683359ea257c5a074eef9f26a2da92e482164c3cf98bc1`.
  Sdist SHA-256:
  `0bdac8496746ae428fa0f67a4b702c1ec78eb177288b3ff1099d9ce485bbece6`.
  Both actual artifact sizes and hashes match the verification report.
- Staging and all ten command-owned temporary directories were removed and
  their actual absence read back. Reports, artifacts and the docs site remain
  acceptance evidence; earlier evidence and unrelated local files are retained.
  Runtime verification used Python 3.13.3/macOS. Python 3.7 grammar passed;
  no new Python 3.7 runtime, additional-platform or remote CI result is claimed.

Acceptance command:

```sh
.venv/bin/python tools/verify_release.py --repo . --worktree-snapshot \
  --include test/test_async_prepared_request.py \
  --include issues/async_prepared_request_design.md \
  --include test/integration/test_request_wire_review.py \
  --output dist/post-2.2.0/review-fixes-6-2026-10-09
```

Local checks and final source/artifact/cleanup readback are retained in
`dist/post-2.2.0/review-fix-6-local-checks-2026-10-09.json`. This fix batch is
complete locally, uncommitted, unpushed and unreleased; package version remains
2.2.0. Plan registration remains UNREGISTERED because no official session binding
was established; no registry transition is claimed. Earlier acceptances remain
intact.

## 17. Cookie, async proxy and CONNECT review fixes (2026-10-09)

The five confirmed findings are fixed within the authorized local outcome:

- Automatically generated Cookie fields are validated after preparation URL
  normalization, hook URL changes and status-response updates. Invalid values
  retain `ValueError` before source work, retry backoff/replay or another network
  attempt. Rejection does not consume a stream or damage a shared H2 connection.
- Async explicit proxy authentication takes precedence over HTTP proxy URL
  credentials, accepts complete field values or legacy bare Basic tokens and is
  sent only in CONNECT. Destination HTTP1/H2 copies omit the field; caller and
  prepared metadata retain it. Explicit credentials partition pooled tunnels.
  Direct/SOCKS routes also omit HTTP proxy credentials from destination fields.
- Shared HTTP1 serialization preserves raw bytes. Async normalization, hook
  metadata, prepared inspection/derivation and H2 retain supplied bytes rather
  than decoding and re-encoding them. Prepared headers expose
  `Mapping[str, Union[str, bytes]]`; numeric values become strings. Existing
  string encodings remain synchronous HTTP1 UTF-8, async HTTP1 Latin-1 and H2
  UTF-8. Protocol-specific encoding is checked after negotiation; invalid H2
  UTF-8 remains a local input error and preserves healthy shared connections.
- Synchronous CONNECT reads a complete header block across fragmented status
  and fields, bounded to 65,536 bytes under one handshake deadline. Subsequent
  tunnel data remains unread for plain HTTP or TLS.
- Every failure after CONNECT socket creation closes that socket, including
  rejection, malformed status, truncation, timeout, send failure and oversized
  headers. A real 407 regression verifies closure before Session shutdown.

Verification in `dist/post-2.2.0/review-fixes-7-2026-10-09/`:

- Added **132 regression cases**, independently read back by comparing the
  installed JUnit test inventory with section 16. Coverage includes automatic
  Cookie selection/retries, live shared H2 isolation, explicit/URL proxy auth,
  caller metadata preservation, pool credential separation, HTTP1/TLS/H2 raw
  byte output for ordinary/prepared/upload calls, invalid H2 UTF-8 isolation,
  CONNECT failure ownership, fragmented responses and unread tunnel data.
  The corrected pre-fix selection had **68 failures and 17 passing controls**.
- Focused tests passed **489 cases**. Installed-wheel acceptance passed
  **2,851 tests + 118 subtests**, with no failures/errors/skips and **91.8710%
  statement coverage**. The one warning is the existing `TestContext` collection
  warning. Public installed consumers passed, including **70 negative markers**
  and the prepared byte-header inspection/narrowing/derivation examples.
- Build, metadata, independent installation, dependencies, smoke and freeze all
  passed. Configured strict mypy (seven modules), Black (74 selected files),
  error-level Pylint and strict MkDocs passed. Three actual loopback documentation
  examples passed; docs checks verified 23 pages, 1,539 links/assets, 24 API
  objects, 39 snippets and 12 pinned source paths. The docs site is retained at
  `dist/post-2.2.0/review-fix-7-docs-site-2026-10-09/`.
- The 292-file frozen source and all 72 package source hashes matched the
  worktree after acceptance. Only this untracked execution record was then
  updated; accepted package/test/type/design/docs bytes remain unchanged.
- Wheel SHA-256:
  `cadb7a468a56952b12bfc94ed236501f32ffee9b4f6f7cb7b31d85cebd98ac02`
  (226,599 bytes). Sdist SHA-256:
  `d079505f6a699838e16cf9fa76fb03f7bb1bdefcc2e99e6ed75d2a9cab46ae99`
  (496,762 bytes). Actual hashes and sizes match the verification report.
- Staging and all ten command-owned temporary directories were removed and
  their actual absence read back. Current reports/artifacts/docs and earlier
  evidence are retained. No unrelated local files were removed. Runtime checks
  used Python 3.13.3/macOS; Python 3.7 grammar passed, without claiming a new
  Python 3.7 runtime, other-platform or remote CI result.

Acceptance command:

```sh
.venv/bin/python tools/verify_release.py --repo . --worktree-snapshot \
  --include test/test_async_prepared_request.py \
  --include issues/async_prepared_request_design.md \
  --include test/integration/test_request_wire_review.py \
  --output dist/post-2.2.0/review-fixes-7-2026-10-09
```

Local checks, source/artifact identity and cleanup readback are retained in
`dist/post-2.2.0/review-fix-7-local-checks-2026-10-09.json`. This batch is complete
locally, uncommitted, unpushed and unreleased; package version remains 2.2.0.
Registration remains UNREGISTERED because the supported CLI could not obtain
an official session binding; no registry transition is claimed. Earlier
acceptances remain intact.


## 18. Actual TLS negotiation and H2 fingerprint review fixes (2026-10-09)

The six confirmed findings and the selected H2 control gap are fixed within the
existing project-owned TLS/H2 engines:

- Exact SETTINGS accept mappings and ordered pairs. Explicit inputs retain
  their entire field set and order, including repeated IDs in sequences; the
  final occurrence controls effective state. None retains the previous default
  packet; empty mappings/sequences send empty SETTINGS. Internal defaults do
  not add fields to the wire. Omitted header-list limits are not advertised or
  imposed as if they had been configured; a separate local allocation bound
  still protects header-block processing.
- Public configuration, mutable-value rechecks, pool identity, connection
  initialization and frame construction reject invalid SETTINGS/window values,
  bools and malformed tuples. Positive initial WINDOW_UPDATE cannot overflow
  the initial 65,535-byte connection window. None/zero omit it; the frame builder
  rejects zero/negative/reserved-bit increments rather than masking them.
- Browser factories copy H2 settings, isolating existing and subsequently
  constructed configurations from caller mutation.
- TLS 1.2 and 1.3 parse the complete ALPN list and require one selected name
  actually present in the successfully sent ClientHello's encoded extensions.
  Later config mutation cannot expand that offer. Malformed, unsolicited,
  duplicate and incorrectly located ALPN selections fail negotiation before
  HTTP or pooling. Actual TLS 1.2 fallback and TLS 1.3 handshakes still succeed.
- Serial, multiplexed and native async H2 share request-field preparation.
  Connection-specific fields and Connection-named hop fields are removed;
  TE accepts only trailers. Input rejection precedes stream/HPACK changes and
  source reads, preserving existing and subsequent requests on a shared TLS/H2
  connection. Byte-valued fields retain their validated UTF-8 representation.
- Public h2_pseudo_header_order and h2_priority_frames configure the complete
  request pseudo-header permutation and ordered initial legacy PRIORITY signals.
  Signals follow SETTINGS and optional WINDOW_UPDATE, once per connection;
  they do not open streams or implement priority scheduling. Weight/exclusive/
  dependency encoding is verified, the first request remains stream 1 and all
  H2 controls partition pooled connections. No backend/plugin abstraction or
  OpenSSL client wrapper was added.

Verification in `dist/post-2.2.0/review-fixes-8-2026-10-09/`:

- Added **278 regression cases**, independently read back against section 17's
  installed JUnit inventory: 123 configuration/parser/serial/async boundary
  cases and 155 actual TLS/H2 network cases. The initial 31-case reproduction
  failed before fixes; its log is retained as `pre-fix-regressions.log`.
- Independent server peers verified actual certificate-authenticated TLS 1.2
  and TLS 1.3, exact raw SETTINGS/window/PRIORITY fields and pseudo-header order
  through sync/async ordinary, prepared and upload entrypoints, direct and HTTP
  CONNECT routes. Pooled connections reused streams 1/3 without repeating
  initialization. Sync CONNECT retains its existing per-request tunnel behavior;
  initialization is verified for each new tunnel. Changed controls were tested
  against distinct pool partitions while the first TLS connection remained live.
- ALPN negative integration cases inject invalid selections at the real
  ServerHello/EncryptedExtensions parser boundary; both handshakes close before
  HTTP or pool admission. This is parser-boundary fault injection during an
  actual handshake, not a claim that the independent server negotiated an
  invalid ALPN through its standard API.
- Installed-wheel acceptance passed **3,129 tests + 118 subtests**, no failures,
  errors or skips, with **91.9580%** statement coverage. The existing TestContext
  collection warning remains the only warning. Installed public consumers and
  all **74 negative type markers** passed. Build, metadata, independent install,
  dependencies, smoke and freeze passed.
- Black passed for 81 selected files; configured strict mypy passed for seven
  modules; error-level Pylint and strict MkDocs passed. Four executable loopback
  documentation examples passed, including the exact fingerprint guide snippet
  over verified TLS 1.3. Documentation checks covered 23 pages, 1,544 links/assets,
  24 API objects, 39 snippets and 12 pinned source paths. The current site is
  `dist/post-2.2.0/review-fix-8-docs-site-2026-10-09/`.
- All **295 frozen files** and **72 package source hashes** matched the worktree
  after acceptance. Only this untracked execution record was then updated.
- Wheel SHA-256:
  `7dff789217a40cb6a959260c417e0837dead99c465467347373dbeaf036e5088`
  (229,461 bytes). Sdist SHA-256:
  `44963a5536832275974b0bec989f67b82eed5541f85070fc0a809f79b53f20f7`
  (507,095 bytes). Actual hashes and sizes matched the report.
- Staging and all ten verifier command-owned temporary directories were removed;
  their actual absence was read back. Two task-owned temporary log files were
  removed after preserving reproduction evidence. Current reports/artifacts/docs
  and historical evidence are retained; unrelated user files were preserved.
  Runtime checks used Python 3.13.3/macOS. Python 3.7 grammar passed; no new 3.7
  runtime, other-platform or remote CI result is claimed.

Acceptance command:

```sh
.venv/bin/python tools/verify_release.py --repo . --worktree-snapshot \
  --include test/test_async_prepared_request.py \
  --include issues/async_prepared_request_design.md \
  --include test/integration/test_request_wire_review.py \
  --include test/test_h2_fingerprint_review.py \
  --include test/integration/test_h2_fingerprint_review.py \
  --include docs/examples/h2_fingerprint.py \
  --output dist/post-2.2.0/review-fixes-8-2026-10-09
```

Local checks and source/artifact/cleanup readback are retained in
`dist/post-2.2.0/review-fix-8-local-checks-2026-10-09.json`. This batch is complete
locally, uncommitted, unpushed and unreleased; package version remains 2.2.0.
Registration remains UNREGISTERED because no official session binding was
available; no registry transition is claimed. Priority scheduling and server-push
consumption remain separate deferred capabilities. Exact custom SETTINGS that
omit ENABLE_PUSH do not disable it on the wire; this client still rejects push.
The guide documents including (2, 0) when the peer should be told push is disabled.


## 19. Local decoded H2 limits and implemented HTTP ALPN (2026-10-09)

Both confirmed findings are fixed within the existing project-owned TLS/H2
engines:

- Exact SETTINGS that omit MAX_HEADER_LIST_SIZE (ID 6) retain the previous
  16,384-byte local decoded header-list budget. Explicit ID 6, including zero,
  controls that budget. No field is added to the advertised SETTINGS, and the
  compressed header-block allocation bound remains separate. HPACK checks the
  budget during decoding, before building an oversized response-header list.
- Serial, multiplexed and native async H2 enforce the budget for active and
  discarded streams, indexed expansion, literals and trailers. Exact decoded
  boundaries and larger explicit limits succeed. Failure closes the connection;
  accepted subsequent blocks retain the required shared dynamic-table state.
- HTTP client ALPN configuration accepts only h2 and http/1.1. Mutable input is
  rechecked before upload preparation and TCP/proxy work, including prepared
  sends. TLS configuration validation and HTTP connection dispatch both enforce
  the implemented protocol set. Raw ClientHello/ALPNExtension encoding remains
  available for non-HTTP packet inspection.
- Negotiated selections are checked after the sync handshake and before async
  pool admission, and checked again when sending on existing pooled entries.
  Unsupported selection closes the transport before HTTP bytes. A bad shared
  async H2 entry is retired as an entire connection rather than released as an
  ordinary stream error. No ALPN keeps existing HTTP1 compatibility.
- The fingerprint guide and Unreleased notes describe the local budget and
  supported ALPN boundary. No TLS backend abstraction or OpenSSL client wrapper
  was introduced.

Verification in `dist/post-2.2.0/review-fixes-9-2026-10-09/`:

- Pre-fix targeted regressions reproduced **27 failures**, with six valid-limit
  controls passing. The preserved log is `local-pre-fix.log`.
- Installed JUnit inventories confirm **148 net additional regression cases**.
  There are 164 new case names: 85 header-budget cases, 13 HTTP configuration/raw
  encoding/dispatch cases and 66 actual TLS network cases. Sixteen existing
  header-limit parameter names were replaced when adding the SETTINGS input
  dimension; this is recorded separately rather than claimed as lost coverage.
- Actual certificate-authenticated TLS 1.2/1.3 peers verify rejection of indexed
  header expansion, exact SETTINGS bytes, larger-limit success and subsequent
  shared HPACK use across sync pooled/unpooled and native async requests.
- Actual TLS handshakes verify supported and absent ALPN, direct/HTTP CONNECT
  routes, ordinary/prepared/upload sends and pooled HTTP1/H2 reuse. Negative
  dispatch cases inject an unsupported result after a valid authenticated
  handshake, then prove no destination HTTP bytes, no source consumption and
  no retained pool/reservation. The independent server actually negotiates a
  supported protocol; these tests do not claim a standard server negotiated an
  invalid name. Configuration rejection is independently tested before source
  preparation or any network work for direct/CONNECT/SOCKS routes.
- Focused checks passed **885 tests**. Independent wheel installation acceptance
  passed **3,277 tests + 118 subtests**, with zero failures, errors or skips and
  **91.9883%** statement coverage. The existing TestContext collection warning
  remains the only warning. Installed public consumers and all **74 negative
  type markers** passed. Build, metadata, independent install, dependencies,
  smoke and freeze passed.
- Black passed for 75 selected files; configured strict mypy passed for seven
  modules; error-level Pylint, git diff checking and strict MkDocs passed. Four
  executable loopback documentation examples passed, including the exact
  fingerprint guide snippet over verified TLS 1.3. Documentation checks covered
  23 pages, 1,544 links/assets, 24 API objects, 39 snippets and 12 pinned source
  paths. The current site is
  `dist/post-2.2.0/review-fix-9-docs-site-2026-10-09/`.
- All **295 frozen files** and **72 package source hashes** matched the worktree
  after acceptance. Only this untracked execution record was then updated.
- Wheel SHA-256:
  `830c2c5f4e710223c138ac29d4da827a87bb32e0174ceac0fa123edf8a7d22d6`
  (229,986 bytes). Sdist SHA-256:
  `7f6615798162dce6f98b5a11242f7c520d4fb4e1031937650c9a974f6f1da493`
  (511,121 bytes). Actual hashes and sizes matched the verification report.
- Staging and all ten verifier command-owned temporary directories were removed
  and their actual absence read back. All six task-owned temporary logs were
  copied to the acceptance directory with hash-checked readback, then removed;
  their absence was verified. Current artifacts/reports/docs and historical
  evidence remain; unrelated files were preserved. Runtime checks used Python
  3.13.3/macOS. Python 3.7 grammar passed; no new 3.7 runtime, other-platform or
  remote CI result is claimed.

Acceptance command:

```sh
.venv/bin/python tools/verify_release.py --repo . --worktree-snapshot \
  --include test/test_async_prepared_request.py \
  --include issues/async_prepared_request_design.md \
  --include test/integration/test_request_wire_review.py \
  --include test/test_h2_fingerprint_review.py \
  --include test/integration/test_h2_fingerprint_review.py \
  --include docs/examples/h2_fingerprint.py \
  --output dist/post-2.2.0/review-fixes-9-2026-10-09
```

Local checks, JUnit inventory delta, source/artifact identity and cleanup readback
are retained in `dist/post-2.2.0/review-fix-9-local-checks-2026-10-09.json`.
This batch is complete locally, uncommitted, unpushed and unreleased; package
version remains 2.2.0. Registration remains UNREGISTERED because no official
session binding was available; no registry transition is claimed. Previous
acceptances and the deferred scheduler/server-push boundaries remain intact.


## 20. H2 response fields, repeated peer SETTINGS and empty TLS extensions (2026-10-10)

All three confirmed findings are fixed within the existing project-owned engines:

- Fully decode HPACK, then validate response field names/values, pseudo-header
  placement and uniqueness, response-only :status, and connection-specific
  fields. Initial, interim and trailer blocks share this boundary. Malformed
  HTTP fields send RST_STREAM(PROTOCOL_ERROR=1), discard queued body/header data
  and fail only the affected stream. Other streams retain shared dynamic-table
  state, including entries inserted after the invalid field. Compression and
  allocation errors remain connection failures. Native async exposes malformed
  fields as H2ProtocolError rather than a retryable transport failure, and stops
  the affected blocked upload producer. Valid repeated fields, empty values and
  internal space/tab remain accepted. Existing trailer consumption is retained.
- Add an ordered SETTINGS-pair parser and apply every peer entry sequentially
  in serial, multiplexed and native async H2. The existing final-value dict API
  remains available. Intermediate table reductions evict entries and the next
  request announces minimum/final sizes; repeated requests then interoperate.
  Invalid intermediate settings and window overflow cannot be hidden by a
  later valid entry. Such failures prevent ACK and further connection reuse.
- Treat absent encoded ClientHello extensions as an empty offered-ALPN tuple.
  Preserve actual encoded bytes and the raw TLS capability. A real extension-free
  TlsConfig.legacy() handshake completes TLS 1.2 and encrypted ping/pong with an
  independent server, without changing secure defaults or high-level SNI.
- Update the fingerprint/wire-control guides and Unreleased notes. No TLS backend
  framework or OpenSSL client wrapper was introduced.

Verification in `dist/post-2.2.0/review-fixes-10-2026-10-10/`:

- The previous locally accepted wheel's SHA-256 and imported module origin were
  checked before running the corrected new regressions. It reproduces **25
  failures** covering injection in all three response phases/engines, repeated
  table limits, hidden invalid settings/window overflow, ordered parsing and
  absent ALPN extraction. `local-baseline.log` is authoritative; preliminary
  test-development logs are retained separately and superseded.
- Installed JUnit inventories confirm **267 added regression cases**, with no
  removed case names: 238 protocol/unit cases and 29 actual TLS network cases.
- Actual certificate-authenticated TLS 1.2/1.3 peers prove sync/native async
  rejection of CRLF Cookie injection in final/interim/trailer blocks, fragmented
  response headers, exact PROTOCOL_ERROR reset, zero injected Cookies and reuse
  of stream 3 on the same connection with the required dynamic-table reference.
  Other peers verify exact minimum/final request table-size bytes after repeated
  SETTINGS, three reusable requests, and connection/pool cleanup without ACK on
  invalid intermediate values. Reader threads/tasks and buffered stream state
  are checked at shutdown. The extension-free legacy test uses its explicit
  legacy verification policy and proves encrypted application-data exchange.
- Focused checks passed **1,187 tests**. Independent wheel installation acceptance
  passed **3,544 tests + 118 subtests**, with zero failures, errors or skips and
  **92.1234%** statement coverage. The existing TestContext collection warning
  is the only warning. Installed public consumers and all **74 negative type
  markers** passed. Build, metadata, independent install, dependencies, smoke,
  frozen source and tool-version checks passed.
- Black passed for 75 selected files; configured strict mypy passed for seven
  modules; error-level Pylint, git diff checking and strict MkDocs passed. Four
  executable loopback documentation examples passed, including the exact
  fingerprint guide snippet over verified TLS 1.3. Documentation checks covered
  23 pages, 1,539 links/assets, 24 API objects, 39 snippets and 12 pinned source
  paths. The site is
  `dist/post-2.2.0/review-fix-10-docs-site-2026-10-10/`.
- All **297 frozen files** and **72 package source hashes** matched the worktree
  after acceptance. Only this untracked execution record was then updated.
- Wheel SHA-256:
  `d98c402d162107142a0144751c84143c1fe69c83b49159462608c9dfde7e93a3`
  (230,412 bytes). Sdist SHA-256:
  `060a5fdf96e105fb6607c9ca58c171c90da33238b438f98707b5e72b968fd9f6`
  (516,515 bytes). Actual hashes and sizes matched the verification report.
- Staging and all ten command-owned temporary directories were removed; their
  actual absence was read back. All eleven task-owned temporary logs were copied
  to the acceptance directory with hash-checked readback, then removed; absence
  was verified. Acceptance artifacts/reports/docs and historical evidence are
  retained; unrelated files are preserved. Runtime checks used Python 3.13.3/macOS.
  Python 3.7 grammar passed; no new 3.7 runtime, other-platform or remote CI result
  is claimed.

Acceptance command:

```sh
.venv/bin/python tools/verify_release.py --repo . --worktree-snapshot \
  --include test/test_async_prepared_request.py \
  --include issues/async_prepared_request_design.md \
  --include test/integration/test_request_wire_review.py \
  --include test/test_h2_fingerprint_review.py \
  --include test/integration/test_h2_fingerprint_review.py \
  --include docs/examples/h2_fingerprint.py \
  --include test/test_h2_peer_review.py \
  --include test/integration/test_h2_peer_review.py \
  --output dist/post-2.2.0/review-fixes-10-2026-10-10
```

Local checks, exact JUnit delta, source/artifact identity and cleanup readback are
retained in `dist/post-2.2.0/review-fix-10-local-checks-2026-10-10.json`.
This batch is complete locally, uncommitted, unpushed and unreleased; version
remains 2.2.0. Registration remains UNREGISTERED because no official session
binding was available; no registry transition is claimed. Previous acceptances
and the deferred scheduler/server-push boundaries remain intact.
