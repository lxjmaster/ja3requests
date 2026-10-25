# Next Development Plan

## Cookie-file typing maintenance (2026-10-25)

Status: **COMPLETE / UNREGISTERED**. Continue the existing internal-typing
lane at the Cookie-file boundary, based on
`35cf17f7169b15687eda85c6fba4d7a0ff166a8a`. Focused mypy reproduced **19
diagnostics** in `_cookie_file.py`, the only selected runtime module.

- [✅] Annotate validation hooks and persistence helpers; include this module
  in the strict source gate, now thirteen modules. Preserve CookieJar inputs,
  text/PathLike paths, boolean options and integer counts.
- [✅] Verify unchanged executable AST, Python 3.7 grammar, formatting,
  error-level lint and the existing Cookie persistence and policy tests.
- [✅] Verify independent installed artifacts, positive consumers and 118
  expected negative markers, full runtime tests and coverage.
- [✅] Deliver scoped changes to existing master, read back the exact remote
  commit and verify Tests, Coverage, Lint, Documentation and Public typing.

Checker-only stdlib views describe private CookieJar storage/locks, Cookie
metadata and its floating-point expiry clock. Narrow casts exist exclusively
under TYPE_CHECKING; runtime validation, format, limits, atomic replacement,
locking and all-or-nothing loading remain unchanged. Reuse existing runtime
tests covering malformed documents, scope, merge and failed writes; add
installed consumer cases for the newly annotated helper boundaries.

Use this workspace with serial edits and independent checks in parallel;
no subagents or new workspace is needed. Preserve unrelated user files and
previous reports. The verifier owns and removes install/staging roots; retain
`dist/post-2.6.0-cookie-file-typing/acceptance-01` reports, manifest, logs and
unpublished candidate artifacts as development evidence. No release, version,
tag, deployment or Issue mutation is selected. Use configured Git identity
and scoped staging; recover within scope without rewriting history. Official
plan-session binding remains unavailable from prior executions; retain
UNREGISTERED without inventing a lifecycle transition or substitute identity.

Local acceptance passed: thirteen strict modules; formatting for the three
changed Python/consumer files; package-wide error-level Pylint; **211 Cookie
persistence/policy tests**. Executable AST matches `35cf17f` after removing
annotations, typing imports and checker-only views/casts; Python 3.7 grammar
passed. The
[independent artifact report](../dist/post-2.6.0-cookie-file-typing/acceptance-01/verification.json)
passed all ten commands: sdist-to-wheel, metadata/inventory, independent install,
dependencies, smoke, installed consumers and **4,764 tests + 118 subtests**,
with **92.7623% statement coverage**, zero failures/errors/skips and the one
existing collection warning. All **118 negative type markers** passed. Current
73 runtime module hashes match the accepted snapshot. Command temporary roots
and top-level staging were removed; retain reports, manifest, logs and both
local candidate artifacts. The snapshot is based on `35cf17f` and retains
development version 2.6.0; it is not a release.

Source delivery completed as `b5d4bb9ca855a09cef0cd162ce750043d0883937`;
remote master readback matches. All five exact-commit workflows passed:
[Tests](https://github.com/lxjmaster/ja3requests/actions/runs/40168444874),
[Coverage](https://github.com/lxjmaster/ja3requests/actions/runs/40168444849),
[Lint](https://github.com/lxjmaster/ja3requests/actions/runs/40168444842),
[Documentation](https://github.com/lxjmaster/ja3requests/actions/runs/40168444861),
[Public typing](https://github.com/lxjmaster/ja3requests/actions/runs/40168444832).
Tests includes Python 3.7-3.13 and the wheel job, all successful. A subsequent
record-only commit carries this completion evidence and is identified by Git
history and its own workflows. No required implementation, verification or
temporary-resource work remains; prior user files and reports are preserved.
No release, tag, deployment or Issue mutation was performed.

## TLS session-cache typing maintenance (2026-10-25)

Status: **COMPLETE / UNREGISTERED**. The next continuation selects the
existing internal-typing lane's TLS session-cache boundary, based on
`64833bd022716c19c58d29607327a3a389cc19ff`. Focused mypy reproduced **38
diagnostics** in `protocol/tls/session_cache.py`, the only selected runtime
module. Preserve the existing in-memory cache and authenticated resumption
policy; no persistence, new TLS feature or protocol configuration is selected.

- [✅] Annotate session entries, TLS 1.2/1.3 tickets, optional lookup results,
  expiry/age methods, insertion/removal and metadata forwarding. Add this
  module to the strict gate, now twelve modules; no casts or ignores.
- [✅] Verify executable AST equivalence after removing typing-only imports,
  annotations and checker-only metadata, Python 3.7 grammar, formatting,
  error-level lint, existing cache and TLS resumption unit/integration tests.
- [✅] Verify independent installed artifacts and positive/negative consumers,
  including 110 expected negative markers, complete tests and coverage.
- [✅] Deliver scoped source/records to existing master, read back the commit
  and verify Tests, Coverage, Lint, Documentation and Public typing for it.

Retain the byte-based TLS 1.2 version fields, optional SNI/trust/expiry metadata,
and existing insertion guards for empty/None identities and ticket secrets.
The private TLS 1.2 keyword schema is checker-only, following project patterns;
runtime dependencies and argument forwarding remain unchanged. Existing tests
already cover capacity, expiry, trust binding, Session IDs and tickets, so reuse
them and add installed typing examples for meaningful annotation boundaries.

Work uses this workspace with serial edits and independent checks in parallel;
no subagents or new workspace is needed. Preserve unrelated user files and all
prior reports. The verifier owns and removes its install/staging roots. Retain
`dist/post-2.6.0-session-cache-typing/acceptance-01` with its report, manifest,
logs and candidate artifacts as unpublished development evidence. No release,
version, tag, deployment or Issue mutation is selected. Use configured Git
identity and scoped staging; recover within scope without rewriting history.
Official plan-session binding remains unavailable from prior executions; keep
UNREGISTERED without inventing a registry transition or substitute identity.

Local acceptance passed: twelve strict modules; formatting for the three
changed Python/consumer files; package-wide error-level Pylint; **94 cache and
TLS 1.2/1.3 resumption unit/integration tests**. Executable AST matches `64833bd`
after removing annotations, typing imports and checker-only metadata; Python
3.7 grammar passed. The
[independent artifact report](../dist/post-2.6.0-session-cache-typing/acceptance-01/verification.json)
passed all ten commands: sdist-to-wheel, metadata/inventory, independent install,
dependencies, smoke, installed consumers and **4,764 tests + 118 subtests**,
with **92.7612% statement coverage**, zero failures/errors/skips and the one
existing collection warning. All **110 negative type markers** passed. Current
73 runtime module hashes and changed consumer/configuration inputs match the
accepted snapshot. Command temporary roots and top-level staging were removed;
retain reports, manifest, logs and both local candidate artifacts. The snapshot
is based on `64833bd` and retains development version 2.6.0; it is not a release.

Source delivery completed as `ef1c05a86bba7a011e8e1b1ec7bd67697dc2c01e`;
remote master readback matches. All five exact-commit workflows passed:
[Tests](https://github.com/lxjmaster/ja3requests/actions/runs/40166429529),
[Coverage](https://github.com/lxjmaster/ja3requests/actions/runs/40166429566),
[Lint](https://github.com/lxjmaster/ja3requests/actions/runs/40166429474),
[Documentation](https://github.com/lxjmaster/ja3requests/actions/runs/40166429504),
[Public typing](https://github.com/lxjmaster/ja3requests/actions/runs/40166429503).
Tests includes Python 3.7-3.13 and the wheel job, all successful. A subsequent
record-only commit carries this completion evidence and is identified by Git
history and its own workflows. No required implementation, verification or
temporary-resource work remains; prior user files and reports are preserved.
No release, tag, deployment or Issue mutation was performed.

## Shared utility typing maintenance (2026-10-25)

Status: **COMPLETE / UNREGISTERED**. The next continuation selects the
existing internal-typing lane's shared utility boundary. Baseline:
`fe892cfb4beda4612ed798239d890c6ea04d4d60`. Focused mypy found **31 diagnostics**
in `utils.py`; the utility module is the only selected runtime module.

- [✅] Resolve those diagnostics and include utilities in the strict source
  gate, now eleven modules. Preserve optional header inputs, byte User-Agent
  values, existing encoding fallback, nullable Cookie values and jar identity.
  Model the legacy retry callback result plus integer-zero sentinel without
  changing its retry algorithm or replacing `HTTPRetry`.
- [✅] Verify Python 3.7 grammar and unchanged executable AST after removing
  annotations, overloads and generic type metadata; pass strict mypy, format
  checks and 235 focused utility/default/Cookie tests.
- [✅] Verify package-wide error-level lint and independent installed artifacts,
  positive consumers, 98 negative type markers and full runtime acceptance.
- [✅] Deliver the scoped source and records to existing master with configured
  identity, read back the exact remote commit and require its five workflows.

Header contracts correct the old `AnyStr` annotations: nonempty byte Basic
credentials already fail at `.encode`, and byte encoding lists already fail
at text joining. Preserve those failures instead of adding coercion. Text and
byte User-Agent fields remain supported independently of other arguments.
Generic legacy tasks retain callback result types and the existing failure
sentinel. Forwarded callback argument types are not validated. Dynamic singleton
storage is typed as objects; no new `Any`, ignores or casts were introduced.

Use the existing workspace, scoped staging and serial edits; independent checks
may run together. No subagents, extra workspace or retained service is needed.
Keep unrelated untracked user files and prior reports. The independent verifier
owns its temporary install/staging roots and must remove them. Retain the new
report, manifest, candidate artifacts and logs under
`dist/post-2.6.0-utils-typing/acceptance-01` as local unpublished development
evidence. No version change, tag, package publication, Issue edit or hosted-site
deployment is selected. Recover within the batch without rewriting history.
The known missing official plan-session binding remains UNREGISTERED; no
substitute identity or registry transition is claimed.

Local acceptance passed: eleven strictly checked modules, formatting on the
four changed Python/test/consumer files, package-wide error-level Pylint and
235 focused tests. The
[independent artifact report](../dist/post-2.6.0-utils-typing/acceptance-01/verification.json)
passed sdist-to-wheel build, metadata/inventory, independent installation,
dependencies, smoke and consumers: **4,764 installed tests + 118 subtests**,
**92.7607% statement coverage**, zero failures/errors/skips and one existing
collection warning. All **98 expected negative type markers** passed. Current
hashes of all 73 runtime modules and changed test/consumer/configuration inputs
match the accepted snapshot. All ten commands returned zero and removed their
temporary roots; top-level staging cleanup passed. Retain the report, manifest,
logs and candidate artifacts. This is a worktree snapshot based on `fe892cf`,
not acceptance or publication of a new version.

Repository delivery completed as `cd3f18d929c0077dec80396d137d7072c2409ba0`;
remote master was read back at that commit. All five exact-commit workflows
passed:
[Tests](https://github.com/lxjmaster/ja3requests/actions/runs/40165918861),
[Coverage](https://github.com/lxjmaster/ja3requests/actions/runs/40165918894),
[Lint](https://github.com/lxjmaster/ja3requests/actions/runs/40165918876),
[Documentation](https://github.com/lxjmaster/ja3requests/actions/runs/40165918883),
[Public typing](https://github.com/lxjmaster/ja3requests/actions/runs/40165918870).
The completion record follows in a documentation-only commit, identified by
Git history and its own workflows. No implementation, acceptance or temporary
resource obligation remains. Unrelated user files and historical reports were
preserved; no release, tag, deployment or Issue mutation was performed.

## Async lifecycle typing maintenance (2026-10-25)

Status: **COMPLETE / UNREGISTERED**. The next continuation advances the
existing incremental internal-typing lane from delivered request defaults to
the confined async lifecycle helpers and their required exception boundary.
Baseline: `0c001e0f24c135863a3f18619ef184b70a8cbfbf`. Focused mypy found
three diagnostics in `_async_utils.py` and one missing constructor annotation
in `exceptions.py`. New protocol capabilities and convenience APIs retain
their independent entry conditions.

- [✅] Annotate the existing exception forwarding boundary and async timeout
  phase metadata; preserve generic coroutine/task results. Add both modules
  to the required strict set, now ten modules, without ignores or casts.
- [✅] Check executable AST equivalence to the baseline after stripping
  annotations/typing imports, Python 3.7 grammar, formatting and strict mypy.
- [✅] Verify direct context/result/cancellation/exception-metadata boundaries,
  affected async integration behavior, error-level lint and independent
  installed consumer/package acceptance.
- [✅] Reconcile the exact delivery scope, repository delivery and new-commit
  Tests/Coverage/Lint/Documentation/Public typing results.

Use the existing workspace and configured Git identity; stage only this batch.
Preserve user files, historical evidence and published 2.6.0. Retain a new local
artifact report under `dist/post-2.6.0-async-typing/acceptance-01`; its version
is only a development candidate and must not overwrite the published package.
The verifier owns and removes its staging/install environments. Work is serial
apart from independent checks; no subagents, service or extra workspace is
needed. Do not rewrite shared history or add a release, tag or deployment.
Official plan session binding was unavailable in the preceding delivery;
no registry transition or substitute identity is claimed here.

Initial local acceptance passed: ten strict modules, Black for the five changed
Python/test/consumer files, package-wide error-level Pylint and 231 focused
tests. The two runtime files have unchanged executable ASTs after removing
annotations/typing imports and pass Python 3.7 grammar. The independent
[artifact report](../dist/post-2.6.0-async-typing/acceptance-01/verification.json)
passed all ten commands, with **4,756 installed tests + 118 subtests**, zero
failures/errors/skips and **92.7733% statement coverage**. The one collection
warning is pre-existing. Positive installed consumers and all **89 expected
negative markers** passed. Current hashes of all 73 runtime modules match.
All command temporary roots and top-level staging were removed by the verifier;
retain the report, manifest, logs and local candidate artifacts as evidence.
This is a worktree snapshot based on `0c001e0`, not a newly published version.

The first repository delivery, `a0fd4c7`, passed typing/lint/docs/coverage but
its [Tests run](https://github.com/lxjmaster/ja3requests/actions/runs/40164958707)
exposed two test assertions. Python 3.7's zero-budget `asyncio.wait_for` requests
cancellation before the child has joined; the new helper test now explicitly
awaits that cancellation before asserting terminal state. Python 3.12 hit the
old client-certificate test's raw PSK-byte substring check in an opaque key
share. A fixed `SessionTicketExtension(b'\x00\x29')` reproduced the false
failure locally; the assertion now parses extension type/length boundaries,
following the adjacent verified-ticket test, with both opaque/empty cases.
These are test-only delivery fixes; runtime helper/exception bytes remain
unchanged. The 17 affected tests and formatting passed. Preserve the initial
CI failure and acceptance-01 as historical evidence; the final test snapshot
is independently verified under acceptance-02 before delivery is closed.

Final acceptance and source delivery are complete. The
[final artifact report](../dist/post-2.6.0-async-typing/acceptance-02/verification.json)
passed all ten commands, **4,757 installed tests + 118 subtests**, **92.7579%
statement coverage** and all 89 negative type markers, with zero failures,
errors or skips and one existing collection warning. Runtime/test/consumer
hashes match the final snapshot; staging and command temporary roots were
removed. Retain acceptance-02 alongside the initial report and failed CI so
the test corrections remain auditable. Both snapshots are local unpublished
2.6.0 development artifacts, not a version publication.

The implementation was delivered as `a0fd4c7`, followed by test corrections
in `283853f2e53fb310270945346d507b99ff85ac07`. Remote master was read back at
that corrected source. All five exact-commit workflows passed:
[Tests](https://github.com/lxjmaster/ja3requests/actions/runs/40165171141),
[Coverage](https://github.com/lxjmaster/ja3requests/actions/runs/40165171108),
[Lint](https://github.com/lxjmaster/ja3requests/actions/runs/40165171099),
[Documentation](https://github.com/lxjmaster/ja3requests/actions/runs/40165171103),
[Public typing](https://github.com/lxjmaster/ja3requests/actions/runs/40165171098).
The remaining record-only commit carries this completion evidence; its Git
history and workflows identify that later documentation revision. There are
no remaining implementation, acceptance or temporary-resource obligations.
No release/tag, Issue edits or site deployment were performed.

## P3 repository delivery selection (2026-10-25)

After the local P1 -> P2 -> P3 completion below, the user's next continuation
selects repository delivery of the remaining P3 annotations, tests and related
acceptance records. The 13 tracked modified files form this delivery batch;
untracked user files and retained local artifact reports are excluded.

Commit with the configured identity, push normally to the existing master,
and require Tests, Coverage, Lint, Documentation and Public typing to succeed
for the actual delivered commit. Reuse the passed local artifact acceptance
only after confirming its runtime, test, consumer and configuration hashes
still match. Git history and the exact-commit workflow runs record execution
and completion; this selection record does not predeclare their results.

The prior local-only scope and unstaged status below describe the earlier
completion boundary. This later selection adds repository delivery without
changing runtime behavior, package version, release/tag state or site hosting.
Work remains serial, with scoped staging and no temporary workspace or new
service. Preserve the existing reports and unrelated files. Any required CI
failure is fixed within scope and verified without rewriting shared history.
No new registry transition is claimed while official session binding remains
unavailable.

## Selected execution: P1 -> P2 -> P3 (2026-10-25)

Status: **COMPLETE / UNREGISTERED**. The user selected the ordered sequence
with "continue in order" after reviewing the concrete preparation below.
This supersedes the earlier planning-only selection for these three outcomes.

- [✅] P1: commit the exact 12-file tooling/evidence batch below, push normally
  to the existing master, and verify its five exact-commit workflows.
- [✅] P2: refresh the five Issues, post the prepared evidence with delivered
  commit permalinks, reconcile the async API mapping and explicitly record the
  selected replacement memory criterion in Issue 41 before closing it.
  Close the five original Issues with scoped acceptance evidence.
- [✅] P3: resolve the two `_request_defaults.py` diagnostics plus directly
  required helper annotations, add the module to strict checking, and verify
  the existing default-merging/runtime/installed-consumer boundaries.
- [✅] Reconcile remote readback, local verification, retention and cleanup.

P1's repository delivery covers the 12 listed files. P3 is a subsequent local
implementation/acceptance batch; no package release, tag or deployment is
selected. Required checks follow the boundaries below. The completed 1 GB run
remains historical evidence for its recorded source snapshot after P3 changes.
Do not alter its JSON or rerun that large measurement solely for annotations.

Use configured Git identity and scoped staging, preserving unrelated local
files. Remote Issue writes use explicit prepared bodies and readback; inspect
actual state before retrying an operation. A failed required CI check is fixed
within the batch and verified before Issue closure. Keep failed evidence,
avoid history rewriting and do not expand runtime semantics to fix types.
Work is serial; no subagents are needed. Retain reports and acceptance logs;
remove only this execution's owned temporary environments/files after use.

The supported status command still lacks an official session binding. Keep
this file UNREGISTERED; no registry transition or substitute identity is claimed.

P1 completed: commit `90b78e1c5f418064ba3d4163a38413353a50968b`
contains exactly the 12 selected files and was pushed normally to master.
Remote master readback matches. All five exact-commit workflows succeeded:
[Tests](https://github.com/lxjmaster/ja3requests/actions/runs/40163061134),
[Coverage](https://github.com/lxjmaster/ja3requests/actions/runs/40163061213),
[Lint](https://github.com/lxjmaster/ja3requests/actions/runs/40163061165),
[Documentation](https://github.com/lxjmaster/ja3requests/actions/runs/40163061186),
[Public typing](https://github.com/lxjmaster/ja3requests/actions/runs/40163061135).
Original JSON equality and the measured source/tool hashes were confirmed
before committing; unchanged local 206-test/large-matrix evidence was reused.

P2 completed: all five original Issues were closed as completed on 2026-10-25.
The posted comments exactly matched their prepared bodies after permalink
substitution, and CLOSED/COMPLETED state and closure times were read back:
[#36](https://github.com/lxjmaster/ja3requests/issues/36#issuecomment-6393595862),
[#37](https://github.com/lxjmaster/ja3requests/issues/37#issuecomment-6393597796),
[#40](https://github.com/lxjmaster/ja3requests/issues/40#issuecomment-6393598648),
[#41](https://github.com/lxjmaster/ja3requests/issues/41#issuecomment-6393601088),
[#42](https://github.com/lxjmaster/ja3requests/issues/42#issuecomment-6393601909).
Issue 41's original memory goal is explicitly superseded by the selected
bounded-streaming criterion; its entire revised body was read back before
closure. API mapping and optional performance-CI/hosting boundaries were
recorded without claiming the original chunk-size-only memory guarantee.

P3 local implementation/acceptance completed:

- Annotated the generated header helpers and request-default pair collections.
  The existing byte-key mapping regression revealed that merged query pairs
  may retain byte keys alongside text defaults. The shared `Params` alias now
  describes those already accepted list/tuple values; homogeneous typed lists
  retain their alternatives because lists are invariant. No casts, ignored
  diagnostics, coercion or new request-validation behavior were introduced.
- Added `_request_defaults.py` to the required strict set: **eight modules
  pass**. Black on the five changed Python/test/consumer files and all-package
  error-level Pylint passed. The two helper implementation files have identical
  executable syntax to `90b78e1` after removing annotations/typing imports.
  Changed runtime modules also passed Python 3.7 grammar; no new multi-version
  runtime CI is claimed for these local edits.
- Existing default-merging/integration/utility tests plus the missing byte/mixed
  pair boundaries passed: **206 tests in 0.71 s**. The installed consumer adds
  typed homogeneous/mixed query lists, byte-key tuples, async/buffered preparation
  and generated-header return types. The existing 85 negative markers remain.
- The [frozen local artifact verification](../dist/post-2.6.0-typing/acceptance-01/verification.json)
  passed sdist-to-wheel build, inventory/metadata/module hashes, Python 3.7
  grammar, independent installation/dependency smoke, consumer typing and
  **4,749 installed tests + 118 passed subtests**, with **92.7568% statement
  coverage**, zero failures/errors/skips and one existing collection warning.
  All ten pipeline commands returned zero and removed their temporary roots;
  top-level staging cleanup passed. The current 73 module hashes match the
  accepted report. This is an unpublished worktree snapshot based on `90b78e1`,
  not acceptance or publication of a new version.
- Retain that verification directory, its manifest/logs and both candidate
  artifacts as local evidence. The candidate wheel SHA-256 is
  `ad6a5edb5e4a8f2a1cb615acf019f4f71e9a7ae7c513030173009f53a01222a0`;
  the sdist SHA-256 is
  `f9e6affd37ed3ff188f1165ced36792accfd064a60d5e7e7bb2acf15f65ee015`.
  They retain version 2.6.0 only as local development artifacts; do not upload
  them over the published release.

Closeout: the task-owned `/tmp/ja3requests-next-sequence.yHct10` directory
(prepared Issue bodies, annotation check and reproducible pytest fixtures) was
removed and absence confirmed after remote readback/verification. The verifier
removed its independent environments and command staging. Original memory JSON
remains byte-identical; unrelated user files and historical evidence remain.
P3 code/tests/docs and the P1/P2 completion records are local, unstaged changes;
P1 alone was committed/pushed by the selected repository-delivery scope. No
release/tag/site deployment was performed. No required work remains for this
selected P1 -> P2 -> P3 execution. Optional capabilities remain proposals.

## Current sequence (2026-10-25)

Status: **PLANNING AND LOCAL PREPARATION COMPLETE / UNREGISTERED**.
This is the current entry point. The dated sections below preserve earlier
selections and acceptance; their pending labels do not reopen completed work.
The present request selects planning and local delivery preparation. Future
repository delivery, Issue administration and runtime changes are identified
below with their own execution boundaries.

### Verified state

- Local and remote master are
  `9af4cc7032b82bea055dcd09b82d5bf8bba80f44`. Tests, Coverage, Lint,
  Documentation and Public typing all succeeded for that commit; the
  [Issue acceptance drafts](issue_acceptance_2026_10_25.md#evidence-baseline)
  link the five runs. The typing batch is already delivered to the repository.
- Latest GitHub Release is v2.6.0, published 2026-10-23, with tag target
  `76f1e6b4fba91c8e53d500f6bc7832cf86ece0e8`. Post-release typing and new
  measurement tooling are not described as part of that released artifact.
- Issue 41 local measurement is complete: 28 cases / 14 comparisons, unchanged
  report hash and matching package/tool hashes. Its tools/tests/docs remain
  uncommitted. A byte-identical
  [repository evidence copy](../bench/streaming-memory-2026-10-23.json) now
  preserves the original JSON independently of local ignored `dist` retention.
- Issues 36, 37, 40, 41 and 42 were re-read on 2026-10-25 and remain OPEN.
  Their original bodies and update times are unchanged since 2026-04-17.
- A new focused diagnostic found **two errors in `_request_defaults.py`**:
  an untyped `default_headers` call at line 84 and inferred query-pair types at
  line 120. This is a maintenance candidate, not a runtime failure.

### Ordered next outcomes

| Order | Outcome and dependency | Work | Acceptance / current selection |
| --- | --- | --- | --- |
| P0 | Make the completed measurement reviewable and reconcile the backlog | Preserve an exact report copy in `bench`, link its provenance, prepare five Issue updates, and record this sequence | Selected now; complete after report equality/hash, links and scope readback. Reuse unchanged measurement/test evidence |
| P1 | Deliver the accepted development tools to the repository; depends on P0 | Commit only the 12 listed files, push normally to existing master, verify the five workflows for the actual new commit | Recommended immediate delivery step. Requires selection of commit/push; no package version or release is needed for development-only tools |
| P2 | Reconcile the five historical Issues; evidence-dependent on P1 for the new memory files | Use the prepared per-Issue evidence. For 41 explicitly adopt the bounded-memory interpretation before closure; for 37 explain the delivered API mapping | Requires selection of exact remote edits/closures. Four Issues have evidence for their required core scope; 41's literal memory wording remains unreconciled remotely |
| P3 | Tighten one bounded internal type boundary; independent of Issue closure | Resolve the two `_request_defaults.py` diagnostics and only directly required helper annotations; add that module to strict checking when clean | Recommended next code batch after tooling delivery. Preserve request behavior, Python >=3.7 and installed public consumers; implementation is not selected by this planning pass |

P2 and P3 have no implementation dependency on each other. Keep one active
write batch; independent reads/checks may run concurrently. No subagents are
needed for this local planning/evidence work.

### P1 exact delivery inputs

The proposed commit contains these 12 files, after a fresh overlap check:

```text
IMPROVEMENTS.md
bench/README.md
bench/requirements.txt
bench/STREAMING_MEMORY.md
bench/stream_memory.py
bench/stream_memory_peer.py
bench/streaming-memory-2026-10-23.json
issues/next_development_plan.md
issues/streaming_memory_acceptance.md
issues/issue_acceptance_2026_10_25.md
tools/tests/test_stream_memory.py
tools/tests/test_stream_memory_peer.py
```

The candidate is development tooling, tests, evidence and repository guidance.
It adds psutil only to optional benchmark requirements. The existing Python
3.12 tooling CI job already installs psutil through `requirements-capture.txt`;
the runtime test matrix and package dependencies remain unchanged. The full
1 GB matrix remains explicitly invoked; machine-specific RSS budgets are not
silently added to general CI. Reuse the successful 206 tooling tests and the
28-case acceptance while their source/tool inputs match; rerun affected checks
only for relevant changes or an actual delivery failure.

Preserve IDE files, `.DS_Store`, debug scripts, historical release records and
other `dist` artifacts. A later delivery must use the actual configured Git
identity, retain the accepted JSON bytes and read back the new remote commit
and its five workflow results. Do not substitute the older green commit's CI
for the new tools' CI.

### P3 bounded code acceptance

Reproduce the current diagnostics with:

```sh
.venv/bin/python -m mypy ja3requests/_request_defaults.py \
  --no-incremental --cache-dir=/dev/null
```

The 2026-10-25 command exited 1 with exactly two diagnostics. A later selected
implementation should give `default_headers` a precise return contract and
correct query-pair inference without coercing inputs or changing runtime
validation. Avoid broad `Any`, ignore directives, module-wide suppression or
an unrequested rewrite of request preparation.

Verify that module and the existing strict set, the existing
`test/test_request_defaults.py` and `test/integration/test_request_defaults.py`,
formatting/error-level lint, and independent installed consumer typing if
public annotations or packaging inputs change. Preserve empty/raw bypass,
ordered query pairs, byte headers, atomic assignment, snapshots and sync/async
behavior. Add a test only for a meaningful uncovered boundary. If resolving
the diagnostics requires a behavior change, return to the compatibility choice
before expanding this type-only batch.

### Deferred choices and completed work

Public documentation hosting needs a host/URL/version policy; optional benchmark
CI needs a workload/runner/comparison policy. Browser changes need a selected
version/platform and fresh capture. Async module-level helpers, streaming
prepared requests, timeout/proxy/query consistency, persistent TLS sessions,
H2 scheduling/push, 0-RTT, ECH/PQ and HTTP3 remain independent choices with
consumer/compatibility requirements. None is a prerequisite for P1-P3.

Do not reopen TLS1.2's 300 ms pause, the selected native-async read-ahead
investigation or legacy packaging removal: all three were completed in 2.1.1,
as recorded in [the later results](../bench/POST_2_1_0_RESULTS.md) and
[the reconciled register](post_2_1_1_plan.md#8-deferred-candidate-register).
Uploads, async files/Cookie files, buffered async preparation, request HEADERS
priority, HPACK exclusions, Chrome 155 subset, redirect policy and opt-in
headers/params defaults have also shipped. Old unchecked historical rows are
not evidence that these features are missing.

### Local verification and retention

The original report and its repository copy must remain byte-identical, with
SHA-256 `641230a2fe374c263931cf717889d3f5f125aba8e511407a05ce1d326a8afe79`.
Read back all links in the changed Markdown, JSON acceptance counts/flags,
report/module/tool hashes, the exact changed-file scope and `git diff --check`.
This documentation/evidence pass needs no repeat full runtime suite, package
build or large measurement. The focused mypy diagnostic above is recorded as
failing evidence for P3, not a passing test.

Retain both JSON copies, the small smoke report and the existing acceptance
record. No service, staging installation or task-owned temporary directory is
created in this pass. Recover only this pass's edits if a check fails; preserve
the original reports and unrelated work. The supported plan status command
still reports a missing official session binding; no registry operation or
session identity is fabricated. This file remains UNREGISTERED.

Completed on 2026-10-25:

- [✅] Refresh remote master, latest GitHub Release, five exact-commit workflows
  and the original bodies/states of all five historical Issues.
- [✅] Confirm the original 28-case / 14-comparison measurement, current package
  and tool hashes, then preserve a byte-identical repository JSON copy.
- [✅] Prepare the five Issue evidence/criterion drafts, the exact 12-file
  delivery set, ordered dependencies and bounded next-code acceptance.
- [✅] Resolve all 102 relative file targets across the six affected Markdown
  records, check the new anchors, report equality/hash and whitespace, and
  confirm no runtime/workflow/package/site source changes in this pass.

P0 is complete. P1-P3 are proposed next execution outcomes with the selections
specified above; they are not unfinished required work for this planning pass.

## Local streaming memory acceptance (2026-10-23)

The user selected the bounded-streaming measurement interpretation for Issue
#41. The fixed **100,000,000 / 1,000,000,000 decoded-byte** matrix passed all
**28 cases and 14 size comparisons** across sync/async HTTP1, TLS 1.2/1.3,
TLS 1.3 H2 and separate gzip/deflate/Brotli paths, with `chunk_size=16384`.
The [measurement guide and results](../bench/STREAMING_MEMORY.md#accepted-local-run-2026-10-23)
and [execution record](streaming_memory_acceptance.md) preserve the exact scope,
budgets, tooling tests and limitations. The
[raw report](../dist/streaming-memory/acceptance-01/measurement.json) is retained
locally under Git-ignored `dist`; the guide includes its hash and reproduction.

The maximum sampled RSS increase over the client baseline was 10,059,776 bytes;
the maximum traced Python peak increase was 789,406 bytes. Maximum growth from
100 MB to 1 GB was 2,539,520 RSS bytes and 407 traced Python bytes. Every case
validated complete content, gated early delivery, no response-body cache and
bounded application chunks; source/tool stability and cleanup passed.
The tooling regression suite passed **206 tests**. The runtime source and its
public streaming contract remain unchanged at
`9af4cc7032b82bea055dcd09b82d5bf8bba80f44`.

This batch is local-only: no commit, push, release or remote Issue edit/closure.
Its evidence supports the user-selected measurement boundary, not the original
literal `all memory <= chunk_size` wording. Repository delivery or remote
acceptance reconciliation remains a separate selection; no further capability
is automatically added. Earlier typing/release sections below are history.

## Typing repository delivery selection (2026-10-23)

The user subsequently selected a scoped commit of the completed typing batch,
push to the existing `origin/master`, and verification of that exact commit's
GitHub Actions runs. The six-file scope is the response annotations, typing
workflow, typing guide, Unreleased notes and two current-status records.
Reuse the unchanged local acceptance below; do not repeat release acceptance
or include unrelated untracked files. The main agent owns edits, commit, push
and readback; an independent read-only lane checks workflow effects and gates.

Delivery requires Tests, Coverage, Lint, Documentation and Public typing to
succeed for the pushed commit. The full-package mypy step may fail as designed;
the strict selected-module and installed-consumer steps must succeed. Commit
history and the exact-commit workflow runs record execution and completion;
this selection record does not predeclare their results. The local-only
boundary below is historical and does not exclude this later repository step.
No version change, tag, publication, Issue closure or hosted-docs deployment is
selected. Preserve existing user files and release evidence; no new workspace
or retained temporary resource is needed. Any recovery remains limited to this
batch, without rewriting shared history or discarding unrelated changes.

## Post-2.6.0 typing completion (2026-10-23)

Local implementation and verification: **COMPLETE**. The next-stage request
selects the two concrete remaining requirements from Issue #36: annotate the
three response-parser helpers and add a non-blocking full-package mypy CI step.
That local batch used `76f1e6b4fba91c8e53d500f6bc7832cf86ece0e8` as its baseline
and did not commit, push, version, publish or change remote Issues. No new
persistent workline was registered for this bounded batch; this section retains
the cross-turn outcome and handoff.

- [✅] Recheck the original Issue requirements independently. Public signatures
  in the named base/session modules, request helpers, `py.typed`, mypy settings
  and the existing structural `Protocol` already satisfy their respective items.
- [✅] Annotate `_read_status_line`, `_read_headers` and `_parse_headers`,
  preserving iterable byte-header inputs, exact returned bytes and runtime
  parsing. Declare the local byte collections and optional content-encoding
  state without changing their values or control flow.
- [✅] Add `python -m mypy ja3requests/` with step-level `continue-on-error: true`.
  Keep the strict seven-module check and installed-consumer checks required.
  Update the typing guide, Unreleased notes and capability disposition.
- [✅] Verify the changed boundaries and remove the task-owned temporary
  snapshot, build artifacts and independent installation. Preserve all existing
  user debug files, IDE state and historical release evidence.

Acceptance on local Python 3.13.3:

- Response/streaming/failure-state tests: **45 passed**. Network streaming and
  streaming-policy tests: **34 passed**, including trailers/connection reuse.
- Black, error-level Pylint and the configured strict seven-module mypy check
  passed. Python 3.7 grammar passed; no new multi-version runtime CI is claimed.
  Removing annotations and typing imports leaves the executable syntax tree
  identical to the baseline. YAML readback confirms all pre-existing workflow
  settings and mandatory steps are unchanged.
- A tracked-source snapshot built an sdist and then its wheel. Both contain the
  exact modified `response.py` and `py.typed`. A fresh independent installation
  passed dependency checks and the existing valid consumer plus all **85 negative
  markers**. Additional installed probes verified all three precise return types,
  list/tuple/iterator inputs, rejection of text/raw-byte header inputs by mypy,
  and runtime empty/missing/malformed/conflicting-header boundaries.
- The full-package diagnostic command intentionally exits **1**: **2,296 errors
  in 57 files**, checking 73 source files, versus **2,303** before this batch.
  `response.py` has no remaining missing-method-signature diagnostics. More
  precise types also expose existing implementation details such as byte-valued
  debug formatting; the full implementation is not claimed to be type-clean.
  These counts are local evidence, not a remote workflow result.

The main agent owned all edits and acceptance; the delegated lane was read-only
Issue/signature/CI auditing. No additional temporary resource is retained and
no tracked user/concurrent edits were present at intake. Rollback, if later
requested, is limited to this batch; unrelated files stay untouched.

The subsequent repository-delivery selection above adds a scoped commit/push
followed by exact-commit CI. Only then can the new CI step be described as
running remotely. Closing #36 remains a separate remote action; package-wide
typing cleanup is not required by its original allow-failure CI criterion.
Issue #41 still needs an agreed memory measurement/acceptance contract before
its original 1 GB / `chunk_size` criterion can be reconciled. No new release or
other conditional capability is selected automatically.

## 2.6.0 release scope (2026-10-23)

The user approved publishing opt-in request defaults as 2.6.0 to official PyPI
and the existing GitHub repository. This release adds headers/params defaults
to both clients, with validation, detached snapshots and one initial merge.
It preserves Python >=3.7 and the existing TLS/H2, retry and redirect contracts.
Current behavior is described in the [release notes](../CHANGELOG.md) and
[configuration guide](../docs/configuration.md#opt-in-request-defaults).

The implementation commit `a29fc2e110194ac3cceb4a9aa1189f38d4366a9a` passed all
five push workflows. Publication requires a separate final 2.6.0 commit,
installed-artifact acceptance, exact-commit CI and public-download readback;
the earlier 2.5.0 development candidates remain historical. Issue closure,
public documentation hosting and further client/protocol work are not selected.

## Repository delivery selection (2026-10-23)

This earlier repository-only selection is historical; the release selection
above subsequently adds versioning and publication.

The user selected the follow-up plan: deliver the accepted opt-in request
defaults increment through a scoped commit, push to the existing `master`, and
verification of that exact commit's CI. Reuse the unchanged local runtime,
test and user-documentation acceptance; first reconcile the two historical
planning records that differ from the frozen candidate. Read the original
requirements of Issues #36, #37, #40, #41 and #42 and record their remaining
acceptance boundaries without changing their remote state.

The [implementation record](post_2_5_0_execution_plan.md) retains the completed
local acceptance and delivery-intake readback. Repository history and GitHub
Actions provide the subsequent commit/push/CI evidence; the historical test
counts below are not new CI results. At that stage, 2.5.0 was the published baseline
and request defaults remained Unreleased. A new package version/publication,
Issue closure, hosting and a new capability batch remain conditional and are
not selected by this delivery step.

## Completed local post-2.5.0 work (2026-10-16)

The original order and fixed scope are recorded in the
[bounded execution plan](post_2_5_0_execution_plan.md): synchronize current release
documentation, implement opt-in headers/params defaults, then inspect remaining
sync/async differences. The implementation was Unreleased against the 2.5.0
published baseline. Conditional protocol/client/hosting candidates remain unselected.
That original batch excluded commits, pushes and releases; the later repository
delivery selection above adds commit/push/CI, but not another release.

## 2.5.0 release scope (2026-10-15)

Version 2.5.0 includes the explicit Chrome 155/macOS supported subset, aligned
synchronous 301/302/303 method and body handling, the selected outbound Huffman,
per-request HEADERS priority and indexing-exclusion controls, synchronous 307/308
body replay, and the subsequent transport/hook/body correctness fixes. See the
[release notes](../CHANGELOG.md) and current user guides for implemented behavior.
The planning and candidate-acceptance records below are dated history; their
pending-task and local-only labels do not describe the 2.5.0 release scope.
Full browser identity and the unselected conditional packages remain outside it.

## Post-2.3.0 planning snapshot (2026-10-13)

The recorded published baseline is 2.3.0 at
`422012063f4ed12e23bda330c38355566d6d373d`. Use the
[remaining-work solution and execution plan](post_2_3_0_remaining_work_plan.md)
for current proposals, compatibility choices, package dependencies and acceptance.
The [post-2.3.0 roadmap](post_2_3_0_follow_up_plan.md) provides context, the
[fingerprint execution record](post_2_3_0_execution_plan.md) retains F1/F2 history,
and the [release notes](../CHANGELOG.md) distinguish released and local changes.
The real TLS + H2 browser capture/difference package F1 is now accepted locally;
see the [received-byte results](tls_h2_capture_results.md). F2 outbound Huffman
also has historical installed-candidate acceptance and is not a new task.
Four subsequent synchronous SNI/ALPN/redirect/timeout fixes are present with
regressions/docs; the old Huffman artifact does not cover those source changes.

Recommended next batches are one compatibility-signaled correction of synchronous
307/308 defaults, then per-request HEADERS weight/exclusive fields (dependency 0)
and bounded HPACK indexing control. Select the redirect version/migration boundary
before implementation; add a compatibility option only for a concrete consumer
need, and retain current 301/302/303 behavior in this batch. H1/H2 can proceed
independently. Final artifact acceptance occurs once per selected frozen batch,
with an independent peer suited to the capability; the existing browser collector
does not cover TLS1.2 or resumption. Reuse the F1 report for a focused selected-TLS
precheck instead of a new inventory phase. F3, Session defaults, prepared streaming
and engineering candidates have separate entry and completion conditions.
Full redirect parity and full Chrome identity remain unachieved.

The current instruction selects planning only. It neither starts these runtime
packages nor selects commit/push/publication, hosting or remote Issue mutation.
The five-Issue disposition below is a dated readback, not a refreshed remote status.
Earlier sections below are dated history; their local-only/unpublished labels
and unchecked candidates do not reopen delivered work.

## 2.3.0 delivery (2026-10-10)

Commit, push and publication of the reviewed buffered async prepared API,
exact H2 controls and protocol/wire fixes are complete in 2.3.0:
[GitHub](https://github.com/lxjmaster/ja3requests/releases/tag/v2.3.0) and
[PyPI](https://pypi.org/project/ja3requests/2.3.0/). Exact-commit installed
acceptance, all five CI workflows and both channels' artifact/installation
readback passed. Evidence is retained under
`dist/release-2.3.0/final-candidate/`. Current docs describe the published API;
prior local-only status and 2.2.0 baseline statements are historical evidence.
Documentation hosting and Session-default/streaming-prepared implementation
remain separate future candidates.

## Selected buffered async prepared requests (2026-10-09)

The user-selected workflow "prepare, inspect or sign, then send" is **complete
locally**. `AsyncSession.prepare_request()`, `AsyncPreparedRequest.with_headers()`
and `AsyncSession.send()` support buffered bodies with read-only inspection,
Session/loop binding and detached Cookie/TLS/proxy snapshots. Explicit Cookie
header copies remain explicit on retry. The existing dispatcher retains hooks,
retry/redirect rules, streaming response ownership and cancellation.
The review findings are fixed: prepared URLs normalize scheme, destination
authority, empty paths and query delimiters before signing, matching the
HTTP1/HTTP2 request target. Both peers independently verify signatures, including
upper-case schemes and port leading zeros. Generated Cookies use the normalized
destination; percent encoding and query order are retained.
The latest fix preserves double/triple leading slashes in the shared async
HTTP1/H2 request target, so prepared signatures match received paths and ordinary
requests no longer gain two extra slashes.

Current acceptance status, test counts and artifact paths are recorded only in
the [execution record](post_2_2_0_execution_plan.md), avoiding stale copies here.
See the [design](async_prepared_request_design.md) and
[2.3.0 guide](../docs/async.md#prepare-inspect-and-send-buffered-requests).
Earlier acceptance records remain superseded history. This candidate remains
uncommitted/unpublished; the latest published baseline is still 2.2.0. Prepared
streaming sources and Session-default merging remain future candidates.

## Request wire-boundary maintenance review (2026-10-09)

The TLS/H2 follow-up repairs exact ordered SETTINGS, configuration validation,
preset isolation, actual offered-ALPN enforcement and valid H2 request fields.
It adds configurable pseudo-header order and initial PRIORITY fingerprint
signals through the existing project-owned TLS/H2 engines. Scheduling remains
a separate deferred capability. Current acceptance is kept in the execution
record; this local candidate is uncommitted and unpublished.

The bounded maintenance passes share final header validation across synchronous,
async and CONNECT paths, isolate proxy credentials from destination requests,
preserve semicolon paths and fragments during query assembly, parse bracketed
IPv6 and use final `Host` authorities for synchronous HTTP1/H2. They also keep
release evidence out of the default `make clean` target and narrow publication
to an explicit version's wheel and sdist. Focused and full local verification is recorded in the linked
execution plan; remote delivery and publication remain unselected.

## Current baseline and follow-up selection (2026-10-08)

The 2.2.0 release is complete: `master`, `origin/master`, and `v2.2.0` point
to `83132c84547b6f7bbcf740b961b6d06a7121b058`. GitHub Release and PyPI 2.2.0
were published after exact-commit tests, typing, documentation, artifact-hash,
and official-index installation checks. The detailed next-stage selection is in
the [post-2.2.0 follow-up plan](post_2_2_0_follow_up_plan.md), with the
[execution sequence](post_2_2_0_execution_plan.md) kept separately.

The completed buffered A3 capability is the current local product boundary.
Further work requires a reproducible maintenance defect or a named capability
outside that boundary. Session-default merging, incremental internal typing,
documentation hosting, and performance CI remain separate candidates. HTTP/3, 0-RTT, ECH,
H2 push/priority scheduling, browser-profile expansion, and legacy TLS suites remain
deferred feasibility decisions. The historical sections below retain their
original evidence and are superseded for current selection by the linked plan.

## Latest local delivery and client completion (2026-10-08)

Follow-up: the user selected fixes for the second review's source-cancellation
and early-generator-cleanup findings. That local work is complete in
`dist/delivery-client-2026-10-08/review-fixes-2/`; the execution record contains
the installed acceptance and cleanup evidence.

The selected [delivery and client capability plan](next_delivery_and_client_plan.md)
is **complete locally**: source readiness, async Cookie files, Session-default
design, streaming upload design, sync/async HTTP1/H2 streaming bodies and async
multipart/files. Session-default merging remains design-only. The review removed
artificial prerequisites and each upload surface received typing/docs/integration
acceptance; see the [execution record](delivery_and_client_execution.md).

The subsequent review's five confirmed findings are fixed: response-header
timeouts no longer cap progressing uploads, async generators keep a stable
request context and finalize started native generators there, source cancellation
wakes H2 response waiters without retry, and wrapped binary streams use their
output-length contract. The final uncommitted snapshot passed **2,527 installed
tests + 118 subtests**, **91.54% coverage**, 59 installed typing negatives and all
documentation checks, including three real local examples. Reports, artifact
hashes and the 295-file manifest are retained under
`dist/delivery-client-2026-10-08/review-fixes-2/`; source identity and actual
temporary-directory cleanup were read back independently.
Python 3.7 grammar passed; no new local 3.7 runtime or remote CI result is claimed.

Commit/push, publication, hosting, Issue writes and the remaining optional lanes
remain unselected. The package version is unchanged; historical completed work
and older evidence below are retained with their original boundaries.

## Latest local follow-up (2026-10-06)

The subsequent review fixes and local integrated acceptance are complete.
HPACK encoder table sizes now count wire bytes; invalid UTF-8 text-header inputs
are rejected before table mutation, and async H2 validates before reserving or
queuing a stream so a local input error cannot fail unrelated requests.
The text-header UTF-8 restriction is a compatibility change, not an HPACK wire
requirement; raw string codecs still preserve arbitrary bytes.

The latest uncommitted snapshot passed **2,158 installed tests + 118 subtests**,
**91.08% coverage**, 47 installed typing negatives, seven strict modules, 72
verifier tests, formatting/lint and full docs checks. Reports and artifact hashes
are retained under `dist/post-2.1.1/final-review-2026-10-06/`; see the current
[execution record](post_2_1_1_execution.md). Earlier candidate results below are
historical. Current package/test bytes were read back against the accepted
snapshot; only completion records changed afterward.

No commit, push, remote CI, release, site deployment or Issue mutation was
selected or performed in this follow-up. The 14 candidate categories and four
async conveniences remain deferred with their existing entry conditions.

## Published baseline and next plan (2026-10-05)

The latest selected commit, push and publication are complete: `master` and
`v2.1.1` resolve to `07c70955fc35c981867eed029c897e7ba6f8cf1c`. See the
[release notes](../CHANGELOG.md),
[GitHub v2.1.1](https://github.com/lxjmaster/ja3requests/releases/tag/v2.1.1) and
[PyPI 2.1.1](https://pypi.org/project/ja3requests/2.1.1/). Independent installed
acceptance passed 2151 tests and 112 subtests with 91.06% coverage. All 11
configured CI jobs passed for that exact revision, including Python 3.7-3.13;
both channels' artifact bytes and a fresh official-index installation matched
the accepted source. These are retained release results, not new checks run
during the subsequent planning task.

The selected P1-P4 sequence from the [post-2.1.0 plan](post_2_1_0_plan.md) is
**complete and released in 2.1.1**: minimal packaging maintenance, frozen
performance baselines, removal of the full-TLS1.2 fixed wait, bounded async
read-ahead and three shared-value typing modules. See the historical
[execution record](post_2_1_0_execution.md) and
[measurement report](../bench/POST_2_1_0_RESULTS.md); their source snapshots kept
version 2.1.0 and are not relabeled as release measurements. At that release, six
modules were in the strict gate and 39 installed typing negative markers passed. The retained
internal backlog is 1786 diagnostics in 53 files, not a count of runtime defects
or a claim that the whole library is type-clean.

The new [post-2.1.1 engineering plan](post_2_1_1_plan.md) selects N1-N3:
state/documentation alignment, reusable local artifact verification plus an
independent docs CI gate, and an HPACK-only typing slice. The user subsequently
authorized that complete local implementation and integrated acceptance, now
**complete locally**. The candidate passed 2,153 installed tests plus 112 subtests
at 91.06% coverage after the three verifier review fixes, 47 installed typing
negative markers, the 7-module strict gate, 72 verifier tests and the full docs
gate. Internal typing backlog is now 1,735
diagnostics in 52 files. See the [execution record](post_2_1_1_execution.md) for
source identities, review, evidence and remaining verification boundaries.
No new release/version or remote CI run is claimed. Current baseline
and local Issue dispositions are recorded. The existing 14 candidate categories
(including partial internal typing) and four async conveniences remain explicit;
listing them does not select all of them for implementation.

The preceding read-only inspection on 2026-10-05 found five open Issues and zero
open PRs. Their state does not make already delivered features missing. Remote
Issue edits/closure, public documentation hosting, another release and optional
features remain unselected. Everything below is retained historical roadmap
context: use the new plan for current tasks, rather than treating older unchecked
items, obsolete version labels or then-current release boundaries as new work.

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
