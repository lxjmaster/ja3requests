# Post-2.1.1 engineering plan

Current follow-up (2026-10-06): local integrated acceptance and record
reconciliation for the subsequent HPACK/runtime review fixes is complete locally.
See the current section of the execution record. Completed N1-N3 evidence below
describes the earlier candidate; remote delivery and deferred features remain
unselected.

The final follow-up candidate passed 2,158 installed tests and 118 subtests at
91.08% statement coverage, 47 installed typing negatives, seven strict modules,
72 tool tests, formatting/lint and the full docs gate. See the execution record
for snapshot identity, cleanup and the explicit UTF-8 compatibility restriction.

Prepared: 2026-10-05. Planning is complete. The user subsequently selected local
implementation of **all N1-N3 and integrated acceptance**, with a fixed outcome
and continuation until complete or genuinely blocked. See the live
[execution record](post_2_1_1_execution.md). Commit, push, publication, deployment,
remote Issue updates and the deferred candidate register remain unselected.

Registration: **UNREGISTERED**. The supported `codex-plan --json status` command
cannot obtain an official session binding. No identity or successful registry
transition is invented. This file preserves the cross-turn scope; registration
failure does not block independent local implementation.

The selected local implementation outcome, **N1-N3 plus integrated acceptance**,
is now **COMPLETE**. N/I checkboxes track that full outcome. The planning-delivery
checklist at the end is retained historical evidence, not implementation status.

## 1. Baseline and unchanged boundaries

- Published source: `07c70955fc35c981867eed029c897e7ba6f8cf1c`, released as
  [GitHub v2.1.1](https://github.com/lxjmaster/ja3requests/releases/tag/v2.1.1)
  and [PyPI 2.1.1](https://pypi.org/project/ja3requests/2.1.1/).
- Retained release evidence: 2,151 installed-wheel tests and 112 subtests passed,
  91.06% statement coverage, all 11 configured exact-commit CI jobs passed,
  including Python 3.7-3.13. Both channels' artifact bytes and a fresh official
  PyPI installation were verified. These are prior release results, not checks
  rerun while writing this plan. Detailed local evidence remains under
  `dist/release-2.1.1/`; that ignored directory is not a public download link.
- The previous [P1-P4 batch](post_2_1_0_execution.md) is complete and released:
  legacy packaging removal, controlled baselines, full-TLS1.2 fixed-wait removal,
  bounded async read-ahead and three shared-value typing modules. Do not repeat
  that implementation or overwrite its [measurement report](../bench/POST_2_1_0_RESULTS.md).
- [Strict typing](../pyproject.toml) currently gates six modules. The retained
  full-internal report has 1,786 diagnostics in 53 files; `hpack.py` accounts for
  43. These are static-checker diagnostics, not 1,786 confirmed runtime defects.
  The installed consumer suite has 39 expected negative markers at this baseline.
- The preceding read-only inspection on 2026-10-05 found five open Issues
  (#36, #37, #40, #41, #42) and no open PRs. This plan reuses that dated readback;
  any later remote maintenance must inspect their then-current contents.

Keep Python >=3.7, the project-owned TLS/H2 engines and native async network I/O.
Preserve certificate authentication, secure and fingerprint defaults, wire
behavior, cancellation, deadlines, resource ownership and flow-control bounds.
Modern verification/docs tools may use a separate interpreter; their requirements
must not raise the library's minimum Python version or add runtime dependencies.

N1-N3 does not select a new version, whole-library type cleanup, a sync/async
unification, TLS backend replacement, protocol optimization or any optional API.
No confirmed release-blocking defect from the preceding analysis is being hidden
behind this engineering work. A newly proven defect must be triaged on evidence
and fixed only within the selected implementation outcome or separately selected.

## 2. Solution and execution order

| Stage | Outcome | Dependency | Exit condition |
| --- | --- | --- | --- |
| N1 | Current-state and documentation alignment | Existing release/code evidence | Current vs historical status is explicit; sync/async proxy claims match code; docs pass relevant checks |
| N2a | Reusable local artifact verification | Explicit source/provenance contract | One validation pipeline verifies committed or explicitly frozen candidate source; failure reports are truthful |
| N2b | Independent documentation CI | N1 documentation and full Git history | Strict site build and existing link/API/snippet/example checks, without deployment permissions |
| N3 | HPACK-only internal typing | Existing typed Huffman/frame boundaries | Seventh strict module, precise installed consumers and preserved HPACK behavior |
| Integration | Accept the exact combined local candidate | N1, N2a, N2b and N3 | Relevant checks pass on the same frozen source; review and cleanup complete |

N1's current baseline and Issue disposition were delivered by the planning task;
its guide corrections are included in the selected implementation. N2a,
N2b and N3 may proceed in independent file lanes. The main integrator owns shared
CI/configuration edits and final acceptance. Integrate source-affecting changes
before freezing the final artifact inputs; do not compare moving source trees.

### Material design choices

- **Verifier source mode:** commit-only is simpler but cannot verify uncommitted
  N3 changes without a separately authorized commit or duplicate temporary
  procedure. Recommend two thin, explicit source collectors with one shared
  verification pipeline: immutable commit and controlled worktree snapshot.
  This is not a generic publishing framework or an automatic resume engine.
- **Typing slice:** HPACK builds on the already typed Huffman boundary and has
  mostly missing function annotations. `stream_state.py` depends on the untyped
  connection class, while TLS `_io.py` exposes generator/decorator behavior to
  both drivers. Prefer HPACK now; defer those coupled contracts. Future candidates
  may follow HPACK -> H2Connection -> stream state -> sync/async drivers, but
  that sequence is not part of this batch's completion criteria.
- **Documentation verification:** keep it separate from artifact verification.
  The existing checker needs historical Git objects and runnable examples;
  `git archive` has no `.git`, and the current sdist does not include the docs
  checker, requirements or examples. No package inventory expansion is needed.

## 3. N1: state and documentation alignment

Expected files: this plan, [the roadmap](next_development_plan.md),
[proxy guide](../docs/proxies.md), [async guide](../docs/async.md) only where a
cross-reference needs clarification, and [docs build guide](../docs/contributing_docs.md).

- [✅] N1.1: Record 2.1.1 as the current baseline and link this next plan. Preserve
  the older roadmap sections, measurements, hashes and dated acceptance as history.
- [✅] N1.2: Record the local Issue disposition below; make no remote edits.
- [✅] N1.3: Scope proxy documentation by API. The synchronous simple parser and
  bare `host:port` examples are not the async URL contract. Async already accepts
  `http`, `socks4`, `socks4a`, `socks5`, `socks5h`, percent-decodes credentials and
  includes the proxy URL in its pool key. Explain actual reuse/ownership, not a
  global claim that all proxy routes bypass pooling. Both APIs lack TLS-to-proxy;
  async rejects the `https` proxy scheme. Do not implement new proxy features.
- [✅] N1.4: Correct the docs build guide's implication that historical source
  paths are checked only when their Git objects are available. The current
  checker unconditionally runs `git cat-file -e`; specify the history requirement.
- [✅] N1.5: Verify edited prose against the current call paths, links, strict
  site build and the existing runnable examples. Do not use public proxy probes.

Code evidence: [async proxy parsing](../ja3requests/async_transport.py),
[async pooling policy](../ja3requests/async_sessions.py),
[sync proxy parser](../ja3requests/sockets/proxy.py), and
[documentation checker](../docs/verify.py).

| Issue | Delivered evidence and remaining boundary | Disposition if remote maintenance is later selected |
| --- | --- | --- |
| [#36](https://github.com/lxjmaster/ja3requests/issues/36) | Public typing/py.typed delivered; internal helpers and implementation checks remain partial | Retain actual outstanding acceptance; HPACK does not complete all original items |
| [#37](https://github.com/lxjmaster/ja3requests/issues/37) | Native async first scope released; naming/API differences and deferred conveniences are explicit | Compare the original goals with the accepted design before deciding closure |
| [#40](https://github.com/lxjmaster/ja3requests/issues/40) | Benchmark suites and controlled measurements delivered; comparison CI is optional | Record release evidence; do not reopen baseline implementation solely because optional automation is absent |
| [#41](https://github.com/lxjmaster/ja3requests/issues/41) | Incremental responses delivered; total memory <= chunk_size is not established or promised by the implementation | Preserve the mismatch; resolve the acceptance/scope explicitly rather than silently marking it satisfied |
| [#42](https://github.com/lxjmaster/ja3requests/issues/42) | Local site, API guides and examples delivered; public hosting is optional and unselected | Separate delivered documentation from a future hosting decision |

## 4. N2a: reusable local artifact verification

Delivered files: [verifier](../tools/verify_release.py),
[tool tests](../tools/tests/test_verify_release.py) and [CLI guide](../tools/README.md).
A small adjacent helper
module is acceptable only if it improves isolation of testable validation logic.
Reuse the retained 2.1.1 verifier's checks and [installed consumer checker](../typecheck/check.py);
do not modify archived release helpers or duplicate the consumer's error parser.

The tool is local verification only: no commit, stash, branch/tag changes, push,
Issue updates, uploads or deployment. It needs no publishing credentials and
must not read `.pypirc`. Ordinary build/install dependency downloads are expected.

### Source and evidence contract

- [✅] N2a.1: Define mutually exclusive commit and worktree-snapshot inputs,
  repository/output paths, a modern tool interpreter (proposed Python 3.12+),
  bounded subprocess execution and machine-readable report fields.
- Commit mode resolves the requested ref to a full SHA, freezes it with
  `git archive`, and records `source_kind=commit` plus the exact SHA.
- Snapshot mode explicitly selects current tracked bytes; new files are included
  only by declared in-scope paths. Freeze into owned staging, compare source
  manifests/hashes before and after copying and fail if relevant inputs drift.
  Record `source_kind=worktree-snapshot`, all selected file hashes and a
  `base_commit` for context only. It is candidate acceptance, never acceptance
  of that base commit or authorization to publish. Do not include unrelated
  IDE/debug files, local release records, credentials or ignored build outputs.
- [✅] N2a.2: Implement those thin collectors and a shared pipeline. Use fresh
  staging and a new output location; refuse conflicting existing outputs rather
  than overwrite prior evidence. Do not add the one-off `--resume-after-smoke`
  recovery path from the 2.1.1 helper.

### Shared validation pipeline

- [✅] N2a.3: Build an sdist, then its wheel. Derive expected project/version,
  archive names, metadata paths and source-module inventory from the frozen
  inputs; remove machine paths and fixed 2.1.1/68-module assumptions. Keep the
  actual equality checks, not merely dynamic counts. Compare package/version,
  dependencies, minimum Python, license and required contents with the frozen
  source and this batch's unchanged compatibility contract. Wheel/sdist agreement
  with each other alone is insufficient.
- Verify strict package metadata, licenses, empty `py.typed`, required fixtures/
  tests/typing files, all corresponding source bytes, archive inventory and
  wheel RECORD hashes/sizes. Generated packaging metadata is expected; not every
  tracked repository file must ship. Do not expand MANIFEST.in for the docs gate.
- [✅] N2a.4: Install in an independent environment, verify isolated import
  origin/module hashes/version, run `pip check`, and retain the existing secure
  defaults, async export and H2 framing smoke checks. Remove source-lookup
  environment overrides and record the actual interpreter/dependency versions.
- Use the frozen source's `typecheck/check.py` against that installed interpreter,
  without `--allow-source`. Reuse its per-line diagnostic-code checks and exit
  status; derive the negative count from actual markers. Do not retain the outer
  helper's hard-coded 39 count or success-log string, and do not weaken the checker.
- Copy tests from the accepted sdist into a run directory without the package
  source, then run the complete unit/loopback selection excluding the existing
  manual `test/test_session.py`, with >=85% statement coverage. Report actual
  tests/subtests/skips/warnings, not a hard-coded 2,151 count. Verify all package
  modules retain Python 3.7 grammar; label that separately from runtime CI.
- [✅] N2a.5: Retain source manifests, artifact SHA-256, command statuses/logs,
  typing results, JUnit and coverage. A failed/unexecuted required step must not
  yield `passed`. Preserve useful diagnostics on failure and clean only owned
  staging after reports are retained; no general automatic resume is required.

### Tool acceptance and integration

- [✅] N2a.6: Add focused tool tests for both source identities, source drift,
  source/metadata mismatch, missing required contents/py.typed, failing subprocess
  and conflicting output paths. Use small fixtures or controlled temporary Git
  repositories; do not multiply full builds/tests for every negative case.
- [✅] N2a.7: Run those tests with the modern tool interpreter and wire them into
  the existing modern-Python wheel job in [test.yml](../.github/workflows/test.yml).
  Keep tools/tests outside the library's Python 3.7-3.13 `test/` collection and
  preserve existing matrix/wheel acceptance; do not introduce publishing steps.
- [✅] N2a.8: Demonstrate commit collection against the accepted baseline and
  snapshot collection against the actual candidate. Share downstream acceptance:
  one full installed run on the final candidate is sufficient if relevant
  collector and validation boundaries have already passed focused tests.

Document the proposed CLI only after its interface is implemented. The previous
release's success does not validate this new tool, and baseline artifact checks
must not be substituted for verification of N3's changed package.

## 5. N2b: independent documentation CI

Delivered file: [docs.yml](../.github/workflows/docs.yml). Reuse [docs requirements](../docs/requirements.txt),
[MkDocs configuration](../mkdocs.yml) and [docs/verify.py](../docs/verify.py).

- [✅] N2b.1: Use the project's existing push/PR/manual trigger pattern, a bounded
  job timeout, concurrency grouping and `contents: read`. Use a modern tool
  Python (proposed 3.12) independently of the library support matrix. Check out
  the tested source with `persist-credentials: false` and `fetch-depth: 0` so
  the pinned historical source objects are present; do not skip those checks.
- [✅] N2b.2: Install the project and existing docs requirements, run
  `python -m mkdocs build --strict` and `python docs/verify.py` with the same site
  directory. The existing checker validates links/assets, required API objects,
  Python snippets, historical source paths and both actual loopback examples.
- [✅] N2b.3: Verify YAML/workflow inputs and run the same local commands after
  N1 edits. If no push is authorized, report workflow/configuration and local
  command acceptance only; actual GitHub CI success is observed after a later
  authorized source delivery. No Pages/OIDC/token-write permissions, remote
  issue comments, hosting configuration or deployment action belongs here.

## 6. N3: HPACK-only typing migration

Expected files: [hpack.py](../ja3requests/protocol/h2/hpack.py),
[pyproject.toml](../pyproject.toml), [valid consumer](../typecheck/valid.py),
[invalid consumer](../typecheck/invalid.py), [typing guide](../typecheck/README.md),
and only tests needed for a demonstrated gap.

- [✅] N3.1: Recheck baseline diagnostics and actual callers before editing.
  Preserve bytes/str header inputs, iterable header pairs, integer/string codec
  outputs, table-size updates, eviction/indexing, sensitive headers and errors.
- [✅] N3.2: Annotate codecs, encoder/decoder helpers and actual state precisely.
  Distinguish the static table's zero-index None sentinel, reverse index, counters
  and optional pending table sizes. Encoder names are normalized strings but
  values can remain bytes; decoder tables hold string pairs. Do not force these
  states into a false common type or add input conversions to satisfy mypy.
- [✅] N3.3: Add only HPACK to the strict list, making seven modules. Preserve
  Python 3.7 syntax/import compatibility and no new runtime typing dependency.
  Do not use widened Any, blanket suppressions, changed index/lookup algorithms,
  new runtime validation or weakened error/size-limit behavior to obtain green.
- [✅] N3.4: Add precise installed-consumer return-type assertions and wrong-input
  diagnostics for HPACK. Preserve all 39 existing negative cases; measure and
  document the new count rather than prescribe it in advance. Reuse the existing
  [typing workflow](../.github/workflows/typing.yml) and checker.
- [✅] N3.5: Run strict source checking and relevant codec/state regressions,
  then independent installed consumers. Record remaining full-internal
  diagnostics once after integration; do not promise a mechanical reduction
  of exactly 43 or completion of the original whole-library typing Issue.

Targeted tests already exist:

- [test_h2.py](../test/test_h2.py), [test_remaining.py](../test/test_remaining.py)
  and [test_h2_huffman.py](../test/test_h2_huffman.py): codecs, indexing, table
  updates/eviction, sensitive fields and Huffman interoperability.
- [test_h2_limits_review.py](../test/test_h2_limits_review.py): raw/Huffman
  decoded byte limits and insertion boundaries.
- [test_h2_hpack_table.py](../test/integration/test_h2_hpack_table.py) and
  [test_h2_discarded_headers.py](../test/integration/test_h2_discarded_headers.py):
  shared decoder state, malformed input and cancelled/discarded streams.
- [test_async_h2.py](../test/test_async_h2.py): cancellation before/after committed
  header writes and preserved shared compression state.

Add behavior tests only for a meaningful uncovered contract. Broader protocol
typing, state-machine refactoring and new benchmarks are not N3 requirements.

## 7. Integrated acceptance, ownership and recovery

- [✅] I1: Reconcile lane diffs against this scope. One integrator owns shared
  workflow/configuration changes; N2 must not accidentally change package inputs,
  and N3 must not absorb connection/TLS drivers or runtime optimizations.
- [✅] I2: Freeze the exact combined candidate and verify installed artifacts,
  source identity, typing and the complete selected suite with >=85% coverage.
  Run the separate full-checkout docs gate, tool tests and applicable existing
  Black/error-level Pylint/hygiene checks. Reuse unchanged successful checks;
  rerun only when affected by integration or new failure evidence.
- [✅] I3: Independently review evidence, source labels, failure paths and public
  semantics. Update implementation status truthfully, retain reports/artifacts
    under a new task-owned output root and remove only created staging/resources.

At implementation start, read applicable local-development rules and reconcile
current files/concurrent edits. Modern-tool tests are not a new supported-runtime
matrix. If publication is later selected, commit-mode and exact-commit remote CI
must validate the final release source; a worktree snapshot is not a substitute.

Do not modify or delete existing release evidence, user debug scripts, IDE files
or shared environments. Use separate task-owned temporary roots and output
paths. A failed experiment may discard only its own generated staging; never
reset the repository or silently revert user/concurrent edits. Preserve failure
logs/statuses before cleanup, and state why any recovery data remains.

If a selected required check fails, identify the cause and make a bounded
in-scope correction. After two non-progressing attempts, choose an independent
step, a safe alternative or report the real dependency. Optional work below
does not gate N1-N3. Do not invent a commit, upload or extra runtime target to
unblock local acceptance.

## 8. Deferred candidate register

The original C01-C17 identifiers are retained. C03 (fixed TLS1.2 wait), C04
(selected throughput investigation/read-ahead) and C05 (legacy packaging) are
complete in 2.1.1. C06 is partial and continues only through N3's selected slice.
That leaves 14 candidate categories including C06, plus four async conveniences;
they are not 18 mandatory unfinished promises. N2 is a new engineering proposal,
not an unfulfilled previous release gate.

| ID | Candidate | Entry condition and acceptance boundary |
| --- | --- | --- |
| C01 | Public documentation hosting | Select host, URL, version policy and deployment authority; verify published routes/assets/version and recovery independently of N2b |
| C02 | Performance comparison CI | Select runner/workload/comparison policy; preserve samples/variance, isolate load and initially report without invented speed thresholds |
| C06 | Further internal typing | N3 covers HPACK only; choose later modules from real dependencies/diagnostics, retaining installed consumer checks |
| C07 | Additional TLS1.2 SHA-384 CBC/static-RSA suites | Specify exact missing suites and independent peer; verify negotiation, PRF, Finished and records; do not reimplement existing GCM or enable legacy suites by default |
| C08 | Cross-process TLS session storage | Select restart use case and secret storage; define trust binding, versioning, expiry, permissions and concurrent writes; Cookie persistence is already delivered |
| C09 | H2 PRIORITY scheduling | Name fairness/latency workload and define scheduling/starvation bounds; basic async DATA rotation already exists |
| C10 | H2 server push | Select a real consumer API and bounded lifetime/cancellation; keep disabled until supported; separate from C09 |
| C11 | TLS1.3 0-RTT | Define eligible operations, explicit opt-in and replay/rejection/retry rules; C08 is needed only for cross-process ticket reuse |
| C12 | Browser profile updates | Name browser/version/platform and fresh capture; validate supported ClientHello/H2 subset and remaining differences |
| C13 | ECH / post-quantum groups | Name target and available primitives; separate feasibility, security and interoperability design from profile updates |
| C14 | Request-body streaming | Define source/length/ownership/non-replayable retry and 307/308 policy; then a bounded protocol slice, slow producer/peer, cancellation and H2-credit tests |
| C15 | HTTP/3 / QUIC | Select target and protocol ownership/dependency boundary; separate architecture/interop project, not an H2 incremental task |
| C16 | Additional runtime/OS/architecture/peer | Name environment and run installed-package/interop acceptance there; metadata, syntax and skips are not support evidence |
| C17 | Session-default merging | Define omitted/None/empty, override/deletion, header casing, query/auth/proxy precedence and cross-origin safety; preserve behavior unless an explicit compatibility change is selected |
| A1 | Async file/path files= | Choose buffered multipart convenience or true C14 streaming; define caller-file ownership, cancellation, replay and memory behavior |
| A2 | Async Cookie-file helpers | Reuse existing format/validation; define snapshots, concurrent mutation and merge/replace; cancellation cannot undo a completed atomic file replacement |
| A3 | Async prepared-request / send | Define freezing, repeated send, hooks and Session/loop ownership before making private metadata public |
| A4 | Async module-level helpers | Start with an explicitly selected eager API or define a session-owning stream context; never close its session before returning an unread body |

Synchronous 307/308 method/body compatibility is an additional possible product
choice, not part of C17 or a promised fix in this plan. Environment proxy discovery,
NO_PROXY, TLS-to-proxy, Trio/AnyIO and cross-loop pools remain outside N1-N3;
their absence is not authorization to expand the batch. Async socks5h/credential
decoding, existing browser presets, sync Cookie files and H2 multiplexing are
already implemented and must not be relisted as missing features.

Commit/push, Issue edits, site deployment and another release remain separate
action sets. Choose any next version only after the actual change scope is known.

## 9. Historical planning-delivery checklist

- [✅] Reconcile 2.1.1, completed work and the preceding read-only inventory.
- [✅] Define N1-N3 tasks, design choices, dependencies, file ownership and scope.
- [✅] Define source provenance, verification, integration, recovery and retention.
- [✅] Preserve all deferred C/A candidates with explicit entry conditions.
- [✅] Check document links, history preservation and diff; reconcile independent
  read-only plan validation.
- [✅] Complete this planning outcome without claiming implementation, test runs,
  plan registration or remote writes.

Planning outcome: **COMPLETE**. All 54 relative file targets across this plan and
the roadmap resolve. The deferred table contains 18 distinct retained C/A
categories, with completed C03/C04/C05 explicitly excluded. The historical
roadmap body is byte-for-byte unchanged. Both independent read-only plan checks
found no material scope, dependency or acceptance defect.

Only these two planning documents changed. No builds, tests, benchmarks,
implementation, staging/commit, remote mutation or task-temporary resources were
created by this planning delivery. The retained plan is the requested deliverable.
Registration remains UNREGISTERED; no successful register/close operation is
claimed. These statements describe only the earlier planning delivery; the
subsequently authorized implementation is tracked above and in the execution record.
