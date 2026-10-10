# Delivery and client capability advancement plan

Prepared: 2026-10-08. Revised after review; selected local execution is complete.
The second review's two cancellation/generator-cleanup fixes are complete in the
accepted local snapshot `dist/delivery-client-2026-10-08/review-fixes-2/`.
Recommended order: current local delivery -> async Cookie files, with independent
Session-default and upload designs. This is an integration order, not a chain of
technical prerequisites. See [the execution record](delivery_and_client_execution.md).

Final local acceptance after the two second-review fixes: 2,527 installed tests,
118 subtests, 91.54% coverage, 59 installed negative typing cases and the complete
docs gate passed. The wheel and sdist are retained under
`dist/delivery-client-2026-10-08/review-fixes-2/`; S1 remains a design-only
deliverable. Unselected remote and optional work does not gate this completed
local outcome.

The separately requested review fixes are complete: upload progress no longer
consumes the response-header wait budget, async generators retain one request
context across pulls and finalize started native generators in that context,
source cancellation wakes H2 response waiters without retry, and wrapped binary
streams do not inherit their underlying file's byte length. Regression and cleanup
evidence is in the execution record.

## 1. Authority, baseline and completion boundary

The follow-up instruction selects local readiness, F1, S1 design, U0, incremental
U1 and U2. Commits, pushes, PR merges, publication, deployment and Issue edits
remain unselected. No version is selected. D1 uses its local-only handoff boundary;
exact-commit/remote acceptance applies when those actions are later selected.

Registration: **UNREGISTERED**. `codex-plan --json status` reports missing official
session binding. No substitute identity is supplied. The file remains usable;
register through the supported CLI when a genuine binding is available.

The preceding engineering batch and review fixes are complete. Its retained evidence reports
2,158 installed tests + 118 subtests, 91.08% coverage, 47 negative typing cases,
seven strict modules, 72 tool tests and a passing docs gate. These are historical
acceptance results, not tests rerun during this planning task. See
[execution evidence](post_2_1_1_execution.md). The worktree remains uncommitted;
local HEAD is `07c7095`. Remote state must be refreshed before remote delivery.

Keep Python >=3.7, project-owned TLS/H2 engines, secure defaults, certificate
authentication, cancellation, connection ownership and bounded flow control.
Modern development tools remain separate from library runtime dependencies.
The new UTF-8 text-header restriction is a compatibility change to document,
not an HPACK wire-format requirement or a typing-only change.

## 2. Stage map and dependencies

| Stage | Deliverable | Entry | Exit |
| --- | --- | --- | --- |
| D1 | Scoped source readiness | Local handoff selected; commit/push separately selected | Exact local inventory, compatibility notes and candidate acceptance; committed/remote identity only when selected |
| D2 | Optional package release | Explicit publication selection and version decision | Exact source artifacts, published hashes and clean installation verified |
| F1 / A2 | Async Cookie-file helpers | Local-only handoff selected | Contract, implementation, failure tests, typing/docs and installed acceptance |
| S1 / C17 | Session-default merge design | Design selected; independent of F1 | Complete semantics matrix and compatibility decision; no runtime changes |
| U0 | Upload design | Streaming scope selected; existing merge semantics retained | Body-source, ownership, length and replay contracts accepted |
| U1 / C14 | Streaming request bodies | U0 accepted | Each selected sync/async HTTP1/H2 slice passes peer, installed typing/docs and integration acceptance |
| U2 / A1 | Async multipart/files convenience | Its actual async U1 transports accepted | Multipart framing, file ownership, replay and async API acceptance |

D2 is optional and does not gate F1. S1 implementation is a separate selection,
not implied by its design completion; U0 can use existing merging if S1 remains
design-only. Do not require unselected hosting, Issue closure or protocol
extensions to finish any stage. No calendar estimates are asserted without
design and environment evidence.

## 3. D1: deliver the current accepted batch

- [✅] D1.1 Inspect current diff and accepted manifests; inventory exact deliverable
  paths. Include verifier source/tests/guide and docs workflow together with their
  CI references. Preserve user IDE/debug files, release records and build outputs;
  do not stage everything or delete unrelated untracked files.
- [✅] D1.2 Add user-facing changelog/migration notes for table-byte accounting,
  invalid-input atomicity, async stream isolation and UTF-8 input rejection.
  Describe unreleased behavior accurately without relabeling published 2.1.1.
- [✅] D1.3 Propose logically coherent commit groups: engineering tools/docs/CI;
  HPACK typing/runtime fixes and async isolation. Inspect each group's dependency
  closure so no commit references a missing tool or validation helper. Use the
  git-commit skill when commits are selected; configured identity only.
- [✅] D1.4 Reuse unchanged checks; run affected checks for changed inputs. For the
  local handoff, verify an explicit worktree snapshot and full-history docs gate.
  A later commit/push handoff must verify the actual committed source.
  Compare implementation/test bytes with accepted evidence.
- [ ] D1.5 If push is selected, inspect remote branch/protection and integration
  policy, push only scoped source, monitor exact-revision checks, read back SHA
  and CI outcomes. Use PR merge only if selected; no direct-branch substitute.

D1 acceptance: explicit source identity, clean deliverable inventory, no omitted
new files, unchanged unrelated work, accurate compatibility notes, and passing
selected checks. Local-only delivery must not claim push or CI success.

Optional Issue maintenance requires its own selection and fresh remote readback.
Reconcile #36's partial internal typing, #37's first async scope, #40's optional
comparison CI, #41's memory-bound wording and #42's optional hosting. Do not close
all Issues merely because local tests pass.

## 4. D2: optional release

- [ ] Decide version from the actual compatibility impact; update release inputs
  before final acceptance, never retag or overwrite existing release artifacts.
- [ ] Verify sdist-to-wheel, metadata/source hashes, independent install, full
  selected tests/coverage, installed consumers and exact-revision runtime CI.
- [ ] Publish only selected channels, then compare downloadable hashes and a
  clean official-index installation with the accepted artifacts.

Use a new evidence directory for final release source. A worktree snapshot is
not release-commit acceptance. An upload failure is not permission to change
version or overwrite remote state silently.

## 5. F1 / A2: async Cookie-file helpers

Implementation anchors: [async session](../ja3requests/async_sessions.py),
[sync reference](../ja3requests/sessions.py),
[file format](../ja3requests/_cookie_file.py), and existing Cookie-file tests.

- [✅] F1.1 Define awaited save/load signatures and return counts. Proposed defaults
  mirror sync: include_session=False, load merge=False. Reuse existing format,
  validation, expiration, domain/path flags and atomic replacement.
- [✅] F1.2 Specify linearization points: save snapshots loop-owned Cookie data;
  load parses/validates detached data off-loop, then applies one loop-owned update.
  Decide merge against commit-time state and document replacement semantics.
  Never allow a worker to mutate the live jar while requests are using it.
  Snapshot every serialized field, including independent extension metadata;
  preserve the commit-time target jar and its Cookie policy identity on load.
- [✅] F1.3 Define overlapping operations, close and cancellation. Recommend owning
  in-flight file tasks through cleanup and serializing per-session file helpers.
  A completed atomic file replacement is not undone by caller cancellation.
  Define how errors/results are observed and when loaded data may be applied.
  Cross-process locking is not implied; document external-writer behavior.
- [✅] F1.4 Implement using Python-3.7-compatible off-loop I/O and existing format
  helpers; avoid holding blocking locks on the event loop or changing sync APIs.
- [✅] F1.5 Test sync/async file interchange, session/expired Cookies, replace/merge,
  malformed/oversized files, filesystem errors, concurrent request mutation,
  overlapping helpers, cancellation before/during replacement, close and cleanup.
  Use events to control worker boundaries rather than timing-only assertions.
- [✅] F1.6 Add positive/negative installed type consumers, documented examples and
  installed full-suite acceptance at >=85% coverage. Test event-loop responsiveness
  and no late jar mutation after the documented cancellation/close boundary.

Exit: usable awaited helpers with explicit snapshot, concurrency and cancellation
semantics. No request-body streaming or TLS-session secret persistence is included.

## 6. S1 / C17: design Session-default merging

- [✅] Inventory actual sync/async behavior, signatures, request preparation,
  redirect/retry hooks and precedence before proposing shared semantics.
  Separate explicitly configured defaults from getters caching the latest request;
  cover observational reads and two independent cross-origin requests.
- [✅] Produce a matrix for omitted / None / empty / explicit values across
  headers, params, auth, proxies, Cookies, timeout and TLS overrides. Scope each
  field explicitly; do not silently select new constructor options.
- [✅] Define case-insensitive header override/removal, repeated query keys,
  mapping copy/freeze behavior, per-request isolation and default mutation timing.
- [✅] Specify cross-origin auth/Cookie/proxy boundaries and hook/retry ordering.
  Explain any intentional sync/async differences.
- [✅] Compare backward-compatible explicit opt-in semantics with changing existing
  defaults; select based on concrete call examples and migration cost. Deliver
  acceptance cases and migration/version advice. Runtime implementation requires
  a separate selection after material choices are resolved.

Exit: no ambiguous precedence cells and no claim that a design equals an implemented
feature. Broader sync 307/308 behavior changes are separately scoped decisions.

## 7. U0-U2: upload project

The selected target retains sync and async streaming bodies over HTTP1 and H2,
delivered as independently accepted slices: async HTTP1, async H2, then synchronous
transports. Async files= depends on its async slices, not synchronous completion.
A finished slice does not complete the entire target. U0 retains existing merge
and synchronous redirect semantics; S1 design does not change them. Buffering is
not a substitute for this streaming target.

- [✅] U0.1 Define body-source interface: known/unknown length, chunks, iteration,
  rewind/reopen capability, who closes caller-owned handles and generators, and
  whether/blocking file reads run off-loop. Separate source from request policy.
- [✅] U0.2 Define framing: Content-Length correctness and unknown-length HTTP1
  chunking, H2 DATA/end-stream, empty chunks, premature EOF and excess data.
- [✅] U0.3 Define one-shot vs replayable bodies, partial sends, retries, auth and
  307/308 redirects. Never automatically replay unsafe/non-rewindable sources;
  define explicit errors and stream/connection disposal on source failure.
- [✅] U1.1 Implement body-source contract and selected HTTP1 writer slice with
  bounded buffering, producer backpressure and timeout/cancellation handling.
- [✅] U1.2 Implement H2 upload flow-control integration, concurrent stream fairness,
  source failure isolation and cancellation while waiting for credit.
- [✅] U1.3 Use independent loopback peers to verify exact payload/framing, known
  and unknown lengths, slow sources/peers, early responses, disconnects, retries,
  redirects, cancellation, concurrent streams and bounded memory as size grows.
  State the actual memory bound; chunk_size alone is not a total-memory promise.
- [✅] U1.4 Give every independently delivered public slice its own type updates,
  positive/negative installed consumers, runnable example, supported/unsupported
  transport documentation and installed integration acceptance. U1 acceptance
  must not depend on selecting U2.
- [✅] U2.1 Implement multipart boundary/metadata encoding and files= adaptation;
  define filename/content-type handling, caller-file ownership and path reopening.
- [✅] U2.2 Verify large-file streaming, multipart byte correctness, error/replay
  paths, installed typing and runnable docs; run full installed acceptance for
  the integrated selected target, not merely isolated writer tests.

## 8. Optional lanes and exclusions

C06 internal typing may run as separately selected small slices, beginning with
actual H2Connection diagnostics and dependency inspection. Avoid concurrent edits
with U1; no blanket suppression, broadened Any or runtime restrictions for mypy.
C01 hosting requires a target/URL/version policy. C02 performance CI requires a
stable workload/runner and initially reports samples/variance without invented
speed thresholds. C12 profiles require browser/version/platform captures; C16
requires named environments and installed interoperability evidence.

C07 suites, C08 TLS persistence, C09 scheduling, C10 server push, C11 0-RTT,
C13 ECH/post-quantum, C15 QUIC, A3 prepared requests and A4 module helpers remain
deferred, not prerequisites. Preserve their entry conditions in the
[candidate register](post_2_1_1_plan.md#8-deferred-candidate-register).

## 9. Execution, recovery and evidence

Use disjoint ownership for parallel F1 runtime/tests, S1 design and U0 design.
The integrator owns shared plans, public docs, typing and acceptance. Integrate
coupled session/protocol edits serially. Reconcile delegated diffs and failure
boundaries before accepting each stage.

At execution start, inspect concurrent work and applicable local-development rules.
Retain per-stage reports under a fresh `dist/` evidence root with source manifests,
commands/statuses, artifacts and coverage; use owned temporary staging and verify
cleanup. Never overwrite earlier evidence or remove user/shared resources.
On a defect, make an in-scope fix and rerun affected checks; after two attempts
without progress, choose an independent required check or report a real blocker.
Remote failures retain local evidence and do not authorize broader remote changes.

Advance only after the selected stage's acceptance passes. Update checkboxes and
execution records from observed results; separate local acceptance, commit identity,
remote CI and publication. Revalidate stale evidence only for changed inputs or
specific unresolved concerns. Optional tasks do not gate completion.

## 10. Planning delivery audit

- [✅] Inspect current worktree and retained completion boundaries.
- [✅] Define ordered stages, dependencies, authority and acceptance criteria.
- [✅] Preserve deferred candidates and avoid reimplementing delivered features.
- [✅] Define serial/concurrent work, evidence retention and bounded recovery.
- [✅] Verify local links and diff hygiene; update the roadmap entry point.

Original planning and every selected local item are complete. Unchecked
remote/publication items remain unselected. The execution record identifies final
source, verification, cleanup and retained evidence; no remote completion is claimed.
