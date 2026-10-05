# Post-2.1.0 maintenance execution

Selected: 2026-10-05, following the user's request to proceed in the proposed
order. The complete selected outcome is local implementation and verification
of the recommended P1-P4 sequence in [the plan](post_2_1_0_plan.md), not just P1.
Optional candidates and remote actions remain unselected. The prior planning
delivery is complete; this execution record tracks the selected local outcome.

Outcome: **P1-P4 completed locally**, including combined-source verification,
independent implementation/data checks and task-owned temporary cleanup. The
retained evidence and actual remaining internal-type backlog are recorded below.

Evidence note: `dist/` paths identify locally retained artifacts, not published
downloads. The original local record is retained separately; temporary directory
names are omitted from this public record. File-plan registration was unavailable;
the supported thread goal was completed after whole-outcome acceptance/cleanup.

Release follow-up: a separate request selected commit, push and publication as
2.1.1. The measurements and development artifact hashes below retain their
original 2.1.0 labels; they are not the new release artifacts.

## Required outcomes and acceptance

- [✅] P1: remove obsolete setuptools test integration, preserve package metadata,
  runtime requirements and contents; verify sdist-to-wheel, independent install,
  dependency/smoke checks and installed typing consumers.
- [✅] P2: measure frozen published `2175105` source with identified tools/runtime;
  cover small H1, full/resumed/reused TLS paths, 64 KiB sync/async H1/H2 workloads
  and repeated 100 MiB sequential async samples. Retain raw evidence and limits.
- [✅] P3a: establish Finished/timeout/failure boundaries, verify any minimal
  TLS1.2 fixed-wait change and compare controlled paths without changing defaults.
- [✅] P3b: investigate reproducible small-response/async costs, test one hypothesis
  at a time, and deliver evidence-backed optimization or a qualified no-change
  conclusion; preserve cancellation and resource ownership.
- [✅] P4: capture actual internal mypy diagnostics, select and complete meaningful
  dependency-based module batches, expand strict coverage and retain installed
  public consumers without suppression or runtime-semantic changes. Record the
  selection from diagnostic evidence and any remaining internal migration.
- [✅] Reconcile changed-code regression/static/package gates, independent review,
  source/artifact identities and documentation. Preserve Python >=3.7; report
  which runtimes were actually exercised locally rather than borrowing old CI.
- [✅] Retain reports and completed source; remove only verified task-owned
  temporary resources. Audit the whole selected outcome before closing the goal.

## Authority and invariants

No version bump, commit/push, remote Issue mutation, site deployment or package
publication. Do not select deferred APIs/protocols as incidental improvements.
Preserve the project TLS/HTTP2 engines, secure/wire defaults, authentication,
timeouts, cancellation, ownership and streaming behavior. Existing untracked
debug scripts, IDE files and release records remain untouched.

## Coordination and measurement isolation

The primary owns this record, integration, performance measurements, P3/P4 scope
selection and final acceptance. A delegated P1 lane owns `setup.py` and isolated
packaging verification; other packaging edits require a concrete necessity.
A second lane inspects P3a test boundaries read-only. All agents report evidence
and retain no authority for remote writes. Shared configuration has one editor.

Start performance runs only after packaging/testing activity is finished. Use
frozen source snapshots, distinct report paths and task-owned loopback peers.
Do not mutate measured source or run CPU-intensive checks concurrently. Static
reading can continue in parallel. Each process has bounded network/teardown
timeouts; retain real process handles when a tool yields.

## Recovery and evidence retention

Keep new raw reports and artifact checks under `dist/post-2.1.0/`, in distinct
batch directories; preserve earlier release and performance evidence. Use
`mktemp -d` for temporary snapshots, installs and certificate staging and record
the resulting exact paths below. Clean only verified owned artifacts after
retaining needed reports. Failed attempts remain identifiable; never overwrite
published artifacts or user/concurrent changes.

For unclear failures use the systematic-debugging workflow: establish a cause,
form one hypothesis and verify its smallest change. After two attempts without
progress, choose a safe alternative or identify the actual dependency. Optional
improvements are not delivery gates; required selected work is not relabeled
optional merely because it remains unfinished.

## Progress evidence

- Initial readback: HEAD is the published 2.1.0 baseline; only the two prior
  planning documents are changed/new among task-owned source files. Existing
  unrelated untracked files were preserved. Local development, lifecycle and
  delegation requirements were read before dependent actions.
- P1 is delegated for implementation and installed-artifact acceptance. P3a
  boundary analysis is read-only; no performance measurement has started.
- The isolated `baseline/` snapshot was extracted from `git archive 2175105`;
  import readback points into
  that snapshot. The 68-module aggregate SHA-256 is
  `d9f9fec5f71be7b345a4c1e77c8bfec410e2ef857d4fad13c6efc86b6e05b4f9`.
  Measurement environment: Python 3.13.3, OpenSSL 3.0.16, cryptography 45.0.5,
  Brotli 1.2.0, pytest 8.4.1, pytest-benchmark 5.3.0 and requests 2.32.4.
- P4 diagnostic precheck (before any internal-type edit):
  `python -m mypy ja3requests --no-incremental` reports 1868 errors in 56 of
  68 source files. Full diagnostics are retained in
  `dist/post-2.1.0/p4/initial-mypy.txt`. This expected backlog is not a newly
  introduced runtime failure or evidence that the public-consumer gate failed.
- P1 used separate task-owned packaging staging. Reports and build/install
  evidence remain under `dist/post-2.1.0/p1/`.
- P1 accepted: only 31 obsolete lines in `setup.py` were removed. The isolated
  sdist-to-wheel build, independent Python 3.13.3 install, `pip check`, H2 smoke
  and installed consumers (including all 36 negative markers) pass. All 74 wheel
  members match the published package byte-for-byte; the 222-member sdist has
  only the intended `setup.py` content difference. Metadata, dependencies,
  licenses and `py.typed` are unchanged; obsolete-entrypoint warnings are absent.
  `dist/post-2.1.0/p1/verification.json` retains commands and artifact hashes.
  The delegate confirmed every build/install process exited before P2 started.
- P2 began on the frozen snapshot: small-H1 uses 9 samples x 1000 requests;
  protocol paths use 5 samples x 40 requests with 4-worker concurrent cases.
  Distinct JSON/log and pytest staging paths preserve each measurement.
- P2 measurement runs completed without failure: 19 protocol cases / 107
  records; 16 async comparison cases / 128 records (7 x 120 requests); four
  native-async 100 MiB cases / 24 records (5 timing samples each plus separate
  allocation samples). Every report confirms stable source/tools and verified
  paths. Small-H1 also confirms stable source. Summary/interpretation is pending.
- P3a red evidence: the four independent full-handshake no-pause cases fail
  specifically because they observe `[0.3]`; all ten new CBC/GCM delayed,
  fragmented, timeout and EOF finishing-boundary cases pass. Only the fixed
  pause and its unused TLS import were removed; the async adapter's now-stale
  comment was updated without behavior changes. Expanded regression is running.
- P4 selected diagnostic batch: H2 frame parsing/building (27 initial errors),
  HPACK Huffman encoding/decoding (6), and ClientHello inspection (17). These
  low-dependency shared value boundaries precede their connection/TLS consumers;
  none requires a connection-state rewrite. This is the planned incremental
  internal migration, not a claim that all 1868 diagnostics will be eliminated.
- P3a green acceptance: all 154 selected TLS/async/wire regressions pass. Three
  AB/BA/AB rounds of seven handshake paths also pass on frozen snapshots; full
  TLS1.2 medians are 309.871/308.784/310.730 ms before versus
  1.253/1.231/1.261 ms after. Existing receive timeout/authentication semantics
  remain unchanged; this is not a new whole-handshake deadline or remote-speed
  guarantee. Raw pair reports are retained under `dist/post-2.1.0/p3a/`.
- P3b hypothesis from source/profiling: exact TLS header/body reads schedule
  separate owned native tasks. Reuse bounded (64 KiB) native read-ahead via the
  existing pending buffer; preserve native task/close/cancellation machinery.
  The operation-count test fails before (`[6,4,4]` instead of one read); the
  completed-read/close race is also covered. After the scoped change all 273
  async transport/pool/Session/Response/H2/TLS tests pass. Controlled paired
  throughput comparison is running on `no-pause/` and `read-ahead/` snapshots.
- P4's three modules now pass their strict check. One Optional-node diagnostic
  was resolved with an explicit child local before the existing None rejection,
  not a runtime cast/check inside the Huffman hot loop. All six selected source
  files pass strict mypy. Installed consumer cases were extended but await final
  rebuilt-package validation; the full internal diagnostic count is not yet
  remeasured. No typing suppression or runtime typing dependency was added.

## Final local acceptance (2026-10-05)

The [performance report](../bench/POST_2_1_0_RESULTS.md) records P2/P3 parameters,
all comparison groups, distributions, source identity and interpretation limits.
The final source aggregate SHA-256 (68 modules) is
`231ba04ff465c16ce121811a7c4ae915aacd2461d23552463028c03fa3fa1ee8`.
Final source, sdist, wheel and independent installed-package module hashes agree.

- P2: four baseline reports passed, including nine 1000-request small-H1 samples,
  19 protocol cases, 16 async cases and four repeatedly measured 100 MiB cases.
  Actual imports came from archived `2175105` source. Earlier protocol/async
  reports' stale distribution metadata (`1.1.0`) was not used as source identity.
  Small-H1, final performance and installed artifact metadata is 2.1.0.
  Historical small-H1 parameters/snapshots
  do not support a strict before/after conclusion; synchronous code is unchanged.
- P3a: the four deterministic no-pause tests provide red-to-green evidence;
  ten CBC/GCM receive-boundary tests plus existing invalid-Finished cases retain
  authentication, fragmentation, timeout/EOF and transcript coverage. The 154
  targeted regressions and three controlled seven-path handshake rounds pass.
  Removing the fixed wait does not change resumed/pooled or async-wait semantics.
- P3b: six 16-case AB/BA/AB comparisons (nine timing samples per group) and eight
  three-sample large-body comparisons pass. Native 64 KiB throughput medians
  improve approximately 25-98%, while Python allocation peaks increase. This is
  bounded read-ahead, not a whole-connection memory cap or latency guarantee.
  Both new transport tests have a two-second failure bound and pass in the final
  full suite. The original operation-count failure is retained separately.
- Combined final-source performance: 16 cases / 64 records plus four 100 MiB
  cases / 16 records pass after P4 integration. Every final large response
  delivered its first chunk before its peer's final send; all payload bytes,
  protocol/connection paths and source/tool stability checks pass. The final
  TLS1.3 H1 sample's 21.387 ms maximum loop lateness is explicitly retained.
- P4: `python -m mypy --no-incremental` passes all six configured source files.
  Full internal diagnostics decrease from 1868 in 56 files to **1786 in 53**
  (68 checked), without suppression. The three selected modules are type-clean;
  the remaining connection/TLS/mutable-state migration is not part of this
  completed incremental batch. Installed valid consumers and all **39** negative
  markers pass; no runtime `typing_extensions` dependency was added.
- Full source regression: `pytest test --ignore=test/test_session.py` with
  `--cov=ja3requests --cov-fail-under=85` passes **2151 tests**, coverage **91.06%**.
  The single existing `TestContext` collection warning remains. The ignored file
  is the existing external/manual selection, not a newly omitted failing test.
- Black (all 68 package modules), error-level Pylint and strict mypy pass.
  Strict MkDocs build passes; `docs/verify.py` passes both runnable examples,
  23 pages, 1483 local links/assets, 18 API objects, 34 snippets and 12 pinned
  source paths. Documentation site output remains local only.
- Final packaging builds an sdist from a clean copy of current tracked source,
  then builds the wheel from that sdist. Inventories remain 222 sdist and 74 wheel
  files. Only the five intended runtime modules plus wheel RECORD differ in the
  wheel; the sdist additionally contains the selected setup/config/test/consumer
  edits. Metadata, runtime requirements, licenses, `py.typed` and Python >=3.7
  are unchanged. Independent install, `pip check`, origin/hash checks, H2/Huffman
  smoke and installed typing all pass. Unrelated untracked user files were not
  copied into package inputs.
- Independent P3 code review and main-agent P4 acceptance found no confirmed
  new blocking defect. A bounded socketpair comparison showed that an extra response can
  remain in the old kernel buffer or the new pending buffer alike; the existing
  response-level surplus-byte limitation is not falsely reported as a new
  read-ahead regression or used to expand into pool redesign.
- A proposed separate performance-report lane hit the agent capacity limit;
  the primary prepared the report and an existing lane performed read-only
  implementation/data checks.
  An earlier review attempt had failed with a tool rate limit and is not counted
  as successful acceptance. No required review was silently dropped.
- Independent report review recalculated all table rows, counts, ordering and
  listed hashes. Two wording corrections distinguish earlier stale metadata
  from final 2.1.0 metadata and whole-run elapsed from per-response completion.
  No measurements were rerun or discarded to obtain a preferred conclusion.
- All 68 runtime modules parse with Python 3.7 grammar (not a Python 3.7 runtime
  test). The seven touched/new Markdown documents have 55 valid local file
  targets; `git diff --check` passes. The final source hash readback is unchanged.

### Retained evidence

`dist/post-2.1.0/final/evidence-manifest.json` validates 26 measurement reports,
their source/tool identities, paths/payloads and final artifact source hashes.
P3a/P3b candidate package sources are retained as small hashed archives, so
removing temporary source roots does not remove the measured variants.
Raw logs, original red tests, profile-scope correction, mypy backlog, coverage,
documentation output and both P1/final build artifacts remain under
`dist/post-2.1.0/`. These ignored local paths are not public download links.

Final development artifacts (not uploaded and not the published 2.1.0 bytes):

| Artifact | SHA-256 |
| --- | --- |
| `final/artifacts/ja3requests-2.1.0-py3-none-any.whl` | `575174a9c95f61a4fad176cf4621ce509c8676184cabc316111fc32973e7083c` |
| `final/artifacts/ja3requests-2.1.0.tar.gz` | `3236394d6da692cac780e4616c27ecfe6388e71db1f53b2918c76f9b1b11b712` |

New runtime/install/benchmark evidence is local Python 3.13.3 only. Python 3.7
syntax and import compatibility are preserved; historical release CI is not
claimed to validate this uncommitted revision. No version change, commit, push,
remote Issue update, documentation deployment or package publication occurred.

### Cleanup and completion boundary

All benchmark, test, build, install and documentation commands have exited.
Before cleanup, `lsof` found no open handles under the two exact task-owned
temporary roots. Both isolated maintenance and packaging staging roots were
removed and their absence checked.
This removed rebuildable source/test/certificate/install staging, not source
edits or user data. The measured candidate source archives and final sdist/wheel
remain available for reconstruction. Reports, logs, profiles, diagnostic history
and local documentation output are intentionally retained as delivery evidence.

P1-P4 has no open required implementation or verification item. Optional API,
protocol, remote Issue, hosting and release candidates remain unselected. The
remaining 1786 internal diagnostics belong to future incremental batches, not
an unfulfilled promise to type-clean the entire library in this batch.
