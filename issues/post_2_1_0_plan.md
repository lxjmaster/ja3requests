# Post-2.1.0 development plan

Prepared: 2026-10-05. This document turns the remaining-work analysis into
bounded batches. The planning delivery below is complete. The subsequent user
request selected the recommended P1-P4 implementation sequence; current status
and evidence are in [the execution record](post_2_1_0_execution.md). Optional
candidates and remote actions remain unselected. The proposal below retains its
original planning boundary; it is not an implementation-completion claim.

Implementation update: the selected P1-P4 sequence is now **complete locally**.
Acceptance includes 2151 passing tests, 91.06% coverage, final installed artifacts,
39 negative typing markers, controlled performance comparisons and temporary
cleanup. P4 completes three selected shared-value modules, not all internal
typing: 1786 diagnostics remain in 53 files. See the
[execution evidence](post_2_1_0_execution.md#final-local-acceptance-2026-10-05)
and [performance results](../bench/POST_2_1_0_RESULTS.md). No new release or remote
maintenance was selected. The proposal sections below remain historical context.

Release follow-up: a separate user request subsequently selected commit, push
and publication as 2.1.1. That delivery does not select any additional roadmap
candidate or change the historical acceptance boundaries in this plan.

Registration: **UNREGISTERED**. The supported plan CLI is available but cannot
obtain an official session binding. No session identity or registry transition
is invented. This file preserves the cross-turn proposal independently.

## Scope and verified baseline

Only this plan and the current-status section of
[the existing roadmap](next_development_plan.md) are changed in this planning
task. No functional edits, test/benchmark execution, remote Issue changes,
commit/push, publication or deployment are included.

- `master` and published `v2.1.0` resolve to
  [`2175105016f83dfe24fcb340e986719bd05ed04d`](https://github.com/lxjmaster/ja3requests/commit/2175105016f83dfe24fcb340e986719bd05ed04d).
  [GitHub Release](https://github.com/lxjmaster/ja3requests/releases/tag/v2.1.0)
  and [PyPI 2.1.0](https://pypi.org/project/ja3requests/2.1.0/) are published;
  their two distribution files were downloaded and verified byte-identical.
- Retained release acceptance: 2135 tests passed; the independent installed-wheel
  run also passed 112 subtests; coverage was 91.06%. One existing collection
  warning remains. `test/test_session.py` is an external/manual exclusion.
- Exact-commit CI passed all 11 configured jobs, including Python 3.7-3.13:
  [Tests](https://github.com/lxjmaster/ja3requests/actions/runs/37268872314),
  [Coverage](https://github.com/lxjmaster/ja3requests/actions/runs/37268872350),
  [Lint](https://github.com/lxjmaster/ja3requests/actions/runs/37268872399),
  [Public typing](https://github.com/lxjmaster/ja3requests/actions/runs/37268872369).
  These are prior release results, not checks rerun during this planning task.
- Read-only inspection found five open Issues (#36, #37, #40, #41, #42) and zero
  open PRs. Open Issue state does not mean its entire implementation is missing.
  Source delivery and 2.1.0 publication are complete and must not be repeated.

Keep Python >=3.7 and the project-owned TLS/HTTP2 engines. Preserve certificate
authentication, secure and wire/fingerprint defaults, cancellation, timeout,
resource ownership and bounded response buffering contracts. Modern build/type
tools may use a separate interpreter; that does not raise library requirements.
Do not add an OpenSSL client backend or executor-based network bridge. Environment
proxy discovery, HTTPS connections to proxies, Trio/AnyIO and cross-loop pools
remain non-goals, not silently added backlog commitments.

## Recommended order and decision points

| Batch | Proposed outcome | Dependency and exit condition |
| --- | --- | --- |
| P0 | Reconcile local roadmap and propose Issue dispositions | Covered by this planning delivery; remote edits remain unselected |
| P1 | Minimal packaging maintenance (C05) | Recommended first implementation batch; independently built and installed artifacts preserve metadata, contents and runtime support |
| P2 | Reproducible 2.1.0 performance baseline (C03/C04 prerequisite) | Frozen source/tool identity and controlled samples; conclude reproduced, unconfirmed or historically incomparable |
| P3a | Investigate TLS1.2 full-handshake waiting (C03) | P2 path evidence plus authenticated Finished/timeout boundaries; make a minimal change only when justified |
| P3b | Investigate small-response/async throughput (C04) | P2 repeatable observation; test one cost hypothesis at a time and preserve cleanup semantics |
| P4 | Incremental internal typing (C06) | Actual checker diagnostics determine module batches; retain installed public-consumer acceptance |

This was the recommended sequence, subsequently selected and completed locally;
it was not an instruction to implement every optional candidate below.
P4 can be investigated alongside P2/P3 in an isolated checkout, but nothing
CPU-intensive should compete with performance measurement. P3a and P3b share
measurement resources and integrate serially; one is not a prerequisite for the
other. P1 does not require protocol changes. Optional branches below require
their concrete entry conditions, not completion of every preceding candidate.

### P0: status and Issue disposition

| Open Issue | Delivered scope | Proposed disposition if remote maintenance is selected |
| --- | --- | --- |
| [#36](https://github.com/lxjmaster/ja3requests/issues/36) | Public annotations, `py.typed`, strict installed consumers | Distinguish delivered public typing from remaining internal diagnostics; do not claim complete internal coverage |
| [#37](https://github.com/lxjmaster/ja3requests/issues/37) | Native AsyncSession/Response/pool and first-scope policy | Replace the obsolete fully-synchronous description; reconcile original acceptance with the explicit deferred APIs before closure |
| [#40](https://github.com/lxjmaster/ja3requests/issues/40) | Sync/async protocol and component benchmarks, reports | Record delivered suite; optional comparison CI is C02, not missing benchmark implementation |
| [#41](https://github.com/lxjmaster/ja3requests/issues/41) | Incremental response framing/decoding, bounded H2 queues and ownership | Replace the obsolete whole-body-buffering description; total memory also includes TLS/H2/decoder state, so an original `chunk_size`-only limit cannot be silently marked satisfied |
| [#42](https://github.com/lxjmaster/ja3requests/issues/42) | Buildable MkDocs site, API pages, guides and examples | Distinguish local site completion from unselected public hosting (C01) |

If remote maintenance is later selected, reread each current Issue, preserve
discussion, link exact release evidence and check its actual acceptance before
updating or closing it. An unmet requirement needs implementation or an explicit
scope decision; rewriting acceptance is not a substitute. No tracker is created
or changed by this plan, and remote bookkeeping does not gate P1.

### P1: minimal packaging maintenance

- Inspect [setup.py](../setup.py), [MANIFEST.in](../MANIFEST.in),
  [pyproject.toml](../pyproject.toml), and existing
  [wheel](../.github/workflows/test.yml)/[typing](../.github/workflows/typing.yml)
  checks before changing package inputs.
- Remove the legacy `PyTest`/`setuptools.command.test`, `tests_require` and their
  now-unused setup wiring. Keep direct pytest entrypoints. Do not migrate all
  metadata, rewrite package discovery, change dependencies or bump the version
  as incidental cleanup. Adjust adjacent configuration only if required.
- Acceptance: build sdist and then wheel from that sdist; inspect both inventories,
  version, runtime requirements, `Requires-Python`, licenses and `py.typed`.
  Install outside the checkout, verify import origin, run `pip check` and the
  existing wheel smoke. Run the installed consumer check described in
  [typecheck/README.md](../typecheck/README.md), not only `--allow-source`.
- Preserve source/metadata compatibility with Python >=3.7 and distinguish build
  tooling requirements. Use the existing supported-runtime gates when this batch
  is delivered remotely; current release CI does not validate a new revision.
  Exit when these gates pass, with no runtime/API expansion or release required.

### P2: controlled baseline before optimization

- Start from a frozen `2175105` source/tool snapshot, not a mutable worktree or
  the old uncommitted benchmark snapshots. Retain source and benchmark hashes,
  dependency versions, Python/OpenSSL, platform, parameters and actual import
  paths. Historical hashes alone do not reconstruct those old snapshots.
- [bench/http1_baseline.py](../bench/http1_baseline.py) prepends its own repository
  root to `sys.path`. Running it from this checkout is not evidence for a separate
  installed wheel. Use matching frozen source/tool roots and label source-based
  measurements honestly; any installed-artifact claim must verify its import.
- Remeasure 1 KiB HTTP/1 small responses; TLS1.2 full, Session ID and ticket
  handshakes; TLS1.3 controls; connection reuse; and 64 KiB sync/async H1/H2
  sequential/concurrent workloads. Repeat the 100 MiB native-async sequential
  scenario with independent samples if using it for a performance conclusion.
- Entry points: `bench/http1_baseline.py`,
  `bench/test_protocol_performance.py::{test_handshake_paths,test_transport}`,
  and `bench/test_async_performance.py::test_async_transport`. Explicitly select
  the async file: default `pytest bench` excludes it. Follow
  [sync methodology](../bench/PERFORMANCE.md) and
  [async methodology](../bench/ASYNC_PERFORMANCE.md).
- Defaults are quick probes, not stability evidence. Increase repetitions and
  requests as needed to characterize variation; declare the warmup policy.
  For candidate comparisons, use identical tooling and interleaved baseline/
  candidate runs. Separate timing, allocation tracing and profiling. Verify all
  payload bytes, negotiated protocol, resumption and connection counts; elapsed
  time alone does not establish the connection path.
- Exit with reproducible raw samples and a qualified conclusion: reproduced,
  unconfirmed, or historical comparison impossible. The latter is not proof of
  no regression. No arbitrary speed threshold or promised percentage is added;
  an evidence-backed no-code-change outcome is valid.

### P3a: TLS1.2 waiting

`Pause(0.3)` in [TLS._handshake_tls12](../ja3requests/protocol/tls/__init__.py)
affects full TLS1.2 handshakes only. The synchronous
[driver](../ja3requests/protocol/tls/_io.py) sleeps; the
[async adapter](../ja3requests/async_transport.py) only yields to its event loop.
This delay does not explain async throughput or resumed-handshake latency.

- First establish immediate, delayed/fragmented, invalid Finished, timeout and
  EOF behavior. Never send HTTP before authentication finishes.
- If evidence permits, remove only that fixed pause and retain the existing
  bounded CCS/Finished receive path. If a real prerequisite exists, wait for that
  explicit condition with a timeout, not another empirical sleep. Do not default
  to modifying the shared I/O executor.
- Minimum relevant regressions: `test/test_tls12_finished.py`,
  `test/integration/test_local_tls12_finished.py`,
  `test/integration/test_tls12_resumption.py`, and TLS1.2 cases in
  `test/test_delivery_timeouts.py`. Shared-state changes also require
  `test/integration/test_async_tls.py` and `test/test_wire_control.py`.
- Exit with preserved authentication, record/transcript, timeout/error and wire
  behavior for full/resumed paths plus controlled paired measurements. A finding
  that the current wait cannot safely be removed must retain the evidence and
  identify the actual dependency, not bypass it for speed.

### P3b: small-response and async throughput

The historical reports contain observations, not an established regression on
the released 2.1.0 artifact or a proven root cause. Synchronous controls also
varied; the retained 100 MiB runs lack repeated timing samples.

- Only after P2, profile a reproducible cost: sync policy/response iteration, or
  async task/Future/callback/read-write granularity. Change one hypothesis at a
  time; do not preselect a broad rewrite.
- Conditional source areas are `sessions.py`, `response.py`, `async_transport.py`,
  `_async_utils.py`, `async_response.py` and `protocol/h2/async_connection.py`
  under `ja3requests/`; these are investigation targets, not mandatory edits.
- Preserve close wakeups, application-task ownership, native-task reclamation,
  repeated-cancellation cleanup, Python 3.7 descriptor deregistration and H2
  committed-write ordering. Do not restore the earlier unsafe fast paths.
- Start async regressions with `test/test_async_transport.py`; add affected
  Session/Response/H2 unit and loopback tests. Verify cancellation, early close,
  stalled peers and unrelated H2 streams, then compare the same controlled load.
  Exit with a supported improvement or a documented no-change conclusion.

### P4: diagnostic-driven internal typing

- Capture actual `python -m mypy ja3requests` diagnostics in the selected
  development environment. The current strict gate covers `_typing.py`,
  `__init__.py` and `retry.py` with `follow_imports = silent`; it does not certify
  implementation-wide cleanliness. Do not invent a remaining-error count.
- Group diagnostics by dependency and choose bounded modules, prioritizing shared
  contracts before their consumers where the diagnostic evidence supports that
  order. Preserve runtime semantics and Python 3.7 imports/syntax.
- Add solved modules to the strict gate incrementally, retain valid/negative
  installed consumers, and test behavior only where changes could affect it.
  No blanket module suppression, widened `Any` or removal of negative cases to
  obtain green output. Exit each selected batch with its diagnostics resolved,
  public acceptance intact and remaining internal scope stated explicitly.

## Complete candidate map: 17-item proposal inventory

The original roadmap had 19 candidates. Source delivery and 2.1.0 publication
are complete; these are the remaining 17, not 17 mandatory implementation steps.
The subsequent execution request selected C03-C06 through P1-P4. Other candidate
rows and the four convenience APIs remain unselected; use the execution record
for progress rather than treating the proposal table as completion evidence.

| ID | Candidate / route | Entry condition and minimum acceptance |
| --- | --- | --- |
| C01 | Public docs deployment (#42), optional | Select host, URL, version policy and deployment authority; strict MkDocs build plus `python docs/verify.py`, then verify deployed routes/assets/version and rollback path |
| C02 | Performance comparison CI (#40), after P2 if selected | Choose useful comparison policy and runner; retain raw samples/variance, isolate load and start as optional reporting without invented hard speed gates |
| C03 | TLS1.2 fixed waiting, P2 -> P3a | Path-controlled latency evidence and authenticated full/resumed/fragmented-handshake acceptance |
| C04 | Small-response/async throughput, P2 -> P3b | Reproducible workload and profiling evidence; preserve ownership/cancellation, payload and connection checks |
| C05 | Legacy packaging, P1 | Small selected maintenance scope; sdist-to-wheel and independent installed acceptance |
| C06 | Internal typing (#36), P4 | Real diagnostics and selected module boundary; incremental strict checks without weakened public types |
| C07 | T07 TLS1.2 SHA-384 CBC/static-RSA suites | Name exact suite IDs and required independent peer; verify negotiation, PRF, Finished and records, without enabling legacy suites in secure defaults |
| C08 | T08 cross-process TLS session persistence | Select restart use case and secret storage; design versioning, expiry, trust binding, permissions and concurrency; test corrupt/stale state and restart resumption. Cookie persistence already exists |
| C09 | T09a H2 priority scheduling | Select fairness/latency workload; define API and starvation bounds with backpressure; test mixed streams. Parsing PRIORITY is not scheduling |
| C10 | T09b H2 server push | Select actual consumer/API; bound queued resources and cancellation, verify unsupported/disabled behavior, and do not enable before implementation |
| C11 | T10 TLS1.3 0-RTT | Select eligible operations and explicit opt-in; design replay/retry/rejection rules and test no duplicate effects. C08 is needed only for cross-process reuse |
| C12 | Browser profile updates | Name browser/version and retain fresh capture; validate supported ClientHello/H2 fields and clearly report remaining differences |
| C13 | ECH / post-quantum groups | Name required peer/browser and primitive support; separate feasibility/security/interop design, not automatic browser-profile expansion |
| C14 | Request-body streaming | Select large-upload need; define body/framing/replay ownership contract and pass slow-producer/consumer, cancellation and H2-credit acceptance below |
| C15 | HTTP/3 / QUIC | Select target and acceptable ownership/dependency boundary; feasibility and architecture decision first, then separate protocol acceptance; not an incremental H2 task |
| C16 | Additional runtime/OS/architecture/peer support | Name the environment; run installed-package and interop acceptance there, distinguishing skips or metadata from actual support evidence |
| C17 | Session-default merge compatibility | Select requests-compatibility need; define unset/None/empty, precedence/deletion and security behavior before changing defaults; see contract below |

### Optional API branch and shared architecture decisions

Four async convenience categories are additional to the 17-item map. Streaming
upload remains C14 and must not be counted again. Keep the first-version limits
in [docs/async.md](../docs/async.md) until the selected APIs are implemented.

| Item | Contract and implementation boundary | Acceptance before delivery |
| --- | --- | --- |
| A1: async file/path `files=` | `async_sessions.py::_prepare/_freeze` and `_typing.py`; choose buffered replayable convenience or C14-backed streaming first. Reuse sync input semantics, not its blocking sender; declare memory and caller-file ownership | Supported input forms, I/O failure/cancellation, file closure policy, retries/redirects and installed types/docs |
| A2: async Cookie-file helpers | Reuse `_cookie_file.py` format, permissions, atomic replacement and scope rules. Save a snapshot; validate loaded data before loop-owned commit | Corrupt files, scoped merge/replace and concurrent mutation; cancelling cannot promise to undo a completed file replacement |
| A3: public prepared request / `send()` | `_RequestMetadata` is private hook metadata, not a ready public contract. Define freezing, Cookie/TLS/proxy snapshots, resend, hooks and loop ownership; preserve synchronous send | Repeat send, mutation boundaries, authentication, cancellation and cross-loop rejection plus types/docs |
| A4: async module-level helpers | `__init__.py`, `async_sessions.py`, `async_response.py`; select eager-only helpers or an explicit session-owning stream context | Never return an unread stream after closing its session; verify normal/failed/early-close cleanup and type contract |
| C14 detail: streaming request bodies | Replace the bytes-only assumptions in `_freeze`, H1 body assembly and H2 `send_request`; define known/unknown length, H1 framing, H2 windows, write timeout, cancellation and non-replayable retry/307/308 policy | Slow producer/receiver, bounded growth as upload size grows, truncation, cancellation, ownership and unaffected neighboring H2 streams; no claim that response streaming already provides upload streaming |
| C17 detail: Session defaults | `base/__sessions.py`, `sessions.py::request`, `requests/request.py`, and async policy if selected. Define case-insensitive headers/deletion, repeated query keys, auth/proxy precedence and cross-origin stripping | Compatibility matrix for unset/None/empty/override; preserve existing behavior unless an explicit opt-in or versioned behavior change is selected |

No convenience API requires selecting all the others. Buffered A1 need not
depend on C14; true streaming A1 does. C17 is not a prerequisite for P1-P4 or
the other APIs. Update typing, migration guidance and examples with any selected
public contract. No new version number or release is preselected.

## Execution verification, parallelism and recovery

- Before a future batch, inspect current state and select its outcome. Follow
  applicable local-development guidance before running services/builds. Keep
  unrelated debug scripts, IDE files, local release records and historical data.
- Packaging and independent typing work may run in separate lanes; assign a
  single editor to shared configuration such as `pyproject.toml`. Async API
  changes share `async_sessions.py`/`_typing.py` and integrate serially. Protocol
  extensions get design/interop acceptance before implementation expands.
- Run one benchmark at a time on the measurement machine; do not build, run full
  tests or mutate its source concurrently. Separate snapshots, environments and
  report paths. A changed source/tool hash invalidates the comparison.
- Verify the smallest affected failure boundaries first. Shared TLS/H2/lifecycle
  changes require relevant sync/async tests. Before code delivery, use existing
  gates as applicable: `python -m pytest test --ignore=test/test_session.py`,
  coverage >=85%, formatting/error-level lint, public typing and independent
  artifact acceptance. Documentation changes require strict build/example
  checks when they affect the site. Do not rerun unrelated successful checks.
- Preserve immutable baseline reports and raw samples; write new reports to
  distinct task-owned paths. Close task-owned connections/tasks/threads and
  remove only verified temporary environments/certificates/staging after needed
  evidence is retained. Do not overwrite historical artifacts or user files.
- If a required check fails, fix only the selected or proven delivery-breaking
  defect; after two non-progressing attempts choose a safe alternative or state
  the real dependency. Unselected improvements do not gate a finished batch.
  Restore only task-owned experimental changes if an approach is abandoned.
- Commit/push, remote Issue updates, public site deployment and package release
  are separate action sets, not implied by a later local implementation request.
  When selected, precheck destination/artifact compatibility and read back the
  exact resulting revision or published artifact; never replace a release tag
  or package version to reuse this plan.

## Current planning-delivery checklist

- [✅] Reconcile release baseline, open Issue state and all 17 remaining candidates.
- [✅] Define recommended batches, API/protocol entry conditions, dependencies,
  architecture boundaries, verification, parallelism and cleanup/retention.
- [✅] Validate document paths/links, scope, candidate coverage and final diff;
  reconcile independent read-only plan review.
- [✅] Finish this planning outcome without claiming implementation, tests,
  registration or remote mutations occurred.

Planning outcome: **COMPLETE**. All 35 relative links across the two roadmap
documents resolve; C01-C17 and A1-A4 each occur once in their inventories.
Independent read-only review found no material scope or execution defects.
Only the two planning documents changed; no temporary resources were created.
Registration remains UNREGISTERED, with no registered close transition claimed.

This checklist tracks the completed planning deliverable only. Subsequent
selection and implementation status live in the execution record above; this
checklist does not mark that implementation done.
