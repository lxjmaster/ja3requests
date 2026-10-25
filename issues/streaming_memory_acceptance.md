# Issue 41: isolated-client streaming memory acceptance

Selected on 2026-10-23 after the user continued the proposed measurement boundary.
Status: **COMPLETE / UNREGISTERED**. Required local work, independent acceptance
and cleanup are complete. The supported plan CLI lacks an official session
binding; no registration or lifecycle transition is claimed and no session
identifier is invented.

## Outcome and scope

Measure a complete **1 GB = 1,000,000,000 decoded bytes** response without
collecting the body, separating client RSS baseline/observed peak, traced Python
allocations, observable protocol/decoder state and application chunk length.
Compare with 100,000,000 decoded bytes in fresh client processes. This is the
user-selected bounded-streaming interpretation, not proof of the original
literal `all memory <= chunk_size` wording. No remote Issue mutation, commit,
push, release or public-contract change is selected.

Use the checkout at `9af4cc7032b82bea055dcd09b82d5bf8bba80f44`; preserve the
runtime library and existing benchmark baselines unless a required defect is
proven. A dedicated parent owns loopback peers and samples only its client
child PID. The child retains counters, maxima and fixed progress checkpoints,
never per-chunk records or heartbeat arrays. No public network traffic or host
trust-store changes are needed.

## Fixed measurement boundary

- Identity bodies: synchronous and native asynchronous HTTP1, TLS1.2 HTTP1,
  TLS1.3 HTTP1 and TLS1.3 H2. Plain HTTP includes a single large chunked body.
- Compression: separate sync/async HTTP1 gzip, deflate and Brotli expansion
  cases. These do not claim every codec/TLS/protocol combination was measured.
- One request, one connection, concurrency one, `chunk_size=16384`, fresh client
  process per case/size; no full-size warmup. Imports/session initialization are
  baseline; request/handshake/stream/cleanup allocations are measured.
- Require byte-content/count validation, first application chunk before the
  parent releases the peer's tail, no response cache, chunk-size enforcement,
  actual negotiated transport and all task-owned resources closed.
- Record Python-visible queue/pending/decoder state separately. These are
  observed payload lengths or explicit queue limits, not exact attribution of
  RSS/native decoder history. RSS includes tracing/observer overhead; sampled
  RSS can miss transient peaks, so retain sample count/gaps and a separately
  labeled lifetime high-water mark.
- Before large runs, freeze conservative scenario regression budgets: request
  RSS increase <=64 MiB, traced Python peak increase <=16 MiB; growth from the
  reference to 1 GB <=8 MiB RSS and <=1 MiB traced Python. They are fixed test
  budgets, not portable library guarantees or `chunk_size`-only bounds. Explicit
  protocol queue budgets and no-cache checks remain additional requirements.

## Required work and ownership

- [✅] Implement the isolated-client controller/probes and bounded gate/peer.
- [✅] Verify meaningful failure controls: cached/oversized output, exceeded
  budgets, truncated response, child failure/timeout and cleanup.
- [✅] Run small actual transport/codec smoke cases, then the fixed two-size
  matrix; retain original JSON measurements, source/tool hashes and failures.
- [✅] Independently review the measurement boundaries and reconcile results.
- [✅] Update measurement guidance, current roadmap and Issue disposition;
  remove task-owned temporary certificates/processes/installations and verify
  no runtime source or unrelated user files changed.

The main agent owns the controller, measurement runs and shared records. A
write-isolated lane owns only the new peer and its tests. Independent read-only
review checks measurement attribution, gating and evidence. A separate capable
review is retained for the final failure/cleanup boundaries.

Reports under a fresh `dist/streaming-memory/` subdirectory are deliverables;
temporary certificates and processes are removed after each run. Do not clear
historical `dist`, IDE state, debug scripts or earlier release records. Fix
required tool defects within this batch; after two non-progressing attempts,
narrow the check or identify the actual dependency. Do not enlarge budgets
after seeing results merely to obtain a pass.

## Pre-measurement evidence

- Independent peer tests: 28 passed; isolated-controller tests: 33 passed.
- Combined existing and new tooling regression suite: **206 passed in 12.82 s**.
- Black and error-level Pylint passed for the two measurement modules.
- The complete 28-case small smoke matrix (131072 / 1048576 decoded bytes)
  passed, retained at `dist/streaming-memory/smoke-01/measurement.json`.
  It predates final attribution metadata and observation-completeness checks;
  the final controller tests passed afterwards. It is not 1 GB acceptance.
- Independent read-only review found no gating implementation issue; final
  acceptance must confirm all 28 cases and 14 size comparisons, exact sizes,
  source/tool stability and successful process/thread/temporary cleanup.

## Final measurement evidence

The [original JSON](../dist/streaming-memory/acceptance-01/measurement.json)
reports **passed** for all **28 cases and 14 comparisons**, with exactly
100,000,000 and 1,000,000,000 decoded bytes, both clients and all seven paths.
It ran on 2026-10-23 from 13:25:25.898 to 13:26:48.632 UTC on macOS 15.7.7
arm64 / Python 3.13.3. Its SHA-256 is
`641230a2fe374c263931cf717889d3f5f125aba8e511407a05ce1d326a8afe79`.
See the [result table](../bench/STREAMING_MEMORY.md#accepted-local-run-2026-10-23)
for per-client/path values and measurement limits.

- Maximum request RSS increase: **10,059,776 bytes** (async Brotli, 100 MB).
- Maximum traced Python peak increase: **789,406 bytes** (async TLS 1.3 HTTP1,
  100 MB).
- Maximum cross-size growth: **2,539,520 RSS bytes** (async H2) and **407 traced
  Python bytes** (async TLS 1.2 HTTP1). All predeclared budgets were unchanged.
- Complete byte-content/count checks, gated first application chunks, no body
  caches and the 16,384-byte application bound passed for every case. Actual
  TLS/ALPN and observed protocol budgets matched the configured paths.
- RSS sampling produced 13 to 1,440 observations per case, with a largest gap
  of 0.02187733305618167 seconds. These are sampled peaks, not absolute bounds.
- All client PIDs differed from the controller; all child exit codes were zero.
  Per-case process/thread cleanup and top-level `source_stable`, `tools_stable`
  and `temporary_removed` were true.
- Independent read-only acceptance recomputed the 14 growth comparisons and
  confirmed all 73 package-module and nine tool hashes still match the report.
  No acceptance-blocking finding remained.

Both JSON reports are local retained deliverables under Git-ignored `dist`.
No library runtime source, public streaming contract, version or remote Issue
was changed. This does not establish the remote literal `chunk_size`-only
criterion or acceptance of an installed release.

## Closeout and retention

The guide's 14 numerical rows were compared directly with the retained JSON;
all matched. Local links/anchors and whitespace checks passed. The runtime
package and `docs/streaming.md` have no diff. No source or tool changed after
the accepted measurement, so the prior successful tooling tests were reused.

The dedicated `/tmp/ja3requests-memory-tests.BJHW9h` test root contained only
this batch's generated pytest fixtures. It was removed after verification and
its absence was confirmed; those fixtures are reproducible by rerunning tests.
The measurement removed its own temporary certificates/keys and child/peer
resources. Earlier peer tests used pytest's shared retention area; their
certificate fixture removed generated certificates/keys, and that shared area
was deliberately not swept. No task-owned live process or credential staging
is known to remain.

Keep `dist/streaming-memory/smoke-01/measurement.json` and
`dist/streaming-memory/acceptance-01/measurement.json` as original local evidence.
On 2026-10-25 a byte-identical
[repository evidence copy](../bench/streaming-memory-2026-10-23.json) was prepared
for the next delivery; the original reports and measured source/tools were
unchanged. See the [current sequence](next_development_plan.md#current-sequence-2026-10-25)
for that later preparation and its delivery boundary.
The subsequent ordered execution delivered the tooling/report as `90b78e1`,
verified all five workflows, and closed Issue 41 after explicitly recording the
selected replacement criterion. The original local measurement boundary and
JSON are unchanged; [the posted acceptance](https://github.com/lxjmaster/ja3requests/issues/41#issuecomment-6393601088)
records the later remote action.
Existing user debug scripts, IDE state, historical release records and other
`dist` artifacts were left untouched. No commit, push, Issue mutation, release
or deployment was performed. No required work remains for this selected local
measurement outcome.
