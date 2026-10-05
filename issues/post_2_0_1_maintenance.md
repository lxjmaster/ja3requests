# Post-2.0.1 maintenance and measurement

Selected: 2026-10-04, following the user's instruction to start the agreed
development sequence. This first delivery batch covers roadmap items 1-3:
retry exhaustion, current documentation, and a small performance baseline.
The subsequent streaming, typing/documentation and asynchronous-design batches
remain in the [roadmap](next_development_plan.md).

Status: completed locally on 2026-10-04. All acceptance items below passed.
No commit, remote delivery or publication was performed for this batch.

Evidence note: `dist/` paths below identify locally retained verification
artifacts; they are not published in the repository or distribution packages.

Registration: UNREGISTERED. `codex-plan --json status` cannot obtain an official
session binding. Do not invent a session identity; retain this file and continue
the authorized local work.

## Outcome and boundary

- Honor `HTTPRetry.raise_on_status` when a retryable response exhausts the
  configured attempts, without changing successful or non-retryable requests.
- Make the current user documentation and roadmap agree with the published
  2.0.1 capabilities and evidence. Preserve dated historical verification.
- Supply a reproducible, loopback-only baseline for first-chunk delivery,
  Python allocation peaks and pooled request throughput before streaming work.
- Deliver reviewed local source, tests, documentation and benchmark results.
  This batch does not include a version bump, commit, push, PR, release, package
  publication, full documentation site or asynchronous client implementation.
- Preserve all pre-existing debug scripts, IDE files, release records, artifacts
  and other worktrees. No shared services or host trust stores are changed.

Baseline: `a291ef30bb6ae53cf38b3d79604c8f34e1865547` (`master`, `v2.0.1`).
The prior analysis verified the published artifact hashes, 59 matching package
source hashes, ten successful master CI checks, and the installed-wheel result
of 1517 tests plus 112 subtests with 89.09% statement coverage. These describe
the released baseline, not acceptance of the changes in this batch.

## Required work and acceptance

- [✅] Add meaningful retry exhaustion regressions and observe the original
  failure. Cover the exception switch, exact attempt count, recovery before
  exhaustion, non-retryable methods/statuses and zero retries.
- [✅] Fix the demonstrated control-flow defect. Preserve response hooks and
  Session response/cookie visibility; verify related retry/Session/hook paths.
- [✅] Align English/Chinese guidance, P-384 opt-in, secure defaults, supported
  browser subsets, release status and the roadmap. Historical records keep
  their original dates, test counts and environment limitations.
- [✅] Implement the loopback benchmark with finite socket/thread waits and
  dedicated pools. Record environment, source identity, parameters, raw samples,
  body integrity and actual accepted-connection counts. Clearly distinguish
  Python allocations from process RSS and current buffering from true streaming.
- [✅] Run the benchmark and retain reproducible results. Check only the relevant
  documented invocations and parameter failure boundaries.
- [✅] Run the selected package suite (excluding `test/test_session.py`) with
  coverage >=85%, Black, error-level Pylint, changed-document link checks and
  diff checks. Review the combined changes and reconcile delegated work.
- [✅] Record final evidence and leave no task-owned server/thread or temporary
  workspace running. Retain benchmark results and task evidence, then close
  this batch accurately. Do not claim the remaining roadmap is implemented.

## Coordination, recovery and retention

The main agent owns retry behavior, regressions, changelog, roadmap, this plan
and final acceptance. One independent lane owns the six selected current/status
documents; another owns `bench/`. Their write sets are disjoint. The main agent
reviews all changes; tests run after relevant source inputs stabilize.

Benchmarks bind only to `127.0.0.1` on OS-assigned ports and create isolated
`ConnectionPool` instances. Tests use existing bounded local fixtures. No
outbound requests or user credentials are required. Preserve the current tree
on failure, identify the failing input, and retry only while evidence advances.
Remove only verified task-owned temporary resources, never broad `dist/` or
workspace cleanup. Retain source deliverables, recorded benchmark samples and
scoped validation evidence under `dist/post-2.0.1-maintenance/` if needed.

## Recorded implementation evidence

- The initial 13 loopback retry cases reproduced four missing-exception
  failures before the fix. Independent review then found that a configured
  retryable 302 could redirect successfully to 200 and still raise; two added
  regression cases reproduced that failure. The final implementation rechecks
  the final response status. All 19 new cases and 77 existing related cases
  passed together (96 passed), including redirects enabled/disabled, zero
  retries, response hooks and Cookie retention. Existing connection-error
  propagation was independently checked without changing its behavior.
- The six delegated documentation files passed relative-link checks (38 paths
  and one heading anchor) and diff checks. Current guidance is separated from
  the dated release/implementation snapshots; no historic test count is changed.
- [Benchmark results](../bench/RESULTS.md) and
  [raw samples](../bench/baseline-current.json) retain six size/latency/memory
  samples and three sequential-throughput samples. All payload checks passed;
  all 59 package hashes and the benchmark script hash match the final source.
  The package aggregate SHA-256 is
  `fec7786a072a0f26dbb729ed1d08d7e51866cc861fa9c44184f01aef54cf98e5`.
- The 1/8 MiB samples had median first-chunk times of 51.66/370.94 ms and median
  Python allocation peaks of 1,209,756/8,549,700 bytes. Every first chunk arrived
  after the final peer send completed. Each throughput sample used one observed
  TCP connection for 30 requests; the median was 4,503.21 requests/second.
  These are descriptive local HTTP/1.1 measurements with deliberate send gaps,
  not universal throughput or RSS claims. Two task-owned interim reports were
  replaced by the final-source report and removed.
- Black and error-level Pylint passed for the package and benchmark. The new
  regression file also passes Black. Combined diff checks and current-plan /
  benchmark relative links passed. Independent review's redirect finding is
  fixed and covered by the final suite; no blocking review finding remains.

## Final local acceptance

The selected source-checkout suite passed **1536 tests**, with **zero failures,
errors or skips**, and **89.57%** statement coverage (7360/8217). It includes all
19 new retry regressions. The existing `TestContext` collection warning remains.
This run used the project's existing `.venv`: CPython 3.13.3 on macOS arm64,
pytest 8.4.1, cryptography 45.0.5 and brotli 1.1.0. It is not a new installed-wheel
or remote-CI result and does not alter the dated 2.0.1 release evidence.

Command (the task-owned pytest base directory was removed after verification):

```sh
COVERAGE_FILE=dist/post-2.0.1-maintenance/.coverage .venv/bin/python -m pytest test --ignore=test/test_session.py --basetemp=/tmp/ja3requests-maintenance.tZpEHA/pytest --cov=ja3requests --cov-report=term --cov-report=json:dist/post-2.0.1-maintenance/coverage.json --cov-fail-under=85 --junitxml=dist/post-2.0.1-maintenance/tests.xml -q
```

Retained: `dist/post-2.0.1-maintenance/pytest.log`, `tests.xml`, `coverage.json`
and coverage data, plus the four `bench/` deliverables. Cleanup removed only
`/tmp/ja3requests-maintenance.tZpEHA` (2.0 MB, 60 generated test files); its absence
was verified. Benchmark-owned sockets, pools and threads exited before its
successful result was written. All pre-existing user files and release artifacts
remain. Plan registration remains UNREGISTERED because the official session
binding is unavailable; this file records completion without inventing a registry
transition.

Next: roadmap item 4, incremental streaming. Start with response body reading and
connection ownership for HTTP/1.1/TLS, then incremental decompression and bounded
HTTP/2 flow control. The measured full buffering remains unchanged by this batch.
