# Native async implementation

Selected: 2026-10-04. Status: complete at the authorized local-delivery boundary.

Evidence note: `dist/` paths below identify locally retained verification
artifacts; they are not published in the repository or distribution packages.

## Fixed outcome and authorization

Implement and locally verify A1-A5 from [the accepted design](async_api_design.md).
Export usable native `AsyncSession`, `AsyncResponse` and `AsyncConnectionPool`.
The project retains its TLS handshake, authentication, record protection,
resumption, ClientHello and HTTP/2 wire control. Share existing protocol state
and crypto with native asynchronous I/O; do not replace them with another TLS
client, thread-wrapped synchronous requests or a generic backend framework.

Preserve the completed, uncommitted synchronous batch and unrelated user files.
Keep Python >=3.7. This outcome includes local implementation, integration,
necessary tests, public typing, docs, reproducible performance evidence and
installed-package acceptance. No commit, push, remote PR/merge, deployment or
publication is selected. The 19 independent roadmap candidates and deferred
async convenience/file APIs remain outside this batch.

Registration: UNREGISTERED. `codex-plan --json status` cannot obtain an official
session binding. Do not invent an ID; continue the authorized local work. The
preceding completed official goal belongs to the synchronous outcome.

## Required work

- [✅] A1: shared TLS state and native TCP/TLS I/O; full/resumed TLS1.2/1.3,
  verification/client authentication, configured wire identity, fragmented
  input, pending bytes and cancellation-safe transport cleanup.
- [✅] A2: asynchronous HTTP/1 parsing and body decoding, AsyncResponse APIs,
  bounded incremental reads, strict decoding, one-consumer/cache semantics,
  correct EOF/trailer handling, early close, timeout and cancellation.
- [✅] A3: session/pool lifetime, loop affinity, borrowed-pool isolation,
  creation/admission cancellation, per-attempt budgets, request metadata,
  retry/redirect/hooks/cookies and existing CONNECT/SOCKS4a/5 paths.
- [✅] A4: native H2 reader/writer, bounded buffers/windows, independent streams,
  peer capacity, cancellation/reset, GOAWAY, HPACK/TLS committed-write ordering,
  and shutdown without waiting for application draining or peer EOF.
- [✅] A5: meaningful failure-boundary and responsiveness regressions, public
  installed typing, runnable docs and fair async performance/memory evidence.
- [✅] Final acceptance: selected full suite excluding test/test_session.py,
  >=85% statement coverage, Black/error-level Pylint, compatible Python syntax,
  strict docs/types and sdist-to-wheel installed-origin validation. Record
  actual runtime support evidence without treating syntax as runtime proof.
- [✅] Reconcile independent work and review core shared-state/cancellation
  boundaries. Update roadmap/design status, retain final evidence, and clean
  only validated task-owned staging/servers/processes.

## Final local acceptance (2026-10-04)

The package exports native `AsyncSession`, `AsyncResponse` and
`AsyncConnectionPool`. Shared TLS transitions and codecs retain the project's
authentication, resumption, ClientHello and record control; native HTTP/1 and
HTTP/2 own their asynchronous I/O, response leases and stream cancellation.
See the [async guide](../docs/async.md), [API](../docs/api/async.md),
[runnable example](../docs/examples/async_client.py) and
[performance report](../bench/ASYNC_PERFORMANCE.md).

All 68 package modules share aggregate SHA-256
`7c6ccaa85405c9f8e8444f2aa83dc190e394aade8669c64c2535c87ade17dca6` across
the checkout, sdist, wheel, installed Python 3.13 package and final measurements.
The source aggregate hashes sorted relative module paths and their SHA-256
digests; it is not the dirty worktree's Git HEAD or the archive hash.

| Acceptance | Evidence |
| --- | --- |
| Final installed suite, Python 3.13.3 | **1847 tests and 112 subtests passed**, zero failures/errors/skips, 44.77 seconds. Tests were copied from the final sdist outside the checkout and imported the installed wheel. Excludes legacy manual `test/test_session.py`; one existing `TestContext` collection warning remains. JUnit (`../dist/async-client/installed-tests.xml`), log (`../dist/async-client/installed-tests.log`). |
| Statement coverage | **90.45%**, 9394 of 10386 statements, above 85%. JSON (`../dist/async-client/installed-coverage.json`), XML (`../dist/async-client/installed-coverage.xml`); raw data retained as `installed.coverage`. |
| Additional actual runtimes | Python **3.11.12/OpenSSL 3.0.16**: all **223 async tests passed** against the final wheel. System **3.9.6/LibreSSL 2.8.3**: all **23 transport tests passed** against the final wheel. 3.11 report (`../dist/async-client/installed-tests-py311.xml`), 3.9 transport report (`../dist/async-client/installed-transport-py39.xml`). |
| Public types | Valid installed consumer passed; all **36 negative diagnostics** matched. `py.typed` and no direct runtime `typing_extensions` import verified. Strict three-file facade check passed. Consumer log (`../dist/async-client/typing.log`). |
| Static/package checks | Black checked 84 package/tool/test/example files; error-level Pylint passed for the package; all 68 package modules parsed with Python 3.7 grammar; dependency and whitespace checks passed. Artifact verification (`../dist/async-client/artifacts.json`), method (`../dist/async-client/verify_artifacts.py`). |
| Docs | Strict build and both actual loopback examples passed: 23 HTML pages, 1483 links/assets, 18 API objects, 34 Python snippets and 12 pinned source paths. Build log (`../dist/async-client/docs-build.log`), verification (`../dist/async-client/docs-verify.log`). |
| Performance/streaming | Final 16 comparison cases and four 100 MiB cases passed, with **72 records**, stable source/tools, verified payload and first chunk before final peer send for the large bodies. Python allocation peaks were 170868–260200 bytes in these four fixtures, not RSS or a universal bound. Raw comparison (`../dist/async-client/performance.json`), large bodies (`../dist/async-client/large-async.json`). Native async is slower in several measured workloads; the report retains the limits and the pre-fix comparison. |

The machine-readable acceptance (`../dist/async-client/verification.json`) and
installed origin/dependencies (`../dist/async-client/installed-origin.json`)
retain the exact local environment. The final installed suite used
`cryptography 50.0.2` and `brotli 1.2.0`; benchmark reports separately retain their
own dependency versions. Dependency compatibility passed without a new library
runtime dependency. Python metadata stays `>=3.7`.

### Distribution and boundaries

The wheel was built through the source distribution, then installed outside the
checkout. Both archives contain `py.typed` and all 68 matching package modules.
They retain metadata version 2.0.1 solely for this local development check;
they are not the published 2.0.1 artifacts and must not be presented as a release.

| Local artifact | SHA-256 |
| --- | --- |
| ja3requests-2.0.1.tar.gz (`../dist/async-client/packages/ja3requests-2.0.1.tar.gz`) | `283f456fa2080fbc6ff775039846e933a1b051e6f68bc82fa0235c1f8226d2f5` |
| ja3requests-2.0.1-py3-none-any.whl (`../dist/async-client/packages/ja3requests-2.0.1-py3-none-any.whl`) | `37d888fcd0dbe068d7b2b6b8ed856706cb31db68d2f06bd93b07c13a7b2d2e78` |

Existing setuptools `command.test` / `tests_require` deprecation warnings
remain; the build succeeded. Their independent packaging-maintenance candidate
does not gate this local delivery. There was no commit, push, PR/merge,
publication, website deployment or newly triggered remote CI.

### Verified fixes and runtime limits

Independent ownership review contributed 12 regressions for dropped responses
in borrowed pools, response replacement/eager consumption, reentrant hooks,
application-task isolation, creation races, repeated close cancellation and
collection of completed cached responses. CONNECT protocol rejection is not
retried as a transient network error. One formatted type-test marker was moved
to the actual diagnostic line; the public type contract did not change.

The extra system Python 3.9 probe initially reported 172 passed / 47 failed.
Its **one confirmed async defect** was a pending native read not awakened by
transport close. The former test swallowed its check's TimeoutError on newer
Python. The implementation now explicitly wakes waiters, cancels only its own
native I/O tasks, observes close/caller-cancellation races, and supervises cleanup.
Regression timeouts can no longer pass as ordinary OSError. The final reports
above include the fixed source and four additional regression cases.

The other 46 failures in that probe describe an unvalidated environment:
30 failed while configuring TLS1.3 peers unsupported by LibreSSL 2.8.3;
14 failed because those peers reject the OpenSSL SECLEVEL cipher configuration;
two failed certificate path validation, reproduced in the existing synchronous
KeyUpdate test before application traffic. Original probe (`../dist/async-client/installed-tests-py39.xml`),
synchronous certificate comparison (`../dist/async-client/py39-sync-ca-probe.log`).
No skips were added to hide these failures. Full TLS compatibility for this
system Python environment is not established; an environment-specific follow-up
requires selection. Python 3.11/3.13 have the actual async TLS acceptance above.

Python **3.7 was not available locally**; syntax checking is not runtime proof.
The existing Python 3.7–3.13 CI matrix remains for an authorized remote source
delivery. This outcome is local implementation and acceptance, not a claim of
new remote CI, every Python/OpenSSL combination, or publication readiness.

### Retention and cleanup

Retain `dist/async-client/` for final reports/artifacts and superseded evidence,
and `dist/docs-site/` for the usable local site. The original 1843-test / 90.44%
snapshot and performance records live under `pre-close-fix/`; they are explicitly
superseded by the final source. Preserve prior `dist/client-roadmap/` and release
evidence, all unrelated changes, debug scripts and IDE files.

The task-created `/private/tmp/ja3requests-async.fEFmRT` build, extracted test and
three-runtime installation environments were moved to Trash after retaining
results; their original path is absent. No task process referenced the directory
at cleanup. Moving to Trash is recoverable and is not a claim of reclaimed disk
space. Test peers and examples completed their normal teardown; no local preview
service was left running. The benchmark lane removed its validated, empty
`/tmp/ja3requests-async-perf-final.KFsEVH` staging after retaining all reports.
All delegated implementation, independent review, docs and performance work was
reconciled. File-plan registration remains UNREGISTERED because the CLI still
cannot obtain an official session binding; no registered transition or new
official goal completion is claimed.

## Ownership, verification and recovery

Main owns async_sessions.py, async_pool.py, exports, cross-lane integration,
request policy tests, documentation/types and final acceptance. Parallel lanes
own TLS/native transport, response framing/decoding, and native H2 respectively;
coordinate any shared-file changes before editing. TLS and H2 wire/cancellation
boundaries receive independent main-agent review. Reuse existing independent
local peers, OS-assigned ports and private ephemeral certificate fixtures.

Use tests appropriate to the changed behavior, then complete the required final
checks on stable source. Keep evidence under dist/async-client/ and retain prior
dist/client-roadmap/ and release evidence. Create staging with mktemp; remove
only task-created resources after retaining results. Preserve user edits,
debug scripts, IDE files and shared infrastructure. No broad workspace cleanup.

After two attempts without narrowing a cause or advancing delivery, switch to
an independent required lane or identify the precise blocker. Fix necessary
change-caused defects, then return to A1-A5; do not expand into speculative
optimizations or unrelated protocol extensions.
