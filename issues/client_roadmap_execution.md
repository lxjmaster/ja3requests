# Client roadmap execution

Selected: 2026-10-04. Status: locally complete (2026-10-04).

Evidence note: `dist/` paths below identify locally retained verification
artifacts; they are not published in the repository or distribution packages.

## Fixed outcome

Execute the agreed main roadmap: real incremental response streaming (#41),
the remaining synchronous performance suite (#40), public typing (#36), a
buildable and accurate documentation site (#42), then an asynchronous API design
(the selected design stage of #37). Complete local implementation, integration,
verification and usable delivery. Do not substitute a smaller milestone for the
whole outcome or expand conditional candidates into requirements.

Core value: the project owns ClientHello serialization, TLS handshake and
record state, HTTP/2 framing and verifiable wire/fingerprint control. No OpenSSL
client engine, Python SSL socket wrapper, alternate TLS backend, or thread
wrapper presented as native async may replace that behavior. Existing
cryptography primitives and independent SSL/OpenSSL test servers remain valid.
No cipher rewrite or generic transport/backend framework is required.

## Scope and starting state

- Preserve the local first maintenance batch and all pre-existing user changes.
  Published baseline is a291ef3 / v2.0.1; maintenance is locally verified, uncommitted.
- Implement and verify locally. Commit/PR/merge/publication remains a separately
  selectable delivery channel; this execution does not select a release version.
- T07-T10, new browser capabilities, HTTP/3, upload streaming and support-matrix
  expansion remain conditional. Preserve Python >=3.7 support and current CI.
- Async implementation follows its design and remains a subsequent selection;
  this outcome must produce a concrete design grounded in the final sync code.
- Registration: UNREGISTERED. The available codex-plan CLI reports no official
  session binding. Official goal lifecycle is tracked separately through the
  supported goal tool; no binding data is invented.

## Required work and evidence

- [✅] #41 response lifecycle: transfer connection ownership to the response;
  release exactly once after valid EOF, discard unread HTTP/1, cancel only the
  affected HTTP/2 stream. Preserve non-streaming public behavior.
- [✅] #41 HTTP/1 and project TLS1.2/1.3: incremental reads, correct length/chunked/
  close framing, no-body cases, truncation and read timeout handling, post-handshake
  messages, existing proxy paths and connection reuse.
- [✅] #41 incremental gzip/deflate/brotli and line iteration; explicit consumed
  response/cache/error semantics and bounded decoder/window memory accounting.
- [✅] #41 HTTP/2: incremental header/body API, per-stream bounded buffers,
  consumption-driven stream credit, independent slow/fast streams, cancellation,
  GOAWAY/RST/trailer/HPACK correctness without changing configured fingerprints.
- [✅] #41 request-policy integration: retries, redirects, cookies and hooks;
  no hidden retry after body delivery; release intermediate responses.
- [✅] #41 deterministic network regressions, large-body memory and first-chunk
  evidence for HTTP/HTTPS/H2; preserve wire-control/authentication regression gates.
- [✅] #40 reproducible full/resumed TLS, HTTP1/2, component and fair shared-scenario
  comparison measurements; retain raw results, environment, source identity,
  content checks and observed paths. Performance automation is optional.
- [✅] #36 public annotations, packaged py.typed, type-check configuration and
  installed external-consumer checks, including valid and invalid examples.
- [✅] #42 buildable docs site, generated API reference, guides/configuration/
  architecture/migration/examples and links matching the implementation.
  Public site deployment is optional.
- [✅] #37 design: AsyncSession/AsyncResponse, cancellation/timeouts/pools/context,
  hooks and protocol scope; reusable codecs/crypto versus synchronous I/O map;
  explicit native-async versus bridge tradeoff and failure acceptance matrix.
- [✅] Final local acceptance: relevant tests plus selected full package suite
  excluding test/test_session.py, coverage >=85%, Black/error-level Pylint,
  docs/type/benchmark checks, sdist-to-wheel and external installed consumer.
- [✅] Reconcile delegated work, verify core wire control remains project-owned,
  update actual roadmap status, clean task-owned temporary resources and retain
  evidence.

Complete the official goal through its supported tool after the final completion
record and relative-link/diff checks; file-plan registration remains UNREGISTERED.

## Final local acceptance (2026-10-04)

The required implementation and design are accepted locally. #41, #40, #36 and
#42 are implemented and verified; #37 is a completed
[design deliverable](async_api_design.md), with no async API implementation.
TLS handshake, record protection and configured wire/fingerprint control remain
project-owned. No commit, push, PR, merge, deployment or publication was performed
for this batch. The [roadmap](next_development_plan.md) lists the independent
next outcomes and their entry conditions.

The final 60-module package source has aggregate SHA-256
`5963161b9673c2004d7c551501265f0cd2c5b151bbe64b512facf7dbe65ca3dd`.
Final acceptance artifacts are under `dist/client-roadmap/final/`; earlier
reports in its parent are historical/pre-review snapshots, not this acceptance.

| Acceptance | Final evidence |
| --- | --- |
| Installed package behavior | **1624 passed, zero failures/errors/skips, 43.44 seconds**, using tests copied from the final sdist and a wheel installed outside the checkout; imports resolve to that environment's `site-packages`. JUnit report (`../dist/client-roadmap/final/installed-tests.xml`). The selected suite excludes `test/test_session.py`; one existing `TestContext` collection warning remains. |
| Coverage | **90.04%** statement coverage: 7756 of 8614 statements, above the required 85%. Coverage report (`../dist/client-roadmap/final/installed-coverage.json`). |
| Response hook ownership | A reproduced leaked-release callback was fixed. Eleven regressions cover distinct replacement chains, shared-body ownership transfer, 200/503 responses, exhaustion, invalid replacements and later hook failures without retry. [Tests](../test/test_hook_stream_ownership.py). |
| Public typing | Installed valid consumer passed; all 23 negative markers produced the expected diagnostics. Package origin and `py.typed` checked; no direct runtime `typing_extensions` import. Log (`../dist/client-roadmap/final/typing.log`), [method](../typecheck/README.md). |
| Static and compatibility checks | Package error-level Pylint, Black for the package and changed tools/tests, strict mypy for the three-file facade, Python 3.7 grammar for all 60 package modules, YAML parsing and relative-link checks passed. Package dependency check passed. |
| Documentation | Strict MkDocs build and actual loopback examples passed; 21 HTML pages, 1265 local links/assets, 12 API objects, 32 Python snippets and 12 pinned source paths checked. [Verification record](../docs/contributing_docs.md), retained site (`../dist/docs-site/index.html`). |
| Performance | Default suite: **26 passed in 31.62 seconds**, 76 measurement records and seven component benchmarks. Source/tool identity was stable. Nine HTTP large-body runs and eight TLS/H2 timing/allocation runs delivered the first chunk before the corresponding final peer send; all content/path checks passed. [Results and final raw artifacts](../bench/PERFORMANCE_RESULTS.md), [method](../bench/PERFORMANCE.md). |
| Distribution | Built sdist then wheel; all 60 package modules match the checkout and both archives byte-for-byte. Both formats contain `py.typed`, retain Python >=3.7 and `brotli>=1.2.0`, and add no runtime typing dependency. Build log (`../dist/client-roadmap/final/build.log`). |

The new batch was not run through remote CI or a new Python 3.7 runtime suite.
Syntax compatibility and prior CI do not substitute for that evidence. Public
type consumers and the selected strict facade pass; the entire internal package
is not claimed to be mypy-clean. Performance allocation figures are traced Python
allocations, not native allocations or total process RSS. The full report retains
the observed short-response throughput decrease and existing TLS1.2 300 ms wait.
The successful build retains existing `setuptools.command.test` / `tests_require`
deprecation warnings. These concrete follow-ups are listed in the roadmap.

### Retained local package artifacts

| Artifact | SHA-256 |
| --- | --- |
| ja3requests-2.0.1.tar.gz (`../dist/client-roadmap/final/packages/ja3requests-2.0.1.tar.gz`) | `be595a93a28ea2e55d6da55fb4fcb182a6d5d5c5631e23b9ba4e5c8d71cd09ae` |
| ja3requests-2.0.1-py3-none-any.whl (`../dist/client-roadmap/final/packages/ja3requests-2.0.1-py3-none-any.whl`) | `d411f8b19af89cf448353c4921d378f002ef846a21bd34f393e022e8cf506975` |

These are local development verification artifacts with unchanged version metadata,
not a replacement publication of PyPI 2.0.1. Documentation acceptance notes and
completion records were finalized after packaging; executable package inputs did
not change. No code, benchmark or docs suite rerun is needed for those record-only
edits.

### Reconciliation and cleanup

All delegated implementation, design and acceptance work is complete and file
ownership has returned to the main agent. Final independent read-only roadmap
reconciliation verified A1-A5, separated delivered history, and added the measured
short-response follow-up and explicit async API deferrals to the inventory.
Task-owned benchmark staging and test services are cleaned up. The final main
staging directory `/tmp/ja3requests-client-roadmap.dkefJG` was moved to
the local Trash directory as `ja3requests-client-roadmap.dkefJG` (absolute user path
redacted). Its original path is absent; it remains recoverable from Trash.
No documentation server is left running.

Retain `dist/client-roadmap/final/` as final local evidence, `dist/docs-site/` as the
usable local documentation deliverable, and prior baseline/release evidence as
history. Preserve the original benchmark baseline, user debug scripts, IDE files
and unrelated changes. File-plan status registration is unavailable because the
supported CLI lacks an official session binding; this does not block the verified
local outcome or the separately supported official goal transition.

## Execution contract and coordination

Main owns response framing/decoding, request/session ownership, TLS socket
integration, cross-lane acceptance and this plan. Independent lanes initially own
new real-network streaming tests, H2 multiplex implementation/tests, and bench/.
Changes to shared files require coordination. Later typing/docs work starts on
stable interfaces. Every lane has bounded local waits and no remote writes.

Streaming iteration does not retain a replay cache. Full content reads before
iteration remain cached; content access after iteration begins raises an explicit
consumed-body error. Early HTTP/1 close discards the connection. Streaming decode
errors fail explicitly. Read timeouts apply while waiting for the next bytes;
after_request runs when the requested response is available (headers for stream,
body for eager reads). iter_lines may retain one incomplete line.

Use event-controlled loopback peers on OS-assigned ports and existing private TLS
fixtures. Preserve existing benchmark baseline and release/maintenance evidence.
Store new acceptance under dist/client-roadmap/ when needed. Remove only validated
task-owned temp directories, sockets and processes; never broad workspace cleanup.
After two attempts without a narrower cause or delivery progress, switch to a
safe independent lane or identify the concrete dependency; do not add unrelated
refactors or speculative defenses.
