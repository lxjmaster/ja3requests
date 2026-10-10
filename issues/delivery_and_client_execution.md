# Delivery and client capability execution

Started: 2026-10-08. The user selected local execution of
[the corrected plan](next_delivery_and_client_plan.md).

## Required outcome

- [✅] D1 local readiness: inventory, future commit groups, compatibility notes and acceptance.
- [✅] F1: awaited Cookie files, cancellation/ownership tests, types/docs and installed acceptance.
- [✅] S1: complete [Session-default design](session_defaults_design.md); no runtime defaults change.
- [✅] U0: accepted [streaming contract and change map](streaming_upload_design.md).
- [✅] U1a: async HTTP1 streaming with installed types/docs and independent peer acceptance.
- [✅] U1b: async H2 streaming, bounded producer queues, fairness and failure isolation.
- [✅] U2: async streaming multipart/files, including framing, ownership and replay.
- [✅] U1c/U1d: synchronous HTTP1/H2 streaming and integrated selected-target acceptance.
- [✅] Final: source identity, required checks, independent review and cleanup reconciled.

Commits, pushes, merges, tags, publication, hosting and Issue writes are unselected.
The version remains unchanged. Local readiness does not claim committed delivery.
Every selected local slice is complete. Unselected remote/optional work remains
outside this completion boundary.

## Second review fixes (2026-10-08)

The user selected "fix findings" after the follow-up review. Local implementation,
regression tests and acceptance of both findings are complete. No commit,
publication or remote write is selected; earlier completed results below remain
historical evidence.

- [✅] Publish asynchronous source cancellation as a terminal request outcome;
  wake H2 header waiters and preserve stream isolation and completed responses.
- [✅] Finish started native async generators in their producer's task/context
  when upload ends early. Keep files and custom iterators borrowed, and document
  the native-generator execution/cleanup contract.
- [✅] Verify targeted cancellation/early-response boundaries, installed artifacts,
  typing and docs; independently review the changes and read back cleanup/hashes.

Parallel ownership: H2 cancellation and its tests are delegated; source/HTTP1
cleanup and documentation stay on the main lane, with independent boundary
review. Preserve unrelated work. Tests use isolated temporary directories that
are removed after execution; retain final artifacts and reports in the existing
delivery evidence root. Registration remains **UNREGISTERED**: the supported
CLI has no official session binding, and no substitute identity is supplied.

The accepted follow-up snapshot is
[`review-fixes-2/verification.json`](../dist/delivery-client-2026-10-08/review-fixes-2/verification.json).
All ten installed artifact checks passed on Python 3.13.3: **2,527 tests + 118
subtests**, **91.54% coverage**, **59 negative typing cases**, zero failures,
errors or skips, and one pre-existing TestContext collection warning. The wheel
is 222,750 bytes with SHA-256
`e71d6b0ddbd6c4cdbef8fbee7f74a757b69b6f6743ec80daba59e1979b5cdc90`; the sdist
is 475,151 bytes with SHA-256
`0820fc14ad16118674200456cfafe5446725135faa4b7012d191d91eadf2abef`.

The source cancellation fix publishes an H2 stream error and wakes header
waiters when a source raises `CancelledError`; the cancellation is propagated
without network retry and other streams continue. Started native async generators
are finalized by their producer task in its original Context, including early
responses, write/credit stops and repeated cancellation; the fresh-generator
contract is documented. Borrowed files and custom iterators remain caller-owned.

Focused checks passed 115 async HTTP/1 tests, 115 async H2 upload tests, 119
source/multipart tests and the broader selected upload suite (313 tests). Actual
Python 3.9.6 H2 upload/base tests passed 72 cases; the H1 cancellation/context
selection passed 22 cases. Black, error-level Pylint and diff hygiene passed.
The strict docs gate passed **23 pages, 1,518 local links/assets, 20 API objects,
38 Python snippets, 12 pinned source paths and all three real examples**.
The verifier staging directory and all command temporary directories were absent
after the run. The worktree remains uncommitted with no new version, push,
publication or remote CI claim.

## First review findings fixed (2026-10-08)

The user requested a new review and then explicitly selected "fix findings".
All three confirmed findings are now fixed and accepted locally:

- [✅] P1: synchronous/asynchronous HTTP1/H2 observe early responses during
  upload, retain independent source/write/flow-control progress deadlines, and
  begin the response-header wait budget after upload completion. The final H2
  END_STREAM write remains supervised even for an empty source.
- [✅] P2: each async generator runs in the same request-context producer task
  across pulls, so caller ContextVars and cross-yield token restoration survive
  normal EOF, cancellation and source deadlines. Shared connection/cleanup tasks
  retain their isolated context. A source that catches deadline cancellation
  cannot overwrite the recorded Timeout by attempting another write.
- [✅] P2: automatic lengths are restricted to plain binary files and standard
  BytesIO. Gzip and other wrappers keep an unknown output length and their
  seekable initial offset; explicit Content-Length is checked against produced
  bytes. No seek-to-end scan or eager decompression is used for wrappers.

The final accepted snapshot is
[`review-fixes-1/verification.json`](../dist/delivery-client-2026-10-08/review-fixes-1/verification.json).
All ten artifact checks passed on Python 3.13.3: **2,503 installed tests + 118
subtests**, **91.51% coverage**, **59 negative typing cases**, zero failures,
errors or skips. The suite has 53 more passing cases than the initial upload
acceptance. The existing TestContext collection warning and manual-session-test
exclusion remain explicit in the report. This is still an uncommitted worktree
snapshot based on `07c70955fc35c981867eed029c897e7ba6f8cf1c`, with no new version,
commit, push, publication or remote CI claim.

Focused acceptance included 100 source/multipart tests, 119 synchronous upload
and TLS tests, and 70 async H2 unit/network tests. Independent HTTP1 review ran
21 boundary cases. Actual Python 3.9 acceptance covered 61 H2 unit tests and 12
HTTP1 progress/context/cancellation cases; this does not claim its TLS runtime
matrix passed. Python 3.7 grammar passed; no local 3.7 runtime was available.
Strict mypy passed seven modules; all 14 changed Python files passed Black, and
all seven changed runtime modules passed error-level Pylint. The unchanged
verifier tool regression evidence remains applicable.

Updated docs and changelog describe the fixed timeout, context and length rules.
The strict docs gate passed **23 pages, 1,518 local links/assets, 20 API objects,
38 Python snippets, 12 pinned paths and all three real examples**. Keep
`review-fixes-docs/` and
[`review-fixes-docs-logs/`](../dist/delivery-client-2026-10-08/review-fixes-docs-logs/)
as local evidence. Source/artifact hashes and the 295-file manifest were read
back; only the three completion records are changed after this snapshot.
The verifier staging directory and all ten command temporary directories are
confirmed absent. Targeted checks used isolated TemporaryDirectory basetemps,
removed and read back after execution. Earlier candidates are historical evidence.

## Initial upload acceptance (before the follow-up review)

The initial accepted worktree snapshot was
[`final-candidate-3/verification.json`](../dist/delivery-client-2026-10-08/final-candidate-3/verification.json).
Its 295-file source manifest is based on HEAD
`07c70955fc35c981867eed029c897e7ba6f8cf1c`; this is uncommitted source acceptance,
not acceptance of that base commit or publication of a new 2.1.1 release.
The report records both artifact SHA-256 values/sizes and 72 package-module hashes.

All ten pipeline checks passed on Python 3.13.3: source-distribution-to-wheel
build, strict metadata, isolated environment/install, dependencies, installed
origin/hash/security/H2 smoke, dependency/tool inventories, installed typing and
the installed suite. Results: **2,450 passed + 118 subtests**, zero failures,
errors or skips, **91.53% coverage**, and **59 negative typing cases**. The one
pre-existing `TestContext` collection warning remains visible in the report.
The manual `test/test_session.py` scenarios retain their documented exclusion.

The first `final-candidate/` failed four existing local SOCKS tests because their
minimal context has `message` but no `data`. The streaming dispatch now uses
`getattr(context, 'data', None)` and preserves the existing buffered branch.
The focused SOCKS/sync-upload suite passed 71 tests, Black and error-level Pylint.
`final-candidate-2/` then passed the complete installed gate. Independent readback
found two docs instructions still describing two examples after the third was
added; those counts were corrected, the docs gate was rerun, and
`final-candidate-3/` accepted the final document bytes. The failed report stays
failed; the earlier passing snapshots are retained as historical evidence.

Final strict documentation build and verification logs are retained under
[`final-docs-logs/`](../dist/delivery-client-2026-10-08/final-docs-logs/), with the
site in `final-docs/`: **23 HTML pages, 1,518 local links/assets, 20 API objects,
38 Python snippets and 12 pinned source paths**. All three real examples passed:
loopback, native async (including Cookie-file round trips), and sync/async upload
plus multipart. The upload example owns its pool and removes its temporary file.

The unchanged strict mypy gate (7 modules), verifier regressions (72 tests),
changed-source error-level Pylint and final Black check (86 files) passed before
artifact acceptance; the affected SOCKS formatting/lint checks passed again after
its fix. Actual Python 3.11 feature regression passed **292 tests**; actual Python
3.9 new/old async H2 regression passed **54 tests**. The system 3.9 network fixture
could not initialize on LibreSSL 2.8.3, so no 3.9 network pass is claimed. Python
3.7 grammar passed in the verifier; its runtime matrix was not run locally.

## Implemented contracts and independent review

F1 provides awaited Cookie-file helpers with detached parse/save state, atomic
replacement, loop-owned jar updates, serialized file helpers, cancellation and
close cleanup. Two additional event-controlled live Set-Cookie concurrency tests
bring the final Cookie-file module to 48 cases; the earlier F1-only snapshot below
is historical.

U1 extends `data=` with binary files and byte iterators, plus async byte iterators
on AsyncSession. Both clients now stream over HTTP1/H2 with length validation,
unknown-length HTTP1 chunking, H2 windows and bounded producer queues. Existing
buffered forms/JSON and synchronous redirect behavior are retained. U2 implements
async streaming multipart/files with stable retry boundaries, lazy path opening,
library-owned handle cleanup and caller-owned handle preservation. Public typing,
examples and transport/replay/ownership documentation accompany these surfaces.

Independent review verified and drove fixes for source ownership across response
transfer, module-helper streaming lifetime, retry/redirect replay, complete early
H2 responses, source failure isolation, zero-credit EOF, and repeated cancellation
on Python 3.9. The cancellation path now joins the pending source task even when
cancellation repeats. Sync H2 has a connection-owned write deadline watcher that
is stopped/joined during cleanup; a real stopped-reader peer verified blocked
write timeout. Empty iterator chunks neither reset the source deadline nor
prevent close. The last independent sync boundary checks passed 9 tests.

Borrowed files/generators remain caller-owned. Cancellation can wait for a current
blocking `read`/`next` to return. File buffering is independent of total file size;
iterator buffering also includes the largest caller-produced chunk and active
upload count. No 64 KiB process-memory or instant-cancellation guarantee is made.
S1 delivered the semantics matrix and explicit opt-in headers/params proposal;
Session defaults were not changed at runtime.

## Initial upload cleanup and retention

Actual filesystem readback confirmed all four candidate staging directories and
all 40 command temporary directories are absent. Artifact/report hashes were
read back independently. Retain the candidate reports/artifacts, source manifests,
coverage/XML/logs, docs snapshots and final docs logs under
`dist/delivery-client-2026-10-08/` as delivery and diagnostic evidence. Existing
IDE/debug files, older release records and unrelated work remain preserved.
That acceptance readback compared all 295 snapshot entries: 292 files matched;
only the three plan/roadmap/completion records changed after acceptance. All 72
module hashes matched, as did implementation, tests, docs and tooling. All 39
local links in those three records resolve, and diff hygiene passed.

## F1 local acceptance

The frozen `f1-candidate/verification.json` under the evidence root passed all ten
commands on Python 3.13.3: 2,204 installed tests + 118 subtests, zero failures/errors/
skips, 91.12% coverage and 51 installed negative typing cases. The new Cookie test
file contains 46 cases; affected source regressions passed 249 tests. Independent
review found and verified a fix for recursive Cookie copying: only shallow Cookie
state and an independent extension dictionary are copied; ignored records and
invalid metadata retain the shared format's filtering/error behavior.

Strict mypy (7 modules), changed-source error-level Pylint, Black and diff hygiene
passed. Full-history docs checks passed: 23 pages, 1,501 links/assets, 20 API
objects, 35 snippets, 12 pinned paths and both real loopback examples, including
the new awaited Cookie round trip. `f1-docs/` is retained. The verifier records
staging cleanup; source manifests/artifact hashes identify F1 before upload work.
Python 3.7 grammar was checked; no new Python 3.7 runtime or remote CI is claimed.

Registration: **UNREGISTERED**. A fresh `codex-plan --json status` failed because
no official session binding was available. No identity was invented and no
registration success is claimed. This did not prevent the completed local
acceptance; the official product goal uses its separate supported lifecycle.

## Baseline and inventory

HEAD: `07c70955fc35c981867eed029c897e7ba6f8cf1c`. Historical acceptance under
`dist/post-2.1.1/final-review-2026-10-06/` reports 2,158 tests + 118 subtests,
91.08% coverage. The preceding review compared all 277 snapshot entries: only the
roadmap and two completion records changed. This does not accept the new features.

Pre-existing deliverables: `.github/workflows/test.yml`, new
`.github/workflows/docs.yml`, `docs/async.md`, `docs/contributing_docs.md`,
`docs/proxies.md`, `ja3requests/protocol/h2/async_connection.py`,
`ja3requests/protocol/h2/hpack.py`, `pyproject.toml`, `test/test_async_h2.py`,
`test/test_h2.py`, `typecheck/{README.md,valid.py,invalid.py}`,
`tools/{verify_release.py,README.md,tests/test_verify_release.py}` and linked
engineering plans/records. New feature files extend this inventory explicitly.
Preserve root debug scripts, IDE files, old release records and prior artifacts.

Future commit groups: verifier/tests/guide plus workflow/docs integration; HPACK
and async admission fixes with tests/types/compatibility notes; independent client
feature slices with tests/types/docs; design/execution records. Inspect dependency
closure and include referenced new files before any later authorized commits.

## Ownership, checks and recovery

Parallel lanes own disjoint files: F1 runtime/tests, S1 design, U0 design. The
integrator owns shared plans, changelog, public docs, typing and final acceptance.
Assign later protocol work only after agreeing interfaces and inspecting results.

Use the existing `.venv`, selected pytest tests and artifact verifier. Each public
slice includes types, runnable examples and installed acceptance. Final gates:
installed suite excluding manual `test/test_session.py`, >=85% coverage, strict
typing, Black, error-level Pylint, verifier tests and full-history docs checks.
Keep Python >=3.7; grammar and actual runtime results are distinct evidence.

Retain evidence under fresh `dist/delivery-client-2026-10-08/` subdirectories.
Remove only task-created fixtures/staging after retaining reports; do not overwrite
old evidence. Cancellation/close must leave no late jar mutation, source worker
or connection/stream leak. Use affected checks during iteration and full acceptance
for stable integration. After two attempts without progress, narrow the cause or
use a safe alternative; only actual dependencies justify blocking.
