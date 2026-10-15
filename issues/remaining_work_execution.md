# Selected remaining-work execution

Started: 2026-10-13. Completed: 2026-10-13. Status: **COMPLETE**.

Post-review source corrections completed: 2026-10-13. See
[the correction evidence](#post-review-source-corrections) for the current source.
The installed candidate and independent H2 reports below retain their original
snapshot identities and predate these corrections; they are historical evidence.

The user authorized execution of the corrected remaining-work plan. The fixed
outcome is R (synchronous 307/308 method/body preservation), H1 (per-request
HEADERS weight/exclusive with dependency 0), H2 (HPACK literal-insertion exclusions),
and final local artifact acceptance for each batch. Conditional TLS additions,
F3, C17, prepared streaming and the long-term register remain unselected.
No commit, push, release, deployment or remote Issue writes are authorized.

Follow [the solution](post_2_3_0_remaining_work_plan.md). Incorporate its final
review corrections: accept R's documented default change under this implementation
instruction and choose the actual version during a separately authorized
publication; use a modern independent installed-wheel H2 probe without Chrome
or adding capture dependencies to library runtime.

Preserve existing Huffman/F1 work, the four transport fixes, historical artifacts,
user debug scripts and unrelated tracked/untracked edits. Work serially without
subagents. Registration remains UNREGISTERED: supported plan status reports no
official session binding; no replacement identity is invented.

## Required work and evidence

- [✅] R: implement 307/308 method and encoded-body/source preservation, current-hop
  policy, post-hook replay decisions and deterministic ownership/cleanup.
- [✅] R: verify buffered and streamed HTTP1/H2, mixed-status/multi-hop redirects,
  source replacement/errors, retries and unchanged 301/302/303/disabled behavior.
- [✅] R: migration/docs, relevant quality/type gates, full source regressions and
  frozen-source installed artifact acceptance.
- [✅] H1: implement request-scoped weight/exclusive metadata in sync, native
  async, prepared and upload paths; dependency 0, exact splitting and pre-I/O validation.
- [✅] H2: implement copied indexing exclusions in shared HPACK/connection policy;
  preserve sensitive literals, default bytes and dynamic table reuse.
- [✅] H1/H2: verify bytes, pool boundaries, hook/retry/redirect snapshots,
  continuations, invalid-input isolation and cancellation/write boundaries.
- [✅] H1/H2: independent received-byte probe of the final installed wheel,
  authenticated sync/async requests and declared retained browser vectors.
- [✅] H1/H2: final source/install tests, quality/type/docs/examples and compatibility
  evidence; retain reports/artifacts and complete cleanup/readback.

Each acceptance identifies its source snapshot, commands, environments,
counts/skips/warnings, wheel/sdist hashes and installed origins. Source-only
results and Python 3.7 grammar do not prove installed or 3.7 runtime behavior.
Reuse tools/verify_release.py and existing peers/encoders. Use reviewed --include
files for feature-owned untracked inputs; do not add a release framework.
Retain final reports, artifacts and this record. Remove only verified task-owned
temporary build/install roots, listeners, producers and certificate staging.
An unavailable conditional peer does not change these selected goals.

## Intermediate evidence (historical)

- R focused replay/ownership suite: 118 passed after correcting cached mutable
  JSON, redirect-construction cleanup and the misplaced early-H2 assertion.
- R initial full source suite: 3750 passed, one pre-existing TestContext
  collection warning, Python 3.13. The final combined-source verification below
  includes the later generated-length and request-hook redirect refinements.
- R installed candidate `dist/verify-remaining-r-02/verification.json`: passed;
  3660 passed, 118 successful subtests, no skips, one warning; coverage 92.4811%.
  Wheel SHA-256 `185602a4e39bb82d9e1af749e666c70678efdcbe92290b12273bf4efddd5d1dd`;
  sdist SHA-256 `808e5979cde30dd7ee3f50f37fb6732a51d5ec09c0b0bb8a794d2bbd60cdc2bc`.
  Candidate `r-01` failed on old minimal response doubles and is superseded.
  Neither candidate validates later changes; final combined acceptance below does.
- R docs: strict MkDocs, docs/verify.py and all four loopback examples passed;
  23 pages, 1546 local links/assets, 24 API objects, 39 snippets, 12 pinned paths.
  Temporary docs output was removed. Seven R files passed Python 3.7 grammar;
  this does not establish Python 3.7 runtime support.
- H1/H2 real TLS1.2/1.3 transport and existing fingerprint suite: 334 passed.
  Subsequent cancellation/fragmentation/collector suite: 77 passed. Later R,
  priority/retry/redirect/HTTP1 and tool assertions: 82 passed. These focused
  results are superseded by the final acceptance below for the combined library.

## Final acceptance

Environment: macOS, `.venv/bin/python` 3.13.3. Base commit remains
`422012063f4ed12e23bda330c38355566d6d373d` on `master`; acceptance identifies the
dirty-worktree snapshot rather than claiming HEAD includes the implementation.
The candidate retains baseline 2.3.0 metadata and is not a new publication.

Source regression command:

```sh
.venv/bin/python -m pytest -p no:cacheprovider test --ignore=test/test_session.py tools/tests -q
```

Result: **3,869 passed, one warning, 31.68 seconds**, before the final narrow
collector request-count adjustment. Afterwards the current tool suite passed
**98 tests in 7.60 seconds**, including the added explicit-path regression.
The library, its tests, documentation and type consumers did not change after
the full source run. No full-source run of 3,870 tests is claimed.
The warning is the pre-existing `TestContext` collection warning caused by its
constructor; `test/test_session.py` is the documented external-service manual test.

### Frozen-source installed candidate

[Final verification report](../dist/verify-remaining-final-01/verification.json):
**passed**. `tools/verify_release.py` froze the reviewed worktree and explicitly
included the feature-owned new files recorded in `source.explicit_new_files`.
Its retained commands/logs cover sdist-to-wheel build, metadata, isolated install,
dependency checks, installed origins and hashes, tests, coverage and consumers.

- Installed tests: **3,772 passed, 118 successful subtests, zero skips, one warning**.
- Coverage: **92.56534668962279%**, above the existing 85% gate.
- Installed valid/invalid type consumers passed with **77 negative markers**.
- At the original acceptance, all **72 library module hashes** matched that
  source snapshot, installed package and independent H2 probe. The source-file
  set was also compared, not only
  individual hashes. Wheel and sdist hashes were re-read from the actual files.
- `staging_cleaned` and every command's `temporary_cleaned` are true; the retained
  staging path is absent on readback.

[Wheel](../dist/verify-remaining-final-01/artifacts/ja3requests-2.3.0-py3-none-any.whl)
SHA-256: `411e0abb75b6b76c5397ba0525b8c5cfc0f3bfb5bd463f9f4594ee00caa30a62`.
[Sdist](../dist/verify-remaining-final-01/artifacts/ja3requests-2.3.0.tar.gz)
SHA-256: `427876af2c562bd5a57a2bc1d6e89446da340776964a3f4ef7871d0a0802ea32`.

### Independent installed-wheel H2 evidence

[H2 verification report](../dist/verify-remaining-h2-02/verification.json):
**eight cases passed**, using `tools.verify_h2_controls` with the exact wheel,
its SHA-256, the final artifact report and explicit client profile `chrome:154`.
The independent server uses Python ssl/OpenSSL; both clients use the installed
project TLS engine and verify the task-owned CA.

The eight cases cover sync/native async, raw/Huffman and empty/`:path` exclusion
policies. Each completes three authenticated TLS1.3/H2 responses on streams
1/3/5. Independent frame/HPACK evidence records dependency 0, weights 256/183,
exclusivity, absence on the third request, path representation and dynamic-table
continuity. Excluding the new path retains 20 rather than 21 table entries after
request two, matching the retained Chrome 155/macOS vectors for these fields.
All 24 response body hashes, raw traffic hashes, installed origins/module hashes,
peer termination and process cleanup were read back successfully.

No new Chrome samples, complete Chrome identity, anti-bot result or randomized
distribution is claimed. TLS1.2 evidence comes from the installed integration
tests; this independent collector's scope is full non-resumed TLS1.3/H2.

The final release snapshot predates the tool-only request-count adjustment.
At evidence readback before completion-record updates, exactly three current
files differed from its `source.files`:
`tools/capture_fingerprint.py`, `tools/verify_h2_controls.py` and
`tools/tests/test_h2_controls_verifier.py`. The existing collector still defaults
to its two legacy paths; the H2 tool explicitly requests three. The successful
H2 report retains and hashes the adjusted tool sources separately and binds them
to the same unchanged wheel and final artifact-report hash. Tools are not
included by `MANIFEST.in`; the old tool snapshot is not presented as current.
That closeout changed only this record and the solution plan. Those two
bookkeeping files also differed from the retained source snapshot; library,
library tests, documentation, type consumers and probe tool bytes were unchanged
at that time. The subsequent corrections below change the library snapshot.

### Quality, documentation and compatibility

- Black checked **29 selected Python files** successfully.
- Implementation error-level Pylint passed. The final `sessions.py` hook change
  and both current tools also passed the supplemental command below. An earlier
  tool lint run failed to resolve project-local imports; supplying the explicit
  repository search path resolved it without a source change.
- Configured strict mypy passed for **seven source files**; this is the configured
  slice, not a claim that all dynamic protocol internals are strictly typed.
- The selected **26 files** passed Python 3.7 grammar parsing. The installed
  verifier also passed its package grammar check. Neither is Python 3.7 runtime
  evidence; the runtime tested here is Python 3.13.3.
- Strict MkDocs build and `docs/verify.py` passed: **23 HTML pages, 1,548 local
  links/assets, 24 API objects, 39 Python snippets and 12 pinned source paths**.
  The synchronous, asynchronous, upload and H2 loopback examples all passed.
- `git diff --check` passed. Plan/record links and completion states were checked
  after closeout; runtime/test/tool bytes were preserved during record updates.

```sh
env PYTHONPATH=/Users/mastluo/MyProjects/ja3requests .venv/bin/python -m pylint -E ja3requests/sessions.py tools/capture_fingerprint.py tools/verify_h2_controls.py
```

## Review and completion boundary

The final review found no new blocking defect or requirement for an additional
framework. R reuses encoded bodies and existing upload ownership; H1 stays
request-scoped with dependency 0; H2 stays a named-field exclusion policy in the
shared encoder. Priority does not split pools, indexing policy does, and the
independent probe reuses the existing collector instead of adding a release
pipeline. Conditional TLS/profile/API/long-term work remains unselected.

All selected R/H1/H2/D checklist items are complete. The runtime matrix beyond
Python 3.13 remains a separately authorized publication gate, as defined in the
solution; no release-readiness or cross-version-runtime claim is made here.
File-plan registration remains **UNREGISTERED** because supported status readback
still lacks the official session binding. No registry success or fabricated
identity is recorded; this does not reopen the completed local acceptance.

Temporary verifier/probe installs, CA-key staging, listeners and child processes
are cleaned according to their reports and path readback. The task-owned strict
documentation output `/tmp/ja3requests-final-docs.TA6FQG` was removed and its absence
verified. Reports, exact artifacts, raw bytes and tool sources are retained as
deliverables. Historical `verify-remaining-r-01` and `verify-remaining-h2-01` are
failed attempts; `verify-remaining-r-02` is passed but superseded. Earlier Huffman
and browser evidence remains historical and is not relabeled as current acceptance.

No commit, push, release, deployment or remote Issue write occurred. User debug
scripts, IDE files, historical release records and unrelated edits remain intact.

## Post-review source corrections

Completed: 2026-10-13. Status: **SOURCE CORRECTIONS COMPLETE**.
The user's `fix findings` instruction selected three confirmed redirect defects,
their regressions and documentation. Work remained serial without subagents.

- Keep destination failures outside completed-hop retries. Each destination
  retains its own HTTP retry budget; exhausted read errors propagate without
  retrying the origin with a finalized upload adapter.
- Clear inherited buffered length framing when hooks clear or replace the
  body. Handle case variants and empty values, and preserve the replacement
  streaming source's inferred or explicitly changed length.
- Compare the context's serialized JSON when validating buffered replay,
  covering `1 -> True`, `1 -> 1.0`, nested edits and dictionary order. Unchanged
  multipart bytes still replay without rereading borrowed files.
- Stabilize the existing H2 priority retry/redirect peer: send GOAWAY to require
  a new connection, then drain until client closure. The original peer's direct
  socket close raced with retry selection; tracing observed a retry on stream 3
  of that same connection instead of stream 1 on a new connection.

Representative regressions for all three defects failed before the fixes:
closed-upload `RuntimeError`, inherited length/duplicate casing after body
removal, and stale JSON bytes after an in-place boolean edit.

Current source verification used `.venv/bin/python` 3.13.3 on macOS:

```sh
.venv/bin/python -m pytest -p no:cacheprovider test --ignore=test/test_session.py tools/tests -q
```

- Final full suite: **3,910 passed, one warning, 31.65 seconds**. The warning
  remains the documented `TestContext` collection warning; the legacy external
  service manual test remains excluded according to `CLAUDE.md`.
- Focused redirect/upload/retry/H2 controls: **195 passed, 2.69 seconds**.
  The H2 retry-sync case also passed in **10 separate test processes** after
  the peer correction. The first full run had 3,909 passes and that one failure;
  it is not presented as a passing run.
- Black checked all **four changed Python files**. Error-level Pylint passed
  for the two implementation files; configured strict mypy passed for its
  **seven source files**. These are scoped quality checks.
- The four changed Python files passed **Python 3.7 grammar parsing**, which
  does not establish Python 3.7 runtime behavior.
- Strict MkDocs build and `docs/verify.py` passed: **23 HTML pages, 1,548 local
  links/assets, 24 API objects, 39 Python snippets and 12 pinned source paths**,
  including all four synchronous/async/upload/H2 examples.

The task-owned documentation build directory was removed and its absence checked.
Tests verified upload worker termination, adapter finalization, borrowed-file
ownership and H2 reader cleanup. Source/docs regressions are the completion
boundary for these corrections: no package was rebuilt, no browser data was
recaptured, and neither `verify-remaining-final-01` nor `verify-remaining-h2-02`
validates the corrected source. Their reports, artifacts and hashes are retained.
No commit, push, release, deployment or remote write occurred.
