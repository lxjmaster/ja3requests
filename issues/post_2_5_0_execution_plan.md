# Post-2.5.0 bounded client work

Selected: 2026-10-16. Local implementation status: **COMPLETE / UNREGISTERED**.

Repository delivery was subsequently selected on 2026-10-23; see the
[current roadmap entry](next_development_plan.md#repository-delivery-selection-2026-10-23).
This file retains the original local implementation acceptance, not a claim
that the subsequent commit, push or CI has already completed. Their evidence
belongs to the exact repository commit, its GitHub Actions runs and the delivery
handoff. Publication and remote Issue changes remain outside that selection.

The user selected the reviewed order: correct current release documentation,
implement opt-in request defaults, then inspect the remaining client behavior
differences. The baseline is 7968ed4ee56e4cdb6b32279ca8463f67625b4545 / v2.5.0.
Preserve the project's own TLS/H2 engines and the existing Python >=3.7 contract.

## Fixed outcome and boundary

Implement `Session.request_defaults` and `AsyncSession.request_defaults` for
headers/params only, following the refreshed
[assignment/merge contract](session_defaults_design.md). No constructor option,
legacy observation-property defaults, auth/proxy/Cookie/TLS/body defaults or
general configuration framework. Merge once before initial preparation; async
buffered preparation includes the snapshot and prepared sends never merge again.

Inspect timeout, proxy parsing and empty-header differences, retaining their
existing behavior and documenting any targeted follow-up. The original selection
did not select HTTP-date retry, public trailers, new TLS capabilities, documentation
hosting, remote Issue writes, commits, pushes or another release.

The supported codex-plan status command cannot obtain an official session
binding. Keep this execution record UNREGISTERED; do not invent an identity.
The original implementation ran serially, with no subagents. The later delivery
uses independent read-only checks for the feature boundary and Issue acceptance;
the main agent owns all edits, staging, commits, pushes and final verification.

## Required work

- [✅] Correct current 2.5.0 README/capability/roadmap entries; preserve dated history.
- [✅] Refresh the design against byte headers, buffered async preparation and
  released redirect behavior; implement the bounded assignment and merge path.
- [✅] Verify default precedence, duplicates, byte values, atomic validation,
  mutation isolation, disabled/empty/raw inputs and legacy observation isolation.
- [✅] Verify actual peer bytes, hook/retry/redirect snapshots, origin stripping,
  async preparation/concurrent sends and source/cancellation ownership.
- [✅] Update public types/consumers, source-only documentation and Unreleased notes.
- [✅] Run affected quality checks, full selected tests, strict docs/examples and
  final frozen-source installed-artifact acceptance using the existing verifier.
- [✅] Record remaining client differences, review exact scope, clean task-owned
  temporary resources and retain acceptance evidence.

## Verification, recovery and retention

Use existing loopback peers and project TLS engines. Test meaningful success and
failure boundaries without external service tests. The selected full command is
`.venv/bin/python -m pytest -p no:cacheprovider test --ignore=test/test_session.py tools/tests -q`.
Installed acceptance uses `tools/verify_release.py` with explicitly included new
inputs in a fresh `dist/post-2.5.0/` output, keeping version 2.5.0 as an unpublished
development candidate. No browser recapture is required by header/query merging.
New source invalidates old package evidence; release-2.5.0 remains historical.

Preserve user debug scripts, IDE state, old release records, historical dist and
any concurrent edits. Fix only in-scope delivery defects; after two attempts
without progress, narrow the check or report the exact dependency. Remove only
verified task-owned temporary sites/installations, retaining reports, artifact
hashes and the accepted development candidate. Do not clear dist or shared state.

## Evidence

- Intake: tracked worktree/index clean at the released commit; unrelated
  untracked files were inventoried and left untouched.
- Intake readback: the two READMEs still linked 2.4.0; the capability guide and
  docs index already identified 2.5.0. Current entries now distinguish the
  published baseline from this Unreleased source increment.
- One shared validation/merge module, additive properties on both clients and
  three initial preparation entry points; no transport, TLS or H2 engine changes.
- 138 new default tests, including received HTTP1/TLS1.3/H2 fields and connection
  reuse, retry/redirect removal, credential stripping, preparation timing,
  concurrent prepared sends, Cookie precedence and cancellation/source ownership.
- Full checkout command: **4885 passed, 1 warning, 33.78 s**. The existing
  `TestContext` collection warning remains; the external manual test was excluded.
- Black: 11 changed Python files; pylint `-E`: four runtime files; default strict
  mypy: seven configured modules. Python 3.7 grammar passed for all 11 changed
  Python files; this is not a Python 3.7 runtime result.
- Source-only consumer precheck: positive consumer and **85 negative markers**
  passed. Installed-wheel verification remains the artifact gate below.
- Strict MkDocs build passed in a task-owned temporary site. `docs/verify.py`:
  **23 HTML pages, 1558 links/assets, 26 API objects, 41 Python snippets,
  12 pinned source paths**, plus all four actual loopback examples passed.

## Remaining client differences: disposition

This inspection preserves the selected boundary. These are documented existing
contracts, not newly selected compatibility corrections.

| Area and evidence | Remaining difference | Concrete follow-up boundary |
| --- | --- | --- |
| Timeout: `base/__contexts.py`, `sockets/https.py`, `_async_utils.timeout_pair` | Sync validation/fallbacks depend on transport; direct TLS HTTP1 uses a 15-second read fallback for `None`. Async validates finite nonnegative budgets and `None` has no phase deadline. | Select a uniform timeout contract only with a consumer scenario and migration decision; use explicit finite budgets now. |
| Proxy: `sockets/proxy.py`, `sockets/socks.py`, `async_transport.py` | Sync simple endpoint parsing and per-response tunnel ownership; async URL parsing/credential decoding, extra SOCKS aliases and pool reuse. | A specific unsupported endpoint/credential requirement can select a bounded parser correction; no parser/pool refactor is required by defaults. |
| Empty headers: `BaseRequest.headers`, `async_sessions._headers` | Sync `{}` selects library headers; async `{}` omits them. Explicit empty bypass is retained even with configured defaults. | Keep the documented opt-in bypass contract; changing native behavior requires a separate compatibility decision. |
| Query values: `BaseRequest.params`, `async_sessions._prepare` | Sync encodes mapping list values without `doseq`; async expands them. | String default pairs and explicit repeated pairs work consistently; no broader query normalization is selected. |
| Hooks/Cookies/TLS snapshots: `Session.send/resolve_redirects`, `AsyncSession._request` | Hook counts, stored-Cookie refresh and TLS copy timing retain API-specific behavior; redirect method/body rules are aligned in 2.5.0. | Retain existing policy tests and the current guides; defaults never re-enter these policy loops. |

HTTP-date Retry-After, public trailers, additional GREASE vectors, streaming
prepared requests and async module-level conveniences retain their existing
consumer/feasibility entry conditions. Do not automatically start them after
this batch. No blocker was found that requires expanding the selected runtime
implementation.

## Frozen development candidate

Final candidate passed: `dist/post-2.5.0/request-defaults-candidate-02/`.
Candidate-01 passed, but is superseded after strengthening two tests: redirect
hooks now assert absence before editing headers, and ordinary concurrent async
calls verify independent overrides as well as prepared resends. The 138 focused
tests passed again (0.78 s); changed-test Black and Python 3.7 grammar passed.
Runtime/library/doc bytes did not change after the full checkout/docs checks.
These are unpublished worktree snapshots with version 2.5.0, not replacements
for the published release. Retain candidate-01 as the initial acceptance record.
The final verifier passed sdist -> wheel construction, strict metadata, package
inventory/RECORD/module hashes, isolated installation, dependency checks and
installed consumer typing (85 negative markers). Installed tests: **4740 passed
plus 118 successful subtests**, zero failures/errors/skips, one existing
collection warning; statement coverage **92.7567567568%**. The installed test
run includes the final strengthened assertions; tools tests passed in the full
checkout run above. This is local Python 3.13.3 acceptance, not new multi-version
runtime CI or a browser recapture.

- Wheel SHA-256: `681f9b0cea2accecd185dc3b0f08b40bbd837a8cb2c394455c08ad7f7ae94e2f`.
- Sdist SHA-256: `6b2e9ae8daca878eb6ecad127f14e4e17673f0a9ad981243f4d2406409fabc23`.
- The frozen manifest has **328 selected files**, with only four explicit new
  inputs (the helper, two test modules and this execution record). User debug
  scripts, IDE state, local release records and historical dist are excluded.
  The original readback recorded all 328 files matching after acceptance.
  Delivery intake on 2026-10-23 found 326 matches and two changed records:
  this file and `issues/session_defaults_design.md`. The earlier assertion that
  only this completion record changed is superseded by that readback.
  Package/test/user-documentation bytes still matched the accepted snapshot;
  the wheel and sdist SHA-256 values above were independently rechecked.
- Both verifier runs report actual staging and per-command temporary cleanup.
  The task-owned temporary docs site and the stray bytecode from the initial
  misplaced helper were removed. Reports/artifacts/manifests remain retained;
  candidate-01 records the superseded initial test assertions.
- At completion of the original local batch, `master`/HEAD remained at the
  released baseline and the index was unstaged.
  No commit, push, publication, hosted docs, remote Issue mutation or version
  change was performed. The file plan is complete; official registration/close
  is unavailable without a session binding and is not claimed.
