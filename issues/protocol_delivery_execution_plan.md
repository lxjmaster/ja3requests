# Protocol Delivery Execution Plan

Updated: 2026-10-03. The user's supplied revised plan is the controlling scope.

## Fixed outcome and authority

Complete the review of PR #52 and incremental PR #53, fix proven required
defects locally on their owning branch, verify the resulting candidates, and
deliver one actionable merge recommendation. This is E1-E2 delivery preparation.

The follow-up execution request authorizes committing and pushing the verified
repairs and checking fresh CI. The user's correction and resumed execution
confirm continuation through E3, including server-side merges and associated
PR readiness/base changes; the previous authorization blocker was an overly
narrow interpretation and has been removed. Publication, history rewriting, remote review
comments and T06-T10 implementation remain out of scope. Execute serially; no
subagents. Preserve unrelated work, debug scripts, IDE files and old artifacts.

Lifecycle: UNREGISTERED. The supported status command cannot obtain an official
session binding. The file plan remains authoritative for execution tracking;
do not infer an ID or treat this tooling limitation as a local-work blocker.

## Historical baseline and evidence

- #52 head: 21f72ae397fd7656ac1c58fcdbfa207bdc7bb94a, base master.
- #53 head: 7711f86446c5512c16311a2db39cdc3888566f70, base #52.
- Both refreshed as OPEN/draft with ten successful remote checks and no submitted
  reviews. These checks apply to the old heads, not unpublished local fixes.
- T05 source/test/wheel manifests matched before repair; preserve dist/t05.
- Existing full-suite selection excludes test/test_session.py. Older Python
  runtime skips remain explicit limitations, not passing evidence.

## Execution checklist

- [✅] Read the supplied revised plan, review skill and routed local rules.
- [✅] Inspect current worktree and refresh PR identities/checks/descriptions.
- [✅] Review #52 TLS authentication/resumption and fragmented/failure paths.
- [✅] Review #52 HTTP/2 allocation, flow control, HPACK and failure/pool paths.
- [✅] Review #52 Cookie persistence and request scope preservation.
- [✅] Review incremental #53 defaults, overrides, isolation, legacy/browser
  behavior and migration documentation.
- [✅] Reproduce and fix three required #52 defects in its isolated worktree:
  H2 reservation timeout, TLS 1.2 resumed Finished timeout, and H2 upload TLS
  record fragmentation.
- [✅] Add meaningful regressions and run affected checks: 62 timeout/recovery
  cases and four independent OpenSSL upload cases passed.
- [✅] Propagate the same runtime deltas and two test files to #53; verify equality
  and retain independently applicable/reverse-checkable patches for both heads.
- [✅] Correct the proven flaky PSK assertion on #52 and propagate it to #53;
  retain wire-level checking and add deterministic opaque-payload coverage.
- [✅] Finish installed-wheel verification: #52 1374 passed/88.89%; #53 1427
  passed/89.04%, both with 58 matching modules and passing formatting/lint.
- [✅] Finalize the single [delivery review](protocol_delivery_review.md) with
  results, source/remote correspondence and the merge recommendation.
- [✅] Complete artifact readback and cleanup. Retain #52's repaired worktree at
  `/Users/mastluo/MyProjects/ja3requests-pr52-delivery-review` and #53 in the
  original checkout; patches/evidence remain under `dist/delivery_review`.
  Task-owned temporary build/install/test directories were removed.

## Acceptance and verification

Every required finding must have code/trigger evidence, branch ownership, a
minimal fix and matching behavioral verification. No unresolved required defect
may be relabeled optional. Do not invent improvements if review finds none.

Reuse unchanged successful checks. For a fix, test affected success/failure
boundaries first; once fixes stabilize, verify each final candidate from an
installed wheel outside its checkout. Confirm import origin, wheel/source
identity, selected full suite, coverage >=85%, package Black and error-level
Pylint. Use --cov-fail-under=85 and preserve the manual-test exclusion.
Documentation-only changes need links/consistency/diff checks, not protocol reruns.

## Conditional merge handoff

After authorization to publish fixes and merge: update #52 first, propagate
to #53, confirm CI on the resulting remote candidates, then merge #52
server-side. Retarget #53 to master, inspect ancestry/final diff and any
conflict resolution, verify final integration checks, then merge #53.
Handle draft/readiness changes within that authorization. Never substitute
a direct master push or unauthorized history rewrite.

Publication remains a separate task with exact source, output directory and
artifact list. Do not use broad make upload/clean targets. T06-T10 remain in
the [roadmap](next_development_plan.md), outside this execution scope.

## Recovery and retention

After two attempts without narrowing a cause or advancing delivery, use a safe
alternative or report the precise hard blocker. Preserve successful evidence
across retries and inspect actual state before retrying mutations.

Retain both local candidates, the review, patches and dist/delivery_review
evidence as deliverables. Preserve dist/t05 and existing debug/IDE resources.
Remove only task-owned installed/build/test staging and generated keys after
readback. No remote authority is needed to finish the selected local outcome.

E1-E2 are complete. The follow-up request extended delivery through E3; do not repeat
unchanged local tests. Revalidated all 138/139 candidate manifest entries and
19/11 retained artifact hashes before committing the repairs.

## E3 preparation checklist

- [✅] Revalidate current worktrees, original remote heads and local evidence.
- [✅] Commit #52 repairs and preserve unrelated files.
- [✅] Commit the identical #53 repairs and merge the updated #52 branch into
  #53 without rewriting history; no additional runtime delta resulted.
- [✅] Push both updated candidates and confirm fresh CI on their exact heads:
  #52 `ad62e9a022bdc271d43c4aba88925773273eaab2`, #53
  `8e8c0926f9df1e72ef6cf2727993ca7efa9dbfb1`; ten checks passed per PR.
- [✅] Record final remote evidence in
  `dist/delivery_review/remote_post_push.json` and the review's E3 handoff.
- [✅] Resume E3 under the user's correction; mark #52 ready and merge it
  server-side as `f0a00507c449e746b287fe58836b4c4c4111341f`.
- [✅] Retarget #53 to master.
- [✅] Verify final #53 candidate `e83d3c4` (ten successful checks) and merge it
  server-side as `f0cac58b3339a8ef68850cd9075efac159a3bea3`.
- [✅] Read back both MERGED records, verify #52 ancestry and confirm final
  master has exactly the same tree as the verified #53 candidate.
- [✅] Record final-master CI: all ten checks passed at `f0cac58`, including
  Python 3.7-3.13, wheel, lint and 89.04% coverage. Evidence is retained in
  `dist/delivery_review/remote_merged.json`.

The earlier missing-authority classification is superseded by the user's
correction and resumed goal. Continue the original E3 outcome without another
approval round. Preserve merge ancestry and retained worktrees.

Publication and T06-T10 remain separate outcomes.

E1-E3 implementation, validation and protocol merges are complete. Documentation
closeout additionally requires these three final records (this plan, the review
and the roadmap) to be committed and merged into master through a documentation
PR. Verify that PR's merged state and remote file equality before reporting full
delivery completion. Local-only retention does not satisfy this final gate.
For this documentation-only change, check links, factual consistency and diff
scope; reuse the successful protocol checks above.
