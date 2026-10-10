# Post-2.2.0 follow-up plan

Prepared: 2026-10-08

Status: **CANDIDATE ROADMAP**. A3 buffered preparation/send is complete locally.
Current acceptance is recorded only in the linked execution plan; remaining
candidates are references, not new implementation obligations.

The detailed execution sequence is recorded in the
[post-2.2.0 execution plan](post_2_2_0_execution_plan.md).

## 1. Outcome and current baseline

Keep the published 2.2.0 client stable, respond to evidence-backed defects, and
select at most one new public capability for the next engineering batch. Do not
turn the entire deferred-candidate list into a commitment.

- `master`, `origin/master`, and `v2.2.0` point to
  `83132c84547b6f7bbcf740b961b6d06a7121b058`.
- [GitHub v2.2.0](https://github.com/lxjmaster/ja3requests/releases/tag/v2.2.0)
  and [PyPI 2.2.0](https://pypi.org/project/ja3requests/2.2.0/) are published.
- The published wheel and sdist hashes, release assets, and official-index
  installation were independently checked. The retained local record is
  `dist/release-2.2.0/verification.json`.
- The accepted release boundary includes synchronous and asynchronous streaming
  request bodies, async multipart/files, async Cookie-file helpers, HPACK
  validation, public typing/docs, and the corresponding cancellation and
  ownership fixes. Do not relist these as unfinished features.
- Python `>=3.7`, project-owned TLS/HTTP2 state, certificate verification,
  cancellation, deadlines, ownership, and flow-control bounds remain unchanged
  constraints.

The repository still contains pre-existing untracked local issue/debug files.
They are retained and are outside this plan's change scope.

## 2. Near-term work selection

The following order is recommended. Items remain unselected until a concrete
need or defect supplies the entry condition.

| Priority | Candidate | Entry condition | Acceptance boundary |
| --- | --- | --- | --- |
| P0 | 2.2.0 maintenance | A reproducible regression, security issue, or compatibility failure is reported | Reproduce against 2.2.0, add the smallest meaningful regression check, fix only the proven cause, and rerun installed/package/docs checks affected by the change |
| P1 | Async prepared request/send (A3) | A future extension needs behavior outside the completed buffered preparation/send boundary | Define a new contract for the extension (for example, streaming replay) before implementation; do not reopen the completed buffered slice |
| P2 | Session-default merging (C17) | A compatibility request demonstrates that current per-request values are insufficient | Preserve omitted/`None`/empty distinctions, header/query/auth/proxy precedence and cross-origin safety; add behavior tests before changing defaults and document compatibility impact |
| P3 | Incremental internal typing (C06) | A real diagnostic blocks maintenance or a named module is needed by a consumer-facing change | Choose one dependency-bounded module, retain runtime behavior, pass strict checks and installed valid/invalid consumers, and report remaining diagnostics honestly |
| P4 | Documentation hosting or performance CI (C01/C02) | A host/owner or reproducible runner/workload policy is selected | Keep deployment/benchmark automation separate from library behavior; verify public routes or retain raw samples and variability without inventing speed gates |

The buffered A3 slice is complete locally and addresses the selected async API
gap. Any further A3 work must name a separate missing capability and acceptance
boundary before implementation.
P2 has higher compatibility risk, and P3/P4 improve maintainability or process
without adding end-user capability.

## 2A. Work-package breakdown and decision gates

The next engineering batch should contain one primary work package. The cards
below make the dependencies visible without authorizing implementation by merely
listing it.

| Card | Depends on | Deliverable | Stop condition |
| --- | --- | --- | --- |
| M0: release maintenance | A reproducible 2.2.0 defect | Regression, focused fix, and exact-snapshot acceptance record | No confirmed defect: close the card without speculative refactoring |
| A3-D: prepared-send contract | A separately named extension beyond buffered preparation | New body/replay or ownership rules, with a fresh acceptance matrix | Any unresolved extension rule: keep the buffered public boundary unchanged |
| A3-I: prepared-send implementation | A3-D accepted | An isolated extension with focused request/response/hook tests and docs | Repeated send, consumed stream, or cross-loop behavior is ambiguous: return to A3-D |
| C17-D/I: defaults | A compatibility need and accepted migration policy | Opt-in or explicitly versioned defaults with precedence tests; no silent change to current calls | Any ambiguity around empty values, cross-origin stripping, or Cookie precedence |
| C06: typing slice | A named diagnostic or dependent feature | One module's strict typing plus installed consumer checks | Type-only churn changes runtime behavior or lacks a useful acceptance boundary |

The selection gate is therefore:

1. Record the concrete user workflow or reproducible defect.
2. Decide whether the current high-level API can already support it with a
   small wrapper or documented pattern. If yes, document that pattern first.
3. If a library change is still justified, select exactly one card and freeze
   its acceptance boundary before editing runtime code.
4. Keep other cards as references. Do not implement A3 and C17 together; their
   request preparation and compatibility semantics would make failures hard to
   attribute and rollback.

The current source reflects the completed contract: synchronous `Request`
objects are transport preparation helpers, async hooks receive private
`_RequestMetadata` snapshots, and `_freeze()` validates and frames their bodies.
`AsyncPreparedRequest` exposes read-only buffered metadata with Session/loop
ownership; it reuses this validation and the existing dispatcher. Any extension
must preserve that contract. Current documentation also
explicitly describes Session header/auth/params/proxy values as non-merging, so
C17 would be a compatibility change even though its design is complete.

## 2B. Selected execution record

The user selected preparation for inspection/signing. A3-D and A3-I are complete
at their buffered-body local boundary. The execution plan contains the only
active/completed checklist and evidence; this roadmap does not duplicate it.
Prepared streaming bodies and C17 remain separate future selections.

## 3. Explicitly deferred candidates

These are feasibility or product decisions, not incremental cleanup tasks:

- TLS 1.3 0-RTT and cross-process TLS session storage: require replay safety,
  ticket protection, expiry and restart semantics before implementation.
- HTTP/3/QUIC: require a separate protocol ownership and dependency design.
- H2 PRIORITY scheduling and server push: require a real consumer workload,
  bounded lifetime, fairness and cancellation rules.
- ECH, post-quantum groups and browser-profile updates: require a named target,
  fresh captures, available primitives and an interoperability/security review.
- Additional legacy TLS 1.2 suites or runtime/OS/architecture support: require
  an exact peer or environment and installed-package evidence.

Do not start these items merely because the 2.2.0 release is complete.

## 4. Execution and verification contract

When one candidate is selected, use this serial sequence:

1. Freeze the 2.2.0 baseline and record the user-visible compatibility goal.
2. Write the smallest API/ownership/error contract and a failure matrix.
3. Implement the selected slice with focused unit and loopback/integration
   coverage. Keep unrelated deferred candidates out of the diff.
4. Run installed-package acceptance on the exact candidate: affected tests,
   full required suite, typing, documentation links/snippets/examples, Python
   3.7 grammar checks, and relevant security/ownership boundaries.
5. Review the diff and retained evidence. Commit, push, and publish only if
   those action sets are separately selected; choose a version after the actual
   compatibility impact is known.

The main work stays serial because the async API, request ownership, and
compatibility semantics are coupled. A documentation or tooling lane may run
independently only after its inputs are frozen; it must not delay or silently
expand the selected product scope.

## 5. Recovery, cleanup and stop conditions

- Preserve unrelated user files and all release evidence. Clean only staging and
  temporary files created by the selected batch after reports are retained.
- If a required check fails, make at most two bounded, evidence-based attempts;
  then isolate the cause, choose an in-scope safe mitigation, or report the real
  dependency. Do not weaken checks or relabel a required item as optional.
- A candidate is complete only when its behavior, installed artifacts, docs,
  typing, cleanup and evidence agree on one source snapshot. A release is not a
  prerequisite for planning and is not implied by this document.

## 6. Next selection

Use the entry conditions above when another concrete need is selected. No C17,
typing, hosting, performance or protocol expansion is required to complete A3.
The next execution should define its own selected outcome and reuse completed
evidence instead of reopening this delivered batch.
