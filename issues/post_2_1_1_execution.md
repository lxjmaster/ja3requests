# Post-2.1.1 local engineering execution

## Current follow-up acceptance (2026-10-06)

The user selected local acceptance and record reconciliation for the subsequent
HPACK and async H2 review fixes. Earlier completed snapshots below remain
historical evidence; they do not accept the changed package bytes.

- [✅] Verify the final snapshot through the independent installed-artifact pipeline.
- [✅] Verify strict typing, formatting, error-level lint, tool tests and docs.
- [✅] Read back source hashes and cleanup evidence, and reconcile current records.

Scope includes UTF-8 byte accounting for encoder insertion/eviction/resizing,
atomic text-header validation, and request-local async validation before shared
writer admission. Rejecting non-UTF-8 header bytes is an intentional text-API
compatibility restriction, not an HPACK wire requirement. Raw string codecs
still preserve arbitrary bytes. These are runtime fixes after N3, not a claim
that the original typing-only migration changed runtime behavior.

Execution is serial for source edits; independent checks may run concurrently.
No subagents are needed. Retain new reports/artifacts under
`dist/post-2.1.1/final-review-2026-10-06/`; preserve prior evidence and unrelated
files. The verifier cleans its owned staging. Commit/push, publication,
deployment, remote Issue edits and deferred feature candidates remain unselected.
Plan registration remains UNREGISTERED: a fresh status probe still reports a
missing official session binding; no substitute identity is supplied.

Outcome: **COMPLETE locally**. Python 3.13.3 acceptance evidence is retained in
`dist/post-2.1.1/final-review-2026-10-06/`:

- `candidate/verification.json`: all ten pipeline commands passed; independent
  installed tests passed **2,158 tests + 118 subtests**, zero failures/errors/skips,
  one existing helper-class collection warning. Statement coverage is **91.08%**
  (9,655/10,601). Installed positive typing and all **47 negative markers** passed.
- Source manifest and both artifact hashes were read back against current bytes.
  The snapshot is an uncommitted candidate, not acceptance of its base commit.
  Python 3.7 grammar passes; no new remote runtime-matrix result is claimed.
- `checks/verification.json`: Black (72 files), strict mypy (7 modules), package
  error-level Pylint, **72 verifier tests**, strict docs build, docs checker and
  diff hygiene all passed. Documentation checks cover 23 pages, 1,494 links/assets,
  18 API objects, 34 snippets, 12 pinned paths and both actual loopback examples.
- Verifier staging and every per-command temporary root were removed and their
  absence verified. The explicitly owned `checks/tool-pytest` fixture directory
  was removed after retaining the successful test log. Reports, built artifacts
  and `checks/docs-site` are deliberately retained as delivery evidence.

Only completion records in this file, the selected plan and the roadmap changed
after snapshot acceptance. Package, tests, tools, workflows and user-facing docs
retain their accepted bytes. Historical N3 runtime-preservation statements below
apply to its original typing-only candidate; the later runtime fixes and UTF-8
restriction are explicitly recorded above. No commit/push, remote CI, release,
deployment or remote Issue mutation was performed.

Started: 2026-10-05. Outcome: implement all N1-N3 and integrated acceptance in
[the selected plan](post_2_1_1_plan.md). The user authorized continuous execution
with this fixed scope. No commit, push, release, deployment or remote Issue change
is selected. Python >=3.7 library support and runtime protocol behavior remain
unchanged; modern tooling runs separately.

Registration: **UNREGISTERED**. The supported CLI cannot obtain an official
session binding. The file plan remains truthful; no identity is invented.
The separately supported official goal is completed through its own tool after
the final completion audit; no successful file-plan registration is claimed.

## Required acceptance

- [✅] N1: Reconcile current/historical status and API-specific proxy/docs guidance;
  verify prose, links, strict documentation build and loopback examples.
- [✅] N2a: Implement and test explicit commit/snapshot source collectors and one
  independent sdist-to-wheel installed-verification pipeline with truthful reports.
- [✅] N2b: Add read-only full-history documentation CI; verify configuration and
  local equivalent commands. Remote CI is not claimed without authorized push.
- [✅] N3: Migrate only HPACK into the strict gate, preserve all previous consumer
  cases and runtime contracts, and run targeted plus installed acceptance.
- [✅] I1: Reconcile implementation lanes and independently inspect their diffs.
- [✅] I2: Accept the combined snapshot with tool tests, installed test/typing and
  coverage checks, docs, formatting, error-level lint and hygiene.
- [✅] I3: Retain evidence, reconcile results and status, and clean task staging.
  Official goal closure follows the completed audit through the supported tool.

## Ownership, recovery and evidence

The main integrator owns tooling, tool CI integration, planning records and final
acceptance. Independent lanes own HPACK/type consumers and proxy/docs/CI files;
a separate test lane owns verifier tests. File ownership is disjoint. The main
integrator reviews actual diffs and failure boundaries before acceptance.

Retain reports, logs and artifacts under ignored `dist/post-2.1.1/`. Temporary
build/install/test staging is task-owned and removed after retaining reports,
including on failure. Existing `dist/release-2.1.1/`, user debug files, IDE state
and unrelated changes remain untouched. Failed evidence is never overwritten or
relabeled passed; reruns use new output directories. Snapshot manifests identify
actual candidate bytes; the base commit is context, not candidate acceptance.

## Results

Outcome: **COMPLETE locally**, 2026-10-05. N1-N3 and integration are delivered;
no deferred candidate was added. The package version remains 2.1.1 because no
new version/release was selected. The new artifacts are uncommitted candidate
evidence, not replacements for the published 2.1.1 artifacts.

### Delivered changes

- Proxy docs separate synchronous simple parsing/per-response ownership from
  async URL parsing, credential decoding, supported schemes and pool ownership.
  Both APIs' TLS-to-proxy boundary remains unchanged. No proxy implementation
  or new feature was added.
- [Local verifier](../tools/verify_release.py) and its [CLI guide](../tools/README.md)
  support exact-commit archives and explicit current-worktree snapshots through
  one installed-artifact pipeline. Build hooks operate on a separate build copy;
  the source comparison tree remains frozen. New files are explicit, conflicts
  refuse overwrite, subprocesses are bounded, and failures retain truthful logs.
- [Tool tests](../tools/tests/test_verify_release.py) cover source identities,
  drift, exclusions, source/metadata/RECORD tampering, missing contents, output
  conflicts, timeout/cancellation cleanup and test-summary accounting. The
  existing Python 3.12 wheel job runs them; its original acceptance and the
  Python 3.7-3.13 runtime matrix are preserved.
- [Documentation CI](../.github/workflows/docs.yml) has read-only permissions,
  full history, Python 3.12, strict build and the existing checker. It has no
  deployment or publishing step.
- HPACK alone joins the strict gate. Encoder bytes/string representations,
  iterable input, decoder string-pair results, table state and algorithms remain
  unchanged. All 39 prior negative markers remain; eight HPACK cases make 47.
  Two regression tests lock previously uncovered existing behavior.

### Initial N1-N3 candidate acceptance

Local checks used Python 3.13.3. All relative evidence paths below are under
ignored `dist/post-2.1.1/`, retained locally rather than public download links.

| Acceptance | Result | Evidence |
| --- | --- | --- |
| Commit collector | Exact baseline SHA `07c70955fc35c981867eed029c897e7ba6f8cf1c`, 271 files | `baseline-collector.json` (collector-only, not a second complete artifact run) |
| Snapshot collector | 277 selected files; contextual base SHA only; all hashes matched the checkout at readback | `candidate-01/source-manifest.json` |
| sdist -> wheel | Build log confirms wheel built from sdist; strict Twine, frozen metadata/bytes/inventory, empty marker, license and RECORD pass | `candidate-01/verification.json`, `build.log`, `metadata.log` |
| Independent installation | 68 module hashes/origins, version, secure defaults, async exports, H2 framing and pip check pass | `candidate-01/smoke.log`, `dependencies.log`, `freeze.log` |
| Complete installed test selection | **2,153 tests + 112 subtests passed**, 0 skipped, 1 warning; **91.07% statement coverage** (9,639/10,584) | `candidate-01/pytest.log`, `installed.xml`, `coverage.json` |
| Installed consumers | Positive consumer and all **47** expected negative markers pass, without source permission | `candidate-01/typing.log` |
| Strict source gate | 7 modules pass | `n3/strict-mypy.log` |
| HPACK targeted regressions | 203 pass; the two new behavior tests also passed against pre-migration library code | `n3/targeted-tests.log`, `targeted-junit.xml`, `baseline-behavior.log` |
| Verifier regressions | **57 pass** | `tool-tests.log` |
| Documentation | Strict build plus both actual loopback examples pass; 23 pages, 1,494 local links/assets, 18 API objects, 34 snippets, 12 pinned source paths | `docs-build.log`, `docs-verify.log` |
| Formatting/lint/hygiene | Black, package error-level Pylint, YAML, merge-conflict, package whitespace/EOF and diff checks pass | `black.log`, `tool-black.log`, `pylint.log`, local hook results |

The one test warning is the existing `PytestCollectionWarning` for helper class
`TestContext` having an `__init__`, not a failing or skipped test. JUnit counts
2,265 cases including the separately reported subtests. Tool and installed
environment versions are retained in `candidate-01/tool-versions.log` and
`freeze.log`, not inferred from configuration.

Full internal mypy was run once after integration: **1,735 diagnostics in 52
files** (previously 1,786 in 53), recorded in `internal-mypy.log`. This remains
non-gating migration backlog, not a count of confirmed runtime defects. The
strict slice is green; whole-library cleanup was not selected.

### Independent review and completion boundary

The main integrator inspected lane diffs and code-backed proxy claims. A separate
reviewer checked tool failure boundaries and the HPACK migration, including
runtime AST equivalence after removing typing-only scaffolding. Verifier tests
exposed missing archive-prefix and unexpected binary-package-entry checks; review
also exposed build-source contamination, interrupted child cleanup and infinite
timeouts. All were fixed, read back and covered by regression tests before the
full snapshot run. No confirmed in-scope blocking findings remain.

At that initial acceptance boundary, only completion bookkeeping in this execution record,
the selected plan and the roadmap was updated. Package, tests, tool, workflow
and user-facing documentation bytes remain those accepted by the snapshot.
Historical roadmap content and prior release/benchmark evidence are preserved.

The actual GitHub workflows were not triggered: configuration/static checks and
local equivalent commands passed, but no new remote CI or Python 3.7-3.13 runtime
matrix success is claimed. Python 3.7 grammar was verified separately. There
were no commits, pushes, remote Issue changes, uploads, releases or deployments.

Build/install/test staging was automatically removed and its absence verified.
The baseline collector and independent-review scratch directories were cleaned.
The three remaining task-owned verifier pytest fixture directories (`pytest-34`
through `pytest-36`) and their current symlink were identified by their test
contents and removed; the shared parent was preserved. Logs, source manifests,
candidate artifacts and the built documentation site remain intentionally as
acceptance evidence. No pre-existing user data or release evidence was removed.

## Review follow-up: three verifier findings

Completed: 2026-10-05. The subsequent review identified three verifier boundary
defects; the user authorized fixing those findings. This follow-up changes only
the verifier, its regression tests/guide, and current completion records. It
does not alter package/runtime behavior, CI, dependencies, or release scope.

- [✅] Exact commit identity: Git inspection disables replacement objects. The
  archive's selected paths and Git blob IDs are compared with the original
  commit tree. Local `export-ignore`/`export-subst` changes that omit or rewrite
  selected inputs fail explicitly. Repository attributes/refs are never edited.
- [✅] Frozen test inputs: every sdist `test/` entry must exist in the frozen
  source with identical bytes, including hooks, configuration and nested paths.
  Unknown test hooks/configuration/shadow packages are rejected before execution.
- [✅] Child temporary cleanup: each pipeline command gets a dedicated owned
  `command-tmp-*` root under the fresh evidence directory through `TMPDIR`,
  `TEMP` and `TMP`. It is removed after the child is reaped, including timeout,
  cancellation and spawn failure. Per-command reports record the actual root
  and cleanup result, independently of the main staging cleanup field.

The test lane added 15 regressions and extended the cancellation-ordering case;
all **72 tool tests passed**, with Black passing after formatting. The main
integrator inspected those changes and an independent reviewer verified real
child/grandchild timeout and SIGINT cancellation cleanup, plus commit exclusions
under archive attributes. No confirmed remaining findings in this fix scope.

New evidence is retained under `dist/post-2.1.1/review-fixes/`:

- `baseline-collector.json`: original-object-checked collection of baseline
  `07c70955fc35c981867eed029c897e7ba6f8cf1c`, 271 files.
- `candidate-02/verification.json`: **passed** for the fixed 277-file worktree
  snapshot, not for a new commit or release. All 68 package module hashes equal
  the initial candidate's hashes. Both artifacts' hashes were read back.
- Installed acceptance: **2,153 tests + 112 subtests passed**, 0 skipped, one
  existing helper-class collection warning, **91.06% statement coverage**
  (9,638/10,584), positive consumer and all **47** negative markers passed.
- All ten pipeline commands passed and each recorded `temporary_cleaned=true`;
  the main staging and every command temporary root were absent at readback.
- `black.log` and `pylint.log`: tool formatting and error-level lint passed;
  merge-conflict and diff checks passed. The unchanged docs gate, strict source
  gate and internal-typing backlog retain their earlier evidence without reruns.

All regression/independent-probe fixtures were created under owned temporary
roots and cleaned. Initial evidence was not overwritten. Only this record and
the roadmap's completion counts changed after the new snapshot acceptance;
verifier, test, guide and package bytes remain those verified. No actual-repo
commits/ref changes, pushes, remote CI runs, publication or deployment occurred.
