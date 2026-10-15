# Post-2.4.0 advancement plan

Prepared: 2026-10-15. Status: **B0 / B1 / B4 COMPLETE (2.5.0 SOURCE)**.

This is the current planning entry point after the published 2.4.0 release.
The original planning delivery is linked from the previous roadmaps. The active
implementation scope is fixed below; other batches remain proposals. Completing
the selected work does not select the remaining register.

Execution selected, 2026-10-15: implement **B0 -> B1 -> B4** following the user's
instruction to proceed with the reviewed plan and keep the outcome fixed. B2,
B3 and the conditional register remain unselected. That implementation selection
excluded publication and preserved the version number. The user's subsequent
instruction selected commit, push and the 2.5.0 PyPI/GitHub release; its final
artifact/CI/publication verification is separate from the development evidence
below. Documentation hosting and remote Issue changes remain unselected.

### Fixed execution checklist

- [✅] B0: reconcile the current capability guide and historical Issue acceptance.
- [✅] B1: add explicit Chrome 155/macOS subset and load its validated defaults.
- [✅] B1: add assertion-based profile-default acceptance, including mismatch
  failures, without browser-derived connection overrides; retain legacy mode.
- [✅] B1: verify actual sync/async TLS/H2 and TLS1.2 fallback, policy isolation,
  persistent HPACK state and third-stream reuse.
- [✅] B4: align 301/302/303 method/body handling, preserve 307/308, and verify
  replay, hook edits, cross-origin policy and source cleanup.
- [✅] Complete focused and final source checks, strict docs/examples and one
  frozen installed-candidate acceptance for the selected combined source.
- [✅] Complete the three-browser and installed sync/async profile-default series
  against that same candidate, retain evidence, and clean owned temporary state.
- [✅] Review the exact final scope and record results; leave B2/B3 unselected.

Registration: **UNREGISTERED**. `codex-plan --json status` reports that an official
session identity needs a fresh PreToolUse binding. No identity is inferred or
substituted. Keep this file usable without claiming registry registration.

Source verification, 2026-10-15: 4,719 tests passed with the existing TestContext
collection warning; default mypy checked seven source files, all-package pylint
error checks and changed-file Black passed. Changed runtime/test files parsed
with Python 3.7 grammar; this is not a Python 3.7 runtime run. Strict MkDocs and
the docs checker passed (23 pages, 1,550 links/assets, 24 API objects, 40 Python
snippets, 12 pinned paths), including all four local examples. All 66 relative
link targets across the capability guide and three plans resolved.

### Final implementation acceptance

All commands used Python 3.13.3. Local evidence is retained under
`dist/post-2.4.0/`; these artifacts are unpublished, with version still 2.4.0.

| Evidence | Result |
| --- | --- |
| `b0-b1-b4-candidate-01/verification.json` | Passed: sdist-to-wheel build, metadata/inventory/module hashes, fresh installation, consumer typing, 4,602 installed runtime tests plus 118 successful subtests, 92.6966% coverage and one existing collection warning. |
| `profile-defaults-h2-01/verification.json` | Passed: installed sync/async using `chrome:155`, `overrides={}`, full TLS/H2 and reused streams 1/3/5. SETTINGS/window/pseudo order, priorities, path insertion, 0->14->20->20 table continuity and independent Huffman choices asserted. |
| `profile-defaults-chrome-01/manifest.json` | Passed: three Google Chrome 155.0.8059.40 browser connections plus installed sync/async, using that same wheel. Profile defaults asserted against every sample; first-request HPACK blocks matched exactly. Raw TLS/H2 bytes and comparison remain retained. |
| `configured-controls-01/verification.json` | Passed: all eight original raw/Huffman, indexed/excluded, sync/async control cases using `chrome:154`; existing tool mode remains usable. |

Accepted wheel SHA-256:
`2cdd2496ad0d403afa85429139e209ab7f74c83d04c2d294ac70fb740b810000`.
The worktree snapshot contains 324 selected files; the only explicitly included
untracked input is this plan. Debug scripts, IDE state, local release records
and historical dist were excluded. All selected bytes were compared with the
snapshot after capture; only the completion record changed at that point.
The review correction below records subsequent tool/test/documentation changes;
the reports above retain their original source snapshots and tool hashes.

Verifier staging, per-command temporary roots, probe installations, private
CA/keys, browser profiles, listeners and peer/process resources were cleaned;
the owned temporary docs site was removed after verification. Artifacts, raw
captures, reports and copied tool sources are retained for review. No remote
writes, commit, push, version change, deployment or release occurred. B2/B3 and
the conditional register remain unselected. This local Python 3.13 acceptance
does not claim a new Python 3.7-3.13 CI run or complete browser identity.

### Review correction: live profile drift checks

Completed, 2026-10-15. The collector now checks each browser's declared TLS
projection against the frozen specification, excluding only documented omissions
and browser extension-order variation. Browser and client traces share the H2
startup/request assertions, including table continuity and literal encoding.
Client checks against the frozen specification remain in place.

The regression suite reproduced 23 previously missed browser-side deviations
before the fix. After the fix, 155 tool and browser-capture tests pass, including
raw SETTINGS/window/version mutations for each of the three browser samples.
Replaying the retained Chrome 155.0.8059.40 five-case series and both retained
three-stream client traces with the corrected checks also passes.

These are local source tests and replays of existing received bytes, not a new
browser capture or installed-candidate run. No package source, preset, version,
wheel or retained dist evidence was changed; the historical tool hashes above
do not describe this corrected collector. The original execution scope remains
B0/B1/B4, with B2/B3 unselected. Publication was not part of that correction;
the later release selection is recorded above.

## 1. Baseline and boundaries

- Published source: `cdc8ddc94bd2173a8d077133e3d2d902de5dced2`, tag `v2.4.0`.
  [GitHub release](https://github.com/lxjmaster/ja3requests/releases/tag/v2.4.0)
  and [PyPI](https://pypi.org/project/ja3requests/2.4.0/).
- Retained acceptance: `dist/release-2.4.0/final-candidate-02/verification.json`:
  4,499 installed tests plus 118 successful subtests, 92.6620% statement coverage,
  one existing collection warning. Exact-commit Python 3.7-3.13 CI passed.
  These are the recorded release results, not checks rerun for this plan.
- Final installed H2 controls and Chrome 155.0.8059.40/macOS evidence are under
  `dist/release-2.4.0/h2-controls-02/` and `chrome-huffman-02/`. Public downloads
  and a fresh official-index installation matched the accepted artifact hashes.
- Already delivered: project-owned TLS1.2/1.3, certificate verification,
  HRR/resumption, native async, H2 multiplexing, request/response streaming,
  async files/Cookie files, buffered async preparation, sync 307/308 replay,
  Huffman, request HEADERS priority and indexing exclusions. Preserve these.

Continue using the project's handshake, key schedule, records and H2 engines.
OpenSSL/Python ssl may be independent peers; no client backend replacement is
selected. Preserve authenticated defaults and the existing Python >=3.7 contract.

At execution intake inspect status/diffs again. Preserve user debug scripts,
IDE state, old release records and all historical dist evidence. Work remains
serial, following the user's no-subagent instruction; independent reads and
isolated checks may run concurrently. Use one active implementation batch.
New commits, pushes, Issue writes, hosting and releases require their own
selected action set; the completed 2.4.0 publication grants no new release scope.

## 2. Decisions and recommended order

| Material choice | Recommendation and reason |
| --- | --- |
| Next fingerprint deliverable | Ship one explicit, measured supported-subset profile first. Full browser identity would depend on unimplemented ECH/PQ and other negotiations, so it has a different scope and completion boundary. |
| Session defaults | Reuse the separate opt-in headers/params design. Automatically consuming legacy Session observation properties would turn historical request state into future defaults. |
| Further TLS work | Add one bounded, independently exercised capability per batch. A numeric extension/suite ID or static captured payload is insufficient acceptance. |

Reviewed queue: **B0 -> B1 -> B4**, with B2/B3 selected later from actual needs.
Each row is independently
reviewable and ends with its own acceptance. B3/B4 have no dependency on B2 and
may move earlier for a concrete client workflow. An accepted batch can be
delivered independently; unrelated rows and the conditional register must not
become release gates. A later selected release may group accepted batches.

| Batch | Concrete result | Dependency / size of change |
| --- | --- | --- |
| B0 | Current capability inventory and honest documentation | Existing release evidence; documentation changes only |
| B1 / F3 | Explicit Chrome 155/macOS supported-subset preset, verified using its own defaults | Existing TLS/H2 controls; small factory/preset changes and focused collector acceptance |
| B2 / T1 | Opt-in GREASE in supported-groups and supported-versions vectors | B1's measured gaps; bounded hello encoding/configuration/pool changes |
| B3 / C17 | Opt-in Session headers/params defaults on both clients | Refresh the existing design against 2.4.0; no TLS changes |
| B4 | Matching 301/302/303 redirect method/body policy | Explicit compatibility correction with migration text; reuse existing replay/ownership paths |

No calendar promise is attached to an unstarted batch. Its entry checks identify
actual files, capable peers and compatibility impact before implementation;
completion is determined by the exit criteria below.

## 3. B0: reconcile inventory before development

Update `IMPROVEMENTS.md` and current guides against 2.4.0. Route old plans to this
entry point while retaining dated historical acceptance. In particular:

- Remove stale missing-feature claims for async files/Cookie helpers, uploads,
  buffered preparation and the released H2/redirect controls.
- Describe remaining sync/async differences precisely, including 301/302/303,
  timeout meanings and proxy parsing. Do not change these behaviors in B0.
- Record the unimplemented and conditional items from Section 8 once; avoid
  maintaining several competing current task inventories.
- Prepare an evidence-backed disposition for Issues #36/#37/#40/#41/#42.
  Remote edits/closure are a separately selected action. For #41, the original
  1 GiB / memory <= chunk_size criterion remains unverified; retain that fact
  and propose an explicit measured acceptance boundary before closure. Distinguish
  process baseline, TLS/H2/decompression buffers and iteration chunk size; a
  documentation update cannot establish the original memory guarantee. Any
  replacement criterion must be explicitly agreed rather than silently weakened.

Exit: capability statements agree with current code and release evidence;
changed links resolve; strict docs/checker pass if site-facing content changes.
No runtime suite or browser recapture is needed for documentation-only edits.

## 4. B1 / F3: deliver a usable browser subset

Target: Chrome 155/macOS, backed by the retained 155 captures and the locally
available 155.0.8059.40 executable observed at planning intake. Verify its actual
version at execution and before live cases. An updated browser is a new target:
preserve old vectors and explicitly select/record the new target before editing
its profile. Do not silently relabel captures or depend on a personal profile.

Primary files: [browser presets](../ja3requests/protocol/tls/browser_presets.py),
[factory](../ja3requests/protocol/tls/config.py),
[collector](../tools/capture_fingerprint.py), their existing tests and the
[fingerprint guide](../docs/fingerprints.md). Reuse the current peer/parser/probes.

Implement one new explicit preset, retaining secure defaults, historical explicit
profiles and implicit Chrome 124 selection. Freeze the supported TLS field list
from the [retained capture](../test/fixtures/chrome155_macos_tls_h2.json):

- Reuse the existing Chrome 154 supported TLS subset as the implementation
  starting point; verify supported cipher/signature preference and extension
  payloads against the 155 bytes before carrying them forward.
- Keep TLS1.3 with TLS1.2 fallback, supported groups `[29, 23, 24]`, generated
  X25519 initial share, fresh 32-byte Session ID and ALPN `h2, http/1.1`.
- Preserve only the chosen sample's relative order for implemented extensions.
  Omit unsupported TLS1.2 ChaCha suites, hybrid group 4588, extra signature
  algorithms and unimplemented extension negotiations. B2's extra GREASE
  vectors are not required by B1.

Publish the exact included/omitted field table with the preset. Numeric IDs or
copied captured payloads cannot establish negotiation support. Fixed extension
order is not a browser randomization model. Do not claim matching browser JA3
or complete browser identity.

H2 connection defaults and explicit request inputs for the retained scenario are:

| Field | Intended value / boundary |
| --- | --- |
| Ordered SETTINGS | `[(1, 65536), (2, 0), (4, 6291456), (6, 262144)]` |
| Initial connection WINDOW_UPDATE | `15663105` |
| Pseudo-header order | `:method, :authority, :scheme, :path` |
| Huffman | `True`, using the existing strictly-shorter policy |
| Literal insertion exclusions | `(':path',)`, using the existing policy |
| Request HEADERS priority | Caller-supplied `(256, True)` and `(183, True)` for the two recorded requests; dependency 0 |
| Application headers | Explicit scenario inputs, not automatically invented browser headers |

The current factory does not load all these preset fields; wire them through
the existing validated properties. Historical presets must retain their current
defaults. Return independent copied configuration state between factory calls.

Critical acceptance correction: the current collector derives SETTINGS/window/
pseudo-order overrides from the browser and applies them to client probes.
That verifies controls, not preset defaults. Add a narrow explicit profile
verification path which sends using preset-owned configuration with **no
capture-derived TLS/H2 overrides**. Record the mode and actual overrides in the
report. Keep the existing configurable-comparison mode working for old evidence.
Request headers and per-request priority stay explicit, recorded inputs.
Profile acceptance must assert every declared matching field and fail on a
mismatch; capture completion and a comparison report are insufficient. Include
negative controls which deliberately change a preset-owned value and prove the
new acceptance fails. Expected subset omissions are recorded, not matching claims.
The third-client-stream check must also use profile defaults without injected
connection settings; the existing override-based controls report cannot replace it.

Acceptance:

- Factory tests verify every declared field, independent copies, unchanged old
  profiles and pre-I/O rejection of invalid configuration.
- Independent received-byte tests verify selected TLS fields and full TLS1.3/H2
  bodies for sync/async; verify the existing TLS1.2 fallback remains functional.
- Profile-default H2 traces verify SETTINGS/order/window, pseudo-order, priority,
  Huffman, path insertion and persistent HPACK table state. Retained equivalent
  inputs give 14 then 20 dynamic entries; a third stream verifies reuse.
- Pool tests verify changed connection policies isolate connections; different
  per-request weights continue sharing a healthy H2 connection.
- A final installed-candidate series includes three browser connections and
  sync/async clients, each completing the recorded two-request reuse scenario.
  The separate third-client-stream check above proves continued reuse. Verify
  every declared matching field; preserve raw bytes, comparison and unresolved gaps.
  Normalize only identified volatile data. Three samples prove observations,
  not an extension-order distribution or external anti-bot success.

Exit: users can select the new preset and reproduce its declared subset without
manually patching connection-level settings. Missing ECH/PQ and other excluded
fields remain explicit. A missing target executable blocks only live B1
acceptance after available offline work; it does not invalidate delivered 2.4.0.

## 5. B2 / T1: one bounded GREASE increment

First increment: add GREASE only to the **supported-groups** and
**supported-versions** offer vectors where those extensions are present.
These two measured omissions can be addressed without implementing a new cipher
or key exchange. Extension slots, dummy key shares, signature-vector GREASE and
randomized extension-order policy remain separate candidates.

Proposed API, not yet implemented: a copied immutable `grease_vectors` selection,
default empty, allowing only `supported_groups` and `supported_versions` in this
increment. Confirm the exact contract at batch entry. Existing `use_grease`
continues its cipher-vector behavior; existing presets/defaults retain their
bytes unless the new policy is explicitly selected.
Reviewed proposal: insert one reserved value at the front of each selected
automatically generated vector. Keep the new selection independent of cipher
`use_grease`. Reject a selection combined with an explicit extension of the same
type before I/O; do not silently ignore it or mutate caller extension objects.
Values belong to a handshake, not configured real vectors or pool identity.
This proposal is not implementation authority for B2.

Start in [configuration](../ja3requests/protocol/tls/config.py),
[hello encoding](../ja3requests/protocol/tls/layers/client_hello.py) and the
[extension encoders](../ja3requests/protocol/tls/extensions/__init__.py); trace
their sync/async preparation and existing pool-policy snapshots before editing.

Generate legal fresh reserved values during hello preparation, retaining their
actual bytes through transcript/PSK-binder processing and HRR. Keep configured
real groups, versions, private keys and negotiable algorithms separate from
GREASE entries. Preserve real preference order and never insert an absent
extension solely to satisfy this option. Pool identity includes the selected
policy, not its fresh random values. Use existing copied configuration paths.

Acceptance: independent decoding verifies reserved-value class, position and
vector lengths; sync/async complete authenticated TLS1.3 and TLS1.2 fallback;
illegal server selections fail before application data. Exercise affected HRR,
resumption/binder and copied-config/pool paths. Do not add unrelated cipher or
extension work after this batch reaches its boundary.

Exit: both selected wire differences are demonstrably configurable and the
handshake remains functional. Verify a final installed artifact; refresh the
browser comparison when making an updated browser-matching claim.

## 6. B3 / C17: Session headers/params defaults

Refresh [the existing design](session_defaults_design.md) against 2.4.0 bytes
headers, prepared snapshots and redirect behavior. Reuse its proposed
`session.request_defaults` assignment API on both clients. It remains a proposal
until this batch is selected and implemented.
Implement at the existing [Session](../ja3requests/sessions.py) and
[AsyncSession](../ja3requests/async_sessions.py) preparation boundaries; the linked
design's old line numbers and GET-only redirect description are historical.

Scope: headers and structured query defaults only. Unconfigured Sessions retain
their existing behavior. Omitted/None per-call fields use configured defaults;
explicit empty fields bypass that field's configured defaults; explicit values
win. Header matching is case-insensitive, query pair order/repeats are preserved,
and raw query input retains its existing path. Keep the existing design's
restricted default header names and string-pair storage; request arguments keep
their current broader types. Validate atomically and expose detached snapshots.

Merge once at initial `request()`/preparation. Prepared send, retries and redirects
must retain that snapshot and must not reinsert headers stripped by hooks or an
origin change. Do not read legacy Session observation properties/last Request.
Add no auth/proxy/Cookie/body/timeout defaults, deletion sentinel or new constructor
framework. Follow existing helpers rather than refactoring both transport stacks.

Acceptance: sync/async precedence, empty/None, duplicate query pairs, byte-valued
headers, caller mutation, invalid replacement, prepared resend/concurrent sends,
hooks and cross-origin stripping. Independent HTTP1/H2 peers observe the merged
request. Installed consumer typing and docs match the additive API.

Exit: repeated calls can share explicit header/query defaults with deterministic
snapshots and no change for unconfigured Sessions. One installed acceptance
closes this batch; a browser capture is unnecessary.

## 7. B4: align the remaining redirect method policy

Recommended compatibility decision: match existing async policy in synchronous
301/302/303 handling, with a documented default correction. A separate mode is
justified only by a demonstrated consumer requiring the old behavior.

| Status | Target policy for both clients |
| --- | --- |
| 301/302 | POST becomes GET with no entity body; other methods retain method/body |
| 303 | HEAD retains method/body; other methods become GET with no entity body |
| 307/308 | Preserve current released method/body/replay behavior |

Change [sync redirect handling](../ja3requests/sessions.py) against the existing
[async policy](../ja3requests/async_sessions.py). Reuse current replay sources,
entity-header cleanup, hooks, route/TLS inheritance
and cross-origin credential stripping. A preserved one-shot source must fail
deterministically before a second send when replay is unavailable. No duplicate
or partial upload is accepted as successful replay. No general redirect-policy
engine, timeout overhaul or proxy parser rewrite belongs to this batch.

Acceptance: method/status matrix at the policy boundary, plus representative
HTTP1/TLS/H2 peers for retained and rewritten bodies, replayable/one-shot sources,
cross-origin hops, hook edits and resource release. Reuse existing proxy/replay
regressions; do not multiply every independent case into one Cartesian matrix.
Document concrete before/after examples such as PUT -> 302 and HEAD -> 303.

Exit: the selected method/body policy matches both clients, with migration text
and installed acceptance. Assess compatibility/version impact if publication is
later selected; this plan does not choose the next release number.

## 8. Conditional register

Select these independently from actual consumer needs. They do not gate B0-B4.

| Candidate | Minimum entry / bounded result |
| --- | --- |
| T2: missing TLS suite/signature | One exact algorithm/key combination, available primitive and capable independent peer; force negotiation, verify authentication/Finished/records and reject unoffered/malformed selections. TLS1.2 ChaCha is a concrete candidate; do not relist working TLS1.3 ChaCha or ECDHE/GCM. |
| T3: TLS extension | One understood extension, e.g. certificate compression or ALPS, current official specification and a capable peer; positive/negative negotiation, transcript, fallback and bounded parsing. Opaque captured payloads stay observations. |
| ECH / hybrid PQ | Named target, dependency/primitive feasibility, key/state contract and real independent interoperability. Separate feasibility from implementation; no copied keys or static payload impersonation. |
| HTTP-date Retry-After | Shared date parsing with deterministic clock tests, past/invalid values and unchanged numeric compatibility; verify sync/async waits and cancellation without real long sleeps. |
| Public response trailers | Define availability after EOF/early close and immutable validated data; HTTP1/H2 and sync/async parity using current incremental readers. |
| Async module helpers | Begin with eager responses; read fully and close the temporary Session on success/error/cancellation. Streaming needs a separately selected owning-context contract. |
| Streaming prepared requests | A named inspection/signing workflow; define source I/O, digest timing, single/repeated send and ownership. Reuse upload sources; keep buffered prepared bytes and independent resend unchanged. |
| Proxy expansion | Choose environment/NO_PROXY or TLS-to-proxy as separate increments; freeze precedence/routing or proxy-vs-destination certificate policy. No blanket proxy subsystem rewrite. |
| Timeout unification | Name the conflicting behavior and migration; preserve native cancellation and phase budgets. A total deadline requires its own explicit contract. |
| Internal typing | One useful module/diagnostic slice, existing runtime behavior and installed consumer checks; no mandatory package-wide rewrite. |
| Docs hosting / performance CI | Choose a host/version policy or runner/workload/comparison policy. Reuse MkDocs/bench tools; verify published routes or raw benchmark samples. Start performance reporting before thresholds. |
| Additional platforms | Name Python/OS/architecture and dependency feasibility; run installed network acceptance there. Current Ubuntu 3.7-3.13 CI is not all-platform evidence. |
| Cross-process TLS sessions | Restart use case, secret storage, trust binding, expiry/version/concurrency and corruption recovery. Cookie persistence is already delivered. |
| H2 scheduling / push | Separate consumer workloads. Scheduling needs fairness/starvation evidence; push needs an ownership/cancellation API. Existing PRIORITY emission is signaling, and push stays disabled until supported. |
| 0-RTT / HTTP3-QUIC | Separate projects: eligible operations and replay/rejection rules for early data; protocol ownership and handshake/transport/HTTP interoperability for QUIC. |

## 9. Verification, evidence and delivery

During development run only focused checks for changed behavior and its failure
boundaries. Add tests for meaningful gaps. Once a selected runtime batch is
stable, freeze one candidate and run the existing tools; do not create another
build/verification framework.

```sh
.venv/bin/python -m pytest -p no:cacheprovider test --ignore=test/test_session.py tools/tests -q
.venv/bin/python -m mypy
```

Run Black on changed Python files, package error-level lint and `git diff --check`.
Strict docs use the existing commands in [the docs guide](../docs/contributing_docs.md)
and an owned temporary site, followed by `docs/verify.py`. Preserve pinned history.

Final local runtime acceptance uses [the existing verifier](../tools/README.md):
`tools/verify_release.py --repo . --worktree-snapshot --include <new-untracked-input>
--output <new-evidence-directory>`, using `.venv/bin/python`. Omit `--include`
when there are no new untracked inputs; repeat it for each selected untracked
regular file, never a tracked file, directory/glob or unrelated file.
Alternatively, after an authorized commit, use `--ref <exact-commit>`.
Check the reported inventory against selected source and all new build/test inputs.
The sdist-to-wheel installation, metadata/module hashes, public types, installed
tests and existing >=85% coverage gate must pass. Grammar checks do not substitute
for Python 3.7 runtime acceptance.

| Batch | Additional required final evidence |
| --- | --- |
| B0 | Link checks, and strict docs/examples when affected |
| B1 | Profile-default installed TLS/H2 traces plus the selected live browser series; no masked preset fields |
| B2 | Capable independent installed sync/async peers for affected vectors/handshake paths; browser refresh for new matching claims |
| B3/B4 | Installed tests including the selected independent HTTP1/H2 behavior; no unrelated browser sampling |

Evidence records actual source kind/SHA or snapshot, wheel/hash, interpreter,
peer/browser version, exact inputs, received bytes, results and cleanup. Old
2.4.0 evidence remains baseline-only after relevant code changes. A later code
change invalidates affected acceptance; bookkeeping alone does not require a
rebuild. Source equality and test count alone do not prove fingerprint parity.

If commit/push/release is later selected: inspect precise file scope and current
remote state, assess version impact, verify the final commit/artifact and actual
CI, then publish only the selected channels and compare public downloads/install.
Do not label local acceptance as hosted CI or publication.

## 10. Recovery, cleanup and completion

After two attempts without narrowing a cause or advancing delivery, choose a
safe alternative, finish independent selected work or report the precise missing
dependency. A missing browser/primitive/peer blocks its affected card, not the
whole backlog. Retain failed evidence; never weaken assertions to obtain a pass.

Use fresh task-owned temporary roots and new evidence output paths. Remove owned
profiles, CA/private keys, probe venvs, listeners and process/thread resources
after capture; remove docs/verifier staging after readback. Retain source
manifests, artifacts, reports and failure evidence. Do not clean historical dist,
user files or shared resources. Preserve partial remote state and inspect before
retrying any later authorized publication; no force push or tag replacement.

A selected implementation batch is complete only when its stated behavior,
failure checks, installed acceptance, affected docs/types, evidence and cleanup
are complete. Record residual optional gaps separately. Close only the selected
workline; future candidates remain unselected rather than unfinished gates.

## 11. Planning delivery checklist

- [✅] Reconcile 2.4.0 release/source/capture evidence and current code boundaries.
- [✅] Identify the collector override issue before defining preset acceptance.
- [✅] Define order, scope, dependencies, compatibility and exit criteria.
- [✅] Carry forward identified remaining candidates with bounded entry conditions.
- [✅] Check plan links, command paths and consistency with linked contracts.
- [✅] Update previous roadmap entry links and review the final documentation diff.

Planning verification, 2026-10-15: all 54 relative links across these three
planning documents and nine command/evidence paths resolved. Tracked-document
`git diff --check` passed; all three files passed trailing-whitespace and final
newline checks. Review reconciled defaults with the linked proposal and redirect
policy with the current clients. No runtime tests, build or new browser capture
was needed or claimed for this documentation-only delivery.

The planning checklist records the earlier design delivery. Current B0/B1/B4
implementation state is tracked in the fixed execution checklist at the top.
Registration remains unavailable as recorded above; no successful lifecycle
transition is claimed.
