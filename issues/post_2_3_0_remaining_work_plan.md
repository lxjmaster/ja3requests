# Remaining work: solution and execution plan

Prepared: 2026-10-13. Status: **PLANNING COMPLETE / SELECTED IMPLEMENTATION COMPLETE**.

Execution selected: 2026-10-13. R, H1, H2 and their D acceptance are now authorized;
follow [the execution record](remaining_work_execution.md). Conditional packages
and publication remain unselected. Earlier planning-only statements are history.

Selected execution completed: 2026-10-13. R, H1 and H2 are implemented and locally
accepted against the final installed candidate. The execution record contains
the source, artifact, independent-peer, documentation and cleanup evidence.
Sections 4-6 retain the selected implementation contracts; later conditional
packages remain proposals and are not completion gates for this delivered batch.

Post-review source corrections completed: 2026-10-13. The three redirect
findings were fixed and the current full source suite passed 3,910 tests.
See [the correction evidence](remaining_work_execution.md#post-review-source-corrections).
The earlier installed candidate remains a historical snapshot; no replacement
package or new browser capture was produced for this correction task.

Review correction: 2026-10-13. Narrow redirect migration and HEADERS priority,
reuse the existing TLS difference report, and select acceptance peers by capability.

The execution instruction selects R, H1, H2 and local D acceptance. It does not
authorize commit, push, publication, deployment or remote Issue changes. This document is the
current planning entry point; the [previous fingerprint execution record](post_2_3_0_execution_plan.md)
retains completed F1/F2 history. `h2_headers_priority` and
`TlsConfig.h2_indexing_exclusions` are implemented in the current source and
unpublished local candidate. Other proposed option names remain design proposals.

Registration: **UNREGISTERED**. The supported `codex-plan --json status` command
reports that an official session identity requires a fresh PreToolUse binding.
No session identity was invented and no registry transition is claimed. The file
plan remains usable. Planning completion is separate from implementation;
the selected engineering packages are complete in the execution record. No
successful registry transition is claimed.

## 1. Outcome, baseline and evidence boundaries

Deliver functioning project-owned TLS handshakes, key derivation and encrypted
records, with independently observable TLS/H2 controls and explicit sync/async
contracts. Reuse the existing engines, upload sources and verification tools.
Keep native async I/O, authenticated defaults and Python >=3.7 compatibility.
Do not introduce an OpenSSL client backend, a fingerprint plugin framework or a
combined rewrite of sessions/transports.

| Existing outcome | Disposition for this plan |
| --- | --- |
| Local HEAD `422012063f4ed12e23bda330c38355566d6d373d`, versioned baseline 2.3.0 | Starting identity, not the identity of the dirty worktree; public endpoints were not refreshed in this planning pass |
| TLS1.2/1.3, resumption/HRR, native async, H2 multiplexing, request/response streaming, async files/Cookies, buffered async preparation | Already implemented; do not reopen as new work |
| F1 collector and Chrome 155/macOS evidence | Completed for the recorded target/scenario; preserve raw samples and provenance |
| F2 outbound Huffman | Implemented and historically accepted against its own installed candidate; do not implement it again |
| Four synchronous fixes: proxy SNI isolation, real HTTP/1.1 ALPN/pool selection, current-request redirect policy, tunneled TLS connect timeout | Present with regressions/docs; preserve them through subsequent changes |
| Handoff result: 3,708 tests passed, one existing collection warning, Python 3.13 | Historical source-test result supplied in the handoff, not rerun for this plan and not installed-package acceptance |
| `dist/verify-huffman-candidate-01/` and `dist/fingerprint-huffman/capture-01/` | Historical pre-fix snapshots; do not claim they validate the current source |
| Original combined R/H1/H2 candidate | Installed acceptance and independent H2 probe passed for their retained snapshot; later source corrections have separate evidence in the execution record |

Read `git status` and overlapping diffs again at execution intake. Distinguish
feature-owned source/tests/docs from `.idea/`, `.DS_Store`, user debug scripts,
old release records and other concurrent changes. A dirty-worktree snapshot is
not automatically a selected commit set. Preserve all unrelated edits.

## 2. Material decisions and recommendations

| Choice | Viable approaches | Recommendation and consequence |
| --- | --- | --- |
| Sync redirect compatibility | Correct 307/308 defaults with migration documentation; or preserve the old behavior through an explicit option where a concrete consumer requires it | The selected execution accepts the default correction. Determine the publication version under separate publication authority; add a compatibility option only for a demonstrated consumer need |
| HEADERS priority placement | Connection-level fixed priority; or per-request metadata | Per-request weight/exclusive tuple with dependency fixed to 0. It covers the captured HTML/image weights on one connection and can survive reconnects. Do not split pools by request weight |
| HPACK indexing control | General callback/rule engine; or a copied set of literal-insertion exclusions | Start with named-field exclusions. It covers the observed path difference without user callbacks inside shared compression state |
| Browser target | Promise complete identity before missing negotiations exist; or publish one measured supported subset | Select an explicit version/platform and matched-field list. Full identity requires all essential negotiations and remains a different completion boundary |
| Verification cadence | Rebuild/retest everything after every intermediate edit; or focused checks followed by one final acceptance per selected batch | Use focused checks during development, then bind installed tests and capability-appropriate peer evidence to one frozen candidate. Browser sampling follows the selected comparison need; relevant later changes invalidate affected evidence |

The HTTP semantics reference is [RFC 9110, Section 15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4).
The HEADERS priority representation is retained for interoperability while the
old priority signaling scheme is deprecated in [RFC 9113, Sections 5.3 and 6.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.3).
H1 below is a wire-fingerprint control, not a scheduling or performance promise.
HPACK distinguishes insertion-free literals from never-indexed literals in
[RFC 7541, Section 6.2](https://www.rfc-editor.org/rfc/rfc7541.html#section-6.2).

## 3. Batches and dependencies

R, H1, H2 and their local D acceptance are selected by the execution instruction.
Other engineering rows remain proposed. A later instruction may select one row
or a named batch without selecting the register.
Do not require completion of optional lanes before delivering a selected batch.

| Package | Deliverable | Dependency / exit boundary |
| --- | --- | --- |
| R | Sync 307/308 default method/body preservation and replay-safe ownership | Default correction accepted; actual method/body/cleanup tests, migration docs and D acceptance |
| H1 | Per-request HEADERS weight/exclusive fields across sync/native async; dependency 0 | Current H2 engines; exact frame/continuation/stream-state tests and D acceptance |
| H2 | Optional HPACK literal-insertion exclusions | Existing Huffman/encoder; independent table/byte/reuse checks and D acceptance; H1 is not a code prerequisite |
| T1-T3 | One selected TLS control or negotiation at a time | Reuse F1's report and confirm only the chosen field, current implementation and capable independent peer; complete authenticated exchange and D acceptance |
| F3 | One explicit capture-calibrated supported-subset profile | Only H1/H2/T cards required by its matched-field list; installed candidate capture and D acceptance |
| C17 | Opt-in Session headers/params defaults | Refresh existing design; snapshot/precedence/origin tests and D acceptance |
| A3-S | Explicit stream-preparation/signing extension | Named consumer workflow and source/signature contract; existing ordinary uploads are sufficient otherwise |
| E / L register | Engineering conveniences and long-term protocol work | Entry conditions in Section 11; select independently |
| D | Final local delivery acceptance for the selected batch | Frozen selected source, installed verification, affected docs/types/captures and cleanup |

Selected local sequence completed: **R -> D**, then **H1 + H2 -> D**, with one
final combined candidate superseding intermediate acceptance. These were two
reviewable batches, not a hard dependency of fingerprint work on redirects.
Future execution requires a separate selection: one TLS card with its focused
precheck, F3 for an explicitly bounded subset, C17 or A3-S. None is selected by
completion of this sequence.
If the next instruction selects delivery of the existing changes only, go
directly to D; none of the new features is a delivery prerequisite.

Work remains serial and no subagents are created, following the user's current
instruction. Independent read-only checks may run together. Use the main agent
to review ownership, validation timing and partial-write failure boundaries.
Do not promise a calendar estimate before the selected contract and peer are
known; package exit criteria, not elapsed effort, determine completion.

## 4. R: synchronous 307/308 redirect semantics

The former synchronous bodyless-GET behavior and its migration are documented in
[the streaming guide](../docs/streaming.md); the corrected behavior is covered by
[redirect regressions](../test/test_sync_redirect_review.py). Changing that default
has a compatibility impact; the execution instruction accepts the default
correction. A publication version remains a separate release decision.

Correct the default for 307/308 once with migration documentation.
R's default change is accepted by the
execution instruction; the actual publication version will be chosen only when
publication is separately authorized.
Do not add `redirect_policy=legacy/standard` preemptively. If a concrete consumer
must retain the old behavior, revise this card with a bounded compatibility option
and its retention/removal contract before implementation. Native async keeps its
current behavior. `allow_redirects=False` continues to disable following.

First-batch method/body matrix:

| Response | Follow-up behavior |
| --- | --- |
| 307 / 308 | Retain method and actual prepared body; require replay if a source was consumed |
| 301 / 302 / 303 | Retain the current synchronous behavior; do not expand this batch into a complete redirect-policy rewrite |
| No supported redirect / no Location / following disabled | Existing response behavior |

This establishes default sync/async agreement for 307/308 only. Other method/status
differences remain documented; this batch does not promise complete redirect parity.

Implementation anchors: [Session.send/resolve_redirects](../ja3requests/sessions.py),
[request preparation](../ja3requests/requests/request.py),
[UploadSource](../ja3requests/_upload.py), [upload ownership](../ja3requests/sockets/_upload.py)
and [public option types](../ja3requests/_typing.py).

1. Carry the actual redirect status through both ordinary and exhausted-retry
   paths. Derive each next hop from the current post-hook transport request;
   retain proxy-route snapshots, TLS policy, connect/read timeout and `h1`.
2. Preserve the encoded body, including buffered forms/JSON/multipart, rather
   than rereading a consumed caller input or changing multipart boundaries.
   Recompute destination authority and managed Cookies; strip cross-origin
   credentials and remove entity headers only when the body is discarded.
3. Stop/join the previous upload producer before replay. Transfer the surviving
   source's ownership before response closure or the enclosing send's finalizer
   can close it; rewind only the source that survives the next hop's hooks.
   Reject a consumed non-replayable source with `StreamConsumedError` before
   sending the destination request.
   Do not close caller-owned files or let two producers read one source.
4. Release each response/pool lease exactly once. Preserve unrelated H2 streams,
   hook order, retry eligibility and bounded redirect limits. Reuse existing
   cleanup paths; do not unify the entire sync/async dispatcher.

Acceptance: buffered POST/PUT/HEAD, replayable files at a nonzero initial offset,
consumed iterators, multi-hop/mixed statuses, same/cross origin and scheme,
direct `send()` without Session history, hook-replaced requests/bodies, retries,
HTTP1/H2, early responses and exceptions. Include unchanged 301/302/303 behavior
and following-disabled cases. Observe method/body bytes at an independent peer,
source read/close counts and surviving pooled requests.
Reuse [sync redirect regressions](../test/test_sync_redirect_review.py),
[sync upload tests](../test/test_sync_upload.py),
[network uploads](../test/integration/test_sync_upload_network.py) and async
comparisons. Run direct/CONNECT/SOCKS regression coverage for touched routing
paths without multiplying every case into a full Cartesian product.

## 5. H1: request HEADERS priority

Implemented per-request `h2_headers_priority=None | (weight, exclusive)`.
`None` keeps current bytes; a supplied tuple always encodes dependency 0.
Both captured requests use that dependency, with weights 256 and 183. This first
card adds no connection-level default, scheduler, URL classifier or callback
system. Arbitrary nonzero dependencies need a concrete use case and a separate
connection-scoped contract; stream identifiers cannot be inherited across connections.

- Carry a copied tuple through high-level calls, prepared snapshots, direct
  sends, hooks and uploads. Preserve it across a request's retries/redirects
  unless a supported request mutation replaces it; document this behavior.
  Dependency 0 remains valid when a retry/redirect uses a new connection.
  Treat it as H2-only metadata with no effect when HTTP1 is negotiated.
- Validate the two-field tuple shape, integer weight 1..256 (reject bool-as-int)
  and boolean exclusivity before source consumption or stream/HPACK mutation.
- Extend [HEADERS construction](../ja3requests/protocol/h2/frame.py) and the
  shared [_header_frames path](../ja3requests/protocol/h2/connection.py).
  Account for the five priority octets in the first frame's payload capacity;
  CONTINUATION frames use the normal capacity and never repeat those fields.
  Preserve END_STREAM/END_HEADERS and atomic header-block write ordering.
- Keep per-request priority out of the pool key: weights 256 then 183 must
  coexist on the same connection. Existing TLS/connection policy partitions
  remain intact. Initial standalone PRIORITY frames retain their separate API.
  Update the fingerprint guide to distinguish request metadata from its current
  blanket statement that H2 configuration participates in pool identity.

Acceptance: captured weights/dependency/exclusive bit, explicit absence, empty
and split header blocks at peer frame-size boundaries, request streams 1/3,
sync serial/multiplexed and native async, ordinary/prepared/upload entrypoints,
HTTP1 fallback, new-connection retry/redirect, invalid metadata and cancellation
before/after write commitment.
Once a shared HPACK/TLS write is committed, preserve the existing all-or-fail
connection rule rather than pretending encoded state can be rolled back.
Use the existing [H2 network suite](../test/integration/test_h2_fingerprint_review.py)
and independent received-frame decoding. Prove unrelated streams survive local
input rejection. Bind the final selected fields to D's installed candidate.

## 6. H2: HPACK literal-insertion exclusions

Implemented `TlsConfig.h2_indexing_exclusions` as a validated, copied sequence of
field names, with an empty default retaining current behavior. Normalize it to
an immutable identity for the encoder and pool policy. Support the required
pseudo-header names as well as ordinary field names; reject malformed inputs
before network/source/HPACK state changes. No per-request indexing callbacks.

The rule suppresses dynamic-table insertion for matching **new literals**.
Existing exact static/dynamic index references remain usable. Sensitive literals
retain never-indexed handling; exclusions cannot opt them into indexing.
Huffman remains independently controlled by `h2_huffman`.

This distinction matters for `:path`: the first `/` can retain its static index,
while the captured second `/pixel.png` uses a literal without insertion. Reuse
[HPACKEncoder](../ja3requests/protocol/h2/hpack.py) in all three H2 send engines.
Changed exclusions select another pooled connection; unchanged policy reuses
the connection and dynamic table. Do not reset tables per request.

Acceptance: empty-policy byte compatibility; independent decoding; raw/Huffman
combinations; sensitive fields; caller/config mutation isolation; invalid inputs;
peer table reduction/growth and zero-size table; first/second/third requests;
serial/multiplexed/native async and prepared/upload paths. Recheck the recorded
browser/client table-size difference (20 versus 21 entries after request two)
against equivalent inputs, without claiming all browser indexing is inferred
from two requests. Update the existing collector assertions narrowly and use
D's final candidate for the selected matching claims.

## 7. T1-T3: TLS differences with functioning negotiation

Reuse the existing [received-byte report](tls_h2_capture_results.md) and
[TLS wire contract](../docs/tls_wire_control.md); do not deliver another complete
TLS inventory as an independent T0 batch. Before a selected card starts, confirm
only its exact required field, current encoding/negotiation boundary and a peer
that can exercise it. Record those three facts in the card's implementation scope.
Consult current official specifications for that selected capability; numeric IDs
and opaque capture payloads alone are insufficient. An OpenSSL/Python ssl server
is suitable only if it supports the selected version, algorithm or extension.

| Card | Minimal solution | Required evidence / stop condition |
| --- | --- | --- |
| T1: GREASE shapes | One explicit, bounded policy for the selected vectors/extension slots; preserve existing default presets and generate fresh values | Actual sent shapes/lengths and valid TLS1.2/1.3 exchange; reject invalid server selections; preserve HRR/resumption/ALPN invariants and pool-policy identity |
| T2: missing suite/signature | Select one exact algorithm/key combination and reuse available cryptographic primitives in the project handshake/record engine | Independent peer forces it; certificate/signature checks, Finished/key schedule and encrypted records work; malformed/unoffered selections fail. No ID-only support claim |
| T3: extension behavior | One understood extension, such as a specifically required compression or application-settings behavior, with its server-state contract | Positive/negative negotiation, transcript and fallback tests; bounded parsing and fragmented reads. Opaque/unknown fields stay documented until understood |
| C13: ECH / hybrid post-quantum group | Separate feasibility, primitive/dependency, key/state and interoperability design | If the essential primitive or peer is unavailable, block only this card; do not copy captured keys/payloads or label it working |

Only run HRR/resumption/fallback/cancellation expansions that the selected change
can affect; preserve existing regressions. All selected TLS runtime cards require
real authenticated sync/async exchanges and D acceptance. Missing full-browser
negotiations do not prevent delivery of a separately selected H2 control.

## 8. F3: explicit supported-subset browser profile

Select one browser version/platform and the exact promised fields before editing
[browser presets](../ja3requests/protocol/tls/browser_presets.py). The retained
Chrome 155.0.8059.39/macOS samples are historical target evidence, not a claim
about the currently installed browser. Verify the executable at capture time.
If it updated, retain the old fixture and label new observations by their actual
version; never silently relabel them as 155 or reopen F1 solely due to an update.

Freeze the matched TLS/H2 fields, request-supplied headers/priority metadata,
randomization policy and unresolved negotiations. A profile configures reusable
defaults; it does not infer page/image priorities or application headers from a
two-request capture. Keep old explicit profiles and implicit Chrome 124 selection
unless a separate migration is selected. Required H1/H2/T cards follow this
field list; full TLS parity is not a prerequisite for an explicitly limited subset.

Verify successful installed sync/async TLS/H2 bodies, connection reuse, changed
connection-policy isolation, independent received bytes and every declared field
against the same final wheel/source. Reuse recorded vectors where appropriate;
live comparisons require the selected available target. Do not claim full Chrome
identity, randomized-order distributions or external anti-bot success.

## 9. C17 and A3-S: client API extensions

C17 starts by updating the [existing headers/params design](session_defaults_design.md)
against current byte-header and prepared-request behavior. Keep the proposed
`request_defaults` assignment API and its limited fields. Omitted/None uses
defaults, explicit empty bypasses them, explicit structured values override them;
raw query values retain their current path. Preserve duplicate query pairs and
case-insensitive header precedence, validate before atomic replacement and
return detached snapshots. Do not add auth/proxy/Cookie/TLS/body defaults.
Merge once at initial request execution/preparation, never from live defaults
again at prepared send, retry or redirect. Test both clients, hooks, origin
stripping, concurrent prepared reuse, byte values, invalid assignment and caller
mutation. Update installed consumers/docs and run D for the selected batch.

A3-S requires a workflow that actually needs inspection/signing of a stream.
Recommend a separate explicit stream-preparation entry rather than changing
buffered `AsyncPreparedRequest.body` from immutable bytes to a mutable source.
Keep the name provisional until its public contract is frozen. Preparation copies
metadata and binds the source without reading/seeking/network I/O. A supplied
digest remains caller-computed; do not secretly pre-read or buffer the stream.
Body-dependent automatic signing needs a separately selected I/O contract.

Start with single-send ownership, deterministic consumed-source errors and no
concurrent sends of one source. Add sequential resend only where explicit replay
capability and successful rewind are established. Open library-owned paths at
send, retain caller-file ownership, and define early close, failed send, Session
close and cancellation before exposure. Reuse existing source/transport paths;
preserve the buffered API's independent concurrent resend. Acceptance includes
HTTP1/H2, length/chunking, signatures at the peer, source counts and cancellation
during read/admission/write/response. Ordinary uploads remain available meanwhile.

## 10. D: final verification and delivery boundary

1. Freeze the selected batch scope. Inspect all tracked modifications and list
   feature-owned untracked inputs explicitly; include new tests, fixtures,
   `requirements-capture.txt` and collector/tool tests when part of the batch.
   The existing verifier freezes all tracked current bytes, so use a scoped
   snapshot/check-out when unrelated tracked edits would contaminate the result.
   Preserve the user's working tree; do not reset it to obtain a clean build.
2. Run the smallest relevant success/failure tests during implementation. At
   final integration, use the project suite, excluding only the documented old
   external-service manual test:

   ```sh
   .venv/bin/python -m pytest -p no:cacheprovider test --ignore=test/test_session.py tools/tests -q
   ```

3. Reuse [verify_release.py](../tools/verify_release.py) for the frozen source,
   sdist-to-wheel build, independent installed tests, existing >=85% coverage
   gate, metadata/dependencies, source/artifact hashes and installed type checks.
   Use `--worktree-snapshot` with reviewed repeated `--include` arguments for
   untracked files, or `--ref` for an authorized committed candidate. Read current
   help and choose a new, nonexisting `--output` directory. Do not invent a
   second release pipeline or upload artifacts from this local verification step.
4. Run affected formatting/error-level lint, configured strict typing and
   installed valid/invalid consumers. Build MkDocs strictly, run `docs/verify.py`
   and affected executable examples. Python 3.7 grammar is syntax evidence only;
   record actual runtime checks. Before a release, require the configured
   Python 3.7-3.13 CI matrix on the final selected commit under delivery authority.
5. Bind capability-specific independent peer evidence to the exact verifier
   wheel, source hashes and installed module origins, using the matrix below.
   All H2/TLS batches need actual received bytes and completed authenticated
   requests. Select a peer that can exercise the changed capability; a browser
   capture is not mandatory for every batch. Baseline captures cannot stand in
   for changed candidate behavior.
6. Record source/command/environment/counts/skips/warnings and cleanup honestly.
   Re-read hashes and retained reports. Re-run a successful gate only after
   relevant changes, new failures or an unresolved concern; record/document-only
   closeout does not require repeating an unchanged protocol capture.

| Selected batch | Evidence from the final installed candidate |
| --- | --- |
| R | HTTP1/H2 peers observe methods, bodies and destination policy; replay/source/response ownership checks pass. No browser sampling is required |
| H1/H2 | Independent frame/HPACK decoding observes the selected priority/indexing bytes, authenticated bodies, reuse and table continuity. Installed network tests can supply this evidence; retained F1 browser vectors supply the comparison target |
| T1-T3 | A capable independent peer forces the selected version, algorithm or extension and verifies the negotiated result, authenticated records and relevant failure paths. Add TLS1.2, HRR or resumption cases only where the selected change can affect them |
| F3 / new browser target / refreshed browser comparison | Corresponding target-browser samples and sync/async candidate traces under equivalent peer/request inputs verify every declared matching field. Preserve the actual browser version and unresolved differences |

The existing [capture_fingerprint.py](../tools/capture_fingerprint.py) is a full,
non-resumed TLS1.3/H2 collector with server tickets disabled. It cannot validate
TLS1.2 algorithms or session resumption. Reuse it when the selected comparison
fits that scenario, with the exact wheel, `--wheel-sha256`, `--artifact-report`,
selected `--client-profile` and a fresh output directory. Existing `--h2-huffman`
is supported; implement/test only the new overrides or assertions that the
selected comparison requires. Other TLS capabilities use appropriate peers;
do not generalize the collector into a universal protocol-verification framework.
Routine H1/H2/T increments need no fresh Chrome series unless their selected
acceptance requires new browser evidence.

This yields a locally accepted, reviewable batch. Commit/push, Issue writes,
hosting and publication need their own user-selected action set. When publication
is selected, determine version and exact file scope from the actual compatibility
impact, verify the final commit/build, and read back installed/downloaded artifacts
from each selected destination. Earlier release authorization does not carry over.

## 11. Remaining engineering and long-term register

These are concrete candidates, not prerequisites for R/H1/H2/F3 delivery.

| ID / task | Entry and minimal solution | Acceptance |
| --- | --- | --- |
| C06 internal typing | One named diagnostic/module needed by maintenance or a selected feature; no package-wide type rewrite | Strict module/dependency slice, unchanged runtime tests, installed consumers; report remaining diagnostics separately |
| C01 documentation hosting | Select host, URL, version policy and deployment authority; reuse current MkDocs output | Public routes/assets/version and recovery readback; local docs CI is already delivered |
| C02 performance CI | Select fixed runner/workloads/comparison policy; reuse existing measurements/tooling | Record raw samples, variance and observed connection/protocol paths; start reporting without invented speed gates |
| A4 async module helpers | Select an eager convenience workflow; temporary Session reads response fully before closing | Success/error/cancellation cleanup; reject streaming-return use until a Session-owning context API is explicitly designed |
| HTTP-date Retry-After | Consumer needs date-form retry; parse supported HTTP dates with existing retry budgets | Controlled clock, past/malformed values, numeric compatibility and deterministic delay bounds |
| Public response trailers | Consumer needs post-body fields; expose validated immutable trailers at completion | Define availability before EOF/after early close; HTTP1/H2 and sync/async parity without changing incremental body semantics |
| Issue reconciliation | Authorized readback of the historical #36/#37/#40/#41/#42 acceptance and released evidence | Update only selected remote Issues; resolve #41's unverified 1 GiB/whole-process memory wording through agreed criteria or measurements, never silently weaken it |
| C07 additional legacy suites | Exact consumer suite and independent peer; reuse T2 negotiation discipline | Authenticated key schedule/Finished/records; no default downgrade |
| C08 cross-process TLS sessions | Restart use case plus selected secret storage/expiry/trust/concurrency contract | Versioned storage, atomic writes, expiry/trust isolation and safe corruption recovery; Cookie persistence is already implemented |
| C09 H2 scheduling | Named fairness/latency workload; explicit scheduling/starvation bounds | Concurrent slow/fast streams and flow-control/cancellation evidence; priority frame emission alone is insufficient |
| C10 server push | Named consumer API and bounded ownership/cancellation design | Valid/rejected push, reset, limits and connection cleanup; retain disabled behavior until supported |
| C11 0-RTT | Explicit eligible operations and replay/rejection/retry policy | Accepted/rejected early data and replay-safe effects; C08 is required only if cross-process tickets are selected |
| C13 ECH/post-quantum | Named target, available primitive/peer and separate protocol design | Selected TLS-card precheck plus real independent negotiation; never advertise unsupported capability as functioning |
| C15 HTTP3/QUIC | Named target and explicit project protocol-ownership/dependency boundary | Separate handshake/transport/HTTP interoperability plan; not an H2 extension or wrapper shortcut |
| C16 added runtime/platform | Named environment and dependency feasibility | Installed runtime/network acceptance there; metadata, grammar checks and skipped cases do not establish support |

## 12. Failure handling, recovery and retention

- After two attempts without narrowing a cause or advancing delivery, use an
  independent safe check, smaller supported path or report the exact dependency.
  Missing a browser/primitive blocks its dependent card, not unrelated packages.
- A required defect in the selected batch must be fixed/verified or mitigated
  within authorization. Optional findings stay in the register; do not turn them
  into hidden release gates. No self-acceptance of a gating residual risk.
- Preserve original source edits and all historical release/capture evidence.
  Keep accepted reports, fixtures, exact tool/source identities and artifacts as
  deliverables. Retain failed attempts only when useful reproduction evidence,
  and label them as failed/superseded.
- Use task-owned temporary build/install roots, loopback peers and isolated
  browser profiles. Remove owned listeners, threads/tasks/process descendants,
  CA/private-key staging and temporary installs after evidence retention; verify
  ownership and actual absence. Do not clear `dist/`, user profiles or shared
  infrastructure. Do not retain traffic secrets in portable fixtures.

## 13. Historical planning completion checklist

This checklist records the completed planning outcome. It does not establish
implementation completion; selected R/H1/H2/D work follows the execution record.

- [✅] Inspect current worktree/instructions and distinguish completed work from candidates.
- [✅] Ground contracts and material choices in source, existing designs and protocol specifications.
- [✅] Define package order, independent dependencies, acceptance, recovery and retention for all remaining categories.
- [✅] Reconcile current roadmap/evidence pointers and check changed document links, whitespace and source preservation.
- [✅] Apply review corrections and verify current links, document formatting and preservation of unrelated changes.

Initial remaining-work planning verification on 2026-10-13: all 90 relative file
links across the five planning/evidence Markdown files resolve; code fences, conflict-marker absence,
final newlines and trailing whitespace checks pass. `git diff --check` passes.
The non-planning tracked diff SHA-256 is unchanged before/after this task:
`411514d2e3c8fe4fb093ccc32e1a9bd4e0a3f953e9e9ad2abcefe2f45c4b048f`.
Existing runtime/test changes and raw artifacts were not edited.
No runtime tests, builds, new captures or remote writes were performed for this
documentation-only outcome. No task-owned temporary artifacts require cleanup;
the five documents are retained deliverables. File-plan registration remains
UNREGISTERED for the official-session binding limitation recorded above.

Review-correction verification on 2026-10-13: all 92 relative file links across
the same five documents resolve; code fences, conflict-marker absence, final
newlines, trailing whitespace and `git diff --check` pass. Three planning documents
were amended. The current non-planning tracked diff SHA-256 is unchanged:
`b74a525f68f99ab5ff902a69c741a9581a8d8bba90dfdf6ad1048458677a5d42`.
The aggregate untracked-file SHA-256, excluding the two edited untracked plans,
is also unchanged:
`386e2ed771bf804b87c2dc11733f9865ec97e27c2417f39cd8e20825c78885b9`.
Historical execution/capture records and runtime/test files remain preserved.
No runtime tests, package builds, new captures or remote writes were performed.
The supported plan-status readback still reports the official-session binding
limitation, so registration remains UNREGISTERED; it does not block this plan
correction or start any engineering package. No temporary artifacts were created.
