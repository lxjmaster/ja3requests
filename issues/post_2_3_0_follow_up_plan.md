# Post-2.3.0 follow-up roadmap

Prepared: 2026-10-12. Status: **F1 + F2 HUFFMAN ACCEPTED LOCALLY**.

Updated: 2026-10-13. Use the [remaining-work solution and execution plan](post_2_3_0_remaining_work_plan.md)
for current package order, proposed contracts and acceptance. This update is
planning-only. Four subsequent synchronous transport fixes are present with
tests/docs; the historical Huffman candidate no longer matches current source.
New combined-source artifact acceptance belongs to the final selected batch.

The selected F1 engineering package has completed local acceptance. The user's
continuation selected and locally accepted one F2 card: benefit-based outbound
Huffman. F3, another
release, documentation deployment and remote Issue changes remain unselected.
The planning record is UNREGISTERED: `codex-plan --json status` cannot obtain a
fresh official session binding. No substitute session identity is supplied.

The detailed [execution solution and plan](post_2_3_0_execution_plan.md) defines
the first F1 package, collector architecture, fixed scenario, source/dependency
scope, phase gates and conditional F2/F3 work. The
[received-byte results](tls_h2_capture_results.md) record its completed F1
implementation, actual captures, existing-API recipe and explicit differences.

## 1. Published baseline and product goal

The published baseline recorded on 2026-10-12 is 2.3.0 at
`422012063f4ed12e23bda330c38355566d6d373d`:
[GitHub v2.3.0](https://github.com/lxjmaster/ja3requests/releases/tag/v2.3.0)
and [PyPI 2.3.0](https://pypi.org/project/ja3requests/2.3.0/).
Both public metadata endpoints were read on 2026-10-12. The retained release
acceptance passed 3,544 installed tests plus 118 subtests; five CI workflows and
12 jobs passed, including Python 3.7–3.13. These are release results, not tests
rerun for this planning task. Exact artifact/download/installation evidence is
in `dist/release-2.3.0/final-candidate/verification.json`, `ci.json` and
`publication.json`.

The product goal remains functioning, project-owned TLS handshakes with
user-controlled TLS and HTTP/2 wire behavior. The client owns the handshake,
key schedule, record processing, H2 frames, HPACK, flow control and stream state.
Cryptography primitives and independent OpenSSL test servers support that goal;
an OpenSSL TLS client wrapper would not satisfy it. Python >=3.7 and authenticated
secure defaults remain constraints.

Already delivered:

| Capability | Current evidence and boundary |
| --- | --- |
| TLS 1.2/1.3, verification, resumption and HRR | [TLS wire contract](../docs/tls_wire_control.md); functioning handshakes, generated private keys and authenticated records |
| Custom H2 fingerprint controls | Exact ordered SETTINGS, initial connection WINDOW_UPDATE, request pseudo-header order and initial standalone PRIORITY signals; [guide](../docs/fingerprints.md) and [real TLS/H2 tests](../test/integration/test_h2_fingerprint_review.py) |
| Native sync/async clients and streaming | Response/request streaming, async multipart/files and Cookie files; source ownership, cancellation and replay contracts are implemented |
| Buffered async preparation/signing/send | `AsyncSession.prepare_request()`, `AsyncPreparedRequest.with_headers()` and `send()` are released; [contract](async_prepared_request_design.md) |
| Package delivery and developer surfaces | Public installed typing, strict documentation CI, local runnable guides and retained performance measurements |

Custom TLS/H2 controls are implemented. Full identity with a particular browser
has a different acceptance boundary: JA3 alone omits extension payloads and H2.
The [Chrome 154 fixture](../test/fixtures/chrome154_macos_hello.json) covers one
ClientHello, and its preset is an explicit supported subset with a different JA3.
It contains no captured H2 settings. The current implicit Chrome profile stays
pinned to 124. Those limitations are measured/documented boundaries, not evidence
that the client delegates its TLS handshake to OpenSSL.

## 2. Recommended order

Choose one principal engineering package at a time. F1 and outbound Huffman are
complete for their recorded snapshots. The current recommended sequence is
R plus local acceptance after a compatibility/version decision, then H1/H2 plus
local acceptance; the latter can be selected independently. The reviewed plan
does not preselect two redirect modes or a separate default-migration batch.
C17 is not a prerequisite for fingerprint work. Package IDs and exact boundaries
are defined in the linked remaining-work plan.

| Priority | Task | Entry / completion boundary |
| --- | --- | --- |
| P0 | Proven maintenance defects | Preserve the four completed fixes; reproduce any newly reported defect before changing code. No new runtime defect is asserted by this planning pass. |
| P1 | R: synchronous 307/308 default correction | Select one compatibility-signaled version and document migration; preserve method/body and source replay. Keep current 301/302/303 behavior; add a compatibility option only for a demonstrated consumer need. |
| P1 | H1/H2: HEADERS priority and indexing control | Per-request weight/exclusive fields with dependency 0, plus connection-scoped literal-insertion policy; actual bytes, reuse, invalid-input isolation and installed acceptance. |
| P1, conditional | T1-T3: selected TLS differences | Reuse F1's report and confirm only the selected field/current implementation/capable peer; implement one bounded control or negotiation. No independent full-inventory batch. |
| P1, conditional | F3: one explicit capture-calibrated profile | Complete only the cards required by the declared matched subset; verify actual installed TLS/H2 requests and retain unresolved differences. |
| P2 | C17: opt-in Session headers/params defaults | A repeated-call workflow needs it. Refresh the existing design against 2.3.0, then implement one isolated public capability with precedence/snapshot tests. |
| P2, conditional | A3-S | Stream preparation requires a consumer workflow and source/signature contract; ordinary streaming uploads are already available. |
| P3 | C06: one internal typing slice | A named diagnostic or selected feature requires it. Bound the module/dependencies; retain installed positive/negative consumer checks. |
| P3 | C01/C02: docs hosting / performance CI | Select the host/version policy or runner/workload policy first. Existing docs builds and frozen measurements remain usable. |
| Per selected batch | D: final local acceptance | Freeze selected source and verify its own installed artifacts/captures. New features are not prerequisites if delivery of existing changes alone is selected. |

## 3. F1-F3: concrete fingerprint work

### F1: completed capture recipe and historical inputs

The locally installed Google Chrome reported `155.0.8059.39` in its application
metadata on 2026-10-12. This was the selected target for the first macOS capture,
not a claim about the latest global Chrome release. Record the executable's
actual version at capture time; a browser update changes the capture target.
Keep the existing 154 fixture as historical evidence.

1. Reuse [the browser capture helper](../test/capture_browser_hello.py)'s isolated
   profile lifecycle and [local H2 peer](../docs/examples/h2_fingerprint.py)
   pattern in a separate development collector. The existing helper closes
   after reading ClientHello; it cannot produce H2 evidence as-is. The collector
   must preserve the initial TLS bytes while completing a server handshake, e.g.
   by feeding them into a server-side `ssl.MemoryBIO`. Consuming ClientHello and
   then wrapping the same socket without replaying those bytes cannot work.
2. Use an isolated browser profile and an owned loopback server/certificate.
   Record the server's ALPN, the actual ClientHello, initial H2 frames, first
   request headers and a second request on the same connection. Include the
   server SETTINGS and responses so compression/flow state is reproducible.
   Browser capture must complete a request; ja3requests must independently verify
   the test certificate and complete requests with its own TLS engine.
3. Retain a small set of fresh connections, raw bytes, hashes, browser/OS/flags,
   request inputs and decoded fields. Account for randomized extension order and
   GREASE without asserting a distribution from a few samples. Normalize only
   identified volatile values; retain vector sizes, ordering and missing fields.
   Captured keys/randoms/tickets are observations, never client replay material.
4. Compare sync and async ja3requests against the same controlled peer inputs.
   Use an independent decoder for received bytes; self-inspection/configuration
   previews alone cannot establish the transmitted fingerprint. Verify connection
   reuse and that changed fingerprint configuration selects a separate pool entry.
5. Produce one field-by-field report: already configurable/matched, configurable
   but different, missing encoding/control, and missing functioning negotiation.
   State which fields the chosen target actually requires. A successful F1 may
   end with a documented configuration and no runtime changes.

Baseline reproduction accepts the explicit released wheel and its fixed SHA-256,
obtained either from retained release evidence or official PyPI. Local `dist/`
reports are optional for this baseline route; the execution plan records the
download recipe and digest. The collector verifies the wheel before installing
its private probes and records their actual origins and module hashes.

First-request fingerprint capture is F1's boundary. Existing HRR, resumption,
TLS 1.2 fallback and cancellation tests remain acceptance obligations when F2
changes those paths; a complete browser capture matrix for all of them is not an
artificial prerequisite for the first report.

### F2: measured extensions only

Current source and retained evidence distinguish the completed increment from
remaining candidates. This planning update does not start their implementation:

| Difference candidate | Actual current boundary | Required evidence if selected |
| --- | --- | --- |
| Outbound HPACK Huffman encoding (complete) | [encode_string](../ja3requests/protocol/h2/hpack.py) supports optional benefit-based coding through `TlsConfig.h2_huffman`; default remains raw | Historical installed-candidate capture passed; preserve this behavior and validate the final combined candidate without reimplementing it |
| Priority fields inside request HEADERS | [build_headers_frame](../ja3requests/protocol/h2/frame.py) sets END_STREAM/END_HEADERS only; configured PRIORITY currently means initial standalone frames | Target requires HEADERS priority; verify exact flags/payload, continuation splitting and validation before stream/HPACK changes |
| H2 header order / indexing choices | Regular input order is retained after protocol filtering; compression/indexing policy is internal | Demonstrate a high-level call cannot express the required captured behavior before adding another configuration surface |
| TLS GREASE / extension payload differences | [wire contract](../docs/tls_wire_control.md) limits GREASE to existing cipher behavior and distinguishes encoding from negotiation | Preserve independent private-key/transcript state, legal server selection, certificate verification and actual completed handshakes |

For any selected F2, freeze a minimal configuration contract and its pool identity
before implementation. Reuse shared encoders/state where appropriate; native
async I/O stays native. Measure exact bytes together with functioning protocol
behavior. A field that can only be advertised remains labeled encoding-only.
ECH, hybrid/post-quantum key exchange and other new protocol negotiations require
C13 feasibility; a browser profile cannot substitute static captured bytes for
those implementations.

Final artifact acceptance uses the candidate wheel from the existing verifier's
passing frozen-source report, with independent sync/async peer evidence bound
to that same wheel and source identity. H2 increments need received-frame/HPACK
and functioning-request evidence; TLS increments need a peer capable of exercising
the selected version, algorithm or extension. The existing collector accepts
only full TLS1.3/H2 with tickets disabled; it cannot prove TLS1.2 or resumption.
Corresponding browser sampling belongs to F3, a new target or refreshed browser
comparison requirements, rather than every runtime increment. Reusing the 2.3.0
baseline capture cannot validate new candidate behavior. Intermediate checks do
not require repeating full acceptance for unchanged inputs. The collector does
not become another build/release pipeline or a universal protocol framework.

### F3: calibrated profile

Add at most one explicitly selected browser/version profile, backed by F1 data
and actual TLS/H2 requests. Document matched fields, intentional subset behavior,
randomization policy and unavailable negotiations. Preserve historical explicit
profiles and compatible implicit selection. If essential target fields cannot
function, report that boundary and keep the result labeled a subset; do not claim
full browser identity or general success against external fingerprint services.

## 4. Client compatibility candidates

C17 reuses the [headers/params-only design](session_defaults_design.md). Its
current-source anchors and byte-header description predate 2.3.0 and must be
refreshed before implementation. In particular, current async preparation retains
byte-valued headers. Apply defaults once at initial `request()` or
`prepare_request()` execution, with explicit values taking precedence; a prepared
`send()` must retain its original snapshot rather than merge live defaults again.
Keep omitted/None/empty rules, caller copies, hooks, retries, Cookies and
cross-origin stripping explicit. Legacy observation properties are not defaults.

Prepared streaming is a separate extension beyond released A3. Its entry case
must require inspection/signing of a streaming body and define source ownership,
single/repeated send, concurrent send, consumed-source errors and digest/signature
timing. Precomputing a body digest can require source I/O; resolve that conflict
with buffered preparation's no-I/O contract instead of silently buffering a large
stream. Existing high-level streaming APIs already cover ordinary uploads.

Sync 307/308 changes need an explicit compatibility/version decision because the
current bodyless-GET default is documented and tested. Recommend one default
correction with migration text; add a compatibility option only for an actual
consumer dependency. Keep 301/302/303 unchanged in that batch. Preserve cross-origin
credential stripping and deterministic cleanup; verify buffered/replayable/
non-replayable bodies over HTTP1/H2. This is independent of prepared-streaming and
Session defaults, and establishes only the selected 307/308 parity boundary.

## 5. Open Issue disposition and remaining register

Read-only GitHub inspection on 2026-10-12 still found five open Issues. Their
original unchecked boxes do not accurately describe the published baseline:

| Issue | Delivered outcome / concrete remainder |
| --- | --- |
| [#36](https://github.com/lxjmaster/ja3requests/issues/36) | Public types, py.typed and installed CI delivered; complete internal helper typing remains partial (C06). Do not claim the whole package is strict-clean. |
| [#37](https://github.com/lxjmaster/ja3requests/issues/37) | Native async, pool/hooks, file/Cookie helpers and buffered preparation delivered. Module layout differs from the old proposal; module-level helpers (A4) and prepared streaming remain candidates. |
| [#40](https://github.com/lxjmaster/ja3requests/issues/40) | Benchmarks and retained reports delivered; PR performance automation is optional C02. Historical samples are not 2.3.0 measurements. |
| [#41](https://github.com/lxjmaster/ja3requests/issues/41) | Incremental responses, decoding and backpressure delivered; retained 100 MiB tests support their specific bounds. The original 1 GiB / memory <= chunk_size wording is not a verified whole-process guarantee; reconcile that acceptance before closure. |
| [#42](https://github.com/lxjmaster/ja3requests/issues/42) | Local MkDocs, API/user guides, runnable examples and docs CI delivered; public hosting is optional C01. |

A future authorized Issue-maintenance pass can attach release/evidence links and
agree remaining acceptance before changing descriptions or closing Issues.

Retain the other original candidate IDs: C07 additional legacy suites; C08
cross-process TLS ticket storage; C09 actual priority scheduling; C10 server push;
C11 0-RTT; C13 ECH/post-quantum negotiation; C15 HTTP3/QUIC; C16 a named additional
runtime/OS/architecture. Each needs its existing peer, workload or security
contract. Initial PRIORITY fingerprint signals already delivered by 2.3.0 do not
implement C09 scheduling. C14 and A1/A2 are released, while A3's buffered boundary
is released and its streaming extension is separate. Small documented gaps such
as HTTP-date Retry-After and a public trailer API need a consumer case before
they become new work packages.

## 6. Execution, acceptance and closure

F1 evidence and its named difference report are accepted locally. F2 outbound
Huffman was accepted in Section 12 of the execution record against its historical
candidate. Remaining fingerprint increments are HEADERS priority, indexing and
selected TLS differences; F3 remains conditional. Use the remaining-work plan
for contracts and final combined-source acceptance. Full browser parity remains
unachieved and is not promised by these subset cards.
Work stays serial because captures, target requirements and protocol state are
coupled. No subagents are used for this planning task. No new TLS backend,
general fingerprint plugin system or combined compatibility refactor is needed.

For an implemented runtime slice, verify the smallest meaningful regressions and
actual wire behavior, then reuse the existing exact-snapshot installed acceptance,
typing/docs and compatibility gates. Add failure tests for affected boundaries;
do not rerun historical benchmarks or unrelated exploratory reviews as release
prerequisites. Select a version from the actual compatibility impact. Commit,
push, publishing and hosting are separate future action sets.

Retain owned captures/reports as deliverables. Remove only verified task-created
profiles, listeners, certificates and temporary installation staging after their
evidence is retained; preserve historical release evidence and unrelated user
files. If target capture or an essential primitive is unavailable, state the
specific missing capability and continue independent planning/evidence work.

Planning completion checklist:

- [✅] Read the published baseline and retained release acceptance.
- [✅] Reconcile delivered capabilities, actual source gaps and open Issue goals.
- [✅] Define task order, dependencies, acceptance, exclusions and retention.
- [✅] Align current/previous roadmap entries and verify changed links and diff.

Initial roadmap planning verification: all 50 relative file targets across the four changed
Markdown files resolve; candidate/Issue coverage, whitespace and
`git diff --check` passed. Source inspection confirmed the H2 sender and byte-header
boundaries. The package's Python ssl references supply CA roots. No runtime
implementation or fresh feature-test result is claimed by this planning record.
