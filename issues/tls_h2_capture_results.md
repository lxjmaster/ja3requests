# TLS/H2 received-byte evidence: Chrome 155/macOS and ja3requests 2.3.0

This is historical baseline/candidate evidence. Its artifact hashes do not
identify the 2.4.0 release. See the [release notes](../CHANGELOG.md) for the
current capability boundary and the GitHub release for final artifact validation.

Recorded: 2026-10-12. Status: **F1 ACCEPTED LOCALLY / BASELINE REPORT**.

Evidence scope, 2026-10-13: baseline and Huffman candidate results below remain
valid for their recorded artifacts. Four subsequent synchronous transport fixes
changed the source; neither capture series nor `dist/verify-huffman-candidate-01/`
validates that latest combined source. Final selected-batch acceptance is defined
in the [remaining-work plan](post_2_3_0_remaining_work_plan.md). No raw capture or
historical artifact was replaced for this planning update.

This report records the F1 acceptance boundary. The subsequent user continuation
selected F2 outbound Huffman in Section 12 of the execution plan; its candidate
acceptance is recorded separately below, without rewriting baseline bytes.

The owned collector completed three fresh Chrome connections and one installed
sync and native async connection. All completed full TLS 1.3, negotiated h2,
returned the expected HTML/image bodies on the same connection, and closed. This
accepts F1's evidence package and demonstrates the existing configurable H2
controls. It does not accept a complete Chrome TLS/H2 identity or any new runtime
capability. Client TLS handshake/key/record state remains project-owned; Python
ssl is the independent capture server only.

## Inputs, provenance and reproduction

- Target: `Google Chrome 155.0.8059.39`, macOS; exact platform/launch flags are in
  the retained manifest and fixture. Version was checked before every sample.
- Client: released `ja3requests-2.3.0-py3-none-any.whl`, SHA-256
  `523fa1d13ebbdd46ba139e6609f3bc955a9ed9a6fb590c13aed7061fc4fc29d4`, source
  `422012063f4ed12e23bda330c38355566d6d373d`. Explicit preset: `chrome:154`.
- Accepted series: `dist/fingerprint-2.3.0/capture-04/`; its manifest, five case
  JSON files, comparison, probe logs and exact `tool-source/` copies are retained.
  The passing release report identifies the baseline, not changed runtime code.
- Tooling: Python 3.13.3/OpenSSL 3.0.16, hpack 4.2.0, cryptography 45.0.5 and
  psutil 7.0.0. Actual installed probe dependency versions/origins are separately
  recorded; every installed package module hash agreed with the selected wheel.
- Peer: same loopback origin/CA/leaf across all five cases; TLS 1.3 only, ALPN h2,
  zero tickets, empty server SETTINGS, fixed small HTML and PNG responses.
  Session caches were disabled after client construction and private pools used.
- Trust: library certificate verification enabled through private CA input;
  Chrome uses a generated leaf SPKI exception and a private profile. These trust
  modes are distinct. No machine trust-store changes were made.
- Portable evidence: [fixed raw samples](../test/fixtures/chrome155_macos_tls_h2.json),
  [offline runtime checks](../test/test_browser_capture.py), and
  [independent tool checks](../tools/tests/test_fingerprint_capture.py).
  The fixture keeps hashes, raw TLS/H2 bytes, independent decoded values,
  completion and compact artifact/process identities. Full manifests/logs remain
  in dist. No private keys or session traffic secrets are fixture inputs.

Use the [actual collector commands](../tools/README.md#real-tls-and-http2-fingerprint-capture)
with a fresh output path. The baseline is downloadable by exact version/hash;
an ignored local release report is optional for reproduction. An unknown
`chrome:999` profile was also tried at
`dist/fingerprint-2.3.0/profile-rejection-01/`: preflight failed before any live
cases and its temporary root/listener were cleaned.

## Existing H2 configuration that matched

Both installed clients received the same explicit overrides and equivalent
ordered regular header inputs. The overrides were:

```python
config = TlsConfig.from_browser('chrome', 154)
config.h2_settings = [(1, 65536), (2, 0), (4, 6291456), (6, 262144)]
config.h2_window_update = 15663105
config.h2_pseudo_header_order = [':method', ':authority', ':scheme', ':path']
```

The collector supplies the captured regular headers separately for each request;
this is part of the controlled input recipe. For example, `priority: u=0, i` on
the HTML and `priority: u=2, i` on the image are header values, distinct from the
HEADERS frame's optional priority field. The result does not imply that preset
154 alone generates Chrome's headers or H2 startup settings.

## Material differences and dispositions

Every row is reproducible from the fixture's raw records/frame bytes and the
case-specific independently decoded fields. Both library clients showed the
same relevant differences. `comparison.json` contains the complete per-field,
per-client table; variable rows use all three browser samples.

| Field | Browser / installed clients | Disposition |
| --- | --- | --- |
| H2 preface and ordered SETTINGS | Exact same preface and `[(1,65536),(2,0),(4,6291456),(6,262144)]` | Matched using existing configuration |
| Initial connection WINDOW_UPDATE | `15663105` in all five cases | Matched using existing configuration |
| Standalone PRIORITY | Absent in browser and configured clients | Matched absence; this says nothing about HEADERS priority or scheduling |
| Request association/order/values | Two requests, same connection; header order and values match supplied browser inputs | Matched for this scenario; observed streams 1/3 are evidence, not a general stream-ID assumption |
| HEADERS flags and priority | Browser flags 37, dependency 0/exclusive true, weights 256 then 183; clients flags 5 and no embedded priority | Missing control; candidate F2 HEADERS-priority policy. Initial standalone PRIORITY cannot reproduce this field |
| HPACK string encoding | Browser uses Huffman on many longer literals and raw encoding on several short literals; clients use raw strings | Missing encoding control; a bounded outbound Huffman policy is a possible F2 increment. Benefit-based policy is a hypothesis to verify against chosen target vectors |
| HPACK indexing on reuse | Browser `/pixel.png` is without indexing; clients add it incrementally | Separate indexing-policy difference; do not treat Huffman alone as a full HPACK match |
| Dynamic table continuity | Request 1: both 0 to 14 entries. Request 2: browser 14 to 20, clients 14 to 21 | Both tables persist across requests; indexing choice causes divergence and changes later dynamic indexes |
| Cipher offer | Browser includes 52393/52392; preset 154 omits them | Missing functioning-negotiation evidence for those suites; merely adding IDs cannot satisfy a selected negotiation requirement |
| Group/share vectors | Browser groups GREASE/4588/29/23/24, shares GREASE:1, 4588:1216, 29:32; clients groups 29/23/24 and share 29:32 | Group 4588 requires an actual primitive and handshake path if selected (C13). GREASE offer shaping is a separate control; generated public-key bytes must not be replayed |
| Extension order | Changes between the three browser samples; preset order is fixed | Observed variation. No claim about distribution or a universal exact order; no missing API is inferred from one ordering alone |
| GREASE positions/shapes | Browser has extension GREASE slots and GREASE in version/signature/group/share vectors absent from corresponding client vectors | Missing structural controls. Values normalize to GREASE class while positions/lengths remain; raw bytes are preserved |
| Signature algorithms | Browser additionally offers GREASE/2308/2309/2310; client offers its existing supported vector | Signature selection/authentication feasibility remains undetermined for extra IDs. No unsupported algorithm is advertised as functioning |
| Supported versions | Browser GREASE/772/771 versus client 772/771 | Stable offer-shape difference. This series negotiated 772 (TLS 1.3); it does not independently accept every advertised fallback |
| Extension types 51764/27/18/17613 | Present in browser; absent from client | Missing fields retained with exact payloads. Interpretation, API and any required negotiation need separate evidence before implementation |
| Extension 65037 | Present in browser with variable opaque payload, absent from client | Variable/undetermined contents; ECH feasibility remains C13 if required. Static copied bytes would not prove a functioning exchange |
| Shared extension payloads | SNI 0, status-request 5, point formats 11, ALPN 16, 23, 35, 45 and 65281 match | Matched under these controlled inputs. Raw payloads and lengths are retained independently |
| ALPN, legacy hello version, record versions, hello count, Session ID length, compression | Same offered ALPN h2/http1.1, version 771, record-version sequence, one ClientHello, Session ID length 32 and compression `[0]` | Matched shapes. Random/Session ID/public-key bytes are intentionally unequal and are not copied |

Unknown or opaque extension contents remain visible in the report. Their absence
is not proof that the server negotiated that extension in the browser case.
Three fresh samples are sufficient for the required observed-variability check,
not for statistical fingerprint claims or external anti-bot service success.

## S4 selection and completion boundary

The selected package is F1: received-byte evidence and a difference report for
the fixed target. Its acceptance requires functioning authenticated library TLS,
configurable H2 observations, independent decoding and honest missing-field
disposition. These requirements are met using the existing APIs; no F2 runtime
extension or F3 new profile is selected by this package. This follows the
execution plan's explicit F1 closure route and does not redefine full browser
identity as subset success.

At F1 closeout, the concrete next candidates were HEADERS priority, outbound
Huffman and indexing policy; Huffman was subsequently completed as recorded
below. For each remaining selected increment, fix its
public API/default/pool identity and exact sync/async byte assertions first.
Accept it using the **final candidate** verifier wheel and independent installed
captures, not the baseline traces. A full Chrome identity requirement additionally
needs the missing negotiation/opaque-extension feasibility above. It remains
unachieved; this report does not turn it into an implementation promise.

## Verification and retention

The affected runtime/tool selection passed **496 tests** locally, including
independent RFC vectors, persistent HPACK decoding, continuation/padding/priority,
two-byte socket-level TLS fragmentation and output draining, decoded-header
limits, wrong artifact/report rejection, deadline/failed-client cleanup,
detached owned descendant termination, queued preconnection isolation and fixed
sample re-decoding. Runtime fixture tests do not import hpack/psutil. The CI
tooling job now explicitly installs their development requirements; hosted CI
has not been run for these uncommitted changes.

The accepted five live cases have passing body/DOM, full/resumed-state and
same-connection checks. Owned groups/observed descendants are gone, peer threads
joined, profiles removed, temporary CA/key/probe roots removed and listener
closed. Extra browser preconnections are recorded separately. Earlier failed
capture-01/02 attempts remain retained and are excluded from calibration;
trial-01 and capture-03 remain historical evidence. The source snapshot copies
and fixture make the accepted bytes inspectable after later tool edits.

No runtime library source changed in F1; no new candidate wheel or package
publication is claimed. Existing release evidence, user debug/IDE files and
unrelated roadmap edits are preserved. Commit/push/release and remote Issue
operations remain outside this engineering package's action set.

## F2 continuation: accepted outbound Huffman policy

The user's continuation selected one measured increment, `TlsConfig.h2_huffman`.
It defaults to False; True uses Huffman only when the encoded octets are strictly
shorter, preserving sensitive-field indexing and compression-table policy. All
90 literal choices in the retained browser samples follow that rule. The same
shared encoder serves synchronous, native async, prepared and upload send paths;
its bit accumulator now retains only the bounded unconsumed tail. The option
participates in pooled connection identity and is validated before sending.

The final verifier at `dist/verify-huffman-candidate-01/verification.json` passed
3,587 installed tests plus 118 subtests, with no skips/failures/errors and 92.14%
statement coverage. Installed positive/negative public typing, package metadata,
source/artifact hashes and Python 3.7 grammar passed. The affected development
selection passed 632 tests; package formatting/error-level lint and source mypy
passed. Strict docs build/checks passed, including the runnable guide's actual
Huffman authority literal over authenticated TLS 1.3.

The final installed candidate series is `dist/fingerprint-huffman/capture-01/`:

| Accepted input / assertion | Evidence |
| --- | --- |
| Candidate wheel | `ja3requests-2.3.0-py3-none-any.whl`, SHA-256 `cb5c8f413b57c7d815996b27bd23953a5b88371d5ec9e17e43d151e07b3f6c13` |
| Passing verifier report SHA-256 | `3c200baa13b3dd53fbead24ae67252e8b10253a8ec99fce2a52e0860751d0ba6` |
| Installed origin/module identity | Private site-packages probes; all 72 module hashes match the candidate wheel/report |
| Selected overrides | `chrome:154` plus captured H2/header inputs and `h2_huffman=True`; actual public option verified at preflight |
| Functioning protocol | Three browser, one sync and one async full TLS 1.3/h2 connections; verification enabled for library; expected bodies/DOM and two requests on each connection |
| First request HPACK | Exact full-block match to all three contemporaneous browser samples in both library clients, under equivalent inputs |
| Request reuse literal policy | 30 independently checked literal name/value decisions per library client across the two requests |
| Table continuity / remaining differences | First request table 0 to 14 for browser and clients; second browser 14 to 20, clients 14 to 21. Indexing policy and HEADERS priority remain different |
| Resource lifetime | Verifier staging removed; profiles/private CA/key/probe roots removed; owned process groups/observed descendants and peer threads terminated; listener closed |

Use the documented collector command with the candidate wheel/hash/report and
`--h2-huffman`. The manifest's `huffman_acceptance.status` is passed; full raw
TLS/H2 records, independent decodings and exact tool-source snapshots are retained.
This candidate comparison uses a fresh common origin/certificate within its own
five-case series. The earlier baseline's ephemeral destination and random TLS
bytes are separate observations, not required byte-equality targets.

The wheel has unchanged 2.3.0 metadata because no release version was selected;
its distinct digest identifies an **unpublished candidate**, not the public
2.3.0 artifact. At its closeout, package/build/test/type/guide inputs agreed with
the accepted frozen source; only plan/report bookkeeping followed at that time.
The later synchronous transport fixes invalidate using this artifact as current
source acceptance. Its original bytes/results remain retained historical evidence,
without a claim of new commit/push/publication.

F2 outbound Huffman is locally accepted. The next concrete H2 candidates remain
HEADERS priority and indexing policy, each needing its own bounded public
contract and candidate verification. F3 is unselected. This increment does not
close the outstanding TLS negotiations or establish full Chrome identity.
