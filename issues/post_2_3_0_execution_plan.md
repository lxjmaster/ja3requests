# Post-2.3.0 fingerprint execution plan

Prepared: 2026-10-12. Status: **F1 + F2 HUFFMAN ACCEPTED LOCALLY / F3 UNSELECTED**.

Scope update, 2026-10-13: this document retains completed F1/F2 execution and
snapshot evidence. The [remaining-work plan](post_2_3_0_remaining_work_plan.md)
governs current planning; its runtime packages have not been started. Four later
synchronous SNI/ALPN/redirect/timeout fixes changed the source, so Section 12's
wheel/captures do not constitute current combined-source artifact acceptance.

Revised after plan review: baseline acquisition is reproducible without local
release evidence; final F2/F3 captures use the selected installed candidate.

This document records the earlier planning and authorized engineering execution
following the [post-2.3.0 roadmap](post_2_3_0_follow_up_plan.md). F1 and the selected
F2 outbound Huffman increment in Section 12 are accepted for their recorded
snapshots. That historical execution authority does not start the newly proposed
packages. F3 remains conditional.
Registration is UNREGISTERED:
`codex-plan --json status` reports no fresh official session binding.

## 1. Fixed outcome and completion boundary

The first engineering package is **F1: one functioning TLS + H2 capture path,
one named browser target, and a received-byte difference report**. It must make
the existing custom fingerprint capability observable against a real browser.
F1 can finish with a documented configuration of existing APIs. F2 adds at most
one required missing wire behavior per increment; F3 calibrates one explicit
profile. They follow the difference report rather than precede it.

The baseline is released 2.3.0 at
`422012063f4ed12e23bda330c38355566d6d373d`. The client's TLS handshake, key
schedule, record state and H2 state remain in project code. Python ssl is the
independent **server** for capture. The contract is functioning, authenticated
requests plus controlled wire behavior; a generated ClientHello or equal JA3
alone does not establish completion.

| Package | Deliverable | Exit condition |
| --- | --- | --- |
| F1 | Capture tool/tests, fixed browser sample, actual sync/async traces, difference report | Real TLS/H2 requests and reuse verified; report distinguishes configurable behavior from missing encoding or negotiation; owned temporary resources cleaned |
| F2, conditional | One bounded TLS/H2 extension, public contract and regressions | Selected captured requirement works in both clients; exact bytes, protocol state, failure behavior, typing and docs pass; final installed candidate capture closes artifact acceptance |
| F3, conditional | One explicitly selected browser/version profile | Actual installed candidate requests succeed and declared matched fields are verified; all subset differences remain explicit |
| Local acceptance | Evidence for the final selected source snapshot | Relevant checks, source/artifact identity and cleanup agree; planning and implementation completion are recorded separately |

Client compatibility, internal typing, hosting, performance automation and the
other protocol candidates keep the roadmap's separate entry conditions.
Commit/push/release and remote Issue changes are outside this engineering package.

## 2. Verified feasibility and approach

Initial planning inspection on 2026-10-12 established the following inputs.
Section 11 records subsequent implementation and actual acceptance:

- Local tooling Python is 3.13.3, with OpenSSL 3.0.16, server-side `wrap_bio`,
  ALPN and TLS ticket-count controls available. This is API/environment evidence,
  not a completed browser/H2 collector test.
- The installed Chrome application metadata says `155.0.8059.39`. S0 must obtain
  the executable's actual version and freeze it for the capture series.
- The existing [capture helper](../test/capture_browser_hello.py) reads one TLS
  record and closes. Its TLS-only CLI and 154 fixture remain valid historical
  tools; they cannot provide a completed H2 transcript without new collection.
- The [H2 example](../docs/examples/h2_fingerprint.py) demonstrates a real TLS
  server/client and H2 bytes. Its certificate has an IP SAN for `127.0.0.1`, but
  lacks a DNS SAN for `localhost`. The collector certificate must cover both.
- The [independent ClientHello decoder](../test/wire_client_hello.py) currently
  requires one record containing one complete hello. Multi-record handshake
  reassembly belongs in the test/tool path before its message decoder is reused.
- Independent `hpack` is not installed locally. [Official PyPI](https://pypi.org/project/hpack/4.2.0/)
  currently provides `hpack==4.2.0`, requiring Python >=3.10; its source verifies ordered raw-byte
  decoding and a persistent Decoder. Keep that dependency in modern capture
  tooling, not package runtime dependencies or Python 3.7 test collection.

| Viable approach | Cost / evidence | Decision |
| --- | --- | --- |
| Owned loopback server using MemoryBIO, with raw TLS input and decrypted H2 taps | One bounded server collector; receives ClientHello and H2 on the same connection; no TLS session-key log is needed | Select for F1 |
| Packet capture plus server TLS key logging and offline dissection | Captures full packet timing; requires platform capture privileges/tooling and handling session-key files | Keep for a later packet-level target if needed |

The selected collector calls `SSLContext.wrap_bio(..., server_side=True)`.
Python's [SSLObject/MemoryBIO contract](https://docs.python.org/3.13/library/ssl.html#memory-bio-support)
provides the needed separation between protocol state and network I/O. Every
socket input is recorded and fed into the input BIO exactly once. Drain and send
the output BIO after handshake/read/write operations, including a WANT_READ
result; preserve partial plaintext writes. EOF, deadlines and shutdown are
explicit. Reading ClientHello away from a socket and then calling wrap_socket
without preserving those bytes is not a valid implementation.

## 3. S0: freeze inputs and establish identity

Before implementing or capturing:

1. Read the current source/worktree and preserve existing roadmap/user changes.
   Record the baseline commit, package-source hashes and tool/test source hashes.
   A dirty planning worktree does not make the unchanged library a new release.
2. Acquire the released wheel through either baseline route below. Check its
   fixed SHA-256 before installation, then use an isolated client-probe
   environment. Run client probes outside the repository without source-path
   overrides; record installed version/origin/module hashes. Local `dist/`
   evidence is optional for baseline reproduction.
3. Freeze one target: Chrome 155/macOS, exact executable version, flags, owned
   loopback origin and fresh temporary profiles. An update during sampling
   invalidates a mixed-version series. Do not install/replace the browser or
   change machine trust settings as a routine capture preparation step.
4. Fix the scenario: full TLS 1.3 with negotiated h2, GET a controlled HTML page,
   then GET its same-origin small image on the same connection. The page has an
   image-load completion marker and a data favicon. Record extra browser streams
   rather than hiding them or assuming the expected streams are always 1 and 3.
5. Use one local server origin/certificate and fixed server SETTINGS/response
   bytes for comparable browser, sync and async cases. Start with empty server
   SETTINGS and documented protocol defaults. Disable server TLS 1.3 tickets,
   use fresh browser profiles and set library `session_cache=None`; record the
   observed full/resumed state rather than assuming a new socket is a full TLS
   handshake. Use private pools for each library case.

S0 output is a short manifest of exact target, scenario, source and package
identities. This closes the main inputs; it is not another general design phase.

### Reproducible baseline artifact input

The released baseline input is:

- Version: `2.3.0`; wheel: `ja3requests-2.3.0-py3-none-any.whl`.
- SHA-256: `523fa1d13ebbdd46ba139e6609f3bc955a9ed9a6fb590c13aed7061fc4fc29d4`.
- Published source reference: `422012063f4ed12e23bda330c38355566d6d373d`.

On 2026-10-12, the actual retained wheel, its accepted verification report and
[official PyPI file metadata](https://pypi.org/pypi/ja3requests/2.3.0/json) agreed
on this wheel digest. The digest is version-specific, not a value to copy into a
future candidate command.

| Route | Input preparation | Evidence boundary |
| --- | --- | --- |
| Existing release evidence | Use the wheel in `dist/release-2.3.0/final-candidate/artifacts/` and optionally supply its adjacent `verification.json` | Check wheel digest, report artifact identity and installed module hashes; preserve the prior evidence |
| Fresh checkout / externally supplied wheel | Download from official PyPI as below, or provide the exact wheel file and the fixed digest | Check wheel digest and installed module hashes; record the published source reference separately from locally verified source identity |

Use an existing Python >=3.12 tooling environment. In a fresh checkout without
one, create the ignored `.venv` with `python3.12 -m venv .venv`; preserve an
existing user environment. The following uses `.venv`. Choose a fresh download
destination for each acquisition attempt:

```sh
.venv/bin/python -m pip download --index-url https://pypi.org/simple \
  --only-binary=:all: --no-deps ja3requests==2.3.0 \
  --dest dist/fingerprint-inputs/baseline-2.3.0
```

The proposed collector verifies the expected digest before installing or
launching probes. Missing local reports do not require rebuilding the baseline
or repeating its full release acceptance. A mismatching or missing wheel fails
preflight; it cannot silently fall back to an editable install or another version.

## 4. S1: build the smallest working collector

### Components and source scope

The following F1 paths are now implemented; the phase descriptions preserve the
fixed plan and Section 11 records the accepted evidence:

| Path / existing anchor | Planned work |
| --- | --- |
| `tools/capture_fingerprint.py` | One CLI containing the owned BIO TLS/H2 peer, browser lifecycle, installed sync/async probes and recording/comparison; explicit wheel/hash inputs, with optional existing artifact-report provenance |
| `tools/tests/test_fingerprint_capture.py` | Fragmentation, independent decoding/state, wrong artifact/hash/report/profile rejection, bounded failure and resource-lifetime checks; runs only in modern tooling |
| `requirements-capture.txt` | Pin independent `hpack==4.2.0` and development-only `psutil==7.0.0` for owned descendant identity/cleanup; install alongside existing tooling/package primitives on Python >=3.12 |
| [test/wire_client_hello.py](../test/wire_client_hello.py) | Small parser/reassembly adaptation only if needed; preserve existing single-record API and fixture assertions |
| [test/test_browser_capture.py](../test/test_browser_capture.py) and `test/fixtures/chrome155_macos_tls_h2.json` | Offline retained-sample/hash/field checks; no browser launch or external hpack import in the library runtime matrix |
| [tools/README.md](../tools/README.md) and [test workflow](../.github/workflows/test.yml) | Reproduction instructions and capture-tool tests in the existing Python 3.12 tooling job |

The collector emits/checks the limited H2 server conversation using test-side
frame parsing, never the production sender/decoder as its sole oracle. Use one
independent `hpack.Decoder` per inbound connection and retain its dynamic table
across requests. Reassemble HEADERS/CONTINUATION, account for optional HEADERS
padding/priority fields, and decode ordered raw header pairs. Preserve unknown
frames in evidence; process required SETTINGS/PING acknowledgements. Reject a
truncated or out-of-bound trace instead of reporting a partial capture as passed.

The HTML/image bodies are small enough to fit protocol-default windows. A full
general H2 server, priority scheduler, backend framework or packet-dissection
platform is unnecessary for this scenario.

Keep environment preparation to a small owned venv/pip subprocess helper. Reuse
the existing verifier's report format and ordinary tooling commands; source
freezing, package builds and full acceptance stay in `tools/verify_release.py`.
The collector does not gain a second build/release pipeline or an environment
management framework.

### Trust and process lifetime

Generate an owned short-lived CA/server certificate with DNS `localhost` and IP
`127.0.0.1` SANs. Library probe subprocesses receive the CA through process-local
`SSL_CERT_FILE` and keep verification enabled. Chrome receives only the generated
server SPKI exception and an owned `--user-data-dir`; record that browser trust
mode separately from library certificate verification. Chromium's
[switch implementation](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/services/network/public/cpp/network_switches.cc)
requires the profile flag and Base64 SHA-256 SPKI values.

A capture passes only when the server sees both expected requests on one TLS
connection, both responses complete, and the client-side body/DOM marker agrees.
The first live browser trial validates the headless launch/completion strategy;
do not proceed to repeated sampling if it exits before the image marker.

Use a proposed 30-second absolute deadline per live case, including browser
request completion, with event-driven reads rather than fixed sleeps. Launch
dependency installation separately with a bounded subprocess timeout. Reap only
the browser process group created in a new session by this collector: terminate
and join for up to five seconds, then kill/join that owned group if necessary.
Verify descendant termination before removing its profile. Close listeners/accepted sockets, join the
owned peer and probe processes, and remove the temporary profile/key/venv root
in finally paths. Report failures with retained partial bytes and actual cleanup
state; do not report them as captures accepted for calibration.

S1 exit: one functioning browser trial and focused tool checks pass. This is the
first feasibility checkpoint for actual browser behavior; documentation/API
inspection in this planning task does not substitute for it.

## 5. S2-S3: sample, compare and report

### Minimum capture series

Collect three fresh browser connections under the frozen target. Each must
contain the completed two-request scenario. This is a small variability sample,
not evidence of a probability distribution for randomized browser behavior.
Then capture one sync and one native async two-request connection using the
installed 2.3.0 wheel and private pools.

Use the released Chrome 154 supported subset as an explicitly labeled starting
configuration. Project captured H2 controls and equivalent request inputs onto
existing APIs where valid; record every override. Copy neither secret-dependent
key shares/binders nor unimplemented negotiations into a supposed working
profile. Compare regular header order/compression with equivalent supplied header
pairs; browser-generated request values are input differences before they are
candidate protocol defects. If no valid current configuration can express a
captured field, record that finding rather than silently inventing one.

For pool partitioning, reuse the existing
[changed-control real TLS tests](../test/integration/test_h2_fingerprint_review.py)
where their configuration coverage applies. Add a check only for a new uncovered
identity boundary; repeating every established failure matrix is unnecessary.

### Evidence and matching rules

One JSON capture format is sufficient. Record source/tool/package identity,
browser/OS/flags, trust mode, connection ID, timestamps, negotiated TLS/ALPN and
full/resumed state. Keep actual client TLS records, reassembled ClientHello,
client/server plaintext H2 frame bytes, ordered decoded headers, completion
results and SHA-256 values. Store repeated setting pairs and duplicate headers
as lists rather than dictionaries. Keep timestamps observational rather than
requiring the same network interleaving between separate runs.

| Comparison | Required preserved information |
| --- | --- |
| TLS | Cipher/group/signature order, extension types/order/lengths and stable contents, ALPN, record versions, key-share group/size, Session ID length and hello count |
| H2 connection start | Preface, exact ordered SETTINGS/duplicates/omissions, initial connection WINDOW_UPDATE and standalone PRIORITY fields/order |
| Request 1 and reuse request | Stream association, HEADERS flags/optional fields, pseudo/regular header order and values, raw HPACK bytes and representations, dynamic-table continuity |
| Functioning connection | Authenticated library handshake, negotiated h2, expected bodies/DOM marker, same-connection reuse and deterministic close |

Normalize identified random/session/public-key bytes to their shapes for a
structural comparison while keeping original bytes. Retain GREASE locations,
type class and payload shape; do not delete it to manufacture equality. Unknown
extension contents stay in the difference report until their semantics are
understood. Variable destination metadata may be normalized only with an explicit
rule and identical request inputs; do not normalize signing targets or ordering.

Apply proposed per-direction capture bounds of 1 MiB and a 64 KiB decoded
request-header budget in the collector. These local tool budgets are recorded,
not advertised as extra peer SETTINGS. Exceeding one is a failed/incomplete
sample. Adjust a bound only for a measured legitimate target, retaining its
reason; do not silently truncate bytes or weaken validation.

Retain attempts under fresh `dist/fingerprint-2.3.0/capture-NN/` directories with
manifest/captures/comparison/cleanup results. Select a compact reviewed browser
sample set for `test/fixtures/chrome155_macos_tls_h2.json`; keep full attempt
evidence in dist. Add a readable `issues/tls_h2_capture_results.md` report when
F1 actually runs, with each row labeled matched, configurable difference,
missing control, missing functioning negotiation, or variable/undetermined.
The [actual results file](tls_h2_capture_results.md) now records the accepted
F1 series; no proposed runtime capability is reported as delivered.

S2 exit: every required live case is complete and independently decodable.
S3 exit: each material difference has raw-byte evidence, a reproducible input and
a disposition; matched-field assertions can be rerun offline.

Implemented CLI after S1 acceptance. This
uses the downloaded baseline; another modern tooling environment can replace
`.venv`:

```sh
.venv/bin/python -m pip install -r requirements.txt -r requirements-capture.txt
.venv/bin/python -m tools.capture_fingerprint \
  --chrome "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --wheel dist/fingerprint-inputs/baseline-2.3.0/ja3requests-2.3.0-py3-none-any.whl \
  --wheel-sha256 523fa1d13ebbdd46ba139e6609f3bc955a9ed9a6fb590c13aed7061fc4fc29d4 \
  --client-profile chrome:154 \
  --output dist/fingerprint-2.3.0/capture-01
```

`--wheel` and `--wheel-sha256` are required. `--artifact-report` optionally adds
the existing verifier's provenance; when present, its status must be `passed`,
and its artifact digest and installed source hashes must agree with the selected
wheel. For the retained baseline route, change the wheel path and add
`--artifact-report dist/release-2.3.0/final-candidate/verification.json`.

`--client-profile` selects an explicit exported browser preset for both probes.
Record its name and every selected API override in the manifest; an unknown
profile fails rather than falling back. Browser observations and client preset
selection are separate inputs. Keep the selected F2 API overrides in one small
shared probe setup used by both send paths; record that setup's source hash and
concrete inputs. No general configuration/plugin framework is needed. The CLI
creates and cleans its installed-probe environment; an existing output directory
fails instead of overwriting earlier evidence. Later attempts use a new exact path.

## 6. S4: choose the smallest follow-up

| Report result | Next action / closure |
| --- | --- |
| Required fields already configurable | Document and verify the configuration; F1 closes without a runtime extension. F3 can calibrate an explicit subset if selected. |
| A required H2 encoding/signal cannot be expressed | Select one F2 card below with its exact wire and compatibility contract. |
| A required TLS field lacks functioning negotiation | Record the required primitive/state transition and C13 feasibility boundary; encoding-only output cannot close that target requirement. |
| Browser variability or input differences explain the mismatch | Improve the comparison explanation/controlled inputs; do not add an unmotivated public knob. |

This is a technical selection gate, not an automatic permission prompt. Continue
within the authorized outcome; clarify only a material target, compatibility or
scope choice. A full browser-identity goal cannot be self-redefined as subset
success when required negotiations are missing.

## 7. F2-F3: conditional runtime execution

First record a short selected F2 card: captured requirement, proposed API/default,
normalization/pool identity, affected send paths, exact success/failure cases and
unsupported remainder. Public option names are decided here, after evidence.

| F2 candidate | Minimal implementation boundary | Specific failure checks |
| --- | --- | --- |
| Outbound HPACK Huffman | One explicit encoder/config policy matching the selected target; define force/benefit-based use from observed bytes; retain the raw codec's existing default contract and sensitive-field indexing policy | Independent known vectors and decoding, table resizing/reuse, invalid input before mutation, raw-byte/UTF-8 API boundaries, sync/async emitted blocks |
| Priority inside HEADERS | One selected priority policy shared by both senders; account for five priority bytes in first-frame capacity and legal CONTINUATION ordering | Self-dependency/ranges before stream or HPACK mutation, exact flags/payload, max-frame edge, END_STREAM/END_HEADERS, pooled identity/reuse |
| TLS GREASE or extension content | One measured field/payload policy that preserves generated secrets, transcript and offered-selection validation | Actual full handshake and relevant HRR/resumption, unsupported selection, malformed input, certificate failure before HTTP and cleanup |

Implement a named card through the existing shared protocol/configuration code.
Run focused regressions before broad acceptance. Keep native async transport and
its cancellation/ownership model. Scheduling, server push, ECH/PQ and unrelated
Session changes are independent capabilities, not implicit parts of these cards.

For F3, add at most one explicit browser-major profile backed by the exact
platform/build/flags capture and matched-field assertions. Label its scope as
that supported subset, including observed randomization and unavailable fields.
Verify a real TLS/H2 request through both clients with the selected profile,
stable copies, pool separation and unchanged historical profile assertions.
Adjust guides/examples to the observed evidence; retain the 154 capture and
compatible implicit selection. No version number or publication is selected by
the planning document.

### Installed candidate capture and final acceptance

The baseline series measures 2.3.0. It is not acceptance evidence for a later
protocol extension or new profile, even if the candidate still reports version
2.3.0. Wheel and source digests distinguish those inputs.

1. During F2/F3 development, run the named-card/profile regressions and affected
   real-peer tests. Intermediate wheel captures can aid diagnosis, but remain
   development evidence until tied to the final accepted source and artifact.
2. Once the selected runtime changes and build/test/docs inputs are ready, run
   the existing verifier in `--worktree-snapshot` mode, including every new
   in-scope untracked input. Use a fresh output directory, for example
   `dist/verify-fingerprint-candidate-01`. Its `verification.json` must pass;
   retain the frozen source file hashes and exact built wheel.
3. Reuse the same collector CLI with `--wheel` set to that report's retained
   `artifacts/<wheel filename>`, `--wheel-sha256` taken from its `artifacts`
   entry, and `--artifact-report` set to that verification report. Select the
   actual F2 configuration or F3 profile through `--client-profile` and the
   recorded overrides. Do not reuse the baseline wheel path/digest by default.
4. Capture one sync and one native async two-request connection from the installed
   candidate. Verify bodies, reuse, negotiated TLS/H2 and the exact selected
   wire fields using independent decoding. Store wheel digest, report digest,
   frozen source identity, installed module hashes, profile/overrides and tool
   hashes with the traces and before/after comparison. Require agreement with
   the verification report; there is no repository-source import fallback.
5. Reuse F1's browser evidence only when the frozen browser target, scenario,
   peer inputs and comparison rules still agree. Keep baseline, browser and
   candidate case identities separate in the report. A final capture failure
   leaves the selected requirement open; fix the proven cause and regenerate
   acceptance only for relevant changed inputs.

One final candidate series can accept F2 and F3 together when they share that
exact source/wheel and their named assertions all pass. Do not rerun the full
acceptance for each unchanged intermediate card. Store each candidate attempt
under a fresh directory such as `dist/fingerprint-candidate/capture-01/`; retain
the baseline traces unchanged. A source or wheel change invalidates candidate
evidence for the changed inputs and requires a newly identified candidate.

## 8. Verification gates by phase

| Phase | Required checks | Boundary |
| --- | --- | --- |
| S0-S1 | Reproducible explicit wheel/hash input; artifact/report/profile rejection before live capture; BIO fragmentation/EOF/deadline/output-drain tests; persistent independent decoder; bad trace/cleanup; one real browser trial | Collector feasibility and source provenance |
| S2-S3 / F1 closure | Three browser samples; installed sync/async full TLS/H2, bodies and reuse; raw hashes/independent fields; offline fixture/tool tests; reproducer/docs consistency; actual temporary cleanup | Captured evidence, not a claim of full browser fidelity |
| F2 | Named-card regressions and affected real TLS1.2/1.3/H2 failure boundaries; both clients; configuration/pool identity; public typing/docs; final installed candidate traces for selected fields | Changed runtime behavior, with artifact acceptance completed on the final selected snapshot |
| F3 / final selected runtime snapshot | Focused profile tests; existing installed artifact, types/docs/quality/compatibility gates once on the final source; actual candidate sync/async bodies/reuse and independently verified declared fields bound to that same wheel/source | Locally accepted implementation; remote delivery is separate |

F1's tool-only dependency installation and tests belong in the existing Python
3.12 tools CI slice. Its current install step supplies only pytest/packaging;
add the existing runtime primitive requirements and `requirements-capture.txt`
there before collecting the new tool tests. Runtime tests/offline fixtures must import no capture-only
dependency; the Python 3.7–3.13 runtime matrix remains unchanged in scope. A live
unpinned browser installation is not a hosted-CI prerequisite; the required local
capture has explicit evidence, and fixed-data/tool checks run deterministically.
The tooling CI must recompute the fixed fixture's decoded fields from raw bytes
with the independent decoder; runtime fixture tests can then compare their
implementation against those retained values without adding the tool dependency.

Existing focused checks usable after relevant implementation:

```sh
.venv/bin/python -m pytest test/test_browser_capture.py \
  test/test_browser_presets.py test/test_h2_fingerprint_review.py \
  test/test_wire_control.py test/integration/test_h2_fingerprint_review.py -q
.venv/bin/python -m mypy
.venv/bin/python -m mkdocs build --strict
.venv/bin/python docs/verify.py
```

Run new capture-tool tests when they exist. For a final changed runtime
candidate, use [the existing verifier](../tools/README.md) with
`--worktree-snapshot` and explicit `--include` entries for every new in-scope
source/test/fixture/document. Choose a fresh output directory. This verifies
installed tests/coverage, Python 3.7 grammar, typing, metadata, source hashes and
temporary cleanup. The full runtime command excludes the external manual
`test/test_session.py`. Reuse passing evidence for unchanged inputs; run another
full acceptance only after relevant changes or a required release-source change.

Formatting/error-level lint use the repository configuration. Benchmark updates
are required only when the selected change has a concrete performance concern;
they preserve raw samples and variability and do not create an invented speed
gate. No current test count is a target that must remain numerically fixed.

## 9. Later client/engineering lanes

| Separate lane | First execution step | Completion requirement |
| --- | --- | --- |
| C17 headers/params defaults | Refresh the [existing design](session_defaults_design.md) for 2.3.0 byte headers and prepared snapshots | One opt-in API; precedence, omitted/None/empty, caller copies, initial preparation, resend snapshot, retries and origin stripping; sync/async tests, installed types/docs |
| Sync 307/308 | Select additive opt-in or an explicit compatibility migration before changing dispatch | Method/body replay for buffered/replayable sources; non-replayable error and credential/transport cleanup over H1/H2 |
| Prepared streaming extension | Name the signing/digest workflow and define preparation I/O and source lifetime | Single/repeated/concurrent sends, consumed-source errors, retry/redirect replay, cancellation and bounded memory |
| C06 internal typing | Name one useful module/diagnostic and its dependencies | Strict slice with runtime behavior retained, installed consumer checks and honest remaining diagnostics |
| C01 docs hosting | Select host/URL/version policy and deployment target | Public route/asset/version readback and a concrete recovery path |
| C02 performance CI | Freeze runner/workloads/comparison policy | Raw samples/variability and observed protocol paths; reporting before performance thresholds |

These lanes can be selected independently after F1 or when a concrete consumer
need changes priority. Combining defaults, redirect migration and prepared-body
ownership into one runtime batch would obscure their compatibility boundaries.

## 10. Recovery, retention and planning acceptance

Execution stays serial for this workline: server/target, captures, differences,
selected protocol card, calibrated profile and final acceptance are dependent.
No subagents are used for the planning task. Use independent review or explicit
failure-boundary verification for a broad protocol change if later authorized;
delegation is not a prerequisite for delivering this plan.

After two attempts without narrowing the cause or advancing the same phase,
choose an evidence-backed alternative or report the precise missing input/API/
target capability. Preserve successful independent checks and failed traces;
do not repeatedly collect new samples to conceal a stable mismatch. A broken
collector is not a library defect until the cause is independently reproduced.

Keep fixtures, source manifests, raw captures, reports and acceptance evidence.
Clean only the recorded task-owned profiles, private certificate/key files,
listeners, probes and installation staging. Record actual PID/thread termination
and path absence. Failure can retain partial traces/logs for diagnosis, but not
an unreported running browser/server or unexplained secret-bearing staging.
Preserve all prior release evidence and unrelated local/user files.

Initial planning acceptance (historical):

- [✅] Read the roadmap, actual source/tooling boundaries and applicable rules.
- [✅] Verify relevant APIs and isolate the development-only dependency boundary.
- [✅] Define the target, approach, phases, proposed paths, evidence and gates.
- [✅] Link the plan from the roadmap and verify links, scope and consistency.
- [✅] Correct baseline acquisition and installed candidate capture after review.

Initial planning verification: all 59 relative file targets across the execution plan,
roadmap and index resolve; whitespace, code fences, phase/dependency coverage,
backlinks and `git diff --check` passed. Local capability inspection confirmed
the required ssl APIs and browser application version. Python/Chromium primary
documentation and the hash-checked official hpack source support the API choices.
At that initial planning checkpoint, the capture tool, browser trials and runtime
regressions had not been executed. Subsequent results are recorded below.

Review correction verification: the retained wheel digest agrees with its passing
report and official PyPI metadata; all 59 relative file targets, code fences,
whitespace and `git diff --check` pass. The CLI contract and phase gates were
read back for baseline/candidate consistency. These are planning checks, not
execution evidence for the proposed collector.

## 11. Engineering execution record

The fixed objective, package order and acceptance boundaries above govern this
execution. Work stays serial; no subagents are used. Commit/push/release remain
outside the current engineering action set.

- [✅] S0: verify the executable target `Google Chrome 155.0.8059.39`, local
  Python 3.13.3/OpenSSL 3.0.16 and the exact released 2.3.0 wheel digest.
- [✅] S1: implement/test the owned collector; real browser trial `trial-01` passed.
- [✅] S2: final `capture-04` completed three browser, one installed sync and one
  installed async cases; actual full TLS 1.3/h2, bodies/DOM and same-connection
  reuse passed. Source/module hashes agree with the selected baseline wheel.
- [✅] S3: retain `test/fixtures/chrome155_macos_tls_h2.json`, independent decoded
  fields, [difference report](tls_h2_capture_results.md) and actual reproduction
  commands in tools/README.md. The collector compares all three browser samples,
  HEADERS priority/flags, stable extension contents, ordered header values and
  HPACK table continuity; unknown/variable contents stay explicit.
- [✅] S4: existing controls satisfy the selected F1 observation contract. F1
  closes through its documented configuration/report route. HEADERS priority,
  Huffman and indexing differences are concrete follow-up candidates; no F2 card
  or F3 profile is selected. Full browser identity remains unachieved and is not
  relabeled as delivered subset parity.
- [✅] Final acceptance: 496 affected runtime/tool tests passed; actual profile
  preflight rejection passed before live cases; source snapshots, baseline wheel
  identity, offline independent decoding and temporary cleanup agree. CI tool
  dependencies and documentation were updated. No runtime library source
  changed, so final F2/F3 candidate-wheel gates are not applicable to F1.

Final F1 review also verified Python 3.7 grammar for changed runtime test helpers,
formatting and relative links. Hosted CI/commit/push/release remain unexecuted.
Keep full attempts, exact tool-source snapshots and baseline release reports in
their recorded dist directories; task-created profiles, private keys, listener,
owned peers and probe installation roots have been removed/reaped. Detached owned
descendants are checked by PID/creation identity and private-profile ownership,
without selecting unrelated Chrome processes.

The file plan remains UNREGISTERED: the current `codex-plan --json status` still
reports missing fresh official session binding. This does not change execution
scope or acceptance requirements. Completion is recorded only with actual evidence.

## 12. Selected F2: benefit-based outbound HPACK Huffman

Selected by the user's instruction to continue after F1 acceptance. The fixed
increment is optional outbound HPACK string Huffman coding in both clients;
HEADERS priority, indexing policy, new TLS negotiations and F3 stay unselected.
All 90 literal name/value decisions in the three retained browser samples match
the rule: use Huffman only when its encoded octet length is strictly smaller.

Public contract: `TlsConfig.h2_huffman: bool`, default `False`. `True` applies
the measured benefit-based rule to literal names/values. Raw `encode_string`
and `HPACKEncoder` keep their existing raw default and receive the same optional
boolean policy. Preserve sensitive-field never-indexing, dynamic-table contents,
peer table updates, strict UTF-8 header validation and raw-octet string encoding.
Configuration is validated before sending and participates in pooled policy
identity. Shared codecs serve sync/native async; no external HPACK runtime
dependency is added. Reuse the existing Huffman table/encoder and keep its
working bit accumulator bounded as outbound strings become a supported path.

Acceptance: independent RFC vectors/all-octet checks, captured literal policy,
invalid input before state mutation, table resize/reuse, both actual TLS/H2 send
paths, policy pool separation, installed public types/docs and the existing
final frozen-source verifier. Independently capture the verifier's installed
candidate wheel with `h2_huffman=True`, retaining exact source/wheel/tool inputs.
Require matching first-request HPACK bytes under equivalent inputs, measured
literal policy on reuse and functioning bodies/reuse; keep the second request's
indexing and HEADERS-priority differences explicit.

Execute serially without subagents. Retain the candidate wheel/report/captures;
remove owned build/probe/browser/server staging. Preserve all F1/release/user
files. Commit/push/release remain outside this action set. The file plan remains
UNREGISTERED until the supported CLI has an official binding.

- [✅] Implement the shared optional codec/config/send-path/pool policy.
- [✅] Verify named success/failure/wire/identity regressions and public typing.
- [✅] Update runnable docs, collector override/independent candidate assertions.
- [✅] Freeze and verify the final candidate, then recapture installed sync/async.
- [✅] Reconcile acceptance, retained artifacts, cleanup and roadmap status.

Development evidence: 632 affected runtime/tool tests passed; source mypy,
package Black/error-level Pylint, strict MkDocs and docs verification passed.
The guide snippet actually sent a Huffman authority literal over authenticated
TLS 1.3. The final installed consumer/artifact/capture gate also passed:

- Verifier: `dist/verify-huffman-candidate-01/verification.json`, status passed;
  3,587 installed tests plus 118 subtests, no failures/errors/skips, 92.14%
  statement coverage, installed positive/negative typing and Python 3.7 grammar.
- Candidate wheel SHA-256:
  `cb5c8f413b57c7d815996b27bd23953a5b88371d5ec9e17e43d151e07b3f6c13`.
  It retains version 2.3.0 metadata but is an unpublished worktree candidate,
  distinct from the released 2.3.0 wheel. No version/publication is selected.
- Candidate captures: `dist/fingerprint-huffman/capture-01/`, using that exact
  wheel and passing report; three fresh browsers and installed sync/async all
  completed full TLS 1.3/h2, expected bodies/DOM and same-connection reuse.
  Independent `huffman_acceptance` passed exact first-request blocks and 30
  literal choices per library client across both requests.
- Package module hashes agree with the verifier and installed probes. The
  capture retains matching report/tool hashes and exact tool-source copies.
  Verifier staging, probe/CA/key roots and browser profiles were removed;
  listener closed and peer/process observation threads/groups/owned descendants
  terminated. Reports, artifacts and traces remain retained deliverables.

The accepted verifier identifies its frozen source snapshot, not an invented
commit or publication. At that closeout, execution-record status edits left
package/build/test/type/guide inputs unchanged and the frozen hashes were checked
again. Later synchronous transport fixes changed package/test/guide inputs;
this is now historical evidence, not a current-source hash-match assertion.
F3 and the remaining HEADERS priority, indexing and TLS differences remain
explicit/unselected for implementation.
