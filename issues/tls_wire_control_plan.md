# TLS wire control: fixed A-E outcome

Completion readback: 2026-10-04. A–E and remote acceptance are complete.
[PR #56](https://github.com/lxjmaster/ja3requests/pull/56) merged as
`a291ef30bb6ae53cf38b3d79604c8f34e1865547`; final head `35b502b` and merged master
passed all ten configured CI checks. The separately authorized release published
this source as [PyPI 2.0.1](https://pypi.org/project/ja3requests/2.0.1/) and
[GitHub v2.0.1](https://github.com/lxjmaster/ja3requests/releases/tag/v2.0.1).
The tag resolves to the merge commit, and published artifact hashes match the
verified files. Release verification passed 1517 tests and 112 subtests with
89.09% coverage. Release evidence remains in `dist/release-2.0.1/`.

The sections below retain the original implementation scope and dated development
evidence, including the earlier 1486-test snapshot. They do not reopen completed
CI, merge or publication work.

Selected 2026-10-04. Baseline: 3fb28be70f999d19cbcb641248aceb242d714906
(published 2.0.0). This workline implemented the user's approved optimization
proposal, not just A+B. Completion required evidence for every requirement below.
File registration remained UNREGISTERED because official CLI session binding was
unavailable; implementation continued. Execution was serial without subagents.

## Original implementation boundary

The project owns ClientHello, handshake state, retry/resumption, key schedule
and records. Cryptography may provide primitive operations; no external TLS
engine may drive the client. OpenSSL is an independent test server only.
No pure-Python cipher rewrite, backend framework, QUIC/ECH, 0-RTT, persisted
TLS sessions, server push, or unrelated suite expansion. Keep secure defaults and
existing preset wire behavior stable unless an explicitly documented correction
is necessary. Do not republish 2.0.0 or start a new release.

## Required outcomes and evidence

- [✅] A: capability/field map and baseline for secure, legacy and representative
  presets; distinguish encoding, negotiation and independently verified support.
- [✅] B: configured Session ID honored; unsupported compression rejected;
  absent versus explicit empty values handled consistently; validation before
  sending. Tests must exercise actual serialization and failure boundaries.
- [✅] C: explicit exact extension ordering/completion rules, dynamic key-share
  and PSK constraints, actual sent ClientHello inspection/JA3. Test received
  bytes with an independent parser, including retry/resumption where applicable.
- [✅] D: opt-in P-384 generation, share encoding, shared secret, validation and
  HRR. Independent full/retry handshakes, fragmented reads, invalid/unoffered
  group/public-key rejection. Existing preset shares must not silently grow.
- [✅] E: select one real browser/version/environment, retain capture provenance,
  compare its actual hello and calibrate a preset. Report all unsupported/different
  behavior honestly; no claim of complete browser impersonation from JA3 alone.
- [✅] Local final: affected regressions, installed-wheel full selected suite,
  >=85% coverage and Black/error-level Pylint. Documentation describes APIs,
  dependency boundaries, capability limits and exact evidence.
- [✅] Remote final: all ten existing CI checks passed on the reviewed final
  feature-branch head `35b502b`. Merge and publication followed under the separate
  release authorization recorded above.

## Original execution and completion requirements

Start A/B, then the required C controls, D and E. An unavailable browser sample
blocks E only; finish independent A-D work first. Preserve all user debug scripts,
IDE files, existing artifacts and worktrees. Retain evidence/artifacts under
dist/wire-control; remove only identified task-owned temporary environments and
browser profiles. No global cleanup. Reuse unchanged passing checks.

Final audit must reconcile every item; tests passing alone do not prove preset
fidelity. Stop and report a real missing dependency after bounded recovery, never
mark partial outcomes complete. This plan does not grant new publication authority.

## Local implementation evidence

A: docs/tls_wire_control.md and test/fixtures/wire_baseline.json; an independent
byte parser asserts published secure/legacy/Chrome120 profiles.
B/C: test/test_wire_control.py; socket-received bytes, explicit empty/zero Session
IDs, cache precedence, invalid compression/groups, exact ordering and raw summary.
test/integration/test_tls13_resumption.py verifies actual PSK and retry records.
D: test/test_p384_wire.py and test/integration/test_wire_p384.py; independent
OpenSSL server, certificate verification, direct/retry and fragmented reads,
both GCM cipher sizes, invalid points and unadvertised/invalid retry groups.
E: test/fixtures/chrome154_macos_hello.json was captured from actual Chrome
154.0.8037.95 using test/capture_browser_hello.py. The explicit profile preserves
supported fields' relative order/content; test/test_browser_capture.py and
TLS 1.2/1.3 integration cases verify it. The report explicitly lists different
JA3 and unsupported sampled fields; no ECH/PQ/H2 imitation work was added.

Initial full development run found two previously invalid test configurations
(TLS 1.3 with only TLS 1.2 ciphers). Fixtures were corrected to their intended
protocol; validation was not relaxed. Focused verification then passed. Final
installed-wheel suite and artifact checks are evidenced below. CI was pending at
this local snapshot; its completed readback is recorded at the top.

## Local implementation acceptance (historical snapshot)

The isolated sdist-to-wheel build and strict Twine check passed. The wheel was
installed in a clean environment outside the repository, and the tests shipped
in the sdist ran against that installed package: **1486 passed and 112 subtests
passed**, zero failures/errors/skips, **89.07%** coverage (7309/8206 statements).
The one pre-existing collection warning remains. Runtime source bytes agree
between the checkout, isolated snapshot, sdist and wheel. JSON capture/baseline
fixtures are included in the sdist. Black and error-level Pylint passed.

Evidence retained: dist/wire-control/verification.json, installed.xml,
coverage.json, pytest.log, command logs, verify_installed.py and artifacts/.
These artifacts still have development metadata version 2.0.0 and MUST NOT
replace or be confused with the already published R02 files. No release is in
scope. Source/test inputs are frozen; subsequent plan-only edits do not require
rebuilding or rerunning passing tests.

## Historical remote preparation snapshot

The user explicitly approved pushing feature/tls-wire-control and creating its
PR for final CI verification on 2026-10-04. At that stage merge and publication
were outside the implementation scope, and remote final acceptance was pending.
The requested completion records were dist/wire-control/remote_ci.json and
local_acceptance.json. Later release authorization and completed verification
supersede that pending state, as recorded at the top.

PR #56 was draft with base master at this historical inspection.
The first CI lint run reproduced Pylint E1102 when pre-commit analyzed files
separately: the TLS ticket callback is assigned in another module. The normal
whole-package Pylint command passed. The hook was aligned with that same
whole-package command (pass_filenames: false), retaining error checks without
runtime changes. All local pre-commit hooks then passed; final head CI still
required readback at that point and subsequently passed.
