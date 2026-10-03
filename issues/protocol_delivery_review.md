# Protocol Delivery Review

Date: 2026-10-03. Original scope: PR #52 and the incremental PR #53, necessary local
fixes, verification, and a merge recommendation. No remote writes, commits,
merges, publication, history rewriting, subagents, or T06-T10 implementation.

## Candidate identity and review result

Follow-up status: the user requested execution of the revised plan. Verified
repairs are now committed on both branches, and #53 incorporates the updated
#52 ancestry without additional runtime changes. Fresh remote CI passed;
the local-only and uncommitted statements below describe the original review
snapshot. The user's subsequent correction and resumed execution confirm the
E3 merge workflow; the previous missing-authority classification is superseded.
No package publication is included.

PR #52 is based on master `7a545688d12327a4487d9ea87f39d496303db6bc` and has head
`21f72ae397fd7656ac1c58fcdbfa207bdc7bb94a`. PR #53 is based on #52 and has head
`7711f86446c5512c16311a2db39cdc3888566f70`. Both remain OPEN/draft with ten
successful remote checks and no submitted reviews at inspection.

**Do not merge the existing remote heads unchanged.** Three required #52
defects were reproduced and fixed first in its isolated local worktree, then
the same source changes and tests were applied to #53. No #53-only required
defect was identified in the incremental migration review. Remote CI still
covers the original heads, not these uncommitted fixes.

One additional #52 test defect surfaced during full verification and was fixed
on #52 before propagation: R4 below changes assertions only, not runtime policy.

**Local acceptance is complete.** #52's installed candidate passed 1,374 tests
with 88.89% statement coverage; #53's passed 1,427 with 89.04%. Both had zero
failures/errors/skips, passed package Black/error-level Pylint and installed
profile checks, and matched all 58 wheel modules to their source snapshots.
The existing TestContext collection warning remains. The local candidates are
ready for authorized commit/push and new CI, not immediate merge of old heads.

## Required findings and disposition

### R1: HTTP/2 connection reservation ignores the waiting request's timeout

- Severity: P1 (unbounded/incorrectly bounded request wait). Owner: #52.
- Location: `ConnectionPool.get_h2_or_reserve` in
  [pool.py](../ja3requests/pool.py), called by `HttpsSocket.new_conn` in
  [https.py](../ja3requests/sockets/https.py).
- Trigger: one request is establishing an HTTP/2-capable connection; a second
  request for the same destination/policy has a shorter connect timeout.
- Evidence: the condition wait had no timeout and the caller supplied none.
  A request with a 30ms timeout remained waiting after 200ms until the test
  released the first reservation. The permanent regression failed before the fix.
- Fix: pass the connect timeout, calculate a monotonic deadline, and bound each
  condition wait by its remaining duration. An unspecified timeout uses the
  five-second handshake fallback. A timed-out waiter does not release the
  original owner's reservation or initiate a new network connection.
- Verification: explicit zero/positive timeout and successful owner-release
  cases in [test_delivery_timeouts.py](../test/test_delivery_timeouts.py).

### R2: TLS 1.2 resumed handshake waits indefinitely for server Finished

- Severity: P1 (peer can indefinitely block a resumed connection). Owner: #52.
- Location: `TLS._handshake_tls12` in
  [tls/__init__.py](../ja3requests/protocol/tls/__init__.py).
- Trigger: the peer echoes a compatible cached Session ID/ticket identity and
  EMS in ServerHello, then withholds ChangeCipherSpec/Finished.
- Evidence: the preceding parser resets the socket timeout to `None`; the new
  resumed branch immediately reads Finished without restoring it. A 30ms
  handshake remained blocked after 200ms, with the socket timeout observed as
  `None`. All four permanent stalled-peer cases failed before the fix.
- Fix: bound the resumed Finished receive and client completion using the
  configured handshake timeout (five seconds if unspecified); restore the
  post-handshake socket setting in `finally`. Failed ticket recovery retains
  the existing invalidation behavior.
- Verification: independent raw socket peers withhold Finished for Session ID
  and ticket recovery, both direct TLS 1.2 and TLS 1.3-offer fallback. Existing
  independent OpenSSL successful recovery and tamper-rejection tests also pass
  in the targeted selection.

### R3: HTTP/2 uploads exceed the TLS plaintext record boundary

- Severity: P1 (ordinary large HTTP/2 uploads fail). Owner: #52.
- Location: `HttpsSocket._send_h2`'s transport callback in
  [https.py](../ja3requests/sockets/https.py).
- Trigger: a 20,000-byte POST with default server windows produces a 16,384-byte
  HTTP/2 DATA payload plus its nine-byte header. The callback encrypted that
  whole frame as one TLS record. Larger advertised frame sizes have the same
  boundary problem.
- Evidence: four new independent OpenSSL cases failed before the fix: TLS
  1.2/1.3, with and without connection pooling. The existing 70KB upload test
  advertised a 4KB stream window, avoiding this boundary.
- Fix: split HTTP/2 transport bytes into at most 16,384-byte TLS plaintext
  fragments under the existing send lock. HTTP/2 frame boundaries, flow-control
  accounting, and fingerprint settings remain unchanged.
- Verification: [test_h2_large_upload.py](../test/integration/test_h2_large_upload.py)
  passes all four cases, checks the complete body, and preserves DATA payload
  sizes of 16,384 and 3,616 bytes.

### R4: PSK absence assertion can match random key-share bytes

- Severity: P2 (flaky verification gate). Owner: #52; test-only fix.
- Location: `test_verified_request_does_not_offer_unverified_ticket` in
  [test_tls13_resumption.py](../test/test_tls13_resumption.py).
- Evidence: the first installed-wheel run passed 1,372 tests but failed this
  assertion: `b"\x00\x29" not in tls.body.extensions`. The earlier assertion
  confirmed no unverified PSK was selected. Random key shares and other opaque
  payloads can legitimately contain those bytes without a PSK extension.
- Fix: walk the serialized extension type/length boundaries and reject a PSK
  type there, while checking complete framing. Add a deterministic opaque
  SessionTicket payload containing the same bytes so the old check's ambiguity
  is covered without depending on random keys.
- Verification: all nine TLS 1.3 resumption unit cases pass; the assertion still
  rejects an actual PSK extension. Runtime code and the built wheel are unchanged
  by this test correction and their successful checks are reused.

## Review coverage and supporting evidence

| Required concern | Inspected implementation and evidence |
| --- | --- |
| TLS policy/resumption eligibility | TLS session selection and cache expiration/removal; `test_tls12_resumption.py`, `test_tls13_resumption.py`, corresponding integration tests |
| Finished authentication/fallback | TLS 1.2 authenticated record reader, TLS 1.3 transcript/Finished/PSK handling; `test_tls12_finished.py`, `test_tls13_transcript.py`, independent recovery and invalid-Finished cases |
| Client authentication/restrictions | TLS 1.2 client signature construction, TLS 1.3 certificate/key matching and post-handshake authentication; certificate and post-handshake integration cases |
| Fragmentation/cleanup | TLS handshake and record reassembly, HTTPS failure cleanup; fragmented peer fixtures, failure/pool tests, R2 regression |
| HTTP/2 streams/flow control | `multiplex.py`, `connection.py`, transport and pool lifecycle; concurrent bodies, interleaved responses, WINDOW_UPDATE, GOAWAY/reset/timeout tests; R1/R3 regressions |
| HPACK/cancelled streams | Header-fragment discard and decoder table updates, bounded HPACK tables; discarded-header and HPACK-table integration tests |
| Cookie persistence | Complete JSON validation before replacement, atomic save, domain/path/session/expiry policy; `test_cookie_files.py` cross-process/failed-write cases and request Cookie scope tests |
| #53 entry-point defaults | Entire incremental runtime diff, Session/factory/module entry paths, direct TLS configuration guard; 53 default-policy integration cases |
| Overrides/pool isolation | Request-specific configuration copy, redirect preservation, HTTPS pool policy and verified hostname checks; `test_verify_config.py`, certificate/default-policy integration tests |
| Legacy/browser compatibility | `secure`, `legacy`, `from_browser` and mutating builders; TLS config/browser tests, migration guide, release notes and both READMEs |

The review does not claim exhaustive protocol security certification. No style
refactoring, dependency upgrade, scheduler, server push or additional curve was
introduced. TLS persistence and early data remain unsupported. Existing TLS
client-certificate/resumption restrictions are intentional, not new blockers.

## Verification record

- Baseline evidence remains in `dist/t05/`; it was not overwritten.
- Before repair: the initial timeout selection had 5 failures/1 pass; the four
  default-window upload cases all failed against OpenSSL.
- After timeout repairs: 62 relevant unit/OpenSSL integration cases passed.
  After transport repair: all four large-upload cases passed.
- New regression inventory: seven timeout/reservation cases plus four upload
  cases, and one additional deterministic case for the corrected PSK assertion.
  Source deltas in all three changed runtime files and both new test files
  were checked for identical propagation from #52 to #53.
- Final wheel/source hashes, installed import origin, JUnit, coverage, formatting
  and error-level lint results are retained separately under
  `dist/delivery_review/pr52/` and `dist/delivery_review/pr53/`.
- Final report and artifact hashes were independently read back after both runs;
  source/test manifests match the retained local candidates. Old T05 artifact
  hashes remain unchanged. Runtime deltas, the corrected existing test and both
  new test files match across the two candidates. Both saved patches pass
  reverse-application checks against their respective local worktrees.
- New local verification used macOS arm64, Python 3.13.3 and OpenSSL 3.0.16.
  Older-runtime remote results remain historical; new fixes have not run remote
  CI. Do not label the new candidate Python 3.7-3.13 CI-verified yet.
- Build recovery: the initial no-isolation build could not import
  `setuptools.build_meta` from the existing venv. The verification runner uses
  the repository's previously successful isolated `pip wheel --no-deps` route;
  this does not alter package sources or global dependencies. Unchanged passing
  formatting/lint results were reused rather than rerun for that retry.
- The runner's initial import-origin assertion compared a resolved `/private/tmp`
  path with an unresolved `/tmp` path on macOS. Resolving both operands corrected
  the verification harness; no import policy or package change was needed.
  The actual successful checks assert installed origin outside both checkouts.

## Handoff and remaining authority

Keep the fixes on #52 first and carry them into #53. Publishing these local
fixes requires commit/push authorization; confirm the resulting remote checks
before recommending the updated remote heads for merge. Neither the previous
green checks nor this local review marks unpublished changes as remotely tested.

After separate merge authorization, merge #52 server-side, retarget #53 to
master, inspect its final ancestry/diff, verify the integration state, and merge
#53 only if required conditions pass. Draft PRs must be made ready as part of
that authorized workflow. Publication is a separate outcome.

Retain both local candidates, the consolidated report and verification artifacts
as deliverables. Task-owned installed/build/test staging is removed after each
verification run. Existing debug scripts, IDE metadata and prior artifacts remain
untouched. No missing remote authority blocks completion of the requested local
review/fix/verification outcome.

Local handoff locations:

- #52 worktree: `/Users/mastluo/MyProjects/ja3requests-pr52-delivery-review`, on
  `feature/protocol-delivery`, with uncommitted runtime/test repairs.
- #53 worktree: `/Users/mastluo/MyProjects/ja3requests`, on
  `feature/secure-defaults-migration`, with the same repairs plus plan/review docs.
- Recovery patches: `dist/delivery_review/pr52/local-fixes.patch` and
  `dist/delivery_review/pr53/local-fixes.patch`; each includes the three runtime
  files, the corrected existing test and both new test files.
- Evidence: per-candidate `verification_summary.json`, `verification.xml`,
  `coverage.json`, wheel, manifests and logs; `remote_snapshot.json` records the
  unchanged remote heads and checks. No package was published.

Cleanup readback: after fixture teardown, candidate verification and moving
#52 to its retained location, only empty test directories and three dangling
pytest fixture links remained. The task-owned links were unlinked and directories
removed with empty-directory removal. Both patches were reverse-checked again
at the final worktree locations. No user files or retained evidence were removed.

## E3 pushed-candidate handoff

On 2026-10-03 the follow-up execution request advanced the verified repairs to
the remote branches. #52 is now `ad62e9a022bdc271d43c4aba88925773273eaab2`;
#53 is `8e8c0926f9df1e72ef6cf2727993ca7efa9dbfb1`, including the #52 ancestry.
Every entry of the original source/test manifests also matches these commits.
The incremental #53 diff contains no duplicate #52 repair delta.

Both exact remote heads have ten successful checks and report CLEAN/MERGEABLE.
They remain OPEN/draft; no server-side merge, retarget or publication occurred.

| Candidate | Python 3.11-3.13 (each) | Python 3.7-3.10 (each) | Remote coverage |
| --- | --- | --- | --- |
| #52 | 1374 passed | 1356 passed, 18 skipped | 88.89% |
| #53 | 1427 passed | 1409 passed, 18 skipped | 89.04% |

The existing manual-test exclusion and older-runtime skip boundaries remain.
Fresh check identities and URLs are retained in
`dist/delivery_review/remote_post_push.json`. Test runs are 37090686073 (#52)
and 37090746597 (#53); coverage runs are 37090686106 and 37090746583.

Recommendation: the updated candidates are ready for the separately authorized
merge sequence: mark #52 ready and merge server-side; retarget #53 to master;
inspect final ancestry/diff and integration checks, then mark ready and merge
#53. Prefer preserving ancestry with merge commits; do not rewrite history or
delete the retained branches/worktrees. Publication remains separate.

The user corrected the missing-authority interpretation and resumed execution.
#52 was marked ready and merged server-side on 2026-10-03 at 02:59:12 UTC as
`f0a00507c449e746b287fe58836b4c4c4111341f`. #53 now targets master; its final
integration candidate will be checked before the second server-side merge.
