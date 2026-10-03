# Next Development Plan

Created: 2026-10-01

## Outcome and scope

This roadmap turns the remaining items in `IMPROVEMENTS.md` into ordered,
verifiable tasks. The planning deliverable is complete. Selected execution
batches and their evidence are recorded below; unchecked tasks remain queued.

On 2026-10-01, the user requested sequential execution of this plan. T01-T04
are complete. On 2026-10-02, the user requested T05; its 2.0.0 implementation
and local acceptance are complete. Delivery CI is tracked on the migration PR.
Subsequent batches follow the order below. Commit, push, merge, release, and the conditional
constructor-defaults migration remain separate outcomes with their stated
authorization and decision dependencies.

Lifecycle registration: **UNREGISTERED**. `codex-plan` is installed, but its
status command could not obtain an official session binding on 2026-10-01.
The binding was still unavailable at the start of T04. Retain this file as the
roadmap and batch checklist. Once binding is available, register the selected
execution outcome as a workline; the remaining future roadmap is reference context.

## Verified T01-T04 baseline (historical)

- The existing checklist in `https_feature_development.md` is checked off.
- The latest installed-wheel local run passed 1362 selected tests with 88.86%
  statement coverage. Black, error-level Pylint, and `git diff --check` passed.
  See the T04 record below; earlier runs remain historical evidence.
- HTTP/2 requires initial non-ACK server SETTINGS and rejects defined response
  and control frames on unopened streams. Cancelled-stream headers still update
  HPACK state; idle PRIORITY and unknown extension frames remain allowed.
- The 2026-10-01 worktree inspection found 43 modified tracked files and 29
  untracked entries before this roadmap was added. Entries include source/tests,
  local IDE metadata, and manual debugging scripts; they need classification.
- `TlsConfig.secure()` and `TlsConfig.legacy()` exist. The constructor still
  selects the legacy configuration and disables certificate verification.
- TLS 1.3 key shares support X25519 and P-256. Cookie and TLS caches are in
  memory. T04 adds explicit Cookie JSON save/load on Session and CookieJar;
  TLS session persistence remains unimplemented. CookieJar pickle compatibility
  is separate from the public file-import API.
- TLS cache entries contain TLS 1.2 master secrets or TLS 1.3 PSKs as well as
  certificate policy and expiry metadata. Ticket age currently uses monotonic
  time, so cross-process persistence needs a new age reconstruction policy.
- CI configuration declares Python 3.7-3.13, a coverage floor of 85%, package
  formatting, error-level Pylint, and an installed-wheel smoke check. Remote CI
  success for the current uncommitted implementation is not established.

## Recommended order

| Order | Task | Priority | Dependency | Completion boundary |
| --- | --- | --- | --- | --- |
| 1 | T01: Prepare the existing implementation for delivery | P0 | Existing worktree | Reviewable change inventory and verified package |
| 2 | T02: Complete secure-profile interoperability evidence | P1 | T01 | Documented matrix with tested and unsupported cells |
| 3 | T03: Prepare the TLS defaults migration guide | P1 | T02 | Examples and compatibility impact documented |
| 4 | T04: Add opt-in Cookie file persistence | P1 | T01 | Cross-process round trip and scope/expiry preservation |
| 5 | T05: Switch constructor defaults in a breaking release | Conditional | T02, T03, release decision | Authorized migration and compatibility checks pass |
| 6 | T06: Expand TLS 1.3 key exchange groups | P2, demand-led | T02 and target group selection | One selected group verified end to end |
| 7 | T07: Verify additional TLS 1.2 SHA-384 suites | P2, compatibility-led | Concrete target suite/peer | Explicit supported or unsupported result per suite |
| 8 | T08: Design opt-in TLS session persistence | P2, demand-led | Secret storage and trust-policy decision | Reviewed design; implementation is a separate phase |
| 9 | T09: Evaluate HTTP/2 scheduling or server push | P3, demand-led | Concrete consumer use case | Select one extension and define its public behavior |
| 10 | T10: Evaluate TLS 1.3 early data (0-RTT) | P3, demand-led | T08 policy if persistence is used; replay policy | Complete design before implementation |

P0 means current delivery readiness. P1 is the recommended next batch. P2 and
P3 are candidates whose implementation depends on a concrete usage requirement.
No calendar dates are assigned before target environments and scope are selected.

## Execution progress

- [✅] T01 completed on 2026-10-01. See [the delivery readiness record](delivery_readiness.md)
  for the complete inventory, candidate commit groups, release-note draft and
  installed-wheel evidence: 1247 tests passed with 88.68% coverage. The wheel and
  reports are retained in `dist/t01/`; task-owned staging was cleaned up.
- [✅] T02 completed on 2026-10-01. See [the secure-profile matrix](../test/secure_profile_matrix.md)
  for the inventory, selected combinations, failure boundaries and environment
  limits. All 52 added cases passed; Black and error-level Pylint passed for
  changed tests. The unchanged library's T01 full-run evidence was reused.
  Passing reports are retained in `dist/t02/`; generated certificate keys and
  task-owned staging were removed.
- [✅] T03 completed on 2026-10-01. See [the TLS defaults migration guide](../docs/tls_defaults_migration.md)
  for verified-service setup, private CA/self-signed certificate handling,
  hostname/SNI behavior, request overrides, profile/ALPN/fingerprint effects,
  and the proposed breaking-release acceptance criteria. Both READMEs link to
  the guide. Nine snippet syntax/configuration checks and eight captured request
  preparations passed; links, anchors, snippet formatting and diff checks passed.
  All 137 Python source/test/example files are unchanged. No temporary fixtures
  were created, and the existing protocol evidence was reused.
- [✅] T04 completed on 2026-10-01. See [Cookie file persistence](../docs/cookie_persistence.md)
  for the format comparison, public APIs, scope/session/expiry rules, bounded
  parsing, atomic writes and file protection/retention. Added 63 passing cases;
  144 targeted tests passed. The installed-wheel full run passed 1362 tests with
  88.86% coverage and one existing collection warning; all 58 module hashes
  matched. Black, error-level Pylint, syntax/links, diff and example checks passed.
  The new wheel and reports are retained in `dist/t04/`; task-created temporary
  Cookie files, generated certificate keys and build/test staging were removed.
- [✅] T05 implementation and local acceptance completed on 2026-10-02 for the
  2.0.0 candidate. See [the defaults delivery record](secure_defaults_delivery.md):
  53 default-policy integration cases and 1415 installed-wheel tests passed,
  with 89.03% coverage. Both READMEs, migration guide and release notes describe
  the breaking behavior. Wheel/reports are retained in `dist/t05/`; task-owned
  staging and generated keys were removed. Remote delivery results are tracked
  on the migration PR. T06-T10 retain target/use-case selection dependencies.

### Delivery follow-up

On 2026-10-01, the user accepted the next delivery step: synchronize stale
Cookie-persistence documentation, commit the T01-T04 source/tests/docs, and
verify remote CI. The delivery branch is `feature/protocol-delivery`; manual
debug scripts and IDE metadata remain outside the commits. The source and test
hashes still match the passing T04 installed-wheel snapshot. Remote verification
is tracked on the delivery pull request; the earlier records remain snapshots
of their respective local batches. T05's 2.0.0 candidate decision and implementation
are complete; merge and publication remain separate authorized outcomes.

## T01: Prepare the existing implementation for delivery

- [✅] Classify tracked and untracked changes into TLS, HTTP/2, Cookie/request
  behavior, tests, and documentation. Preserve all existing user changes.
- [✅] Identify which untracked source/tests are required deliverables, including
  `protocol/h2/multiplex.py`; keep IDE metadata and manual scripts out of the
  candidate change set unless the user selects them. Do not delete them.
- [✅] Prepare coherent candidate commit groups and a release-note draft that
  states tested behavior and remaining limits.
- [✅] Build the wheel and verify installed imports and request framing outside
  the source tree, including the multiplex module and secure/legacy profiles.
- [✅] Run the selected local verification gates after any relevant changes and
  record the tested environment and result.

Acceptance: every candidate deliverable is identified; the built package contains
required modules; relevant local gates pass. Commit/push and remote CI are later
delivery actions when authorized. T01 does not require publishing a package.

## T02: Complete secure-profile interoperability evidence

- [✅] Inventory existing secure-profile tests before adding cases. Record
  protocol version, cipher, certificate key type, key exchange group, HTTP mode,
  connection reuse/resumption, and normal/fragmented reads.
- [✅] Identify concrete missing combinations needed for the next release.
  Prioritize explicit TLS 1.3 suites and TLS 1.2 AES-128/256-GCM, RSA/ECDSA
  certificates, X25519/P-256, and secure configuration with opt-in HTTP/2.
- [✅] Add only missing representative cases and failure boundaries; reuse
  existing tests for hostname/chain rejection, authentication, and resumption.
- [✅] Verify the affected selection on the declared supported Python/OpenSSL
  environments available locally or in authorized CI. Mark unavailable cells
  unverified rather than reporting a full matrix as passing.

Acceptance: a repository matrix maps each supported claim to test evidence and
lists unsupported/unverified environments. Existing coverage is not duplicated,
and unsupported configurations cannot silently bypass certificate verification.

## T03 and T05: Prepare and execute defaults migration

T03 is compatibility preparation in the current API:

- [✅] Document verified service setup, custom CA/self-signed certificate trust,
  hostname/SNI behavior, legacy-server configuration, and request-level overrides.
- [✅] Show how to select `secure()` or pin `legacy()` and explain their effects
  on TLS negotiation, ALPN, and ClientHello/JA3 fingerprints.
- [✅] Define the proposed breaking-release policy and migration acceptance
  criteria, including Sessions constructed without an explicit TLS config.

Acceptance for T03: examples use existing supported APIs and explicitly describe
behavior changes; constructor defaults are not changed by documentation work.

T05: the user requested the next task on 2026-10-02; implement the recommended
2.0.0 candidate. Publishing, deployment and merging remain separate actions:

- [✅] Change default construction consistently across entry points.
- [✅] Verify certificate rejection, TLS fallback, explicit legacy opt-in,
  verification overrides, and pool isolation after the default change.
- [✅] Update version/release notes and both READMEs for the selected release.

Acceptance for T05: T02/T03 evidence is complete for the selected release scope;
the new defaults and compatibility entry point pass relevant checks. Publishing
or deploying that release is a separate authorized action.

## T04: Add opt-in Cookie file persistence

- [✅] Compare a versioned JSON representation with standard-library file jars
  using representative Cookies. Select a format that preserves required domain,
  host-only, path, Secure, HttpOnly, expiry, and extension metadata.
- [✅] Define explicit save/load operations, merge versus replace behavior, and
  whether session Cookies may be restored. Keep persistence opt-in.
- [✅] Implement bounded file parsing and atomic writes to a caller-selected
  path. Do not use pickle for the public import path.
- [✅] Verify a round trip in a separate process, expired-Cookie filtering,
  domain/path/Secure behavior, duplicate names, malformed input, and failed
  writes that preserve the existing file. Reuse current request-filter tests.
- [✅] Add examples and clearly state that saving Cookies writes sensitive
  authentication state; document the file protection and retention policy.

Acceptance: loaded Cookies retain their original request scope; invalid input
does not partially replace the jar; application code can persist Cookies without
serializing a Session, its locks, connection pool, or TLS secrets.

## T06 and T07: Extend compatibility selectively

T06 selects one TLS 1.3 group at a time. P-384 is a candidate because TLS 1.2
already has related curve support, not a commitment that TLS 1.3 works today.

- [ ] Select a target peer/group and confirm all required library primitives.
- [ ] Add matching key generation, key-share encoding, group validation, and
  HelloRetryRequest handling for the selected group.
- [ ] Verify full handshakes, retry, fragmented reads, fresh shares, and rejection
  of invalid/unoffered groups. Update configuration validation and docs.

T07 targets an actual legacy interoperability requirement:

- [ ] Select an exact SHA-384 CBC or static-RSA suite and an independent peer.
- [ ] Verify negotiated-suite checks, PRF/key derivation, Finished authentication,
  record integrity, and relevant failure boundaries.
- [ ] Document the result. Leave a suite explicitly unsupported if the required
  peer or implementation evidence is absent; do not add it to the secure profile.

Acceptance: claims apply only to selected suites/groups and tested environments.
Existing secure defaults and JA3 presets change only when explicitly in scope.

## T08: Design TLS session persistence

- [ ] Establish whether cross-process resumption is needed separately from Cookie
  persistence, and select a storage/key-management mechanism available to callers.
- [ ] Define protected secret storage, record versioning, atomic update behavior,
  maximum size, expiry reconstruction, and concurrent-process access.
- [ ] Bind persisted entries to destination, SNI, TLS configuration and trust
  policy. Define invalidation for certificate expiry and trust-policy changes.
- [ ] Specify rejection/fallback behavior for corrupt, stale, unverifiable, or
  unsupported records, without exposing master secrets or PSKs in logs.
- [ ] Specify process-restart and independent-peer tests before implementation.

Acceptance: a reviewable design resolves secret protection and authentication
policy. It must not serialize existing cache objects directly or imply that
elapsed monotonic time remains valid after restarting a process.

## T09 and T10: Optional protocol extensions

T09 must select scheduling or server push as separate outcomes:

- [ ] For scheduling, define the caller API, fairness/backpressure behavior and
  flow-control interaction, then verify starvation and concurrent-body cases.
- [ ] For push, first define how callers receive, accept/cancel and bound pushed
  responses, then design promised-stream lifecycle, HPACK and resource limits.
  Enabling a SETTINGS flag alone is not an implementation.

T10 concerns application data sent before the handshake completes:

- [ ] Define explicit caller opt-in, replay eligibility and retry semantics.
- [ ] Define ticket early-data limits and interaction with authentication,
  rejected early data, redirects and resumed connections.
- [ ] Require independent-peer acceptance/rejection tests and evidence that
  rejection/retry cannot silently duplicate application side effects.

Acceptance: each extension has its own selected outcome, API and failure cases
before protocol code changes. No extension is necessary to finish T01-T04.

## Restrictions that remain intentional

TLS 1.2 resumption without extended master secret and resumption with configured
client certificates remain separate policy limits. Opt-in TLS 1.3 post-handshake
authentication is already implemented. Removing these limits is not a queued
bug fix; reconsider them only for a selected use case with authentication tests.

## Verification, coordination, and retention

For code changes, first run the smallest relevant unit and loopback integration
selection. At a coherent delivery boundary, run the existing selected full suite:

```sh
.venv/bin/python -m pytest test --ignore=test/test_session.py --cov=ja3requests --cov-report=term -q
.venv/bin/black --check ja3requests
.venv/bin/pylint --errors-only ja3requests
git diff --check
```

Keep the 85% CI floor; higher prior coverage is evidence, not proof of correctness.
The legacy manual `test_session.py` selection remains explicit. Use independent
loopback peers and bounded socket/thread waits. Artifact changes require an
installed-package compatibility precheck/readback; docs-only work needs link and
diff checks rather than a repeated protocol test run.

Start execution serially because TLS config/cache/request behavior overlaps and
the current worktree is shared. No subagents are used for this planning task.
Reconsider delegation only when the user explicitly requests it and independent,
write-safe lanes exist. Never overwrite unrelated or concurrent source edits.

Keep the roadmap, test evidence, and requested build artifacts as deliverables.
Clean only verified task-owned temporary files/environments. Preserve existing
debug scripts and IDE files. On a failed implementation attempt, retain the
last usable artifact and return to the smallest reproducible case; after two
attempts without progress, use a safe alternative or report the precise blocker.

T05 implementation and local acceptance are complete for the 2.0.0 candidate.
At the initial 2026-10-03 inspection, PRs #52 and #53 were OPEN and draft, each
with 10 successful checks. The subsequent review and dependency-ordered merges
are complete, as recorded in the [execution plan](protocol_delivery_execution_plan.md).
Publication remains separate. T06 is the next optional
development candidate and requires a selected group/peer. T07-T10 retain their
target/use-case dependencies. No later implementation is included in T05 delivery.

On 2026-10-03, delivery review found and locally repaired three #52 runtime
defects and one flaky test, then propagated the repairs to #53. The installed
candidates passed 1374 tests/88.89% (#52) and 1427 tests/89.04% (#53). See the
[consolidated review](protocol_delivery_review.md) for evidence and worktree
locations. Under the follow-up execution request, repairs have been committed
on both branches and #53 incorporates the updated #52 ancestry. Fresh remote
checks passed on #52 `ad62e9a` and #53 `8e8c092` (ten each; coverage 88.89%
and 89.04%). Following the user's correction and resumed execution, #52 merged
as `f0a0050`; #53 subsequently passed final integration checks and merged into
master as `f0cac58`. E1-E3 delivery is implemented, with final master matching
the tested candidate tree. Publication and T06-T10 remain outside this outcome.
