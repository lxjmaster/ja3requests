# Read timeout consistency: bounded compatibility design

Prepared: 2026-10-25. Status: **N3 DESIGN COMPLETE / IMPLEMENTATION SELECTED 2026-10-27**.
Source baseline: `e28ee3302679455decd6348c89cf9f23b76fe2b0`.
This design follows [the ordered sequence](next_development_plan.md). The
2026-10-27 continuation selected its implementation, tracked at the top of that
plan. The proposal below records the original design boundary; current usage
is documented in [the timeout guide](../docs/request_policy.md#opt-in-phase-read-budgets).
No package version change or publication is selected.

## 1. Outcome and boundary

Make an explicit read-side None budget mean no deadline consistently when a
caller selects the new policy, while preserving the existing default policy.
The read-side budget also controls the current request-write/upload progress
waits; it is not a total request/response timer. Connect-phase unification,
proxy grammar, retries, hooks and total-deadline APIs are separate work.

The distinction matters for `timeout=(connect, None)`, not just timeout=None.
Scalar and tuple input, buffered requests, prepared sends and streaming bodies
must use the same selected read-side policy. The original design did not select
implementation; the later continuation now selects the API below.

## 2. Verified current matrix

The rows below come from source inspection. The two H1 send methods were also
called with in-memory socket adapters: HTTPS set 15.0 for None and retained 0
and 2.5 exactly; plain HTTP retained an existing 7.0 timeout when given None.
Those probes establish configuration behavior, not end-to-end timing guarantees.

| Route / wait | None today | Explicit finite / zero today | Evidence |
| --- | --- | --- | --- |
| Sync direct HTTP1 send/read, fresh or pooled | `send()` does not reset the socket timeout; connect or previous-use state may remain | Non-None read value calls settimeout; zero selects nonblocking socket behavior | [HttpSocket.send](../ja3requests/sockets/http.py) |
| Sync HTTPS HTTP1, direct or tunneled | HttpsSocket sets 15 seconds before application writes/reads | Supplied value is passed to settimeout, including zero | [HttpsSocket._send_h1](../ja3requests/sockets/https.py) |
| Sync HTTP through CONNECT/SOCKS | Tunnel send sets read timeout to None, resetting prior socket state | Supplied value is passed to settimeout | [ProxySocket.send](../ja3requests/sockets/proxy.py), [SocksProxySocket.send](../ja3requests/sockets/socks.py) |
| Sync HTTPS through CONNECT/SOCKS | Tunnel TLS path constructs HttpsSocket and reaches its H1/H2 rules | Destination TLS receives the context's connect setting; application path receives the read setting | Same proxy sources and HttpsSocket._create_tls |
| Sync H2 settings/capacity and flow-control waits, headers and incremental body | Stream wait helpers use a 15-second fallback; shared reader socket stays blocking | Per-wait deadlines use supplied budget; another stream's progress does not satisfy this stream's predicate | [H2MultiplexConnection](../ja3requests/protocol/h2/multiplex.py) |
| Sync H2 application writes | Serialized TLS write guard receives a 15-second fallback | Guard receives a monotonic deadline; expiry can close the shared transport after a partial write | HttpsSocket._send_h2 and [_H2WriteGuard](../ja3requests/sockets/_upload.py) |
| Sync H2 compatibility collector | `receive_response` owns one 15-second collection deadline | One deadline across headers and body, rather than a reset for each chunk | H2MultiplexConnection.receive_response; the public socket adapter uses incremental headers/read_stream |
| Sync H1 upload source/response | Source None adds no deadline; response waits use the transport's effective read timeout after upload completion/headers | Existing per-progress source/write waits; response-header waiting does not cap total upload time | [UploadExchange](../ja3requests/sockets/_upload.py) |
| Native async H1/H2, direct and supported proxy routes | No read-side phase deadline; shared readers/writers retain their own ownership rules | Per-write/credit/source/read waits; cancellation propagates and owned expiry raises library Timeout | [phase_wait](../ja3requests/_async_utils.py), [AsyncResponse._wait_read](../ja3requests/async_response.py), [AsyncH2Connection](../ja3requests/protocol/h2/async_connection.py) |

Application time between chunks is outside the next network-read wait. A
buffered read repeatedly consumes body progress and is not a total deadline.
Retries/redirects may repeat operations and budgets; backoff and hooks are not
silently added to a read timer. Existing errors after a returned streaming
response are not automatically retried.

### Separate connect boundaries

Do not describe all synchronous timeout=None waits as unlimited. H2 pool
reservations default to 5 seconds; TLS contains stage-specific 5-second fallbacks
and TLS1.2 polling behavior. Plain TCP uses the passed socket timeout per address
candidate. CONNECT has an explicit finite negotiation deadline when configured;
SOCKS negotiation uses the established socket's timeout. These do not form one
common synchronous DNS/pool/TCP/proxy/TLS budget.

Async [_attempt](../ja3requests/async_sessions.py) creates one attempt connect
deadline across admission and establishment. The native transport does not apply
legacy TLS settimeout calls to the nonblocking socket; its outer phase budget
governs establishment. A finite sync connect budget is therefore not claimed to
be identical to the async overall connect phase.

## 3. Approaches and recommendation

| Approach | Benefit | Compatibility / implementation cost |
| --- | --- | --- |
| Redefine None globally in the next maintenance release | No additional public option; simpler eventual contract | Existing synchronous calls can wait indefinitely instead of expiring at implicit 5/15-second boundaries; not a compatible maintenance change |
| Add one explicit read-side policy while retaining legacy default | Existing callers keep their limits; callers can select predictable read-side None semantics | Requires policy validation/snapshots and correct H2 per-operation propagation; connect differences remain documented |

**Recommend the explicit read-side policy.** Proposed Session property:
`read_timeout_policy`, with values `legacy` (default) and `phase` (opt-in).
This interface is now selected for implementation. AsyncSession already
has the target phase semantics and receives no new policy property in this
increment. A future major-version default change would be a separate choice.

### Proposed phase contract

- Validate the policy at assignment and snapshot it for each request/prepared
  send. An invalid assignment leaves the old policy intact. Existing Session
  observation properties do not become request defaults.
- For selected phase policy, validate the read budget before source/network
  work: None or a finite nonnegative number, excluding bool. Preserve existing
  scalar/two-item timeout shapes; reject malformed shapes deterministically.
  Connect behavior stays outside this increment; do not import a new total
  connect deadline into synchronous transports.
- A read value of None sets the selected application operation's deadline to
  absent. A finite value bounds each relevant progress wait. Zero remains zero;
  it is never replaced with 15. Sync nonblocking and async immediate-expiry
  mechanics are not promised to have identical scheduling behavior.
- Plain H1 checkout resets socket state even for None. HTTPS and tunneled paths
  propagate the same selection after setup. This prevents an earlier request's
  finite read budget leaking into a later phase-policy request.
- H2 carries the resolved policy/budget per request/stream and serialized write,
  rather than capturing the first Session's policy in a shared connection closure.
  Legacy None and phase None must remain distinguishable at the application
  boundary. A different stream's traffic must not extend a finite deadline.
- Keep shared control-frame/reader lifecycle limits separate from caller-owned
  application deadlines. Making an application wait unlimited must not remove
  unrelated protocol/resource bounds or let one stream cancel another writer.
- Preserve upload progress semantics and early responses. Borrowed file handles
  return only after their source worker finishes; None does not promise an
  uncooperative blocking source can be interrupted immediately.
- Preserve existing synchronous exception translation and native async Timeout/
  CancelledError distinctions. Normalize error classes only in a separate
  selected compatibility change.

## 4. Compatibility and migration

The default legacy policy retains current behavior and signatures. Opting into
phase can intentionally make a stalled read/write wait indefinite. Applications
that need a bound should provide a finite read component, for example
`timeout=(3, 15)`. That example does not recreate an old overall duration or
unify legacy connect defaults.

For prepared requests, the preparing request captures its selected policy;
later Session policy changes do not silently modify that prepared request.
Per-send mutable context is cloned. Retries and redirects retain the same
snapshot instead of rereading live policy. Direct low-level Request/transport
construction without the proposed policy keeps legacy behavior.

Reuse does not itself justify separate pools: operation budgets belong to the
current request. An implementation must prove per-checkout H1 reset and per-stream
H2 isolation, including mixed legacy/phase requests on a shared connection. If
the existing adapter cannot preserve that isolation, resolve the specific
propagation boundary before implementation; do not silently use first-owner
policy or disable all pooling.

## 5. Deterministic implementation acceptance (not yet run)

| Case | Required observation | Smallest useful method |
| --- | --- | --- |
| Legacy default and explicit legacy | Current H1/H2 fallback behavior retained | Actual send/wait methods with recording adapters and controllable clocks |
| Phase None on fresh/reused plain H1 | Earlier connect/read timeout is reset | Two sequential requests with different budgets on one observed connection |
| Phase None on HTTPS / proxy / SOCKS H1 | No hidden 15-second application budget | Actual route adapters plus event-gated loopback TLS/tunnel integration |
| H2 None / finite on one connection | Independent stream/read/write budgets, no first-owner-policy leak | Shared H2 peer with interleaved traffic and selectively withheld DATA/credit |
| Finite read without body progress | Correct timeout and ownership release | Controlled time/events, no production-duration sleep |
| Application pause / continued progress | Chunk processing does not consume a total-response budget | Gate chunk delivery and advance the relevant clock between waits |
| Zero, invalid numbers and shapes | No truthiness fallback; invalid phase input fails before side effects | Actual public preparation/send paths; track source pulls and connection calls |
| Streaming upload with early response | No total upload cap; source/write budgets and final cleanup remain owned | Existing sync/async upload fixtures with explicit progress events |
| Prepared/retry/redirect policy snapshot | Later Session edits cannot change an in-flight/prepared policy | Existing prepared/defaults/retry fixtures; inspect actual subsequent attempts |
| Async external cancellation | Remains CancelledError; scoped cleanup completes; unrelated H2 stream usable | Existing cancellation/phase-boundary tests plus one relevant shared-stream case |

Existing test files to reuse include test_timeout.py, test_delivery_timeouts.py,
test_response_failure_state.py, test_async_session.py, test_async_h2.py and
sync/async upload plus proxy/TLS network fixtures. Some historical unit checks
only restate fallback expressions; they do not prove actual transport behavior.
New checks should exercise real boundaries instead of duplicating formulas.

After implementation is selected: verify focused routes first, preserve Python
3.7 runtime support and installed consumer typing, then freeze one independent
artifact and check its exact source/configuration hashes and delivery CI. N1/N2
typing completion is not a prerequisite for this independent behavior change.

## 6. Current completion boundary

Source inspection, the current behavior matrix, in-memory H1 probes, approach
comparison, one recommended opt-in policy, migration rules and acceptance cases
are complete. No timeout code, public setting, new runtime test or dependency
was added. No listener, worker, environment or temporary artifact remains from
the design probes. This does not claim the proposed implementation/tests passed.
