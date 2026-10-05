# TLS, HTTP and component performance measurements

This explicitly invoked suite extends issue #40 with independent loopback TLS
peers, observed handshake/reuse paths, HTTP/1.1 and HTTP/2 workloads, and
`pytest-benchmark` component measurements. The original [HTTP/1.1 baseline](README.md),
[results](RESULTS.md), `http1_baseline.py` and `baseline-current.json` retain the
measurement evidence from before streaming work; the public JSON redacts two
local paths as described in the results. These measurements are descriptive;
they do not impose throughput or memory thresholds on CI.

The completed local snapshot, raw artifact hashes and larger streaming runs are
recorded in [PERFORMANCE_RESULTS.md](PERFORMANCE_RESULTS.md).
The later frozen 2.1.0 baseline and controlled maintenance comparisons are in
[POST_2_1_0_RESULTS.md](POST_2_1_0_RESULTS.md).

## Run locally

Use the project's Python 3.12+ development environment. Measurement packages are
optional development dependencies, not runtime requirements:

```sh
.venv/bin/python -m pip install -r bench/requirements.txt
.venv/bin/python -m pytest bench -q \
  --perf-output bench/performance-local.json \
  --benchmark-json bench/components-local.json
```

Use new output names for each run. `--perf-output` refuses an existing file.
`--benchmark-json` is owned by pytest-benchmark; choose a new path for it too.
The suite is not collected by the normal `pytest test` selection and does not
change production CI or run any public website request.

A small method check:

```sh
.venv/bin/python -m pytest bench -q \
  --perf-repeat 1 --perf-requests 4 --perf-concurrency 2 \
  --perf-body-bytes 65536 --perf-iterations 10
```

Useful focused commands:

```sh
.venv/bin/python -m pytest bench/test_protocol_performance.py -q -k handshake
.venv/bin/python -m pytest bench/test_protocol_performance.py -q -k transport \
  --perf-body-bytes 1048576
.venv/bin/python -m pytest bench/test_component_performance.py -q \
  --benchmark-json bench/components-local.json
```

Defaults are three timing samples, 12 measured requests, four concurrent workers,
64 KiB response bodies, 200 operations per component round, and a five-second
socket/thread timeout. Request count must be divisible by worker count. Timing
samples and one additional allocation sample use separate fresh peers and pools.
`--perf-repeat`, `--perf-requests`, `--perf-concurrency`, `--perf-body-bytes`,
`--perf-iterations` and `--perf-timeout` control these parameters explicitly.

## What is measured and what proves the path

| Workload | Measured interval | Required observations |
| --- | --- | --- |
| TLS 1.2/1.3 full handshake | Individual project `TLS.handshake()` calls and complete request cycles | Fresh configuration/cache and TCP connection for each request; independent server reports `session_reused=false` |
| TLS 1.2 Session ID and ticket resumption | Handshake and request intervals after one excluded seed request | New TCP connection for every measured request; server reports `session_reused=true`; Session ID peer disables tickets |
| TLS 1.3 ticket resumption | Same separation of seed and measured requests | New TCP connections and actual server-confirmed resumption |
| Pooled request reuse | Request intervals after one excluded warmup | One accepted TCP/TLS connection, multiple responses, zero measured client handshakes; never labeled TLS resumption |
| HTTPS HTTP/1.1 sequential/concurrent | Public `get(stream=True)` through body iteration, validation and close | One session/connection per worker, complete expected payload, observed connection counts and negotiated protocol/cipher |
| HTTPS HTTP/2 sequential/concurrent | Same request interval and a separate Python-allocation run | One shared session/connection; concurrent peer waits for a worker cohort and interleaves DATA; observed overlapping stream count and stream IDs |
| HPACK cold/warm tables | `pytest-benchmark` encode/decode round trip | Decoded headers exactly match the six-header input; cold case includes fresh codec creation, warm case preserves tables |
| Pool checkout/return | `pytest-benchmark` existing pool operations | Actual local socketpair, health probe included, same socket returns to the pool |
| Cookie selection | `pytest-benchmark` scope filtering/header generation for 10/100 Cookies | All expected scoped name/value pairs appear; no network request |
| JA3 preview / inspection | Separate `pytest-benchmark` operations | Preview includes ClientHello preparation/key generation; inspection reuses one record and generates no new keys; both match the expected JA3 |

TLS cases verify certificates using the existing ephemeral trusted-CA fixture.
The client is always this project's TLS implementation in `ja3requests` rows.
Existing independent `test.mock_servers.local` helpers provide OpenSSL server
contexts and basic frame parsing/encoding. `bench/peers.py` adds bounded concurrent
accepts, records negotiated protocol/cipher/reuse, and respects HTTP/2 connection
and stream flow-control windows. It does not import the project TLS or HPACK
codecs. On normal teardown the certificate fixture removes its private keys and
certificate files; its temporary directory follows pytest's retention policy.
Final task acceptance explicitly cleans its owned staging directory after
retaining the measurement reports. No CA is installed in the host trust store.

TLS 1.2 uses `ECDHE-RSA-AES128-GCM-SHA256`; TLS 1.3 uses
`TLS_AES_256_GCM_SHA384`. The peer checks both selections. The Session ID peer
retains native SSL objects and finishes each handler after its response, matching
the existing resumption fixture's server-cache lifetime. Socket reads and shutdown
joins are bounded. Each successful test closes its dedicated sessions, pools,
listeners and peer threads before its result is accepted.

The concurrent H2 workload is deliberately cohort-based: headers from the worker
cohort arrive before interleaved response DATA begins. This makes real overlapping
streams observable. It is not a server scheduling benchmark and is not used as a
direct comparison against the H1 worker-per-connection workload.

## Shared HTTP/1.1 comparison

If `requests` is installed, it runs exactly the HTTP/1.1 TLS 1.2/1.3 workload with
the same peer code, body size/content, worker count, warmup count, cipher, verified
CA, explicit timeout, `Accept-Encoding: identity`, complete body validation and
response close. Both libraries use one persistent session per worker, avoiding
assumptions about concurrent sharing of a `requests.Session`. Environment proxy
and credential discovery are disabled for the requests client. Each library has
a fresh independent peer for its sample, and actual connection counts must match.

Requests uses its own TLS backend as a separately named comparison; it never
replaces this project's client engine. Requests does not participate in H2 or the
project-internal handshake/component measurements. These are shared-workload
observations, not a claim of equal API semantics, browser fingerprinting, or a
universal fastest library. If requests is absent, its cases are explicitly skipped
and the outcome/reason appears in the local report.

## Reports and interpretation

`--perf-output` records every request/handshake sample, per-connection TLS and
reuse observations, H2 stream overlap, peer response timing, payload checks,
separate Python allocation peaks, test outcomes, all parameters, dependency and
OS/runtime versions, Git state, and SHA-256 of every package module and benchmark
helper/fixture. Peer response timestamps are process-local `perf_counter` values;
only intervals within the same run may be compared. Each client request also
records absolute `request_started_at`, `request_returned_at`, `first_chunk_at`
and `response_complete_at` values from the same process clock. Sequential cases
can pair measured requests with server responses in order after excluding the
recorded warmups, for example to compare the first chunk with `last_send_started`.
Concurrent client rows are grouped by worker while peer records follow completion
order; do not zip those lists or infer per-request pairing from their position.
No ticket, private key,
certificate bytes, credentials or raw ClientHello is stored.

`--benchmark-json` records pytest-benchmark's component rounds and statistics,
with the same source/tool identity and parameters attached. Use its documented
comparison options for component reports if needed; this suite defines no pass/fail
speed policy. Body/path assertions establish that a measurement ran the intended
operation; passing them alone does not establish a performance improvement.

Timing samples run without `tracemalloc`. The additional memory sample traces
Python allocations during the measured requests, after connection warmup. This
includes allocations in the server and executor threads and excludes native
allocations, process RSS, pre-existing objects and warmup handshakes. The peer
allocates its fixed 16 KiB-or-smaller body chunk before tracing. Clients validate
and discard each yielded chunk without accumulating the complete response.
Component peaks measure one separate operation after the timing rounds.

`source_stable_during_run=false` or `tools_stable_during_run=false` invalidates a
run as a comparison baseline. Even a stable run during concurrent development is
only a snapshot; retain final measurements after the selected source is frozen.
Repeat the same arguments/environment when comparing before and after streaming,
and report variability and raw samples. Loopback timing, scheduler effects,
tracing, certificate verification and peer work limit extrapolation to remote
production services. This synchronous suite does not measure async clients;
see the separate [native async measurements](ASYNC_PERFORMANCE.md). Protocols
not implemented by the library remain outside both suites.
