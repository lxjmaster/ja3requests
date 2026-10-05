# Synchronous client performance snapshot

Recorded on 2026-10-04 against the locally modified post-2.0.1 source checkout.
The default suite passed **26 tests in 31.62 seconds**, producing 76 measurement
records and seven component benchmarks. Source and benchmark-tool identities
remained stable throughout the run. Additional cleartext HTTP and 100 MiB
HTTPS/H2 runs used the same package source hash and passed their content/path
checks. This records a local implementation snapshot, not a published release,
remote CI result, or general performance guarantee.

## Reproduction and retained evidence

Default run, 10:19:34.555222–10:20:06.197746 UTC:

```sh
.venv/bin/python -m pytest bench -q \
  --perf-output dist/client-roadmap/final/performance.json \
  --benchmark-json dist/client-roadmap/final/components.json \
  --basetemp /path/to/new-task-owned-directory/pytest
```

Use fresh output filenames; `--perf-output` refuses an existing destination.
The [methodology](PERFORMANCE.md) defines timing intervals, warmups, body
verification, cipher matching, peer scheduling and limitations.

| Artifact | Contents | SHA-256 |
| --- | --- | --- |
| `dist/client-roadmap/final/performance.json` | Raw protocol/request samples, peer observations, allocations, source/tool identity and outcomes | `d7c2e78e2ad54f67b6552a4cc76cca53508a6b2645bbf3a737cc562f6ca35235` |
| `dist/client-roadmap/final/components.json` | pytest-benchmark component rounds and statistics | `9a8f7715362bcc32a8af6f6f0cd14511a091b579fd4365d0d6fb002726468761` |
| `dist/client-roadmap/final/http1-streaming.json` | Original HTTP/1 tool rerun at 1/8/100 MiB, three repeats | `fe9fe047ac9da02d85a2cd068a5d2e1977d40c3d8d7c256cb7d0aadc5f680c37` |
| `dist/client-roadmap/final/large-tls-h2.json` | Four 100 MiB TLS/H2 cases, each with separate timing/allocation samples | `1c2b163c91803828b9e92cab156773f29647b67d165219381a81803044859f76` |

The final raw files are local acceptance artifacts in ignored
`dist/client-roadmap/final/`; they are not included in the public repository or
release packages. The paths above identify local evidence, not download links.
The four same-named JSON files in its parent
`dist/client-roadmap/` are retained **pre-review snapshots**, with source hash
`631f03cec1ad2bd1ab73edf2fdfebae4c57a694a79fa11a0ba0e97e50bcd059e`.
They predate the final response-hook ownership fix and are not final acceptance
evidence. All numerical results below use the four final artifacts above.
The original `http1_baseline.py` and baseline measurements under `bench/`
remain unchanged. Their documentation now labels the historical scope, and the
public `baseline-current.json` redacts only two local paths and adds export metadata.

Environment: CPython 3.13.3, macOS 15.7.7 arm64, cryptography 45.0.5,
Brotli 1.2.0, pytest 8.4.1, pytest-benchmark 5.3.0 and Requests 2.32.4.
The independent server used OpenSSL 3.0.16. ja3requests uses its own TLS protocol
implementation; Requests is a separately identified client/backend comparison.
HEAD was `a291ef30bb6ae53cf38b3d79604c8f34e1865547`, with uncommitted development
changes. All 60 package modules have aggregate SHA-256
`5963161b9673c2004d7c551501265f0cd2c5b151bbe64b512facf7dbe65ca3dd`.

Distribution metadata reports `ja3requests=2.0.1` in this final run. The actual
imported package path is this repository's `ja3requests/__init__.py`, whose source
includes the local roadmap changes. The recorded source paths/hashes identify
what was measured; these are not measurements of an installed, unmodified
2.0.1 wheel. The earlier distribution-metadata value in the retained pre-review
JSON is preserved as historical environment evidence.

## Full handshake, resumption and connection reuse

Each row has three runs of 12 measured requests with 1 KiB bodies. Latency
medians pool the 36 individual samples. Resumed and pooled rows exclude one seed
request per run. TLS1.2 uses ECDHE-RSA/AES-128-GCM; TLS1.3 uses AES-256-GCM.

| TLS / path | Client handshake median | Complete request median | Observed path per run |
| --- | ---: | ---: | --- |
| TLS1.2 full | 315.146 ms | 317.916 ms | 12 new connections, zero resumed |
| TLS1.2 Session ID | 0.427 ms | 0.983 ms | 13 connections including seed; 12 resumed |
| TLS1.2 ticket | 0.424 ms | 0.998 ms | 13 connections including seed; 12 resumed |
| TLS1.2 pool reuse | No measured handshake | 0.593 ms | One connection including seed |
| TLS1.3 full | 1.782 ms | 2.474 ms | 12 new connections, zero resumed |
| TLS1.3 ticket | 0.730 ms | 1.432 ms | 13 connections including seed; 12 resumed |
| TLS1.3 pool reuse | No measured handshake | 0.263 ms | One connection including seed |

Server `session_reused` and accepted-connection counts establish the paths;
speed alone is not used as evidence of resumption. The TLS1.2 full path still
contains an explicit `time.sleep(0.3)` in `TLS._handshake_tls12` before waiting
for the server Finished. Its measured cost includes that existing policy, so
this table is not a comparison of intrinsic TLS1.2 versus TLS1.3 cryptographic
cost. Reviewing that wait against the handshake state machine is a concrete
follow-up candidate; this measurement did not change it.

## Shared HTTP/1.1 workload

Each timing sample uses 12 fully verified 64 KiB responses after one warmup per
worker. Three samples supply the median and range below. One separate memory
sample uses `tracemalloc`. Both libraries use one persistent Session per worker,
the same independently verified peer cipher/content, and explicit read limits.

| TLS / workers | ja3requests requests/s, median (range) | Requests requests/s, median (range) | Python peak KiB, ja3requests / Requests |
| --- | ---: | ---: | ---: |
| TLS1.2 / 1 | 1860 (1756–2735) | 2210 (1858–2814) | 112.0 / 85.4 |
| TLS1.2 / 4 | 1406 (1366–1599) | 1750 (1748–1785) | 311.3 / 257.5 |
| TLS1.3 / 1 | 2551 (2485–3075) | 1744 (1739–2387) | 111.5 / 85.4 |
| TLS1.3 / 4 | 2294 (2175–2330) | 1868 (1737–1874) | 310.8 / 250.1 |

Actual connection counts were one/four as selected; these transport rows reuse
connections and exclude handshake warmups. The short samples and overlapping
ranges in some cases do not support a universal library ranking. They do not
compare browser identity, complete API semantics or remote-service performance.

## Project HTTP/2 workload

| TLS / workers | Requests/s, median (range) | Median first chunk | Median complete request | Python peak | Observed overlapping streams |
| --- | ---: | ---: | ---: | ---: | ---: |
| TLS1.2 / 1 | 1030 (1023–1206) | 0.381 ms | 0.861 ms | 164.2 KiB | 1 |
| TLS1.2 / 4 | 1074 (707–1526) | 1.588 ms | 3.087 ms | 315.2 KiB | 4 |
| TLS1.3 / 1 | 1373 (1369–1429) | 0.320 ms | 0.699 ms | 178.5 KiB | 1 |
| TLS1.3 / 4 | 1065 (1021–1125) | 1.413 ms | 3.319 ms | 322.0 KiB | 4 |

All H2 cases used one TCP/TLS connection. The concurrent peer waits for a
four-stream cohort before interleaving DATA, making overlap observable. This
server scheduling differs from the H1 worker-per-connection workload; these rows
are not a controlled H1-versus-H2 speed ranking. Requests has no H2 comparison
row in this suite.

## Incremental delivery at larger body sizes

The original unmodified cleartext HTTP/1 tool was rerun with 64 KiB peer chunks,
a 2 ms inter-send gap and three repeats per size. Both old and new consumers
discard each chunk after checking its contents. The old result is the retained
[pre-streaming baseline](RESULTS.md); the new source is the snapshot above.

| Body | Old median first chunk | Current median first chunk | Old / current median Python peak | Current first chunk before final send |
| --- | ---: | ---: | ---: | ---: |
| 1 MiB | 51.66 ms | 1.072 ms | 1,209,756 / 161,825 bytes | 3/3 |
| 8 MiB | 370.94 ms | 1.191 ms | 8,549,700 / 161,964 bytes | 3/3 |
| 100 MiB | Not measured | 1.429 ms | Not measured / 161,734 bytes | 3/3 |

All nine current samples verified every expected body byte and delivered the
first chunk before the peer's last send began. The nearly unchanged traced
allocation at 1/8/100 MiB supports incremental consumption for this fixture.
The times include tracing and deliberate peer delays; they are not unrestricted
download throughput. The separate short 1 KiB sequential test reported median
2809.04 requests/s versus 4503.21 in the older run, both with one reused
connection. That observed decrease is retained as well: these short runs do not
show that every workload became faster. A longer controlled comparison can
separate scheduler variation and iterator/policy costs before selecting an
optimization.

The additional HTTPS/H2 command selected the four sequential ja3requests cases:

```sh
.venv/bin/python -m pytest bench/test_protocol_performance.py -q \
  -k 'test_transport and ja3requests and not True' \
  --perf-repeat 1 --perf-requests 1 --perf-concurrency 1 \
  --perf-body-bytes 104857600 --perf-timeout 30 \
  --perf-output dist/client-roadmap/final/large-tls-h2.json \
  --basetemp /path/to/new-task-owned-directory/pytest
```

All four tests passed. Each timing/allocation run excludes one complete warmup
request. All eight measured requests verified 100 MiB of content and delivered
their first chunk before the paired final peer send began.

| 100 MiB case | First chunk, timing run | Complete request, timing run | Peak Python allocation, separate run |
| --- | ---: | ---: | ---: |
| TLS1.2 HTTP/1.1 | 0.297 ms | 178.233 ms | 100,309 bytes |
| TLS1.2 HTTP/2 | 0.294 ms | 456.378 ms | 204,418 bytes |
| TLS1.3 HTTP/1.1 | 0.235 ms | 154.908 ms | 99,423 bytes |
| TLS1.3 HTTP/2 | 0.240 ms | 379.098 ms | 203,581 bytes |

The client and server timestamps use the same process-local `perf_counter`.
For these sequential cases, the measured response is the peer record after the
one warmup. Concurrent rows in the default suite cannot be paired merely by
array position. This 100 MiB experiment has one timing sample per case; it
establishes the measured delivery/memory behavior, not latency variability or
a robust throughput ordering.

## Component observations

Each result uses three pytest-benchmark rounds of 200 operations. These are
operation medians, with separate single-operation Python allocation peaks.

| Operation | Median | Python peak, one operation |
| --- | ---: | ---: |
| HPACK encode/decode, cold table, six headers | 5.991 microseconds | 1,180 bytes |
| HPACK encode/decode, warm table, six headers | 3.254 microseconds | 528 bytes |
| Pool checkout/return, live socketpair with health probe | 1.599 microseconds | 849 bytes |
| Cookie selection/header, 10 scoped Cookies | 49.152 microseconds | 9,412 bytes |
| Cookie selection/header, 100 scoped Cookies | 438.296 microseconds | 45,306 bytes |
| JA3 prepare/preview, including key generation | 114.445 microseconds | 8,282 bytes |
| Inspect one existing ClientHello record | 9.366 microseconds | 3,870 bytes |

The JA3 operations intentionally measure different work. Inspecting a record
does not generate new keys and is not a substitute for preparing the hello
that a request will send. Raw component round values remain in the companion
JSON; no speed threshold is added to CI.

## Limits and resource retention

All allocation figures are traced Python allocations, including measured peer
and executor activity. They exclude process RSS, native crypto/Brotli memory,
pre-existing objects and excluded warmups. The HTTP baseline traces its timing
run, while the TLS/H2 suite separates tracing from timing; compare within the
documented measurement method. Compression, long lines, configured H2 windows,
TLS authentication and application aggregation have their own memory costs.

The default suite confirmed source/tool stability, successful test outcomes,
monotonic client timing fields, full payload checks and seven complete component
round series. Servers, connections and pools shut down at test completion.
Normal certificate-fixture teardown removed private keys and certificates.
Task-owned method-check and final pytest staging directories were removed after
retaining the four final JSON artifacts above. The generated docs site is
retained separately as a local deliverable. No external service was contacted by
these workload runs, and no commit, publication or deployment was performed.
