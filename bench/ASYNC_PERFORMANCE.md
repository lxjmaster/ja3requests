# Native async performance evidence

The frozen local async snapshot, including the transport-close wakeup fix,
passed all 16 comparison cases and all four
100 MiB streaming cases on 2026-10-04, producing 72 measurement records. All
payload, protocol, connection ownership and streaming checks passed; source and
benchmark tools remained unchanged during both runs. Native async provides
incremental delivery and cooperative loop progress in these measurements, with
lower sequential HTTP/1 throughput than the two synchronous comparisons.

This explicit suite measures `AsyncSession` with the project's own TLS 1.2/1.3
and HTTP/2 engines. It reuses the independent loopback
OpenSSL peer and raw-report infrastructure from [PERFORMANCE.md](PERFORMANCE.md).
The default `pytest bench` selection remains the existing 26 tests; select
`bench/test_async_performance.py` directly to run these 16 additional cases.

## Reproduction and measurement boundaries

Create `dist/async-client/` first, then run the normal comparison after freezing
package and benchmark source:

```sh
.venv/bin/python -m pytest bench/test_async_performance.py -q \
  --perf-output dist/async-client/performance.json \
  --basetemp /path/to/new-task-owned-directory/pytest
```

Defaults are three timing runs and one separate Python-allocation run per case,
12 measured requests, four concurrent workers, 64 KiB response bodies and a
five-second network timeout. Every response byte is checked and discarded while
streaming. One warmup per session excludes TCP/TLS setup; the synchronous
comparison's executor threads are also started before measurement.

The larger-body acceptance command selects only the four native sequential
TLS/protocol cases, with a separate 100 MiB timing and allocation response each:

```sh
.venv/bin/python -m pytest bench/test_async_performance.py -q \
  -k 'native_async and sequential' \
  --perf-repeat 1 --perf-requests 1 --perf-concurrency 1 \
  --perf-body-bytes 104857600 --perf-timeout 30 \
  --perf-output dist/async-client/large-async.json \
  --basetemp /path/to/new-task-owned-directory/pytest
```

Use new output files and task-owned temporary directories. `--perf-output`
refuses an existing destination. Certificate fixtures remove their keys on normal
teardown; the caller removes its isolated pytest staging directory after keeping
the JSON evidence. All listeners, sessions, sockets and peer workers close at the
end of each sample. Nothing is sent to an external service.

| Workload | Shared controls | Recorded evidence |
| --- | --- | --- |
| Async, synchronous ja3requests and Requests HTTP/1.1 | Same peer, TLS version/cipher, certificate verification, body, timeout, workers and one warm persistent session/connection per worker | Actual connection count, no measured TLS resumption, every body byte, request/header/first-chunk/completion times |
| Native async HTTP/2 | One shared session and connection; peer waits for the worker cohort before interleaving DATA | Negotiated ALPN, observed pending stream count, stream IDs, per-stream first chunk and complete body |
| Event-loop responsiveness | A callback requested every 1 ms during the measured native-async workload | All observed callback intervals, median/p95 interval, maximum lateness and the unfinished final interval |
| Streaming memory | Fresh sample after warmup; allocation tracing separate from timing | Peak Python allocations, first chunk before the peer's final send for bodies of at least 1 MiB, full expected byte count |

TLS 1.2 uses ECDHE-RSA/AES-128-GCM; TLS 1.3 uses AES-256-GCM. The peer verifies
the actual selected version, cipher and protocol. Requests uses its own backend
as a labeled HTTP/1.1 comparison and does not participate in H2 measurements.
Synchronous clients run in the prestarted worker executor; only native async
rows include loop-heartbeat measurements. These observations compare a common
workload, not identical API, thread or TLS implementations.

H2 results are paired with peer response timestamps by stream ID. HTTP/1.1
warmups open worker connections serially, so each worker can be paired with that
connection's subsequent response records. Concurrent result arrays are never
paired by global completion position. Timestamps use process-local
`perf_counter`; comparisons are valid only inside the corresponding sample.

The heartbeat is descriptive, without a latency pass/fail threshold. It measures
the whole local client/peer workload, including scheduling, byte validation,
Python parsing/crypto and any runtime pauses. A short run can contain few
callbacks; its raw observation count and intervals are retained. The unfinished
tail contributes to maximum observed lateness when it exceeds 1 ms. This avoids
silently omitting a final period of event-loop starvation, but does not make the
experiment a hard real-time guarantee.

`tracemalloc` includes measured client, server and executor Python allocations.
It excludes pre-existing objects, warmup handshakes, process RSS and native
OpenSSL/cryptography/decoder memory. The fixed peer body chunk is allocated
before tracing; consumers do not collect whole responses. Heartbeat records and
request metadata remain part of the measured allocations. H2 scheduling uses a
cohort while H1 uses separate connections, so H1/H2 rows are not a controlled
protocol-speed comparison. Large-body runs supply one timing sample per case,
which proves that workload's delivery path but does not characterize variability.

## Frozen source and retained evidence

Environment: CPython 3.13.3, macOS 15.7.7 arm64, cryptography 45.0.5,
Brotli 1.2.0, pytest 8.4.1, pytest-benchmark 5.3.0 and Requests 2.32.4. The
independent TLS server used OpenSSL 3.0.16. Both reports identify all 68 package
modules with aggregate SHA-256
`7c6ccaa85405c9f8e8444f2aa83dc190e394aade8669c64c2535c87ade17dca6`.
HEAD was `a291ef30bb6ae53cf38b3d79604c8f34e1865547`, with uncommitted development
changes. The imported package was this repository's
`ja3requests/__init__.py`; the metadata version `2.0.1` does not describe an
unmodified published wheel. The measurements identify the local source snapshot,
not a release or another supported Python runtime.

| Artifact | Run in UTC / outcome | SHA-256 |
| --- | --- | --- |
| `dist/async-client/performance.json` | 13:01:22.688856–13:01:36.358362; 16 tests passed in 13.65 s, 64 records | `a1e0370bcf6dc4bf34cb75d23e68220a37e6061631ad4c92f34296bc0cad2334` |
| `dist/async-client/large-async.json` | 13:01:55.327103–13:02:22.241503; 4 tests passed in 26.87 s, 8 records | `e6bd960956b15c37df7e922220a947c5fa30825926aaaa41607507b2a7d81092` |

The two runs executed sequentially. Both report `pytest_exitstatus=0`,
`source_stable_during_run=true` and `tools_stable_during_run=true`. They retain
all raw request/peer times, loop intervals, allocation peaks, TLS observations,
source/tool hashes, dependency versions, Git identity and test outcomes.
These local JSON files remain in ignored `dist/async-client/`; they and the
pre-fix reports below are not included in the public repository or release
packages. The paths identify local evidence, not download links.

The previous 72 records used package hash
`9b360034572bcf2ae3e45a5834c86adf330df71cb4a26b43e79704cc0d5cbb17`.
They predate the fix that wakes a pending native socket read when its transport
closes, and are retained as pre-fix evidence rather than final acceptance:

| Preserved artifact | SHA-256, unchanged after relocation |
| --- | --- |
| `dist/async-client/pre-close-fix/performance.json` | `be1d2edbaaea70121346b0871dfc11fc9d951aba9634499e8f4ae28f38a8d218` |
| `dist/async-client/pre-close-fix/large-async.json` | `9354ed64084ca3e07493477237509575f52aff262c7a74b2c3b90831e2c7f8cd` |

Method checks are retained separately as `method-check.json` (16 cases, 32
records, 64 KiB bodies) and `method-large.json` (four sequential cases, eight
records, 1 MiB bodies). They preceded the final freeze and are not used in the
tables below. Collection of the original `pytest bench` suite still reported
exactly 26 tests. The benchmark method also received an independent read-only
review, with no blocking finding.

## Shared HTTP/1.1 measurements

Each timing run transfers twelve verified 64 KiB responses after excluded
warmups. Values are requests/second: median of three runs, followed by the
observed range. Four workers use four warmed connections for every client.

| TLS / workers | Native async | Synchronous ja3requests | Requests |
| --- | ---: | ---: | ---: |
| TLS1.2 / 1 | 845 (838–947) | 2431 (1954–3210) | 1882 (1745–2458) |
| TLS1.2 / 4 | 1595 (1578–1621) | 1360 (1332–1489) | 1665 (1621–1716) |
| TLS1.3 / 1 | 840 (783–887) | 2087 (2052–2234) | 1648 (1636–1787) |
| TLS1.3 / 4 | 1706 (1663–1787) | 2161 (2080–2166) | 1695 (1667–1824) |

The separate allocation samples recorded these peak Python bytes:

| TLS / workers | Native async | Synchronous ja3requests | Requests |
| --- | ---: | ---: | ---: |
| TLS1.2 / 1 | 187,311 | 120,689 | 93,234 |
| TLS1.2 / 4 | 278,170 | 304,974 | 253,662 |
| TLS1.3 / 1 | 186,658 | 120,179 | 93,234 |
| TLS1.3 / 4 | 296,140 | 270,566 | 255,258 |

The native async path is slower for these short sequential requests. Concurrent
results overlap some comparison ranges and do not establish a universal ranking.
The async acceptance result is correct native cooperative I/O and ownership;
these numbers do not claim that adding async increases every workload's speed.

## HTTP/2 and loop responsiveness

Every H2 sample used one connection. Concurrent samples observed four pending
streams before interleaved response DATA, so the workload exercised shared
connection multiplexing. Latency medians use 36 individual requests per row.
Loop lateness is the largest observed excess over the requested 1 ms interval
across the three untraced runs; it is not the callback interval itself.

| TLS / workers | Requests/s median (range) | Median first chunk | Median complete | Python peak bytes | Max loop lateness |
| --- | ---: | ---: | ---: | ---: | ---: |
| TLS1.2 / 1 | 512 (494–519) | 0.715 ms | 1.910 ms | 190,585 | 0.080 ms |
| TLS1.2 / 4 | 546 (540–555) | 2.823 ms | 7.036 ms | 259,694 | 0.085 ms |
| TLS1.3 / 1 | 529 (528–530) | 0.705 ms | 1.863 ms | 189,845 | 0.109 ms |
| TLS1.3 / 4 | 645 (586–655) | 2.526 ms | 6.050 ms | 261,510 | 0.122 ms |

The four H2 rows contain 67, 63, 66 and 54 heartbeat observations respectively
across their timing runs. Native HTTP/1.1 timing runs recorded 18–41 callbacks
per TLS/concurrency group; their maximum lateness was 0.058/0.150 ms for TLS1.2
at one/four workers and 0.079/0.152 ms for TLS1.3. These are small local samples.
The larger-body workload below provides hundreds of additional observations.

## 100 MiB streaming

All eight measured responses, including the separate allocation samples,
delivered the first chunk before their paired peer's final send and verified
all 104,857,600 bytes. Each sample excluded one equally sized warmup response.
Timing columns use the untraced run; memory comes from the additional run.

| TLS / protocol | First chunk | Complete response | Python peak bytes | Heartbeat observations | p95 callback interval | Max loop lateness |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| TLS1.2 / HTTP/1.1 | 0.708 ms | 999.643 ms | 175,401 | 986 | 1.024 ms | 0.042 ms |
| TLS1.2 / HTTP/2 | 0.794 ms | 1764.676 ms | 260,200 | 1726 | 1.043 ms | 0.079 ms |
| TLS1.3 / HTTP/1.1 | 0.681 ms | 968.077 ms | 170,868 | 956 | 1.023 ms | 0.043 ms |
| TLS1.3 / HTTP/2 | 0.777 ms | 1672.554 ms | 257,087 | 1636 | 1.042 ms | 0.057 ms |

The measured Python peaks stayed below 261,000 bytes while streaming 100 MiB in
these fixtures. They include heartbeat observations and independent peer work;
they are not a universal memory cap. Compared with the smaller fixture, request
counts and retained measurement metadata differ, so these rows must not be used
to infer a reduction in per-request memory. The traced runs themselves took
1.592–3.481 seconds and are deliberately excluded from throughput conclusions.

## Observed change after the close-wakeup fix

Benchmark-tool hashes, measurement arguments and recorded environments are
identical between the preserved and final runs. The source changed to include
the required close-wakeup correction. Native async throughput medians declined
in every 64 KiB case; the earlier faster results are not substituted for these
final measurements.

| Native async case | Pre-fix requests/s | Final requests/s | Median change |
| --- | ---: | ---: | ---: |
| TLS1.2 / HTTP/1.1 / 1 worker | 1352 | 845 | -37.5% |
| TLS1.2 / HTTP/1.1 / 4 workers | 2014 | 1595 | -20.8% |
| TLS1.3 / HTTP/1.1 / 1 worker | 1288 | 840 | -34.8% |
| TLS1.3 / HTTP/1.1 / 4 workers | 2068 | 1706 | -17.5% |
| TLS1.2 / HTTP/2 / 1 worker | 838 | 512 | -38.9% |
| TLS1.2 / HTTP/2 / 4 workers | 1026 | 546 | -46.7% |
| TLS1.3 / HTTP/2 / 1 worker | 893 | 529 | -40.7% |
| TLS1.3 / HTTP/2 / 4 workers | 1126 | 645 | -42.7% |

The untraced 100 MiB completion times also increased:

| Case | Pre-fix complete | Final complete | Observed change |
| --- | ---: | ---: | ---: |
| TLS1.2 / HTTP/1.1 | 430.463 ms | 999.643 ms | +132.2% |
| TLS1.2 / HTTP/2 | 818.885 ms | 1764.676 ms | +115.5% |
| TLS1.3 / HTTP/1.1 | 409.746 ms | 968.077 ms | +136.3% |
| TLS1.3 / HTTP/2 | 707.389 ms | 1672.554 ms | +136.4% |

These are observed changes, not an isolated causal estimate of the fix. The
synchronous ja3requests comparison's throughput medians also varied from -38.6%
to +40.0%, and Requests from -27.9% to -3.7%, between the two runs. There was no
randomized interleaving of source versions or control of all machine scheduling
state; the large cases have only one timing run each. The final source still
passes the requested delivery, correctness, responsiveness and memory checks.
This measurement records the slowdown without adding a performance threshold
or undertaking an optimization.

Task-owned pytest staging was removed after retaining the final reports,
unchanged pre-fix records and the two earlier method reports.
All benchmark listeners, native async tasks, sessions and peer threads terminated.
No package source changed during measurement, and no commit, publication or
remote write was performed.
