# Post-2.1.0 maintenance measurements

Measured locally on 2026-10-05. Removing the synchronous TLS1.2 full-handshake
fixed pause eliminated its approximately 300 ms wait. Bounded native-async
read-ahead improved every paired 64 KiB throughput median and every paired
100 MiB completion median in this workload. It increased measured Python
allocation peaks; neither universal speed nor lower event-loop latency is claimed.
The synchronous small-response investigation resulted in no code change.

These are source-snapshot measurements, not a new release. Package version and
Python >=3.7 requirements are unchanged. See the [execution record](../issues/post_2_1_0_execution.md)
for correctness, packaging and incremental typing acceptance. The established
[protocol methodology](PERFORMANCE.md), [async methodology](ASYNC_PERFORMANCE.md)
and [small-H1 methodology](README.md) remain applicable. Their earlier results
describe historical snapshots and are not overwritten by this report.

Release follow-up: this maintenance was subsequently selected for 2.1.1. Its
version-label change does not retroactively relabel these measured snapshots or
turn their local acceptance into release CI evidence.

## Source, environment and reproducibility

Environment: CPython 3.13.3, macOS 15.7.7 arm64, OpenSSL 3.0.16 on the independent
server, cryptography 45.0.5, Brotli 1.2.0, pytest 8.4.1, pytest-benchmark 5.3.0
and Requests 2.32.4. No test/build/type-check workload ran alongside measurements.
No public service was contacted by the benchmarks.

| Snapshot | Construction | Aggregate SHA-256 of 68 package modules |
| --- | --- | --- |
| Published source baseline | `git archive 2175105016f83dfe24fcb340e986719bd05ed04d` | `d9f9fec5f71be7b345a4c1e77c8bfec410e2ef857d4fad13c6efc86b6e05b4f9` |
| `no-pause` | Baseline plus P3a and the corresponding async comment update | `122e17cfd1368d5ed950c3c7bdeec7b864ff5587f2a66724788a2cc13a52768b` |
| `read-ahead` | `no-pause` plus P3b, excluding P4 to isolate the comparison | `583da9dc548096c1f8e9a0d33e807b999824ff3b1334c33d30b3bcf89eb7876b` |
| Final merged source | All five changed runtime modules, including P4 annotations | `231ba04ff465c16ce121811a7c4ae915aacd2461d23552463028c03fa3fa1ee8` |

All reports verify actual imports from their frozen source roots, stable package
and benchmark hashes, payload bytes, requested TLS/ALPN and connection paths.
The archived roots have no Git metadata; `git_before.unavailable` is expected.
Earlier protocol/async reports record stale development-environment distribution
metadata of `ja3requests` version `1.1.0`; it does **not** identify their imported
source. The small-H1 report and both final performance reports record 2.1.0.
The explicit commit, import paths and module hashes identify each snapshot.
The final wheel was independently installed and verified as version 2.1.0 with
matching source.

The benchmark/fixture tool map is identical across the protocol/async reports.
Its canonical `json.dumps(map, sort_keys=True)` SHA-256 is
`50ddc68fe5cd57360e206b4e12639c9f26b0366ae450b085fc9c1d5c38bab70b`.
The small-H1 script hash is
`102da44f5bc8283d7a6db78d3376f78c3684c25a99eae5bf0cfc5956555ffd03`.

Run each command from the corresponding frozen source root using the absolute
path to the development interpreter. Choose new absolute report/staging paths;
`--perf-output` refuses an existing file. `http1_baseline.py` imports from its
own root, so running another checkout's script does not measure an installed wheel.

```sh
# Substitute paths to the selected snapshot, interpreter and task-owned output.
cd /path/to/frozen-source
python_bin=/path/to/project/.venv/bin/python
bench_results=/path/to/new-results
bench_staging=/path/to/task-owned-staging
mkdir -p "$bench_results" "$bench_staging"

# P2: published-source baseline.
"$python_bin" bench/http1_baseline.py --sizes-mib 1 --repeat 9 --requests 1000 \
  --output "$bench_results/http1-release.json"
"$python_bin" -m pytest bench/test_protocol_performance.py -q \
  --perf-repeat 5 --perf-requests 40 --perf-concurrency 4 \
  --perf-output "$bench_results/protocol-release.json" --basetemp "$bench_staging/protocol"
"$python_bin" -m pytest bench/test_async_performance.py -q \
  --perf-repeat 7 --perf-requests 120 --perf-concurrency 4 \
  --perf-output "$bench_results/async-release.json" --basetemp "$bench_staging/async"
"$python_bin" -m pytest bench/test_async_performance.py -q \
  -k 'native_async and sequential' --perf-repeat 5 --perf-requests 1 \
  --perf-concurrency 1 --perf-body-bytes 104857600 --perf-timeout 30 \
  --perf-output "$bench_results/large-async-release.json" --basetemp "$bench_staging/large"
```

For P3a, select `bench/test_protocol_performance.py -k handshake` with
`--perf-repeat 1 --perf-requests 8 --perf-concurrency 4`. Run baseline/candidate
in AB, BA, AB order, with distinct reports for each invocation.
For P3b, select the explicit async file with `--perf-repeat 3 --perf-requests 120
--perf-concurrency 4` in the same AB, BA, AB order (`no-pause` versus `read-ahead`).
For each 100 MiB pair use three repeats, one request/worker and timeout 30;
select the exact parametrized test, for example
`'bench/test_async_performance.py::test_async_transport[native_async-TLSv1.2-http1.1-sequential]'`.
H1 ran before/after; H2 ran after/before, for each TLS version. This is order
balancing, not randomized experimental control. Final-source checks use the
same three-repeat small and large async selections, after all code was frozen.

## P2: verified baseline and synchronous small responses

P2 completed 19 protocol cases / 107 records, 16 async cases / 128 records and
four large-body cases / 24 records. Timing and allocation tracing are separate.
The 1 KiB cleartext H1 workload completed nine samples of 1000 requests, each
on one verified reused connection, with median **11,037 requests/s**
(9,252–11,726). There is no warmup in this small-H1 script. Its nine 1 MiB
streaming samples also verified every byte and first-chunk delivery before the
peer's final send.

Full/resumed handshake values below are medians and ranges across 200 measured
handshakes per row. Pooled cases make no measured handshake at all.

| Path | Client handshake milliseconds |
| --- | ---: |
| TLS1.2 full | 307.099 (301.999–313.290) |
| TLS1.2 Session ID | 0.234 (0.171–1.127) |
| TLS1.2 ticket | 0.243 (0.175–2.365) |
| TLS1.3 full | 1.130 (1.001–2.525) |
| TLS1.3 ticket | 0.430 (0.375–0.989) |

The repeated native-async baseline whole-run elapsed medians for 100 MiB were 1036.4/1887.3 ms
for TLS1.2 H1/H2 and 1014.9/1780.2 ms for TLS1.3 H1/H2. These five-sample
observations include worker orchestration in addition to the one measured
response. They establish a current baseline, but are not substituted for the
closer per-response completion comparisons below.

Synchronous profiling covered one 1000-request throughput sample plus the
script's separate 1 MiB streaming sample and setup/teardown. The table includes
peer/thread activity, so its cumulative durations are neither client-exclusive
CPU percentages nor throughput results. It shows the existing Session/request,
response parsing/iteration and Cookie extraction paths (1001 Session requests,
3003 Cookie extraction calls). That is diagnostic evidence, not proof that an
individual stage is unnecessary. Historical 30-request runs use different
parameters and uncommitted snapshots not reconstructed here. A historical
regression is therefore **not isolated**, nor shown to have disappeared.
No synchronous policy/response refactor was justified by this evidence.

## P3a: remove only the full-TLS1.2 fixed wait

Four independent CBC/GCM full-handshake tests first failed because they observed
`sleep(0.3)`. Ten delayed/fragmented, timeout and EOF boundary tests already
passed. Removing the pause preserved authenticated Finished processing, the
existing receive timeout and its restoration. The expanded 154-test regression
selection passed. It does not introduce a whole-handshake deadline.

Three paired rounds each checked seven full/resumed/pooled paths. Values below
combine 24 measured handshakes per non-pooled row, not allocation samples.

| Path | Before ms, median (range) | No-pause ms, median (range) |
| --- | ---: | ---: |
| TLS1.2 full | 309.55 (304.03–312.75) | 1.24 (1.16–3.60) |
| TLS1.2 Session ID | 0.46 (0.24–5.40) | 0.27 (0.20–0.36) |
| TLS1.2 ticket | 0.45 (0.28–1.82) | 0.29 (0.22–0.41) |
| TLS1.3 full | 1.60 (1.38–2.45) | 1.67 (1.36–2.60) |
| TLS1.3 ticket | 0.60 (0.39–0.84) | 0.66 (0.53–0.78) |

Full-TLS1.2 per-round medians were 309.871/308.784/310.730 ms before and
1.253/1.231/1.261 ms after. The control paths and pooled throughput also vary;
the pause was never on resumed/pooled paths, so their changes are **not attributed
to its removal**. The old async adapter only yielded for `Pause`, not slept for
300 ms. This finding therefore does not explain async throughput.

## P3b: bounded native-async read-ahead

Source tracing and profiling identified separate owned native tasks for tiny TLS
header/body reads. The selected change reads at most 65,536 socket bytes and
keeps excess bytes in the existing pending buffer, returning at most the requested
amount. It retains native tasks, application-task ownership, cancellation,
descriptor deregistration and close wakeups. A completed-read/close race cannot
restore the pending buffer after close. TLS record, plaintext and H2 buffering
remain distinct; this is not a 64 KiB total-connection memory guarantee.

The operation-count test failed before the change (three native reads instead
of one); the close-race test and 273 affected async regressions pass afterwards.
Both new socketpair tests have a two-second failure bound. Independent review
found no confirmed new response-boundary or resource-ownership defect.

The first async profile metadata incorrectly claimed peer-thread exclusion;
the actual call table contains peer work. Its unmodified evidence and correction
are retained in `p3b/profile-scope-note.md`. No client-exclusive CPU proportion,
coroutine call count inferred from resume counts, or speedup from instrumented
durations is claimed. The operation-count test and uninstrumented measurements
provide the optimization evidence.

### 64 KiB paired throughput

Each cell is requests/s, median (range) of **nine timing samples**, each with
120 complete verified responses after one excluded warmup per session. The
three allocation samples per cell are separate. Sequential/concurrent means
one/four workers. H1 uses one connection per worker; H2 uses one shared connection
and verifies four overlapping streams for concurrent cases.

| Client / TLS / protocol / workers | No-pause | Read-ahead |
| --- | ---: | ---: |
| Native async / 1.2 / H1 / 1 | 914 (887–922) | 1339 (1292–1367) |
| Native async / 1.2 / H1 / 4 | 1895 (1792–1945) | 2361 (2295–2404) |
| Native async / 1.2 / H2 / 1 | 576 (550–582) | 920 (824–934) |
| Native async / 1.2 / H2 / 4 | 571 (551–589) | 1089 (961–1122) |
| Native async / 1.3 / H1 / 1 | 941 (858–973) | 1437 (1370–1475) |
| Native async / 1.3 / H1 / 4 | 2024 (1339–2036) | 2550 (2411–2607) |
| Native async / 1.3 / H2 / 1 | 596 (486–612) | 992 (974–1008) |
| Native async / 1.3 / H2 / 4 | 601 (578–617) | 1188 (1127–1213) |
| Sync ja3requests / 1.2 / H1 / 1 | 3123 (3004–3283) | 3209 (2838–3364) |
| Sync ja3requests / 1.2 / H1 / 4 | 2580 (2361–3027) | 2530 (2309–2627) |
| Sync ja3requests / 1.3 / H1 / 1 | 3508 (3316–3580) | 3393 (3213–3723) |
| Sync ja3requests / 1.3 / H1 / 4 | 2746 (2150–2889) | 2794 (2747–2942) |
| Requests / 1.2 / H1 / 1 | 2642 (2480–2692) | 2459 (1864–2784) |
| Requests / 1.2 / H1 / 4 | 2467 (2170–2503) | 2402 (2111–2483) |
| Requests / 1.3 / H1 / 1 | 2668 (2504–2731) | 2592 (2393–2650) |
| Requests / 1.3 / H1 / 4 | 2378 (1909–2520) | 2410 (2382–2519) |

Native medians improve by approximately 25–98%. Unchanged synchronous controls
still vary, and synchronous sequential H1 remains faster in this fixture.
Different worker/peer scheduling makes this unsuitable for ranking H1 against H2.

Native allocation peaks below are bytes, median (range) across three separately
traced samples. They include peer work, retained measurement metadata and loop
observations, exclude native allocations/RSS and are not a per-request cap.

| TLS / protocol / workers | No-pause Python peak | Read-ahead Python peak |
| --- | ---: | ---: |
| 1.2 / H1 / 1 | 594749 (594725–595389) | 707769 (687095–707769) |
| 1.2 / H1 / 4 | 626845 (623437–644264) | 786050 (759775–787078) |
| 1.2 / H2 / 1 | 574798 (574750–575887) | 677810 (677690–682754) |
| 1.2 / H2 / 4 | 589590 (589310–589614) | 600562 (600428–605030) |
| 1.3 / H1 / 1 | 594176 (593856–594216) | 700195 (666197–700403) |
| 1.3 / H1 / 4 | 623158 (622478–625224) | 779801 (750970–782542) |
| 1.3 / H2 / 1 | 573570 (573482–573978) | 676710 (676638–676718) |
| 1.3 / H2 / 4 | 587962 (586214–589090) | 601563 (589225–605695) |

The requested loop callback interval is 1 ms. Across the nine untraced samples
per native row, before/after callback counts are respectively
1152/782, 540/421, 1842/1117, 1828/937, 1125/733, 516/394, 1784/1045 and 1753/851
in table order. Shorter runs naturally provide fewer callbacks. Maximum observed
lateness ranges from 0.182–9.527 ms before and 0.148–6.975 ms after; the candidate
6.975 ms outlier occurs in TLS1.2 sequential H2. Raw intervals and unfinished
tails are retained. This is cooperative progress evidence, not a latency bound
or a demonstrated latency improvement.

### 100 MiB paired streaming

Three untraced completion samples and one separate allocation sample per cell;
each has one excluded, equally sized warmup. Every measured response delivers its
first chunk before its paired peer's final send and verifies 104,857,600 bytes.

| TLS / protocol | No-pause complete ms, median (range) | Read-ahead complete ms, median (range) | Python peak bytes, before / after |
| --- | ---: | ---: | ---: |
| 1.2 / H1 | 1044.92 (1040.56–1049.32) | 539.68 (537.94–540.62) | 177777 / 269721 |
| 1.2 / H2 | 1887.12 (1877.08–1903.35) | 988.57 (979.04–995.67) | 277571 / 281508 |
| 1.3 / H1 | 1011.04 (1010.21–1011.70) | 517.35 (517.11–520.86) | 175372 / 275370 |
| 1.3 / H2 | 1782.88 (1769.21–1797.37) | 893.93 (885.45–961.90) | 264351 / 284656 |

Read-ahead median first chunks are 0.66/0.91/0.67/0.74 ms in table order
(all timing samples: 0.64–0.92 ms). Candidate callback observations total
1583/2822/1524/2627, with per-sample p95 intervals 1.03–1.10 ms and maximum
lateness 0.097/0.176/0.082/1.368 ms. Baseline maximum lateness reaches 7.640 ms
in TLS1.2 H2. Traced peaks remain well below the response size, but differ from
the 120-request small-body workload partly because retained metadata differs.
These samples cannot establish a universal memory or scheduling guarantee.

## Final merged-source verification

After integrating P4, all 16 comparison cases and four 100 MiB cases passed
again, with 64 and 16 records respectively. This final snapshot has the same
68 module hashes as the independently installed wheel. These are final-source
sanity measurements, not an additional interleaved estimate of P4's effect.

| Native async TLS / protocol / workers | 64 KiB requests/s, median (range) |
| --- | ---: |
| 1.2 / H1 / 1 | 1322 (1315–1329) |
| 1.2 / H1 / 4 | 2238 (2230–2370) |
| 1.2 / H2 / 1 | 904 (829–916) |
| 1.2 / H2 / 4 | 1020 (978–1047) |
| 1.3 / H1 / 1 | 1408 (1404–1431) |
| 1.3 / H1 / 4 | 2439 (2215–2601) |
| 1.3 / H2 / 1 | 996 (912–998) |
| 1.3 / H2 / 4 | 1193 (1181–1212) |

| TLS / protocol | 100 MiB complete ms, median (range) | First chunk ms, median (range) | Python peak bytes | Maximum loop lateness ms |
| --- | ---: | ---: | ---: | ---: |
| 1.2 / H1 | 526.59 (523.99–527.11) | 0.75 (0.74–0.80) | 269193 | 0.058 |
| 1.2 / H2 | 951.61 (949.67–955.49) | 0.79 (0.78–0.85) | 301081 | 0.207 |
| 1.3 / H1 | 543.32 (514.23–581.54) | 0.72 (0.71–0.82) | 274810 | 21.387 |
| 1.3 / H2 | 871.99 (868.84–876.36) | 0.72 (0.68–0.84) | 294462 | 0.159 |

All sixteen final large-body responses, including allocation samples, satisfy
the first-chunk and payload checks. The 21.387 ms TLS1.3 H1 scheduling outlier
is retained, not discarded or presented as an implementation-level latency
guarantee. The experiment does not isolate its source. No arbitrary performance
threshold was added to CI.

## Retained evidence and limits

Raw JSON, logs, profiles, build artifacts and diagnostics are retained locally
under ignored `dist/post-2.1.0/`; these are evidence paths, **not public download
links**. Reports retain each request, connection, source/tool hash, timing sample,
allocation sample and loop interval. Original failed tests/profiles remain
separately named. The benchmark peers close listeners, connections, sessions,
native tasks and worker threads before successful completion; task-owned source,
certificate and installation staging is removed after final acceptance.

| Evidence | SHA-256 |
| --- | --- |
| `p2/http1-release.json` | `cf1fa7acc887e6f10ea047b25960366a4291a5dfd8442c97012e6a089c63fdbe` |
| `p2/protocol-release.json` | `dcf38355809ff15df7e737f63096c3be4f08707788a201ee10a14dc9315f3c37` |
| `p2/async-release.json` | `b141c49b9b0686db292d9e8a70d815ee7a1106e81efd1453564d745d33883048` |
| `p2/large-async-release.json` | `1f7f0269eb6343a0bbc921063263522101e6275043da8908603570631a422aee` |
| `final/async-performance.json` | `362e4f648a5c44c5c7b71fe9a7b8199177b9d09d2b1f49019debf8f2c55e6be3` |
| `final/large-performance.json` | `73793ca08147115c8a5f0f6102685996ba6f96ee6480feab20b79f27d3cb47a2` |

P3a comparisons are `p3a/pair-{1,2,3}-{baseline,no-pause}.json`; P3b comparisons
are `p3b/pair-{1,2,3}-{no-pause,read-ahead}.json` and
`p3b/large-{TLSv1.2,TLSv1.3}-{http1.1,h2}-{no-pause,read-ahead}.json`.
The final evidence manifest records their hashes and validation results.
Local Python 3.13.3 results do not stand in for new Python 3.7–3.12/other-OS CI.
Previous release CI is historical evidence only. No commit, push, version bump,
site deployment or package publication is part of this maintenance delivery.
