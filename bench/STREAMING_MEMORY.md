# Isolated-client streaming memory acceptance

This explicitly invoked tool measures the source checkout using the project's
synchronous and native asynchronous clients. It addresses the selected
[Issue 41 measurement boundary](../issues/streaming_memory_acceptance.md):
validate complete large responses without accumulating their bodies, while
separating application chunks, observable protocol state and process memory.
It does not claim that all memory is bounded by `chunk_size`, alter the public
[streaming contract](../docs/streaming.md#framing-compression-and-memory), or
perform installed-release acceptance.

## Reproduce

Use the existing development environment with Python 3.12 or newer on macOS or
Linux, including the project's runtime dependencies and pytest. Install the
optional measurement dependencies:

```sh
.venv/bin/python -m pip install -r bench/requirements.txt
```

First exercise every selected transport and codec with small responses:

```sh
.venv/bin/python -m bench.stream_memory \
  --body-bytes 131072 1048576 \
  --output dist/streaming-memory/smoke-01
```

Then run the default two-size acceptance matrix:

```sh
.venv/bin/python -m bench.stream_memory \
  --output dist/streaming-memory/acceptance-01
```

Each output directory must be new; existing results are never overwritten.
The tool creates its parent directories as needed and writes `measurement.json`,
including partial evidence if a case fails. A small smoke run is not evidence
for the default 1 GB workload. Inspect available selectors with:

```sh
.venv/bin/python -m bench.stream_memory --help
```

`--clients` and `--cases` can restrict a diagnostic run. `--body-bytes` accepts
exactly two increasing decoded sizes above the 32,768-byte gated prefix.
`--chunk-size` defaults to 16,384 and cannot exceed that value for this peer.
The default case timeout is 180 seconds and requested RSS sampling interval is
0.01 seconds; changing these parameters must remain visible in the report.

## Fixed workload

The default matrix has 14 client/path combinations, each measured at
**100,000,000** and **1,000,000,000 decoded bytes**: 28 fresh client processes.
Here, **1 GB means 1,000,000,000 bytes**, not 1 GiB. Both clients use every row:

| Case selector | Independent peer and response |
| --- | --- |
| `http-chunked` | Plain HTTP/1.1; one large logical HTTP chunk sent in bounded blocks |
| `tls12-http1` | TLS 1.2 HTTP/1.1 with Content-Length |
| `tls13-http1` | TLS 1.3 HTTP/1.1 with Content-Length |
| `tls13-h2` | TLS 1.3 HTTP/2 DATA with the existing peer's flow control |
| `gzip` | Plain HTTP/1.1 chunked, gzip-encoded repeated-byte payload |
| `deflate` | Plain HTTP/1.1 chunked, zlib-wrapped deflate payload |
| `br` | Plain HTTP/1.1 chunked, Brotli-encoded repeated-byte payload |

These representative compression cases exercise high expansion. They do not
claim measurement of every codec/TLS/protocol combination, TLS 1.2 H2, concurrent
streams, or arbitrary compression histories. Reports keep encoded wire-body
bytes separate from decoded response bytes; encoded counts exclude HTTP chunk
framing and H2 frame headers.

Each case performs one cold request on one connection with concurrency one.
There is no full-size warmup. The independent peer and RSS sampler live in the
parent process; only the dedicated client child's PID is sampled. Imports and
Session initialization precede the client baseline. The request, handshake,
streaming and client cleanup occur in the measured interval.

The peer generates repeated `x` bytes from a fixed block no larger than 16 KiB.
It withholds the tail after a 32 KiB decoded prefix. The controller releases
that gate only after the child reports an actual nonempty application chunk;
compressed prefixes are flushed without terminating their encoded streams.
This establishes incremental delivery through an event dependency, not a
cross-process timestamp comparison. A yielded block may be smaller than
`chunk_size`, including the first Brotli block.

The child checks every byte and the final decoded count, then discards each
chunk. It records counters, maxima and at most four progress checkpoints,
without retaining per-chunk arrays or heartbeat samples. Checks also require
no response-body cache, chunk bounds, actual TLS/ALPN selection where applicable,
peer gate evidence, and process/thread cleanup.

## Interpret the measurements

| Field group | Meaning and limit |
| --- | --- |
| RSS baseline and sampled peak | Client process resident memory, including native libraries and tracing/observer overhead; excludes the separate server process |
| RSS sample count and maximum gap | Evidence of the sampling cadence actually achieved; the requested interval alone does not guarantee capture of transient peaks |
| Process-lifetime RSS high-water mark | Supplemental OS observation, including imports and other pre-request work; not a transfer-only peak |
| `tracemalloc` baseline/current/peak | Traced Python allocations in the client; not all native decoder, crypto or allocator memory |
| Protocol observed maxima and limits | Python-visible response cache, pending payloads, decoder tails/output and H2 queues; state lengths or explicit queue budgets, not complete per-layer memory attribution |
| Application maximum chunk | Largest yielded byte string, required to be no larger than the configured `chunk_size` |

RSS and Python allocation measurements overlap and must not be added together.
Subtracting `tracemalloc` from RSS does not identify native decoder memory.
Native zlib/Brotli history windows are not separately attributable by these
probes. Some state is observed at yield points, while H2 queue checks observe
frame dispatch; neither is a universal all-time memory inventory.

The [acceptance plan](../issues/streaming_memory_acceptance.md#fixed-measurement-boundary)
fixes these conservative regression budgets **before** the large run:

| Check | Fixed budget |
| --- | --- |
| Request RSS increase from client baseline | 64 MiB |
| Traced Python peak increase from its baseline | 16 MiB |
| RSS-increase growth from the smaller to larger body | 8 MiB |
| Traced Python peak-increase growth across sizes | 1 MiB |

These are scenario-specific regression thresholds, not portable library memory
guarantees. Explicit protocol-state budgets and the no-cache check remain
additional requirements. Passing two finite workloads supports the stated
configuration only; it is not a mathematical proof for every response size or
environment. Do not increase budgets after seeing results merely to obtain a
pass, or describe a successful run as `all memory <= chunk_size`.

## Accepted local run (2026-10-23)

The full matrix passed: **28 cases and 14 size comparisons**, using exactly
100,000,000 and 1,000,000,000 decoded bytes with `chunk_size=16384`.
The [repository evidence JSON](streaming-memory-2026-10-23.json) is a
byte-identical copy of the original local report retained under Git-ignored
`dist/streaming-memory/acceptance-01/measurement.json`. The repository copy was
prepared on 2026-10-25; this is not a new measurement. It contains no host-local
absolute paths or credentials, and no measurement, metadata or hash was
changed. Both copies have SHA-256
`641230a2fe374c263931cf717889d3f5f125aba8e511407a05ce1d326a8afe79`.

This run used checkout `9af4cc7032b82bea055dcd09b82d5bf8bba80f44`, macOS
15.7.7 arm64, Python 3.13.3, psutil 7.0.0, cryptography 45.0.5 and Brotli 1.2.0.
It ran from 13:25:25.898 to 13:26:48.632 UTC. The runtime package was unchanged;
the report retains the source and local tool hashes. Source/tool stability and
temporary-directory removal were all confirmed. Every child exited with code
zero; all reader and peer threads stopped.

All numeric columns below are **bytes**. RSS and Python columns are increases
over each process's respective pre-request baseline, not total process memory.
Growth is `max(0, increase_at_1GB - increase_at_100MB)`; zero can represent a
decrease, not identical memory use. Exact baselines, sampled peaks and lifetime
high-water marks remain separate fields in the JSON.

| Client | Case | 1 GB RSS increase | 1 GB Python peak increase | RSS growth | Python growth |
| --- | --- | ---: | ---: | ---: | ---: |
| sync | http-chunked | 622592 | 264020 | 0 | 45 |
| sync | tls12-http1 | 5734400 | 515496 | 0 | 0 |
| sync | tls13-http1 | 6045696 | 624531 | 393216 | 0 |
| sync | tls13-h2 | 8306688 | 778607 | 1327104 | 0 |
| sync | gzip | 770048 | 263975 | 0 | 0 |
| sync | deflate | 1409024 | 263975 | 819200 | 0 |
| sync | br | 9912320 | 263975 | 671744 | 0 |
| async | http-chunked | 2588672 | 331423 | 655360 | 311 |
| async | tls12-http1 | 7471104 | 678805 | 589824 | 407 |
| async | tls13-http1 | 9912320 | 789258 | 2048000 | 0 |
| async | tls13-h2 | 9289728 | 787778 | 2539520 | 0 |
| async | gzip | 1687552 | 308193 | 753664 | 0 |
| async | deflate | 1425408 | 307687 | 327680 | 0 |
| async | br | 9994240 | 331719 | 0 | 0 |

Across **both** sizes, the largest RSS increase was 10,059,776 bytes
(9.59 MiB, async Brotli at 100 MB): baseline 41,713,664, sampled peak 51,773,440.
The largest traced Python peak increase was 789,406 bytes (0.753 MiB, async
TLS 1.3 HTTP1 at 100 MB). Maximum cross-size growth was 2,539,520 RSS bytes
(2.42 MiB, async H2) and 407 traced Python bytes (async TLS 1.2 HTTP1).
All four predeclared budgets passed without adjustment.

Every case verified the complete payload, a first application chunk before tail
release, no body cache and an application maximum of 16,384 bytes. Observable
H2 connection queues and per-stream bodies peaked at 65,535 bytes for sync and
49,151 for async, within their recorded budgets; these are not whole-process
memory totals. RSS sampling obtained 13 to 1,440 samples per case; the largest
observed gap was 0.021878 seconds (rounded up), despite the requested 0.01-second
interval. Transient peaks between samples and native decoder histories remain
subject to the measurement limits above.

This is local evidence for the selected bounded-streaming interpretation. It
does not satisfy or replace the remote Issue's literal `all memory <= chunk_size`
wording, close that Issue, or establish acceptance of a published package.

On 2026-10-25, the owner selected the proposed replacement memory criterion
and ordered repository delivery and Issue reconciliation. The tools/report
were delivered in `90b78e1` with five successful workflows. Issue 41's original
memory goal was explicitly superseded before it was
[closed with the scoped evidence](https://github.com/lxjmaster/ja3requests/issues/41#issuecomment-6393601088).
This administrative acceptance leaves the original report and public memory
guarantees unchanged.

## Evidence and cleanup

The report retains parameters, package/tool hashes, runtime/dependency versions,
Git identity, per-case and cross-size outcomes, child exit status, sampling
statistics, peer observations and cleanup results. Source/tool stability is
checked across the run. Inspect `status` and all selected cases/comparisons;
partial or failed runs are not acceptance evidence.

Output reports are retained deliverables. Dedicated client processes, reader
threads, peer listeners/connections and temporary certificate/key staging are
cleaned up by the run. No host trust store is modified, no public service is
contacted, and no commit, push, Issue write, package publication or deployment
is performed. This checkout-specific evidence must not be substituted for
verification of an independently installed release artifact.
