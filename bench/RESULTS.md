# First local HTTP/1.1 baseline

Recorded on 2026-10-04, 05:07:41.671799-05:07:43.651462 UTC using:

```sh
.venv/bin/python bench/http1_baseline.py --output bench/baseline-current.json
```

The command completed successfully. [baseline-current.json](baseline-current.json)
contains all nine samples, parameters, timing evidence, and source hashes.
The public JSON redacts only the two absolute executable/package paths to
repository-relative paths and adds export metadata. Measurement values, dates,
runtime versions and source/tool hashes are unchanged; the original report is
retained locally and is not distributed.
The benchmark script also passed Black and error-level Pylint. Invalid zero
repeat counts and non-finite send intervals were rejected before measurement.

## Snapshot

- CPython 3.13.3, macOS 15.7.7, arm64.
- Runtime versions: ja3requests 2.0.1, cryptography 45.0.5, brotli 1.1.0.
- Git HEAD: `a291ef30bb6ae53cf38b3d79604c8f34e1865547`.
- The working tree had tracked changes and untracked files. This measures the
  then-current development checkout, not an untouched release tag.
- All 59 package source files were stable throughout the run; their aggregate
  SHA-256 was `fec7786a072a0f26dbb729ed1d08d7e51866cc861fa9c44184f01aef54cf98e5`.
- Benchmark script SHA-256:
  `102da44f5bc8283d7a6db78d3376f78c3684c25a99eae5bf0cfc5956555ffd03`.

## First chunk and Python allocations

Each size used three fresh sessions, pools, and loopback servers. The peer sent
64 KiB pieces with a configured 2 ms wait between pieces. Client calls used
`stream=True`, and the consumer iterated without concatenating chunks. Both
measurement paths verified the expected length and every byte of the fixed
payload; all nine samples record `payload_verified=true`. Timing started before
`Session.get`, so buffering inside that call is included.

| Response size | Median first-chunk time | Median Python peak allocation | First chunk before final peer send |
| --- | ---: | ---: | --- |
| 1 MiB | 51.66 ms | 1,209,756 bytes | 0 of 3 samples |
| 8 MiB | 370.94 ms | 8,549,700 bytes | 0 of 3 samples |

In all six samples, the first client chunk arrived after the final peer
`sendall` completed. Peak allocation increased by approximately the additional
7 MiB of response data. This is consistent with full-body buffering in
`Response.iter_content` at that pre-streaming snapshot; it did not provide
incremental network delivery or a memory bound independent of response size.
The incremental behavior introduced in 2.1.0 is measured in the later
[performance report](PERFORMANCE_RESULTS.md), not in this baseline.

These times include the deliberate peer send intervals and scheduler/tracing
overhead. They are not raw download speed. `tracemalloc` measures Python
allocations in both the client and server threads, not process RSS or native
allocations. The server's single fixed chunk was allocated before tracing;
it did not construct either full response in memory.

## Sequential connection reuse

Each of three samples made 30 sequential, fully consumed 1 KiB requests with
no peer send interval or tracing. Timing included the initial connection,
checking the full payload, and closing each response; there was no warmup.

| Sample | Requests/second | Accepted TCP connections | Requests on that connection |
| --- | ---: | ---: | ---: |
| 1 | 6,030.50 | 1 | 30 |
| 2 | 4,161.01 | 1 | 30 |
| 3 | 4,503.21 | 1 | 30 |

The median was 4,503.21 requests/second. Actual server-side connection counts
confirm reuse in every sample. The short samples show substantial timing
variation, so this number is a descriptive local baseline, not a universal
throughput result or a CI regression threshold.

This first baseline covers cleartext HTTP/1.1 only. HTTPS, HTTP/2, async behavior,
cross-library comparison, and longer performance measurements remain outside
this result. It does not close the broader scope of issue #40 or implement #41.
All benchmark-owned server sockets, threads, and isolated pools were closed
before successful exit; only this documentation, script, and JSON evidence are
retained. Two provisional task-owned sample files were superseded by the
verified final-snapshot result and removed.
