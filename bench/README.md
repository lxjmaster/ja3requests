# HTTP/1.1 loopback baseline

Run the existing source checkout through the public `ja3requests.Session` API.
This small baseline addresses the first part of issue #40 and provides a before
measurement for incremental streaming in #41. It does not complete the broader
benchmark issue or measure TLS, HTTP/2, async clients, or other libraries.
The script adds no dependencies beyond the project's installed runtime packages.
The first retained measurement is summarized in [RESULTS.md](RESULTS.md), with
every sample and source hash in [baseline-current.json](baseline-current.json).
The public JSON is a redacted export: its executable and package paths are
repository-relative, while all measurement values and source/tool hashes are
unchanged. The original report is retained locally and is not distributed.

From the repository root, using the existing development environment:

```sh
.venv/bin/python bench/http1_baseline.py --output bench/baseline-local.json
```

The defaults run three samples for each of 1 MiB and 8 MiB responses, sent in
64 KiB pieces with a 2 ms interval between pieces. Three further samples each
make 30 sequential, fully consumed 1 KiB requests without the send interval.
The default run is intended to finish in seconds. All socket operations and
server joins have finite timeouts. The peer binds only to `127.0.0.1` on an
OS-assigned port; all sockets, pools, and threads are closed before exit.
No certificate, external service, or system configuration is involved.

For a smaller run or a clearer deliberate transmission delay:

```sh
.venv/bin/python bench/http1_baseline.py --sizes-mib 1 --repeat 1 --requests 10
.venv/bin/python bench/http1_baseline.py --sizes-mib 1 8 --gap-ms 5 --output bench/baseline-delayed.json
.venv/bin/python bench/http1_baseline.py --help
```

Without `--output`, JSON is printed to stdout. An output path must not already
exist: retain samples under distinct names instead of replacing evidence.

## Measurements

- `request_return_seconds`: from immediately before `Session.get(stream=True)`
  until that call returns.
- `first_chunk_seconds`: from the same start until the first `iter_content`
  chunk reaches the caller. This includes the request call itself. Starting
  the clock only before iteration would hide buffering below `Response`.
- `server_last_send_started_seconds` and `server_last_send_completed_seconds`:
  times bracketing the final body piece's `sendall`, relative to the client
  start on the same monotonic clock. `first_chunk_before_final_send` establishes
  whether the caller received a chunk before the final piece even began sending.
  A time inside the final send bracket is not evidence of early delivery.
- `python_peak_bytes`: peak allocations reported by `tracemalloc`, enabled
  immediately before the request and stopped after full iteration. This includes
  Python allocations in the peer's thread and is **not process RSS**, native
  allocation size, or a TLS memory benchmark. The peer allocates one fixed body
  chunk before tracing and sends slices repeatedly; it never constructs the
  full response body. The client consumes chunks without joining them.
- `requests_per_second`: sequential complete responses per second, including
  the first connection, full payload verification, and each response close,
  with no warmup or tracing.
  `accepted_connections` and `requests_per_connection` independently record
  actual TCP reuse. Passing a pool alone does not prove reuse.

Each sample uses a fresh dedicated pool and server. The JSON retains every
sample, all parameters, UTC timestamps, Python/platform/dependency versions,
package path, Git HEAD and dirty flags, benchmark-script SHA-256, and hashes of
every package source module. The source is checked again after measurement;
`source_stable_during_run=false` means the run spans a concurrent source change
and should be repeated on a stable snapshot for comparison. Dirty flags include
unrelated local work and newly added benchmark artifacts; package hashes identify
the actual library source independently.

Both measurement paths verify the expected body length and every byte against
the fixed peer payload. `payload_verified=true` records that check. The streamed
consumer checks each chunk without joining the full body; its complete time
includes verification, while first-chunk time stops when the first chunk arrives.

The implementation measured in the 2026-10-04 pre-streaming baseline read the
entire body before yielding the first `iter_content` chunk. These measurements
describe that historical snapshot, not the incremental reader introduced in
2.1.0. This script itself does not change response reading or pooling. Use the
recorded results as a baseline, not a universal throughput claim or a
cross-machine regression threshold.

The subsequent #41 implementation has separate peer-controlled first-chunk,
buffering, early-close/pool ownership, incremental decoding, and HTTP/2
cancellation/flow-control checks. Those paths are not established by this
HTTP/1.1 baseline; see the later [performance results](PERFORMANCE_RESULTS.md).
