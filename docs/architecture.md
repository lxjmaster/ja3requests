# Architecture

The synchronous and async APIs provide policy and ownership over project-owned HTTP/TLS
protocol state. This separation is central to reproducible wire behavior.

| Layer | Main modules | Responsibility |
| --- | --- | --- |
| Public client | `ja3requests.__init__`, `sessions`, `retry`, `cookies` | Request entry points, Cookies, policy, redirects, hooks, retry decisions |
| Async client and ownership | `async_sessions`, `async_response`, `async_pool`, `async_transport` | Native socket waits, task-local requests, borrowed pools, deadlines, cancellation and response leases |
| Request preparation | `requests.request`, `requests.http`, `requests.https`, `contexts` | Validate/serialize requests and choose direct/proxy transport |
| Response lifecycle | `response.HTTPResponse`, `response.Response` | Headers, framing, incremental decoding, public consumption and connection release |
| Connection ownership | `pool`, `sockets.http`, `sockets.https`, `sockets.proxy`, `sockets.socks` | Direct pools, TCP/tunnel ownership, TLS socket adaptation, response release |
| TLS protocol | `protocol.tls`, `tls13`, `record_layer`, `config`, `session_cache` | ClientHello, handshake/retry/resumption, authentication, key schedule, TLS records |
| HTTP/2 protocol | `protocol.h2.connection`, `multiplex`, `frame`, `hpack`, `huffman` | Frames, HPACK, connection reader, stream state and flow control |
| Async HTTP/2 driver | `protocol.h2.async_connection` | Connection-owned reader/writer tasks, bounded DATA queues, committed-write ordering and per-stream cancellation |
| Crypto primitives | `cryptography` | Encryption/AEAD, key exchange, signatures and X.509 parsing/verification support |
| Trust discovery | Python `ssl` | Read default CA roots; not the client handshake engine |

## Request and response lifetime

A Session prepares a transport request and runs `before_request`. The transport
checks out or opens a connection, performing the project's TLS handshake for
HTTPS. It parses response headers and transfers body/connection ownership to the
response. Eager mode then loads the complete body; streaming mode returns with
the body pending. Cookies, HTTP retries, redirects and response hooks are
applied at their policy boundaries.

As a streaming caller consumes data, framing and decompression advance. Valid
EOF releases an HTTP/1 connection or an HTTP/2 stream once. Early close discards
an HTTP/1 connection or cancels the H2 stream. H2's connection reader dispatches
frames to bounded stream buffers; consumption grants additional stream credit.
The configured initial wire settings remain separate from that runtime credit.

There is no OpenSSL client engine (`SSL_connect`, `SSLContext.wrap_socket` or an
OpenSSL subprocess) hidden under the public client. `cryptography` can itself
depend on OpenSSL for primitives. Independent integration/benchmark **servers**
use OpenSSL/Python `ssl`; a compared Requests client uses its own separately
identified TLS backend. These are different roles.

## Evidence boundaries

Unit tests check codecs and policy; controlled loopback peers check protocol
interoperability, real first-byte/EOF/cancellation behavior and socket-received
ClientHello bytes. Release evidence names the source/version and environment.
Performance evidence distinguishes full handshake, resumed handshake and
connection reuse, validates response contents and records observed paths.

The original guides preserve dated verification records. They are not evidence
that a later checkout passed the same installed-wheel or remote CI checks.
Building this site validates documentation and API extraction, not all runtime
protocol combinations.

## Native async ownership

The `AsyncSession` introduced in 2.1.0 uses native asyncio socket waits while retaining
the project's TLS handshake/record transitions and crypto primitives. Sync and
async responses share byte-fed incremental content decoding. The async H2
driver reuses connection/frame/HPACK state with connection-owned reader/writer
tasks and stream-scoped waiters; it does not wrap the synchronous client's
socket operations in a worker thread.

Sessions own default async pools and borrow explicitly supplied pools. Request
state is kept per task; cancellation detaches that request's lease and finishes
scoped cleanup. A cancelled pooled H2 response cannot close an unrelated stream.
Caller cancellation remains cancellation; owned phase expiry is a `Timeout`.
See the [async guide](async.md) for visible differences from synchronous body
access, eager decoding, redirects, hooks and pool close behavior.
