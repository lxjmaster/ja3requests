# Project-owned TLS and verifiable wire control

The client implements its own ClientHello encoding, handshake state, retry,
resumption, key schedule and TLS record processing. It does not use OpenSSL's
TLS client engine (`SSLContext.wrap_socket`, `SSL_connect` or a subprocess).
`cryptography` provides primitive encryption, key exchange, signatures and X.509
validation and can depend on OpenSSL. Python `ssl` currently supplies default
CA roots only. Explicit CA bundles remain supported. This is a Python TLS
protocol implementation, not an OpenSSL-free implementation of every cipher.
OpenSSL in integration tests is an independent **server**, not the client.

## Field and capability contract

| Input | Wire behavior | Negotiation/validation boundary |
| --- | --- | --- |
| `cipher_suites` | Preserve caller order; optional leading GREASE | Numeric encoding does not imply every suite is implemented; reject unoffered server selection |
| `supported_groups` | Preserve caller order and uint16 identifiers | TLS 1.3 implements X25519/P-256/P-384; other advertised IDs are encoding only |
| `key_share_groups` | Ordered subset of advertised implemented groups | Fresh corresponding private keys; reject invalid subset and HRR selection |
| `signature_algorithms` | Encoded in caller order | Actual scheme/key verification must be implemented; advertisement alone is not evidence |
| `session_id` | Bytes of length 0..32, including empty and a one-byte zero value | Explicit setter value takes precedence over TLS 1.2 cache offers; constructor default permits cache policy |
| `compression_methods` | Only `[0]` | Other values rejected before ClientHello, not silently replaced |
| `client_random` | Explicit 32 bytes or generated per hello | HRR preserves the original random; callers should not pin production randomness |
| `client_hello_record_version` | `0x0301` default; TLS 1.3 also allows `0x0303`, TLS 1.2 also allows `0x0302`/`0x0303` | Controls the initial ClientHello header; TLS 1.3 retries always use `0x0303` |
| `server_name`/destination | SNI generated when hostname supplied | A custom SNI must match this value; certificate identity remains the request destination |
| `extensions` | Extension objects; custom content precedes automatic additions | Duplicates rejected; groups/signatures/ALPN declarations must agree with configuration |
| `extension_order` | Explicit ordering of the final generated extension set | Conditional SNI(0), cookie(44), PSK(41) slots may be absent; PSK must be last when emitted |
| `alpn_protocols` | Ordered encoded protocols | Existing HTTP/1.1 and HTTP/2 paths; declaring another protocol does not implement it |
| `use_grease` | Existing leading cipher-suite GREASE behavior | Not a complete browser GREASE policy for all fields |

Empty TLS 1.3 groups and empty cipher lists fail validation; they are not default
requests. The constructor supplies defaults. Session settings are validated at
ClientHello preparation before any TLS bytes are sent. Lower-level ClientHello
and Extension encoders remain usable for encoding-only experiments. An unknown
extension can be encoded by subclassing `Extension`; this does not claim support
for the corresponding server behavior. No generic plugin/backend framework is added.

The normal high-level TLS 1.3 path generates `key_share` and PSK from private
keys/cache state. Caller-provided replacements are rejected: replaying a public
key or binder without the matching secret cannot establish a working session.
Custom `supported_versions` in that path must match the implemented default
TLS 1.3/TLS 1.2 offer. Trust verification remains independent of wire choices.
Custom `psk_key_exchange_modes` must advertise only `[1]` (`psk_dhe_ke`);
PSK-only mode is not implemented. TLS 1.3 ServerHello must echo the exact
ClientHello Session ID on both direct and retried handshakes. TLS 1.2 may assign
a different ID when establishing a new session.

## Exact order and actual sent bytes

```python
from ja3requests import TlsConfig

config = TlsConfig.secure()
config.extension_order = [0, 43, 10, 51, 13, 16, 45, 23, 44, 41]
config.client_hello_record_version = 0x0303
```

The list orders completed extensions, including dynamically generated ones;
it does not synthesize missing extensions. Missing or additional nonconditional
types are errors. An HRR cookie uses its explicit slot; if no slot was provided,
the protocol inserts it immediately before PSK (or at the end). This is the one
documented retry insertion, not an arbitrary reorder. A cached PSK must have a
41 slot when exact ordering is used. All emitted PSK extensions remain last.

`config.get_ja3_string(server_name="example.com")` previews a **fresh** prepared
hello. It is not a report of a pooled/resumed connection. At the low-level `TLS`
object, `sent_client_hellos` is an immutable tuple of actual successfully sent
records, including ClientHello2 after HRR. To inspect one without generating keys:

```python
from ja3requests.protocol.tls.client_hello_info import inspect_client_hello

# tls is the TLS object used by this connection.
for record in tls.sent_client_hellos:
    summary = inspect_client_hello(record)
    print(summary["ja3"], summary["extensions"], summary["key_shares"])
```

Summaries omit hostnames, ticket bytes, randoms and public-key bytes. Raw records
may contain destination names and resumption identities: they are not logged by
default and should not be published indiscriminately. Failed/partial sendall is
not recorded as a successfully sent hello. Inspection accepts one complete
ClientHello record, not an arbitrary pcap or multi-record stream.

JA3 covers only five fields and ignores GREASE. Matching JA3 is not proof of
matching extension contents, record behavior, HTTP/2 behavior or browser identity.
Tests independently decode socket-received records rather than trusting the
production inspector's output as the sole oracle.

## P-384, explicitly selected

```python
config = TlsConfig.secure()
config.supported_groups = [29, 24]  # X25519, P-384
config.key_share_groups = [29]     # A P-384-only peer requests HRR
```

Use `[24]` as initial shares for a direct P-384 handshake. P-384 uses a 97-byte
uncompressed public point and 48-byte ECDH result. Independent OpenSSL peers
exercise normal and seven-byte reads, direct and retried handshakes, AES-128-GCM
and AES-256-GCM with certificate verification. Negative cases cover malformed
points and unadvertised/already-offered HRR groups. Existing X25519/P-256,
resumption and repeated-retry tests remain required.

Secure defaults remain `[29,23]`. Historical browser presets explicitly freeze
their previous initial shares, even when they advertise group 24. Supporting a
new group does not silently add a key_share to those presets.

## Chrome 154 capture calibration: an explicit supported subset

`TlsConfig.from_browser("chrome", 154)` is calibrated against the checked-in
[capture](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/fixtures/chrome154_macos_hello.json) from Google Chrome
154.0.8037.95 on macOS, headless, a new temporary profile and loopback localhost.
The artifact records exact flags, platform, capture time, bytes and SHA-256.
[Capture tool](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/capture_browser_hello.py) documents reproduction. It does
not use a personal profile, authenticate to a site or retain the temporary profile.

This profile is intentionally labeled a **supported subset**, not full Chrome
impersonation and not a matching JA3. Existing implicit Chrome selection stays
at 124; version 154 must be explicitly requested. Historical profiles remain
browser-inspired unless separately backed by a capture.

| Captured behavior | Supported-subset profile / explicit difference |
| --- | --- |
| 32-byte Session ID, null compression, record version 0x0301 | Same shape, fresh Session ID |
| Cipher preference order | Same relative order; omit TLS 1.2 ChaCha suites 52393/52392 |
| Supported groups GREASE/4588/29/23/24 | 29/23/24 only; hybrid post-quantum group 4588 not implemented |
| Key shares GREASE(1 byte)/4588(1216 bytes)/X25519(32 bytes) | Fresh X25519 only; P-384/P-256 can be requested through HRR |
| Captured extension order | Preserve relative order of implemented fields for this sample; no claim about distribution across randomized browser handshakes |
| Extension payloads 0,5,11,16,23,35,45,65281 | Match capture for the same hostname |
| Extensions 65037,51764,18,27,17613 | Omitted; no ECH, extra sampled capability, SCT request, certificate compression or ALPS implementation added |
| GREASE in several vectors and extensions | Only existing cipher GREASE retained; different values/content elsewhere |
| Signature list including GREASE and 0x0904/05/06 | Keep implemented traditional configured schemes; omit those sampled additions |
| HTTP/2 settings | Capture is TLS-only; no Chrome H2 SETTINGS claim or invented values |

The subset is tested against independent TLS 1.3 and TLS 1.2
ECDHE-RSA/AES-128-GCM servers. This is not evidence that every advertised suite
works against every peer. Correcting remaining sample differences would require
separately scoped functionality, not silently expanding this A-E workline.

## Evidence and non-goals

`test/fixtures/wire_baseline.json` records the published 2.0.0 secure, legacy and
Chrome 120 profiles. Random/public-key bytes are normalized while ordered fields,
share sizes and JA3 remain asserted. New wire tests cover actual socket bytes,
configuration rejection, exact ordering, retry/resumption and preset calibration.
Full selected suite, installed-wheel checks and current CI remain final gates.

No cipher rewrite, new TLS engine/backend abstraction, ECH/QUIC/0-RTT, persisted
TLS sessions or server push is part of this change. Default CA-root extraction
still uses Python ssl; replacing that auxiliary dependency is not needed to
restore protocol/JA3 control. No changes disable certificate verification.
