# JA3, browser presets, and HTTP/2

## Preview a ClientHello

```python
from ja3requests import TlsConfig

config = TlsConfig.secure()
config.validate(strict=True)
print(config.get_ja3_string(server_name="example.com"))
```

JA3 encodes the ClientHello version, ordered cipher suites, extension types,
supported groups and point formats, with GREASE excluded. It omits many extension
payloads, record behavior, HTTP content and HTTP/2 settings. TLS1.3 ClientHello
uses a legacy version field, so the JA3 version alone is not the negotiated TLS
version. A preview prepares a fresh hello; resumption and HelloRetryRequest can
change the actual sent extensions.

At the low-level `TLS` object, `sent_client_hellos` holds successfully sent
ClientHello records. `inspect_client_hello(record)` decodes one complete record
without generating new keys. See [exact wire control](tls_wire_control.md) for
ordering, validation, retry/PSK rules and the difference between a numeric field
that can be encoded and a negotiation the client actually implements.

## Browser-inspired configurations

```python
from ja3requests import TlsConfig

config = TlsConfig.from_browser("chrome", version=154)
config.validate(strict=True)
print(config.get_ja3_string(server_name="example.com"))
```

Specify a version for reproducible selection. Omitting Chrome's version still
selects the historical 124 default. Chrome 154 is an explicitly captured,
supported subset, with a different JA3 from the capture. It does not add ECH,
post-quantum key exchange, ALPS, certificate compression or full browser GREASE.
Other presets are browser-inspired unless backed by separate capture evidence.
Factory presets verify certificates; profile choice and trust remain separate.

## Enable HTTP/2 and choose its fingerprint

```python
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

config = TlsConfig.secure()
config.alpn_protocols = ["h2", "http/1.1"]
config.h2_settings = [(1, 65536), (2, 0), (4, 6291456), (6, 262144)]
config.h2_window_update = 15663105
config.h2_pseudo_header_order = [":method", ":path", ":authority", ":scheme"]
config.h2_priority_frames = [(3, 0, 201, False), (5, 3, 101, True)]
config.h2_huffman = True
config.h2_indexing_exclusions = [":path"]
config.validate(strict=True)
with Session(tls_config=config, pool=ConnectionPool()) as session:
    response = session.get("https://example.com/", h2_headers_priority=(256, True), timeout=5)
    image = session.get("https://example.com/pixel.png", h2_headers_priority=(183, True), timeout=5)
```

Those explicit numbers are an illustrative configuration, not a claim about a
particular browser. `h2_settings` accepts a mapping or ordered setting pairs and
preserves exactly their order and field set. Repeated IDs in a pair sequence are
sent in order; the last value controls local state. `None` sends the default
SETTINGS; `{}` or `[]` sends an empty SETTINGS. Omitted values use protocol
defaults internally, without adding fields to the wire. Response decoding also
has a local budget: omitting `MAX_HEADER_LIST_SIZE` (ID 6) keeps a 16,384-byte
decoded header-list limit, counting name/value octets plus 32 bytes per field.
An explicit ID 6 selects that limit, including zero. This local fallback adds
no advertised setting; compressed header blocks have a separate allocation bound.

Received peer SETTINGS are applied entry by entry in wire order. Repeated
header-table limits evict entries at each reduction and the next request block
announces the smallest and final sizes. Invalid intermediate values fail the
connection even if a later entry for the same ID is valid.

Responses are checked after complete HPACK decoding and before their fields are
exposed. Invalid names, NUL/CR/LF or surrounding space/tab in values, misplaced
or duplicate pseudo-headers and connection-specific fields reset the affected
stream with PROTOCOL_ERROR. Interim responses and trailers use the same checks.
Other streams retain their shared compression state; decoding/allocation failures
still fail the connection. Accepted trailers remain consumed without a public
trailer collection API.

`h2_window_update` selects the initial connection-window increment: `None` or
`0` sends no WINDOW_UPDATE, and a positive integer cannot overflow the initial
65,535-byte window. SETTINGS values and frame sizes are validated before TLS
transmission. Mutable configuration values are copied on assignment and rechecked
before use; browser factories provide independent state.

`h2_pseudo_header_order` is a complete permutation of the four request
pseudo-headers. `None` keeps `:method, :authority, :scheme, :path`.
`h2_priority_frames` supplies ordered `(stream_id, dependency, weight, exclusive)`
tuples. Stream IDs are nonzero 31-bit integers; dependencies may be zero but
cannot reference the same stream; weights are 1–256; `exclusive` is a bool.
These legacy PRIORITY frames follow initial SETTINGS and any WINDOW_UPDATE,
once per connection. They signal priority without opening streams or implementing
a scheduler; the first request still uses stream 1. Connection-level H2 controls
participate in pool identity and apply to synchronous and native async clients.

`h2_headers_priority=None | (weight, exclusive)` is request metadata. `None`
keeps HEADERS without priority fields; a tuple writes dependency 0, the exclusive
bit and weight 1–256. Boolean weights and non-boolean exclusivity are rejected
before source consumption or network I/O. The five priority bytes count toward
the first frame's limit and are absent from CONTINUATION frames. Priorities do
not split connection pools: weights 256 and 183 can share streams 1 and 3.
Retries/redirects retain the metadata unless a request hook replaces it. It has
no wire effect with HTTP/1.1. Native async `prepare_request()` snapshots it;
`AsyncPreparedRequest.h2_headers_priority` is read-only and `with_headers()`
preserves it. These legacy fields control the wire fingerprint, not scheduling.

`h2_indexing_exclusions` defaults to `()`. Assignment copies, lowercases and
deduplicates valid field names into an immutable tuple, including pseudo-header
names such as `:path`. Matching new literals use the HPACK representation without
dynamic-table insertion; existing exact static/dynamic index references remain
usable. Sensitive literals retain never-indexed handling. For example, `/` can
use its static index while a new `/pixel.png` is sent without insertion.
This policy is independent of Huffman encoding. Changed exclusions select a
different pooled connection; an unchanged policy preserves its dynamic table.

`h2_huffman` is a boolean, default `False`. Setting it to `True` uses HPACK
Huffman coding for each outbound literal name/value only when the encoded
octets are strictly shorter. Equal-length or larger results retain raw encoding.
The same rule applies to both clients, including prepared sends and streaming
uploads, and a changed policy selects a separate pooled connection. Sensitive
fields still use never-indexing; dynamic-table/indexing choices are unchanged.
Header inputs remain valid UTF-8, while the low-level `encode_string` primitive
can encode arbitrary octets. Existing presets keep their raw default.

The policy matches the literal choices in the retained Chrome 155/macOS two-request
capture, and its first request's HPACK block matches under equivalent supplied
headers. A complete browser fingerprint also depends on HEADERS priority, indexing
policy and TLS fields; enabling this option does not assert full browser identity.

The peer must
negotiate `h2` via ALPN (application-layer protocol negotiation). HTTP client
configuration accepts only `h2` and `http/1.1`; no selected ALPN retains HTTP/1.1
compatibility. A selected name must have appeared in the actual sent ClientHello
and must be implemented by the client, or the connection closes before HTTP
transmission or pooling. Raw `ClientHello`/`ALPNExtension` encoding can still
represent other names for packet inspection. There is no h2c
upgrade API in this guide.

On both clients, a request's `h1=True` offers only `http/1.1` through a separate
configuration copy. It cannot reuse a pooled H2 connection and does not change
the Session's ALPN settings for later requests. This applies to direct and proxy
routes.

The H2 implementation owns frames, HPACK, flow control, stream lifecycle and
multiplexing. Streaming uses per-stream consumption-driven credit, while the
configured initial SETTINGS and WINDOW_UPDATE remain the wire choices. Large
configured windows permit correspondingly larger buffering. Default SETTINGS
disable server push, and explicit `ENABLE_PUSH=1` is rejected. If an exact custom
SETTINGS omits `ENABLE_PUSH`, no implicit field is added; the peer's protocol
default allows push, but this client still rejects PUSH_PROMISE and provides no
push consumer. Include `(2, 0)` to advertise disabled push. Priority scheduling
is not implemented. Connection-specific request fields and fields named by
`Connection` are removed; `TE` accepts only `trailers`.
A TLS-only browser capture
does not establish that browser's HTTP/2 SETTINGS.

Run the [local fingerprint example](examples/h2_fingerprint.py) to verify an
actual TLS handshake and inspect the initial H2 frame bytes without an external
service.
