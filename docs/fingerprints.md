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
config.validate(strict=True)
with Session(tls_config=config, pool=ConnectionPool()) as session:
    response = session.get("https://example.com/", timeout=5)
```

Those explicit numbers are an illustrative configuration, not a claim about a
particular browser. `h2_settings` preserves the caller's ordered setting pairs;
`h2_window_update` selects the initial connection-window increment. The peer must
negotiate `h2` via ALPN; otherwise the client uses HTTP/1.1. There is no h2c
upgrade API in this guide.

The H2 implementation owns frames, HPACK, flow control, stream lifecycle and
multiplexing. Streaming uses per-stream consumption-driven credit, while the
configured initial SETTINGS and WINDOW_UPDATE remain the wire choices. Large
configured windows permit correspondingly larger buffering. Server push is
disabled and priority scheduling is not implemented. A TLS-only browser capture
does not establish that browser's HTTP/2 SETTINGS.
