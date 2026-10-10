# ja3requests

ja3requests is a synchronous and native asynchronous Python HTTP client with its own TLS protocol
implementation. It owns ClientHello encoding, handshake and record state,
session resumption, and HTTP/2 framing, so applications can configure and inspect
what the client sends. `cryptography` supplies cryptographic primitives and X.509
support; Python `ssl` supplies the default CA roots. See the
[architecture](architecture.md) for the implementation boundaries.

## Which version does this site describe?

This site describes [2.3.0](https://github.com/lxjmaster/ja3requests/releases/tag/v2.3.0),
including incremental response streaming, native async, streaming request bodies,
async multipart/files, async Cookie files, buffered async prepared requests,
exact H2 fingerprint controls, public typing and transport maintenance.
The generated API reference reads the checkout's source and docstrings.
Dated acceptance records in the existing guides remain historical. Building
these docs locally does not deploy a public documentation site.

The current client supports HTTP/1.1, explicitly negotiated HTTP/2, TLS 1.2 and
TLS 1.3, connection reuse, HTTP/SOCKS proxies, Cookies, hooks and configurable
HTTP retries. Native `AsyncSession`, `AsyncResponse` and `AsyncConnectionPool`
are available starting with 2.1.0. HTTP/3, QUIC, ECH, post-quantum key exchange,
TLS 0-RTT remains outside the implemented scope; streaming request bodies are
available for the supported HTTP/1.1 and HTTP/2 paths.

## Start here

- [Install and make a request](getting_started.md).
- [Learn defaults, overrides and errors](configuration.md).
- [Own the lifetime of a streaming response](streaming.md).
- [Use native async requests and borrowed pools](async.md).
- [Configure trust, client certificates and resumption](tls.md).
- [Control JA3, browser-inspired profiles and HTTP/2](fingerprints.md).
- [Run local examples](examples.md), [read the synchronous API](api/client.md),
  or [read the async API](api/async.md).

The secure default verifies certificates, offers TLS 1.3 with authenticated
TLS 1.2 fallback, and uses HTTP/1.1 ALPN. A JA3 match alone does not prove browser
equivalence. The explicitly selected Chrome 154 preset is a documented supported
subset with differences from the captured browser; implicit Chrome stays at 124.
