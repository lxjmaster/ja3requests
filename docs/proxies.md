# HTTP and SOCKS proxies

The mapping key is the **destination URL scheme** (`http` or `https`); the
value selects the proxy. Pass the mapping to the request explicitly. `Session`
and `AsyncSession` have different proxy parsing and connection-reuse contracts.
Neither API reads PAC files, environment proxy settings or `NO_PROXY` rules.

## Synchronous Session

```python
from ja3requests import Session

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://user:password@127.0.0.1:8080",
}
with Session(use_pooling=False) as session:
    response = session.get("https://example.com/", proxies=proxies, timeout=(3, 10))
```

The example assumes a running HTTP proxy. Credentials are placeholders.

| Value format | Transport behavior |
| --- | --- |
| `host:port` or `http://host:port` | HTTP CONNECT tunnel |
| `http://user:password@host:port` | CONNECT with Basic proxy authentication |
| `socks5://host:port` | SOCKS5 CONNECT, destination name sent to the proxy |
| `socks5://user:password@host:port` | SOCKS5, offering no-auth and username/password methods |
| `socks4://userid@host:port` | SOCKS4 for an IPv4 literal; SOCKS4a for a hostname |

The synchronous SOCKS schemes are `socks4` and `socks5`; `socks4a` and `socks5h`
are not supported scheme aliases in this API. `socks4` already uses SOCKS4a for
hostnames, and `socks5` sends the destination name for proxy-side DNS. The proxy
host itself must still be reachable from the client.

The synchronous parser expects a simple `host:port` endpoint and does not provide
general URL parsing/percent-decoding for credentials or bracketed IPv6 proxy
endpoints. Supply values in the supported form rather than assuming Requests'
entire proxy URL grammar.

An explicit `Proxy-Authorization` request header takes precedence over proxy URL
credentials for HTTP CONNECT. Pass a complete field value such as `Basic <token>`;
the legacy bare Base64 token is also accepted. The field is sent only in CONNECT
and is removed from the destination's HTTP1/H2 request, including streaming
uploads. Caller headers remain intact so retry attempts can authenticate again.
Final fields are validated before opening the proxy connection.
CONNECT reads the complete response header block, including fragmented status
and fields, with a 64 KiB limit and one handshake timeout budget. It leaves
tunnel bytes unread for the destination protocol. A rejected, malformed,
truncated, oversized or timed-out handshake closes its connection before the
error returns.

## Native AsyncSession

Pass `proxies` to the awaited request, for example
`await session.get(url, proxies=proxies)`. Async values require a URL with an
explicit supported scheme, hostname and port; a bare `host:port` value is not
accepted.

| Value format | Transport behavior |
| --- | --- |
| `http://host:port` | HTTP CONNECT tunnel |
| `http://user:password@host:port` | CONNECT with Basic proxy authentication |
| `socks4://userid@host:port` or `socks4a://userid@host:port` | SOCKS4 for an IPv4 literal; SOCKS4a for a hostname |
| `socks5://host:port` or `socks5h://host:port` | SOCKS5 CONNECT, destination name sent to the proxy |
| `socks5://user:password@host:port` or `socks5h://user:password@host:port` | SOCKS5 with username/password support |

Async URL parsing percent-decodes proxy credentials: for example,
`http://user:p%40ss@127.0.0.1:8080` supplies password `p@ss`. These are placeholder
credentials. Both `socks5` and `socks5h` use proxy-side destination DNS; selecting
`socks5` does not switch to local destination lookup. The async URL parser also
accepts bracketed IPv6 proxy endpoints, subject to normal network reachability.

An explicit `Proxy-Authorization` request header takes precedence over HTTP
proxy URL credentials. Complete field values and legacy bare Base64 tokens are
accepted. It is sent only in HTTP CONNECT and removed from destination
HTTP1/H2 fields, including prepared sends and uploads. Direct and SOCKS routes
also omit this HTTP proxy field from destination requests. Caller and prepared
metadata keep the original value for inspection and retries.

## Tunnel and TLS boundaries

Both HTTP proxy implementations use CONNECT even for an `http://` destination;
the proxy must permit that destination port. Neither API implements TLS to the
proxy itself. The synchronous parser does not make a proxy connection encrypted
when its value starts with `https://`; use `http://` for an HTTP proxy endpoint.
The async API rejects the `https` proxy scheme.

## HTTPS still uses the project TLS implementation

CONNECT/SOCKS first creates a tunnel. The project then emits its own ClientHello
and performs TLS to the destination through it. `tls_config` and `verify` have
the same destination-authentication meaning as direct HTTPS. A custom SNI does
not replace the destination used for certificate identity verification.

## Reuse, timeouts and close

Synchronous proxy connections use per-response ownership rather than the direct
connection pool. Consume or close a streaming response to release the tunnel.

Async proxy routes participate in the normal async pool when pooling is enabled.
The pool key includes the destination host/port/scheme, the complete proxy URL
(including credentials), explicit CONNECT authentication and the HTTPS TLS
policy. Different proxy URLs or explicit authentication values therefore do not
share a pooled connection. Reusable HTTP/1 responses return
their lease after complete consumption; early close discards the connection.
Negotiated HTTP/2 uses the usual stream ownership and cancellation rules.
`use_pooling=False` uses per-request connections. Default async sessions own
their pool; an explicitly supplied pool is borrowed and remains the caller's
responsibility. See [async pooling and close](async.md#pools-concurrent-tasks-and-close).

For synchronous routes, proxy errors include `ProxyError` and `ProxyTimeoutError`.
Async proxy negotiation is part of the connect budget: negotiation failures can
raise `ProxyError`, expiry raises `ja3requests.Timeout`, and caller cancellation
remains `asyncio.CancelledError`. See the [protocol error reference](api/response.md)
and [async timeout contract](async.md#timeout-cancellation-and-request-policy).
