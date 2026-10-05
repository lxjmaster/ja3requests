# HTTP and SOCKS proxies

The mapping key is the **destination URL scheme** (`http` or `https`); the
value selects the proxy. Pass the mapping to the request explicitly.

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

The HTTP proxy implementation uses CONNECT even for an `http://` destination;
the proxy must permit that destination port. The value prefix `https://` does
not implement TLS to the proxy. Use an HTTP proxy endpoint for this path.
`socks5h`, PAC files, environment proxy discovery and `NO_PROXY` routing are not
implemented APIs. SOCKS5 already sends the destination name for proxy-side DNS;
the proxy host itself must still be reachable from the client.

The current parser expects a simple `host:port` endpoint and does not provide
general URL parsing/percent-decoding for credentials or bracketed IPv6 proxy
endpoints. Supply values in the supported form rather than assuming Requests'
entire proxy URL grammar.

## HTTPS still uses the project TLS implementation

CONNECT/SOCKS first creates a tunnel. The project then emits its own ClientHello
and performs TLS to the destination through it. `tls_config` and `verify` have
the same destination-authentication meaning as direct HTTPS. A custom SNI does
not replace the destination used for certificate identity verification.

Proxy connections currently use per-response ownership rather than the direct
connection pool. Consume or close a streaming response to release the tunnel.
Connect/read limits and failures include proxy negotiation; error types include
`ProxyError` and `ProxyTimeoutError` from the
[protocol error reference](api/response.md).
