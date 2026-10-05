# Configuration and errors

This page describes synchronous `Session` behavior. The [async guide](async.md)
documents its distinct timeout, pool ownership and response contracts.

## Defaults and precedence

| Setting | Current default | How to override |
| --- | --- | --- |
| TLS profile | `TlsConfig.secure()` behavior | `Session(tls_config=config)` or request `tls_config=config` |
| Certificate verification | Enabled | Request `verify=True`/`False`; omitted/`None` inherits the selected config |
| TLS versions | TLS 1.3 with authenticated TLS 1.2 fallback | Explicit `TlsConfig` settings |
| Groups / initial shares | X25519 and P-256 | `supported_groups` and `key_share_groups` |
| ALPN | `['http/1.1']` | `config.alpn_protocols = ['h2', 'http/1.1']` |
| Timeout | `None` | Request scalar or `(connect, read)` tuple, in seconds |
| Redirects | Enabled; HEAD helpers disable them | `allow_redirects=False`; current redirect limit is 8 |
| Body loading | Eager (`stream=False`) | `stream=True` |
| HTTP retry policy | None | `Session(retry=HTTPRetry(...))` |
| Connection pool | Shared default pool | Dedicated `pool=ConnectionPool()` or `use_pooling=False` |
| TLS session cache | Created for a Session config when absent | Set `config.session_cache` before creating the Session |

The request first chooses its explicit `tls_config`, otherwise the Session's
configuration. An explicit `verify` then overrides that selection for the
request without changing the Session's verification setting. A copied
verification override retains the same cache object; reuse also checks the
effective authentication and TLS policy. The effective configuration follows
redirects. It does not prevent an HTTPS-to-HTTP redirect; applications requiring
HTTPS throughout must control redirect destinations.

Configure TLS before beginning requests. If trust roots change, use fresh pools
and fresh configs/caches or restart the client; existing authentication cannot
be invalidated by editing a CA file. `verify` supports booleans, not a CA-file
path. See [trust configuration](tls.md).

Cookie state, constructor TLS/pool/retry settings and registered hooks are the
supported persistent Session settings. Do not assume that assigning Requests-style
`session.headers`, `session.auth`, `session.params` or `session.proxies` merges
those values into each request: `Session.request()` currently uses its own
arguments for them. Pass them explicitly or wrap the calls in application code.

## Errors are not one normalized family

| Situation | Error / behavior |
| --- | --- |
| Invalid method, scheme, params or data | Relevant validation exceptions, also some `ValueError` / `AttributeError` paths |
| HTTP 4xx/5xx | Returned normally unless `raise_for_status()` raises `HTTPError` |
| Retryable status exhausted with `raise_on_status=True` | `MaxRetriedException`; final response remains on `session.response` |
| Replaying an uncached stream | `StreamConsumedError` |
| Invalid/truncated compressed stream | `ContentDecodingError` |
| TLS handshake/authentication failure | TLS exceptions or the transport's connection failure |
| Socket failure/read timeout/truncated body | May expose `OSError`, `socket.timeout`, `EOFError`, or protocol-layer errors |

`RequestException` is the base for the public request/TLS/streaming exceptions,
but `MaxRetriedException` directly inherits `RuntimeError`. The exported
`Timeout` and `ConnectionException` classes do not mean every transport error is
converted into those types. Catch errors at the actual operation boundary,
including inside a streaming loop, and preserve the original failure cause.

```python
from ja3requests import HTTPError, MaxRetriedException, RequestException

def fetch_status(session, url):
    try:
        response = session.get(url, timeout=(3, 10))
        response.raise_for_status()
        return response.status_code
    except HTTPError as error:
        return error.response.status_code
    except (RequestException, MaxRetriedException, OSError, EOFError):
        raise
```

This illustrates the distinction; it is not an exhaustive normalization wrapper.
The [generated exception reference](api/response.md) also includes the lower-level
socket and proxy classes.
