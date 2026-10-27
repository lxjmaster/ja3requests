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
| Read timeout policy | `legacy` | Assign `session.read_timeout_policy = 'phase'` for unlimited read-side `None` |
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

Cookie state, constructor TLS/pool/retry settings and registered hooks are
persistent Session settings. Do not assume that assigning Requests-style
`session.headers`, `session.auth`, `session.params` or `session.proxies` merges
those values into each request: `Session.request()` currently uses its own
arguments for them. For headers/params, version 2.6.0 adds the explicit
opt-in API below; other fields remain per-request.

## Opt-in request defaults

This API is available starting with **2.6.0**.
Assign `request_defaults` on either `Session` or `AsyncSession`. It starts as
`None`; `None` or `{}` clears it. There is no constructor argument. Only
`headers` and `params` are accepted, and each field opts in independently.

```python
from ja3requests import Session

def fetch_page(url):
    with Session(use_pooling=False) as session:
        session.request_defaults = {
            "headers": {"X-Client": "worker"},
            "params": [("tag", "a"), ("tag", "b"), ("page", "1")],
        }
        response = session.get(
            url, headers={"x-client": "caller"},
            params=[("tag", "x"), ("tag", "y")], timeout=3,
        )
        return response
```

The example sends one `X-Client: caller` field and appends
`page=1&tag=x&tag=y` after any existing URL query.

| Per-request input | Configured headers | Configured params |
| --- | --- | --- |
| Omitted or `None` | Library headers, overlaid by configured headers | Configured ordered pairs |
| Nonempty mapping / pairs | Explicit headers overlay library + configured headers, ignoring name case | Explicit keys remove all matching default pairs; remaining defaults precede all explicit pairs |
| Empty supported value | `{}` bypasses configured headers; sync still adds library headers, async does not | `{}`, `[]`, `()`, `''`, `b''` bypass configured params |
| Raw `str` / `bytes` query | Not a header mapping | Bypasses configured params; native query encoding applies |

Default header values may be text, bytes or numbers. Default params must be a
string-to-string mapping or an ordered sequence of two-string pairs; duplicates
and order are retained. Explicit query inputs keep the existing encoding:
sync does not expand mapping list values, while async does. A bytes key is
distinct from a string key when replacing defaults. URL query keys are never
removed by this merge.

Assignments copy and validate all fields before replacement. The getter returns
a detached snapshot; editing it or the original input does not change the
configuration. Unknown fields and invalid types raise `TypeError`; duplicate
case-insensitive default header names, forbidden names and invalid header syntax
raise `ValueError`. `Authorization`, `Proxy-Authorization`, `Cookie`, `Host`,
`Content-Length` and `Transfer-Encoding` are forbidden in defaults. Keep these
in the existing auth, Cookie and explicit request APIs. Other custom values
remain application-managed and apply to every initial destination on the Session.

Defaults merge once before initial preparation. `before_request` may remove an
optional field with `request.headers.pop("X-Client", None)`; retries and redirects
do not merge again. No `None`-as-deletion syntax is provided. Async
`prepare_request()` captures defaults when awaited, and `send()` uses the prepared
snapshot even after configuration changes. Standalone sync prepared sends do not
apply Session defaults. Async coroutines capture defaults when execution begins,
before the first await; creating a coroutine does not capture them. Synchronize
sync configuration assignments with concurrent requests, as with other Session
configuration. Legacy Session observations never become defaults.

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
