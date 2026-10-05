# Migrating from Requests

The familiar request verbs and response properties make small call sites easy
to adapt, but ja3requests is not a drop-in replacement for the entire Requests
transport and extension system.

This migration table covers the synchronous API. [Native async](async.md)
has separate body, redirect, timeout and pool ownership contracts.

```python
import ja3requests

response = ja3requests.get(
    "https://example.com/",
    params={"page": 1},
    headers={"Accept": "application/json"},
    timeout=(3, 10),
)
response.raise_for_status()
```

## Check each behavioral dependency

| Requests usage / assumption | ja3requests behavior / migration |
| --- | --- |
| `get/post/...`, `params`, `data`, `json`, `files` | Similar high-level entry points; request bodies are prepared in memory |
| `.status_code`, `.headers`, `.content`, `.text`, `.json()` | Available; `.headers` is a regular dictionary, and `.text` uses Content-Type's charset or UTF-8 with explicit `.encoding` override |
| Automatic status exceptions | Neither normal success path implies `raise_for_status()`; call it explicitly |
| `Session.headers/auth/params/proxies` merging | Pass these arguments on each request; the current Session request path does not merge those properties |
| `verify='/path/ca.pem'` / `REQUESTS_CA_BUNDLE` | Boolean `verify`; configure roots using `SSL_CERT_FILE` before creating clients |
| `cert=(cert_file, key_file)` | Use `TlsConfig.client_cert` and `TlsConfig.client_key` |
| `HTTPAdapter`, `mount`, urllib3 retry objects | No adapter compatibility layer; use `Session(retry=HTTPRetry(...))` |
| Environment proxies / `socks5h` | Explicit request `proxies`; supported SOCKS5 already sends the destination name to the proxy |
| `hooks={'response': ...}` | Use lists under `before_request` / `after_request`; callbacks accept one object |
| `iter_content(decode_unicode=True)` | This API yields bytes and has no `decode_unicode` argument |
| Re-reading a response after streaming iteration | Uncached iteration is single-use and raises `StreamConsumedError` on replay |
| Requests/urllib3 exception hierarchy | Catch ja3requests errors and actual protocol/OS errors as described in the error guide |
| Requests' exact redirect method/history behavior | Current redirect follow-ups use GET; do not assume Requests' 307/308 body replay or a compatible `history` API |
| Session close always owns the pool | Default pool is shared; supply a dedicated pool for Session-scoped shutdown |

The redirect implementation has a limit of eight and strips sensitive headers
on a cross-origin redirect. If an API relies on preserving a method/body across
307/308, set `allow_redirects=False` and implement its required policy explicitly.
HTTP status, TLS authentication and application authentication are separate
checks; a successful fingerprint match does not authenticate a server.

## Migrate TLS deliberately

`TlsConfig()` uses verified secure defaults. `TlsConfig.legacy()` preserves the
old TLS1.2 RSA/AES-CBC offer and disables verification unless explicitly changed.
A browser preset selects wire settings; it does not replace certificate policy
or guarantee complete browser impersonation.

Read [configuration and errors](configuration.md), [streaming](streaming.md),
[proxy support](proxies.md) and the [TLS migration guide](tls_defaults_migration.md)
for the exact differences relevant to the application. Start with the local
[runnable examples](examples.md) before using application credentials or private
services.
