

# Ja3Requests
[![Tests](https://github.com/lxjmaster/ja3requests/actions/workflows/test.yml/badge.svg)](https://github.com/lxjmaster/ja3requests/actions/workflows/test.yml)
[![Coverage](https://github.com/lxjmaster/ja3requests/actions/workflows/coverage.yml/badge.svg)](https://github.com/lxjmaster/ja3requests/actions/workflows/coverage.yml)
[![PyPI](https://img.shields.io/pypi/v/ja3requests.svg)](https://pypi.org/project/ja3requests/)

**Ja3Requests** is a http request library that can customize ja3 or h2 fingerprints.

TLS handshakes and records are implemented by this project; cryptographic
primitives use `cryptography`. See the [wire-control contract](docs/tls_wire_control.md)
for exact extension ordering, actual ClientHello inspection, opt-in P-384 and
capture-backed browser-profile limitations. Browser-inspired presets are not
a guarantee of complete browser impersonation.
The explicit `TlsConfig.from_browser("chrome", 154)` profile is a supported
subset with a different JA3 from the captured browser; ECH and post-quantum
groups are not implemented. Implicit Chrome selection remains at version 124.

[中文文档](README-zh.md)

```pycon
>>> import ja3requests
>>> session = ja3requests.Session()
>>> response = session.get("http://www.baidu.com/")
>>> response
<Response [200]>
>>> response.status_code
200
>>> response.headers
{'Content-Length': '405968', 'Content-Type': 'text/html; charset=utf-8', 'Server': 'BWS/1.1', 'Vary': 'Accept-Encoding', 'X-Ua-Compatible': 'IE=Edge,chrome=1', ...}
>>> response.text
'<!DOCTYPE html><!--STATUS OK--><html><head><meta http-equiv="Content-Type" content="text/html;char...'
```

Ja3Requests supports HTTP/1.1 over HTTP and HTTPS. HTTPS connections can also
negotiate HTTP/2 with ALPN. Version 2.0 defaults to verified TLS 1.3 with TLS 1.2 ECDHE/GCM fallback.
Version 2.2.0 release links: [PyPI](https://pypi.org/project/ja3requests/2.2.0/)
and [GitHub](https://github.com/lxjmaster/ja3requests/releases/tag/v2.2.0).
This release adds streaming request bodies, async multipart/files and async
Cookie-file helpers; see [release notes](CHANGELOG.md) for scope and limits.

## Installing Ja3Requests and Supported Versions

Ja3Requests is available on PyPI:

```console
$ python -m pip install ja3requests
```

Ja3Requests officially supports Python 3.7+.

## HTTPS Certificate Verification

Version 2.0 verifies server certificates by default. `TlsConfig()`, `Session()`
and module-level requests use the secure TLS 1.3/TLS 1.2 ECDHE-GCM profile.
The explicit secure profile remains available:

```python
import ja3requests

config = ja3requests.TlsConfig.secure()
with ja3requests.Session(tls_config=config) as session:
    response = session.get("https://example.com/")
```

The secure profile verifies certificates, offers only TLS 1.3 suites and TLS 1.2
ECDHE/AES-128/256-GCM suites, and uses HTTP/1.1 ALPN. It does not impersonate a browser.
Its TLS 1.3 ClientHello includes X25519 and P-256 key shares by default. To send
only X25519 initially while allowing a P-256 HelloRetryRequest, set
`config.key_share_groups = [29]` before creating the Session. Version 2.0.1 also
supports P-384 through explicit `supported_groups`/`key_share_groups`
configuration, including HelloRetryRequest. The secure defaults remain
`[29, 23]` (X25519/P-256); see the [P-384 configuration example](docs/tls_wire_control.md).
TLS 1.3 connections also process server KeyUpdate messages, including requests
to update the client sending key.
Session caches can resume TLS 1.3 connections with in-memory tickets and
PSK-DHE; 0-RTT is not supported.
TLS 1.2 connections can resume an in-memory Session ID, or a session ticket
when `SessionTicketExtension()` is configured. The original session must use
extended master secret and match the current certificate policy. Import the
extension from `ja3requests.protocol.tls.extensions`.
You can also enable verification for one request with `verify=True`.
For a destination-specific JA3 string, call
`config.get_ja3_string(server_name="example.com")` so the SNI extension is included.
A pooled session can run concurrent HTTP/2 requests, including requests with
bodies, on one TLS connection. Responses are matched by stream ID, and request
DATA respects the peer's frame size and connection and stream flow-control
windows. HTTP/1.1 connections remain serial.
Server push is disabled because pushed responses are not supported; an
explicit `SETTINGS_ENABLE_PUSH=1` configuration is rejected.
Legacy HTTP/2 PRIORITY signals are accepted but do not affect request scheduling.
Version 2.1.0 reads HTTP/1.1 and HTTP/2 response bodies
incrementally with `stream=True`, including project TLS record decryption and
gzip/deflate/Brotli decoding. Version 2.0.1 buffered the full body.
Close responses when stopping early; iteration does not retain a replay cache.
See [streaming and memory limits](docs/streaming.md) for ownership, decoding
errors, read timeouts and the distinction between chunk size and total memory.

An explicit `verify=True` or `verify=False` overrides the session setting for
that request, including redirects. `TlsConfig.legacy()` explicitly restores
the 1.x TLS 1.2 RSA/AES-CBC offer and disables certificate verification.
The new defaults change ClientHello/JA3 fingerprints and reject untrusted,
expired or wrong-host certificates. See the
[TLS defaults migration guide](docs/tls_defaults_migration.md) for private CA
trust, hostname/SNI behavior, request overrides, legacy-server setup, and the
2.0 compatibility changes. Browser preset factories retain their explicit
wire settings and now verify certificates; custom builders inherit the source
configuration's verification and extensions. See [release notes](CHANGELOG.md). The [secure-profile matrix](test/secure_profile_matrix.md)
records verified combinations and environment limits; [local protocol tests](test/README.md)
describe the underlying cases.

TLS 1.2 and TLS 1.3 client-certificate authentication use `client_cert` and
`client_key` when the server requests a certificate. Configured TLS 1.3 client
certificates do not use PSK ticket resumption. TLS 1.3 post-handshake client
authentication is opt-in: append `PostHandshakeAuthExtension()` to
`config.extensions` before creating a session. It uses the same certificate and
key settings; with no client certificate, it sends an empty Certificate message.
This extension changes the ClientHello fingerprint.

## How To Use

The [user guide and generated API reference](docs/index.md) cover configuration,
fingerprints, TLS, proxies, retries, hooks, cookies and connection pooling.
The [documentation build guide](docs/contributing_docs.md) explains how to build
and check the site locally. Version 2.1.0 also includes
[public type annotations](typecheck/README.md) and a packaged `py.typed` marker, a
[synchronous performance suite](bench/PERFORMANCE.md), and a
[task roadmap](issues/next_development_plan.md).

Version 2.1.0 provides native `AsyncSession`, `AsyncResponse` and
`AsyncConnectionPool`, retaining project-owned TLS/H2 with asyncio socket waits.
See the [async guide](docs/async.md) and
[runnable local async example](docs/examples/async_client.py).

```python
import asyncio
from ja3requests import AsyncSession

async def main():
    async with AsyncSession() as session:
        async with await session.get("https://example.com/data", stream=True) as response:
            response.raise_for_status()
            async for chunk in response.aiter_content(65536):
                print(len(chunk))

if __name__ == "__main__":
    asyncio.run(main())
```

For async full-body access use `await response.read()`, `await response.text()`
or `await response.json()`; `.content` reads only a completed cache. Both async
body modes reject invalid compression. Explicit async pools are borrowed and
must be closed by their owner after all sessions finish.

For an incrementally consumed response, keep its lifetime explicit:

```python
from ja3requests import Session
from ja3requests.pool import ConnectionPool

with Session(pool=ConnectionPool()) as session:
    with session.get("https://example.com/data", stream=True, timeout=(3, 10)) as response:
        response.raise_for_status()
        for chunk in response.iter_content(chunk_size=65536):
            print(len(chunk))
```

### Unreasonable Request Method
Ja3Requests supports multiple request methods such as Get, Post, Put, Delete, etc.
```python
import ja3requests

session = ja3requests.session()
# Get
session.get("http://example.com/")

# POST
session.post("http://example.com/")
...
```

### Use The Headers Attribute
```python
import ja3requests

headers = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Host": "example.com",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0"
}

session = ja3requests.session()

response = session.get("http://example.com/", headers=headers)
print(response)
```

### Use The Params Attribute
```python
import ja3requests

session = ja3requests.session()

params = {
    "page": 1,
    "page_size": 100
}
# OR
# params = "page=1&page_zie=100"
# OR
# params = [("page", 1), ("page_size", 100)]
# OR
# params = (("page", 1), ("page_size", 100))
response = session.get("http://example.com/", params=params)
print(response)
```


### Post Data
```python
import ja3requests

session = ja3requests.session()

data = {
    "username": "admin",
    "password": "admin"
}
# OR (Content-Type: application/x-www-form-urlencoded)
# data = "username=admin&password=admin"
# OR
# data = [("username", "admin"), ("password": "admin")]
# OR
# data = (("username", "admin"), ("password", "admin"))

response = session.post("http://example.com/", data=data)
print(response)
```


### Post Json

```python
import ja3requests

session = ja3requests.session()

data = {
    "username": "admin",
    "password": "admin"
}
# OR
# import json
# data = json.dumps(data)

response = session.post("http://example.com/", json=data)
print(response)
```


### Post Files

```python
import ja3requests

session = ja3requests.session()

with open("/user/home/demo.txt", "r") as f:
    response = session.post("http://example.com/", files={"field_name": f})
print(response)

# OR
# response = session.post("http://example.com/", files={"field_name": "/user/home/demo.txt"})

# multiple files
# response = session.post("http://example.com/", files={"field_name": ["/user/home/demo.txt", "/user/home/demo2.txt"]})
```


### Use the proxies attribute

```python
import ja3requests

session = ja3requests.session()

proxies = {
    "http": "127.0.0.1:7890",
    "https": "127.0.0.1:7890"
}

response = session.get("http://example.com/", proxies=proxies)
print(response)

# With Authorization information
# proxies = {
#     "http": "user:password@127.0.0.1:7890",
#     "https": "user:password@127.0.0.1:7890"
# }
```


### Use the cookies attribute

```python
import ja3requests

session = ja3requests.session()
cookies = {
    "sessionId": "xxxx",
    "userId": "xxxx",
}
# OR
# cookies = "sessionId=xxxx; userId=xxxx;...."
# OR
# cookies = <CookieJar()>

# Or set cookies in headers = {"Cookies": "sessionId=xxxx; userId=xxxx;...."}

response = session.get("http://example.com/", cookies=cookies)
print(response)
```


### Persist Cookies to a file

Use `session.save_cookies(path)` and `session.load_cookies(path)` for explicit
JSON persistence across process restarts. Loading replaces stored Cookies by
default; `merge=True` merges by domain/path/name. Session/discard Cookies require
`include_session=True` on both operations, and expired Cookies are always skipped.
Files can contain login tokens in plaintext and use `0600` permissions on POSIX.
See [Cookie file persistence](docs/cookie_persistence.md) for scope, format, limits,
failure behavior and the runnable example.

### Allow Redirects

```python
import ja3requests

session = ja3requests.session()

# Default allow_redirects=True
response = session.get("http://example.com/", allow_redirects=False)
print(response)
```


## Reference
- [HTTP](https://developer.mozilla.org/en-US/docs/Web/HTTP)
- [HTTP-RFC](https://www.rfc-editor.org/rfc/rfc2068.html)
- [TLS v1.1-RFC](https://datatracker.ietf.org/doc/html/rfc4346)
- [TLS v1.2-RFC](https://datatracker.ietf.org/doc/html/rfc5246)
- [TLS v1.3-RFC](https://datatracker.ietf.org/doc/html/rfc8446)
- [IANA Registry Updates for TLS and DTLS](https://datatracker.ietf.org/doc/html/rfc8447)
- [HTTP2-RFC](https://httpwg.org/specs/rfc9113.html)
- [SSL-CONFIG-GENERATOR](https://ssl-config.mozilla.org/)
- [SHA-256/384 and AES GCM](https://www.rfc-editor.org/rfc/rfc5289.html)
- [ECC Cipher Suites for TLS 1.2 and Earlier](https://www.rfc-editor.org/rfc/rfc8422.html)
- [TLS EXTENSIONS](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
