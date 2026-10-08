# Runnable examples

## A self-contained loopback example

From an installed source checkout:

```sh
.venv/bin/python docs/examples/loopback.py
```

[Download/view the script](examples/loopback.py). It binds only an OS-assigned
loopback port and shuts the server down before exiting. It demonstrates:

- A JSON request, status handling and response Cookie persistence.
- A controlled 503 response followed by a successful HTTP retry, with hooks.
- A streaming first chunk while the peer deliberately withholds the remainder.
- Incremental gzip/deflate/Brotli content and byte-line iteration.
- A Cookie-file round trip in its own automatically removed temporary directory.
- TLS/JA3 configuration previews without making an external HTTPS request.

The HTTP peer is a local demonstration. Its successful run does not establish
TLS, proxy or HTTP/2 interoperability; those paths have independent integration
tests and controlled performance peers. The script uses actual public APIs and
asserts the content and consumption behavior it demonstrates.

## Native async loopback example

From the current source checkout with its package installed:

```sh
.venv/bin/python docs/examples/async_client.py
```

[Download/view the async script](examples/async_client.py). It exercises native
async requests against an event-controlled HTTP peer on an OS-assigned loopback
port: awaited JSON/text, Cookies and an awaited file round trip, retries and an async hook, prefix-before-tail
streaming, gzip/deflate/Brotli, byte lines, caller cancellation and an explicitly
borrowed pool. It closes accepted connections, joins tasks and stops the server
before exiting. There are no external requests or retained files.

The [async guide](async.md) describes body caching, strict decoder failures,
timeouts and pool ownership. This HTTP demonstration is not TLS/H2 or supported
environment acceptance; those paths have their own integration tests.

## Streaming upload example

Run the streaming upload APIs against a loopback HTTP peer:

```sh
.venv/bin/python docs/examples/uploads.py
```

[View the upload script](examples/uploads.py). It checks sync/async binary files,
fixed and chunked framing, delivery of the first bytes before source EOF, and
async multipart fields with repeated files. A standard-library parser checks
the multipart body. Caller handles remain open; the temporary path fixture and
local server are cleaned up. This HTTP/1 example complements the independent
TLS/H2 and proxy integration tests; it does not establish those paths by itself.

See [upload ownership and replay](streaming.md#upload-replay-and-ownership) before
reusing a source across requests or enabling retries.

## Existing application examples

The repository's `examples/` directory includes basic requests, browser
configurations, Session Cookies, proxies, streaming, retries, hooks, HTTP/2,
mutual TLS and resumption. Service URLs and certificate/proxy paths in application
examples must be supplied by the caller; they are not a claim about a running
service or credentials.

The existing standalone Cookie example can be run without a service:

```sh
.venv/bin/python examples/11_cookie_file_persistence.py /path/to/new-demo-cookies.json
```

Its parent directory must exist and the destination must be new. Unlike the
loopback script's temporary fixture, this example intentionally retains the file
for inspection. [Cookie persistence](cookie_persistence.md) describes the format
and retention contract.

## Validate the site and snippets

```sh
.venv/bin/python -m mkdocs build --strict
.venv/bin/python docs/verify.py
```

The checker validates built internal links/anchors and required generated API
objects, checks all Python snippets for Python 3.7 syntax, then executes all three
loopback examples. Placeholder HTTPS and certificate snippets are syntax-checked,
not executed against unknown services. See [building these docs](contributing_docs.md).
