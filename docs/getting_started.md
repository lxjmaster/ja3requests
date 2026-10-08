# Getting started

## Install the intended version

The package declares Python 3.7 or later. A particular source checkout's local
tests do not establish every supported interpreter's CI result.

For the version described by these guides:

```sh
python -m pip install 'ja3requests==2.2.0'
```

For source development, install the checkout into an isolated environment:

```sh
python -m venv .venv
.venv/bin/python -m pip install -e .
```

The documentation builder has separate optional dependencies and requires a
newer interpreter; see [building these docs](contributing_docs.md).

## Make a verified request

```python
import ja3requests

response = ja3requests.get("https://example.com/", timeout=5)
response.raise_for_status()
print(response.status_code)
print(response.text)
```

This example contacts an external service. The [local example](examples.md)
runs without an Internet service. `timeout=5` supplies connect and read limits;
omitting the argument leaves blocking operations without an explicit limit.
Successful HTTP transport does not automatically reject a 4xx or 5xx status:
call `raise_for_status()` if those responses should raise `HTTPError`.

`params` sets query parameters, `data` sends form/raw data, and `json` encodes a
JSON value. Supply request headers through the request argument:

```python
from ja3requests import Session
from ja3requests.pool import ConnectionPool

with Session(pool=ConnectionPool()) as session:
    response = session.post(
        "https://example.com/api",
        json={"name": "demo"},
        headers={"Accept": "application/json"},
        timeout=(3, 10),
    )
    response.raise_for_status()
    payload = response.json()
```

Use either `json` or `data`/`files` for one request. Multipart uploads are built
in memory; they are not incremental uploads. A dedicated pool makes the
Session's close boundary explicit. Read [Sessions and pools](sessions.md) before
sharing clients or pools.

## Read a large response incrementally

```python
from ja3requests import Session
from ja3requests.pool import ConnectionPool

with Session(pool=ConnectionPool()) as session:
    with session.get("https://example.com/archive", stream=True, timeout=10) as response:
        response.raise_for_status()
        received = 0
        for chunk in response.iter_content(chunk_size=65536):
            received += len(chunk)
        print(received)
```

Starting with 2.1.0, `stream=True` returns after headers
and `iter_content()` consumes network data incrementally. Version 2.0.1
buffered the response even with this flag. Iteration does not retain a replay
cache; see [streaming responses](streaming.md) before accessing `.content` after
iteration or abandoning a response early.
