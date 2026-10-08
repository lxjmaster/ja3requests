# Async Session, response and pool API

These APIs, introduced in 2.1.0, use native asyncio I/O with project-owned TLS/H2 state.
See [the async guide](../async.md) for body ownership, awaitable methods, strict
decoding, phase timeouts, cancellation and the borrowed-pool contract. The
synchronous API retains its existing behavior.

## AsyncSession

`data=` streaming sources and `files=` multipart are documented in the
[upload guide](../streaming.md#streaming-request-bodies). The Cookie-file
helpers are awaited; see [Cookie files](../cookie_persistence.md#native-async-files).

::: ja3requests.async_sessions.AsyncSession
    options:
      members:
        - request
        - get
        - post
        - put
        - patch
        - delete
        - head
        - options
        - save_cookies
        - load_cookies
        - aclose
        - tls_config
        - pool

## AsyncResponse

Response factories are transport adapters; application requests return a fully
initialized response. `status_code`, `headers`, `raw_headers`, `url` and `request`
are metadata attributes. `content` reads only an existing cache; use the
awaitable body methods or async iterators to receive data.

::: ja3requests.async_response.AsyncResponse
    options:
      members:
        - read
        - text
        - json
        - aiter_content
        - aiter_lines
        - aclose
        - content
        - encoding
        - cookies
        - closed
        - location
        - is_redirected
        - raise_for_status

## AsyncConnectionPool

An explicit pool is borrowed by its sessions. The owner must await `aclose()`
or use an async context after all borrowing sessions finish.

::: ja3requests.async_pool.AsyncConnectionPool
    options:
      members:
        - aclose

## Exceptions

The existing [exception classes](response.md#public-exceptions) are shared.
Async timeout expiry raises `Timeout`; caller cancellation remains
`asyncio.CancelledError`. Both eager and streaming decoding use the strict
`ContentDecodingError` contract.
