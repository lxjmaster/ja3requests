# Pools, retry, and Cookies API

## Connection pools

Pool limits govern retained connections; sharing a dedicated pool also shares
its close boundary. See [Sessions and pools](../sessions.md).

::: ja3requests.pool.ConnectionPool
    options:
      docstring_style: google
      members:
        - close_all

## HTTP retry policy

The [retry guide](../request_policy.md) explains retry counts, default methods,
status exhaustion, numeric Retry-After and streaming failure boundaries.

::: ja3requests.retry.HTTPRetry

## Cookie jar

Use [Session Cookie APIs](client.md) to persist effective Session state.
The getter returns a snapshot. [Cookie-file persistence](../cookie_persistence.md)
documents the serialization format and validation.

::: ja3requests.cookies.Ja3RequestsCookieJar
    options:
      members:
        - get
        - set
        - get_dict
        - set_cookie
        - update
        - save
        - load
