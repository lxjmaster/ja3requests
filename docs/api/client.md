# Requests and Session API

These sections are generated from the source checkout's actual signatures and
docstrings at build time. The guides document precedence and implementation
boundaries where a short docstring is insufficient.

This page covers the synchronous client. Native async classes have their own
[generated reference](async.md) and [guide](../async.md).

## Module entry points

::: ja3requests
    options:
      members:
        - session
        - request
        - get
        - post
        - put
        - patch
        - delete
        - head
        - options

## Session

`close()` closes an explicit dedicated pool; the shared default pool remains
available. Common request options such as `stream`, `allow_redirects` and
request-level `hooks` are forwarded through `**kwargs`. See
[Sessions](../sessions.md), [configuration](../configuration.md) and
[request policy](../request_policy.md) for the behavior of each option.
`data=` upload sources accept binary files and byte iterators over
HTTP/1.1 and H2. See [uploads](../streaming.md#streaming-request-bodies)
for source ownership, framing and retries; synchronous `files=` remains buffered.

::: ja3requests.sessions.Session
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
        - close
        - save_cookies
        - load_cookies
        - cookies
        - response
        - tls_config
        - pool
      inherited_members:
        - cookies
        - response
