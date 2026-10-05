# TLS and fingerprints API

`TlsConfig.from_browser()` selects the repository's preset defaults when no
version is supplied; implicit Chrome remains 124. The explicit Chrome 154
profile is a supported subset, not complete browser impersonation. See
[fingerprints](../fingerprints.md) and [wire control](../tls_wire_control.md).

::: ja3requests.protocol.tls.config.TlsConfig

## Inspect actual ClientHello bytes

`TLS.sent_client_hellos` is available on the low-level connection TLS object and
records successful sends. `get_ja3_string()` is a fresh preview and does not
prove a connection resumed or reused the same hello.

::: ja3requests.protocol.tls.client_hello_info.inspect_client_hello

## In-memory session cache

Cache entries contain authentication and secret state. They are not included
in Cookie-file persistence. Configure the cache before starting requests.

::: ja3requests.protocol.tls.session_cache.TLSSessionCache
    options:
      members:
        - clear
