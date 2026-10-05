# TLS Defaults Migration Guide

This guide describes the breaking defaults migration released in 2.0.0 (T05 of
[the development plan](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/issues/next_development_plan.md)) and retained in the
published [2.0.1 release](https://github.com/lxjmaster/ja3requests/releases/tag/v2.0.1).
`TlsConfig()` and implicit Session/module-level configurations select the secure profile and
verify server certificates. `TlsConfig.legacy()` pins the 1.x behavior.

The [interoperability matrix](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/secure_profile_matrix.md) records tested
combinations and peer capability limits, with dated historical evidence kept
separate from the current release. The 2.0.1 release passed the configured
Python 3.7–3.13 CI gates; older-peer skips remain explicit limitations. Installed
1.x releases retain their own defaults and may not expose every API below.

## 1. Choose a profile

| Setting | 1.x defaults / `TlsConfig.legacy()` | 2.0 defaults / `TlsConfig.secure()` |
| --- | --- | --- |
| Certificate verification | Disabled | Enabled |
| TLS negotiation | TLS 1.2 | TLS 1.3 with authenticated TLS 1.2 fallback |
| Cipher suites | `0x002F`, RSA/AES-128-CBC/SHA-1 | TLS 1.3 AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305; TLS 1.2 ECDHE-RSA/ECDHE-ECDSA AES-128/256-GCM |
| Named groups | No configured list | X25519 and P-256; both initial TLS 1.3 key shares |
| ALPN (application protocol negotiation) | No configured list | `http/1.1`; HTTP/2 can be selected explicitly |
| GREASE | Disabled | Disabled |
| TLS 1.2 extended master secret | No configured extension | Offered |

Version 2.0.1 adds P-384 through explicit configuration, including
HelloRetryRequest. It does not change the default groups or initial key shares
shown above. See the [wire-control guide](tls_wire_control.md) for the opt-in
configuration and independently verified paths.

For a verified service:

```python
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

config = TlsConfig.secure()
config.validate(strict=True)
with Session(tls_config=config, pool=ConnectionPool()) as session:
    response = session.get("https://example.com/", timeout=5)
    print(response.status_code)
```

The dedicated pool is closed when this context exits. A Session using the shared
default pool does not close that shared pool on exit. Configure a profile before
starting requests; connection reuse can otherwise retain an earlier handshake.

The factory and module-level APIs also accept an explicit configuration:

```python
import ja3requests
from ja3requests.pool import ConnectionPool

with ja3requests.session(
    tls_config=ja3requests.TlsConfig.secure(), pool=ConnectionPool()
) as session:
    response = session.get("https://example.com/", timeout=5)

response = ja3requests.get(
    "https://example.com/", tls_config=ja3requests.TlsConfig.secure(), timeout=5
)
```

Module-level `request`, `get`, `post` and the other convenience methods internally
create a Session. An explicit request `tls_config` selects that request's profile.
In 2.0, omitting it selects the secure configuration in all these entry points.
Direct `TLS.set_payload()` or `TLS.handshake()` without configuration also uses
secure defaults, even if the ClientHello body was inspected beforehand.
`ClientHello` itself remains a wire encoder, not a certificate policy API.
Plain `http://` traffic has no TLS certificate or ALPN negotiation.

## 2. Prepare certificates and private trust

For verified HTTPS, the service must supply a valid server certificate and the
intermediates needed to build a chain to a locally trusted root. The certificate
must be in its validity period and contain the destination in its Subject
Alternative Name (SAN). A DNS URL needs the DNS name; an IP URL needs the matching
IP address entry. RSA and P-256 ECDSA server certificates have representative
secure-profile evidence in the matrix.

The request API supports boolean `verify`; it has no CA-bundle path argument.
Do not use `verify="/path/to/ca.pem"`, `config.ca_certs` or a Requests-style
`REQUESTS_CA_BUNDLE` setting as a substitute. This implementation obtains trust
anchors through `ssl.create_default_context().get_ca_certs(binary_form=True)`.
The private verifier's `ca_certs` argument is not exposed by Session requests.

To add a private CA using the tested file route, configure `SSL_CERT_FILE` before
requests start. Supply a PEM bundle containing the intended CA roots. If the
application needs public and private roots from that file, prepare a combined
bundle; do not assume setting a private file preserves the usual default file.
Other default trust sources can still depend on the Python/OpenSSL installation.

```python
import os
from pathlib import Path

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

ca_bundle = Path("/path/to/private-ca-bundle.pem").resolve(strict=True)
os.environ["SSL_CERT_FILE"] = str(ca_bundle)
with Session(tls_config=TlsConfig.secure(), pool=ConnectionPool()) as session:
    response = session.get("https://service.internal/", timeout=5)
```

This environment setting affects the process, not just the Session. Set trust
before creating clients and keep it stable during requests. The current pool
and TLS cache do not bind entries to the contents of this environment-selected
bundle. After changing trust, restart the client process or use fresh dedicated
pools and fresh TLS configurations/caches so an old connection or resumed session
does not retain an earlier authentication decision.

### Self-signed certificates

A server-supplied self-signed certificate is not automatically trusted, even if
the server sends it as a root. For local or private services, the verified path
is to explicitly trust a private CA root (which may itself be self-signed) in
the bundle and serve a CA-issued leaf with the required SAN and server usage.
The test fixtures use this layout without installing trust on the host.

Arbitrary self-signed server leaf certificates used directly as trust anchors
have no passing result in this guide's evidence. Merely putting one in the PEM
file does not establish that its constraints satisfy the verifier. Reissue it
under a trusted private CA for the demonstrated setup. Adding trust never fixes
an expired certificate or a wrong destination name. `verify=False` skips the
certificate checks; it is not a custom-trust configuration.

## 3. Keep destination identity separate from SNI

SNI (Server Name Indication) chooses the server's virtual TLS service. By default,
the URL destination supplies it for each connection; this does not mutate the
Session configuration. Setting `config.server_name` overrides the SNI value.
Certificate identity is still checked against the URL destination, including
when an HTTP CONNECT or SOCKS proxy provides the transport. The HTTP `Host`
header also does not override the certificate identity.

```python
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

config = TlsConfig.secure()
config.server_name = "route.internal"
with Session(tls_config=config, pool=ConnectionPool()) as session:
    response = session.get("https://service.internal/", timeout=5)
```

This requires a certificate valid for `service.internal`, and the server must
route SNI `route.internal` to that service. Connecting to `https://127.0.0.1/`
with a DNS SNI override still requires `127.0.0.1` in the certificate's IP SAN.

## 4. Handle legacy servers explicitly

First try `secure()`: it already falls back to a TLS 1.2 ECDHE/AES-GCM server.
A server supporting only the old RSA/AES-CBC suite needs a different explicit
configuration. `TlsConfig.legacy()` pins that old offer and disables certificate
verification. Enable verification separately when retaining that cipher offer:

```python
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

config = TlsConfig.legacy()
config.verify_cert = True
with Session(tls_config=config, pool=ConnectionPool()) as session:
    response = session.get("https://legacy.internal/", timeout=5)
```

This retains TLS 1.2 and `0x002F`; it does not gain the secure profile's cipher
offer or forward secrecy. The certificate still needs trusted roots and the
correct identity. Removing the `verify_cert` assignment restores the complete
legacy authentication setting. Neither profile automatically retries a failed
verified handshake with certificate verification disabled. Disabling verification
also does not add a missing cipher suite or key exchange group.

## 5. Understand request overrides and redirects

| Request argument | Effective certificate verification |
| --- | --- |
| Omitted or `verify=None` | Inherit the selected request/Session TLS configuration |
| `verify=True` | Enable for this request |
| `verify=False` | Disable for this request |
| `tls_config=another_config` | Select that request's configuration; an explicit `verify` then overrides it |

```python
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

with Session(tls_config=TlsConfig.legacy(), pool=ConnectionPool()) as session:
    response = session.get("https://legacy.internal/", verify=True, timeout=5)
    assert session.tls_config.verify_cert is False
```

Changing `verify` copies the request configuration and preserves the selected
configuration's thread-safe cache; it does not mutate the Session setting. The
effective TLS configuration is carried through redirects. Consequently, `verify=False` also
applies to redirected HTTPS destinations; use `allow_redirects=False` when an
exception should apply only to the original request. An HTTPS-to-HTTP redirect
has no TLS authentication; applications requiring HTTPS throughout must control
redirect destinations. Existing tests cover override isolation, redirects and
rejection of unverified connection reuse after a verification upgrade.

## 6. Review HTTP mode and fingerprints

The secure profile offers HTTP/1.1 by default. To offer HTTP/2 with HTTP/1.1
fallback, set ALPN before constructing the Session:

```python
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

config = TlsConfig.secure()
config.alpn_protocols = ["h2", "http/1.1"]
config.validate(strict=True)
with Session(tls_config=config, pool=ConnectionPool()) as session:
    response = session.get("https://example.com/", timeout=5)
```

HTTP/2 is used when the peer negotiates `h2`; otherwise the implementation uses
HTTP/1.1. HTTP/2 responses can share a pooled connection concurrently. The
[matrix](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/secure_profile_matrix.md#explicit-http2-cases) records the
selected secure HTTP/2 combinations; it does not prove every possible cipher,
certificate or group permutation. Server push remains disabled.
In published 2.0.1, even `stream=True` buffered response bodies before
`iter_content()` yielded chunks. Version 2.1.0 implements
incremental network consumption, explicit response ownership and single-use
uncached iteration. See the [streaming guide](streaming.md) for that
behavior; this does not change the published 2.0.1 acceptance record below.

Changing profiles changes the ClientHello cipher and extension lists and thus
the JA3 fingerprint. ALPN, supported groups, SNI presence and additional
extensions can change it too. A destination-specific preview is available:

```python
from ja3requests import TlsConfig

secure = TlsConfig.secure()
legacy = TlsConfig.legacy()
print(secure.get_ja3_string(server_name="example.com"))
print(legacy.get_ja3_string(server_name="example.com"))
assert secure.server_name is None
```

The preview describes the prepared ClientHello for that configuration. A
resumed handshake can add ticket/PSK extensions; compare the actual traffic if
that distinction matters to a consumer. TLS 1.3 uses the legacy version field
in this ClientHello, so JA3's version field alone does not identify the negotiated
TLS version. Changing key-share contents does not necessarily change a JA3 string
because that string does not include every extension payload.

The secure profile is not a browser impersonation preset. If an application
depends on a browser/custom fingerprint, retain its explicit configuration and
make its verification policy explicit as well:

```python
from ja3requests import TlsConfig

config = TlsConfig.from_browser("chrome", version=120)
config.verify_cert = True
```

The `from_browser()` factory keeps the preset's explicit wire settings and now
verifies certificates. The mutating `create_chrome_config()`,
`create_firefox_config()` and `create_custom_config()` methods keep the source
configuration's verification and extensions. Starting them from `TlsConfig()`
therefore inherits secure verification and the extended-master-secret extension;
start from `TlsConfig.legacy()` and set `verify_cert` explicitly if the old
extension offer is required. No builder claims exact browser behavior for all
handshakes or broadens the interoperability evidence.

The explicitly selected `from_browser("chrome", 154)` profile added in 2.0.1 is
a capture-calibrated supported subset with a different JA3 from the captured
browser. ECH and post-quantum groups are not implemented, and implicit Chrome
selection remains version 124. The [wire-control guide](tls_wire_control.md)
lists the exact differences and the API for inspecting sent ClientHello records.

## 7. Version 2.0 breaking-release policy and acceptance

The published 2.0.0 release switched implicit configuration to the secure profile;
2.0.1 retains that policy.
`legacy()` remains the compatibility entry point, `secure()` stays explicit,
and request verification overrides keep their scope. Authentication rejection
never silently retries with verification disabled. See
[the release notes](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/CHANGELOG.md).

The completed migration's acceptance criteria remain regression requirements:

- `TlsConfig()`, `Session()`, `ja3requests.session()` and all module-level request
  methods have consistent implicit verification, cipher, group and ALPN settings.
  Sessions created with an explicit config retain it; overrides retain their
  documented scope. Inspect direct protocol use without a config separately.
- Profile construction keeps `secure()` and `legacy()` from recursing
  through constructor defaults or inheriting unintended settings. Browser
  and custom builders that call the constructor retain their explicit
  wire settings, with their verification policy documented.
- Verified TLS 1.3 and TLS 1.2 fallback work for the selected release matrix.
  Wrong identity, expired/untrusted chains and bad authentication fail before
  application requests, on HTTP/1.1 and the selected HTTP/2 connection paths.
- Explicit legacy opt-in, custom CA trust, verification overrides, redirects,
  pool separation and resumption policy pass the relevant checks. A fresh secure
  request cannot reuse a connection authenticated under incompatible settings.
- Record results for the Python/OpenSSL environments selected for that release.
  Resolve or explicitly narrow unsupported environments before advertising a
  broader support claim; local results alone do not establish remote CI success.
- Update constructor/profile tests, installed-wheel checks, version/release notes,
  both READMEs and the migration guide together. Describe the certificate
  rejection, cipher compatibility, ALPN and fingerprint changes to callers.

Applications can migrate by selecting `secure()` or pinning `legacy()`,
supplying the intended trust bundle, and checking their own service and
fingerprint requirements against the recorded matrix. T03 provided the preparation guide; T05 implements the selected 2.0 defaults.

## Evidence and validation

Behavior references: [profile and JA3 tests](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/test_tls_config.py),
[request/redirect policy tests](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/test_verify_config.py),
[certificate and proxy tests](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/integration/test_certificate_verification.py),
and the [T02 matrix](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/secure_profile_matrix.md). The 2.0.1 release readback
on 2026-10-04 confirmed merge/tag source `a291ef30bb6ae53cf38b3d79604c8f34e1865547`,
ten successful CI checks, and matching published artifact hashes on
[PyPI](https://pypi.org/project/ja3requests/2.0.1/) and
[GitHub](https://github.com/lxjmaster/ja3requests/releases/tag/v2.0.1).
Its installed-wheel selection passed 1517 tests and 112 subtests with 89.09%
statement coverage; see [the test notes](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/README.md) for exclusions and
historical evidence. This is release evidence, not a test result for later changes.

The T01 full run and T02 added cases provided the earlier protocol baseline used
during T03. [T04 Cookie persistence](cookie_persistence.md) retains its separate
historical installed-wheel result. The following T03 record also remains historical.

Recorded on 2026-10-01: all nine Python snippets passed syntax checks using the
Python 3.7 grammar on the local Python 3.13 interpreter, and their configuration
code executed successfully. Eight request preparations passed with captured
transport; the placeholder CA path resolution was stubbed. Snippet formatting,
relative-link/anchor checks and `git diff --check` passed. The 137 Python source,
test and example files matched the pre-T03 hashes; no protocol suite was rerun.
This syntax check is not a Python 3.7 runtime result.

The placeholder URLs and CA path must be replaced with the application's service
and trust inputs. These preparation checks do not claim live handshake results
for those services or validate the contents of an application-supplied CA file.
