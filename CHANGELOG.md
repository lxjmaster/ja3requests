# Release Notes

## 2.0.1 — explicit TLS wire control

- Honor configured Session IDs, reject unsupported compression and conflicting
  extension declarations before sending TLS bytes, and support exact extension
  ordering and inspection of the actual sent ClientHello/JA3.
- Add opt-in TLS 1.3 P-384, including HelloRetryRequest and fragmented reads.
  Secure defaults and historical preset initial key shares remain unchanged.
- Add an explicitly selected Chrome 154 supported-subset profile, calibrated
  against a retained browser capture. It has a different JA3 and does not claim
  complete browser impersonation; ECH and post-quantum groups are not implemented.
- Validate TLS 1.3 Session ID echoes on direct and retried handshakes, require
  record version 0x0303 on retry, and reject unimplemented PSK exchange modes.
- Keep the client TLS protocol project-owned. Cryptography supplies primitive
  operations; OpenSSL is used only as the independent TLS test server.

Compatibility: invalid custom configurations that were previously ignored or
accepted now fail early. TLS 1.3 initial record versions are 0x0301/0x0303;
TLS 1.2 also permits 0x0302. Custom PSK exchange modes must be `[1]`.
See [the wire-control contract](docs/tls_wire_control.md) for supported fields,
protocol constraints and browser-profile differences.

## 2.0.0 candidate — secure TLS defaults

This is a development candidate, not a package publication announcement.

### Breaking changes

- `TlsConfig()`, implicit Sessions, factory Sessions and module-level requests
  now verify server certificates. They prefer TLS 1.3, allow TLS 1.2
  ECDHE/AES-GCM fallback and offer HTTP/1.1 ALPN by default.
- Untrusted, expired and wrong-host certificates fail before HTTP is sent.
  Trust private services through `SSL_CERT_FILE`; disabling verification does
  not establish private trust. There is no automatic insecure retry.
- Cipher, group, ALPN and extension defaults change ClientHello/JA3 fingerprints.
  The default profile is not a browser impersonation preset.
- `from_browser()` retains preset wire settings but now verifies certificates.
  Mutating browser/custom builders retain their source configuration's
  verification and extensions; a default source now inherits secure settings.
- Direct protocol handshakes without an explicit configuration also select
  secure defaults. Low-level `ClientHello` remains a wire encoder.

### Compatibility

- `TlsConfig.secure()` explicitly selects the new default profile.
- `TlsConfig.legacy()` pins the 1.x TLS 1.2 RSA/AES-CBC offer, empty group/ALPN
  lists and disabled certificate verification. Verification can be enabled
  independently on that profile.
- Explicit request `verify=True`/`False` still overrides the selected profile
  for that request and its redirects, without changing Session defaults.
- Cookie persistence and protocol features delivered by T01–T04 are retained.
  TLS session persistence, server push and 0-RTT remain unsupported.

See [the migration guide](docs/tls_defaults_migration.md) for trust setup,
hostname/SNI rules, legacy services and fingerprint compatibility.
