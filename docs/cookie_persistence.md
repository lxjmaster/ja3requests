# Opt-in Cookie File Persistence

Cookie files persist HTTP authentication and preference state across process
restarts. Saving and loading are explicit operations; Session construction and
context exit do not read, save or delete any Cookie file.

## API and defaults

| Operation | Effect | Result |
| --- | --- | --- |
| `session.save_cookies(path, include_session=False)` | Save stored Session Cookies to the selected file | Number saved |
| `session.load_cookies(path, merge=False, include_session=False)` | Replace stored Cookies with the eligible file entries | Number loaded |
| `session.load_cookies(path, merge=True, include_session=False)` | Merge eligible entries, replacing only matching identities | Number loaded, not the final jar size |
| `jar.save(path, include_session=False)` / `jar.load(path, merge=False, include_session=False)` | The same operations on `Ja3RequestsCookieJar` | Number saved/loaded |

`path` is a string or `Path` pointing to a caller-selected file; its parent
directory must exist. There is no implicit filename or automatic persistence.
The Session operations support its default jar and a standard-library
`CookieJar` assigned through `session.cookies`. Assigning a dict instead of a
CookieJar is not supported by these file operations.

By default, Cookies with `discard=True` or no expiry are excluded on both save
and load. These are session/discard Cookies. Pass `include_session=True` to both
operations to restore them across application restarts. Their original flags
and absence of expiry are preserved; the option does not create a new lifetime.
Expired entries are always excluded, including when this option is enabled.

A Cookie's identity is `(domain, path, name)`. Identical names on different
domains or paths remain separate. Merge replaces a matching identity with the
file's entry; replace removes previously stored entries, including when an
otherwise valid file contains no eligible Cookies. Loading preserves the jar's
existing Cookie policy; policy objects are not serialized.

Session operations use the stored jar, not the aggregate returned by the
`session.cookies` getter. That getter produces a snapshot and can include
Cookies from the last request/response. Calling `session.cookies.load(...)`
therefore modifies a snapshot; use `session.load_cookies(...)` to affect future
requests. Transient per-request Cookies are not included in `save_cookies()`.

## Example

Create the application's private state directory before saving. After its usual
requests have acquired Cookies, save the stored jar:

```python
from pathlib import Path
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

path = Path("/path/to/private-app-state/cookies.json")
with Session(tls_config=TlsConfig.secure(), pool=ConnectionPool()) as session:
    # Run the application's authenticated requests here.
    saved = session.save_cookies(path)
```

In a later process, load before starting requests:

```python
from pathlib import Path
from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool

path = Path("/path/to/private-app-state/cookies.json")
with Session(tls_config=TlsConfig.secure(), pool=ConnectionPool()) as session:
    loaded = session.load_cookies(path)
    # Requests now use the restored jar and its domain/path/Secure restrictions.
```

To retain an application-managed session login Cookie intentionally, pass
`include_session=True` to save and load. To keep unrelated stored entries while
importing a file, pass `merge=True` to load.

The [runnable example](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/examples/11_cookie_file_persistence.py) writes and
reloads a scoped demonstration Cookie without contacting a service:

```sh
python examples/11_cookie_file_persistence.py /path/to/private-app-state/demo-cookies.json
```

It requires a new destination to avoid replacing an existing application's
Cookie file and leaves the demonstration file for the caller to remove.

## Format decision and preserved state

The format is UTF-8 JSON with `format="ja3requests.cookies"`, `version=1`, and
a `cookies` array. Records retain all Cookie constructor fields: version, name,
value, port and its flag, domain and its specified/initial-dot flags, path and
its specified flag, Secure, expiry, discard, comment, comment URL, RFC 2109 flag,
and extension metadata (`rest`). `HttpOnly`, `SameSite` and other extension
attributes retain their values. A valueless Cookie retains `value=null`.

| Candidate | Local representative round trip | Decision |
| --- | --- | --- |
| Mozilla/Netscape standard-library file | Retained host-only and Secure, but lost `path_specified`, `HttpOnly`, `SameSite` and custom metadata in the Python 3.13 probe | Insufficient for the selected metadata contract |
| LWP standard-library file | Retained most scope fields, but changed `HttpOnly: None` to the string `"None"` | Suitable for exchange when those changes are acceptable; not selected here |
| Versioned JSON | Explicit fields and strict validation preserve the required flags and metadata | Selected for this API |

Comments and extension values support text, booleans, null and signed 64-bit
integers. Nested objects, arrays, floats, bytes and arbitrary Python objects are
not supported as metadata; saving such an eligible Cookie fails before replacing
the destination. Cookie protocol versions 0 and 1 are supported. Files are data,
not pickle state; CookieJar pickle compatibility is separate from this loader.

The file retains scope; it does not broaden it. Host-only Cookies remain limited
to the original host, domain Cookies retain their domain policy, paths still
restrict matching, and Secure Cookies remain excluded from HTTP requests. A
manually created Cookie with an empty domain was already unscoped and remains
unscoped after loading. Loading does not assign it a new origin.

## Validation and failure behavior

- Maximum file size: 1 MiB. Maximum number of records: 3000, before filtering.
  Loading reads at most the size limit plus one byte before parsing.
- Unknown schema versions/fields, duplicate JSON fields, duplicate normalized
  Cookie identities, invalid types/text, oversized integers, invalid UTF-8 and
  malformed JSON are rejected with `ValueError`.
- The entire input is validated before any jar mutation, even for merge or
  excluded entries. Invalid files leave existing Cookies unchanged.
- File access/write errors propagate as `OSError` subclasses. Missing files are
  not treated as an empty jar. Invalid boolean options or a non-CookieJar Session
  store raise `TypeError`.
- Save creates a temporary file in the destination directory, writes and flushes
  it, then atomically replaces the selected path. A failure before replacement
  preserves the existing destination and removes the temporary file. Atomic
  replacement is not a guarantee against data loss after a system power failure.

## File protection and retention

Cookie values can be login tokens. The file stores them in plaintext; it is not
encrypted. On POSIX, the temporary and resulting file use owner-only permissions
`0600`, including when replacing a more permissive file. Other operating systems
require caller-managed directory/file access controls; they are not locally
verified by this task. Keep the containing directory private and exclude this
file from source control, shared logs and unintended backups.

The caller owns retention: remove the file when the login is revoked or no
longer needed. Session closure leaves it intact. Expired entries are ignored on
load and omitted by the next save; expiry does not erase an older file by itself.
Multiple processes writing the same destination use last-replacement-wins
semantics. Serialize such writes in the application if updates must be combined.

Only Cookie records are persisted. Session locks, connection pools, TLS secrets,
cache entries and application configuration are not included.

## Verification

[File tests](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/test_cookie_files.py) cover a separate-process round trip,
host/domain/path/Secure filtering, duplicate names, nullable values and metadata,
session-Cookie opt-in, expiration, merge/replace, Session/standard CookieJar
integration, malformed input, size/count limits, failed atomic writes and POSIX
permissions. Existing [request Cookie tests](https://github.com/lxjmaster/ja3requests/blob/a291ef30bb6ae53cf38b3d79604c8f34e1865547/test/test_cookie_persistence.py)
are reused for response extraction and request filtering.

Recorded on 2026-10-01: 63 new file cases passed; the targeted selection passed
144 tests. The selected full suite passed 1362 tests from a freshly installed
wheel outside the source checkout, with 88.86% statement coverage and one existing
`TestContext` collection warning. All 58 package module hashes matched the source
snapshot. Black, error-level Pylint, syntax/link checks and the runnable example
passed. The wheel and full-run reports are retained in ignored `dist/t04/`;
task-created build/test staging, the demo file and generated certificate keys
were removed. Other Python/OpenSSL environments and remote CI remain unverified.
