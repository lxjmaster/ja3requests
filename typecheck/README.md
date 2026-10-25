# Public typing acceptance

The package ships inline annotations and a PEP 561 `py.typed` marker. The public
facade covers top-level request helpers, `Session`, `Response`, `HTTPRetry`,
`TlsConfig`, Cookie jars, and connection pools. Native `AsyncSession`,
`AsyncResponse`, and `AsyncConnectionPool` include awaited methods, asynchronous
iterators, context managers, and synchronous/awaitable hook result types.
The existing dynamic protocol
implementation is not claimed to be fully type-clean.

Install the development checker with Python 3.9 or newer:

```sh
python -m pip install -r requirements-typing.txt
python -m mypy
```

The pinned checker supports property getters and setters with different types,
such as a `str` encoding getter that accepts `None` to reset automatic detection.
The library retains Python 3.7 syntax and runtime support. `TypedDict`, `Unpack`,
and `Literal` imports from `typing_extensions` occur only under `TYPE_CHECKING`;
no typing package is added to runtime requirements. These postponed annotations
serve static tooling, and are not a runtime `get_type_hints()` reflection API.

For local development, the explicitly labeled weaker source precheck is:

```sh
python typecheck/check.py --allow-source
```

Release acceptance must use a wheel installed in an independent environment:

```sh
python -m build --outdir /path/to/task-owned/dist
python -m venv /path/to/task-owned/wheel-env
/path/to/task-owned/wheel-env/bin/python -m pip install /path/to/task-owned/dist/ja3requests-VERSION-py3-none-any.whl
python typecheck/check.py --python /path/to/task-owned/wheel-env/bin/python
```

The script verifies package origin and the installed `py.typed`, probes imports
without permitting the library to import `typing_extensions` at runtime, and
copies both consumers to a temporary directory outside the repository. It
removes source lookup environment variables. `valid.py` must pass strict mypy,
including `assert_type` checks that catch an accidental `Any` return. Every
`# E:` line in `invalid.py` must produce its specific diagnostic; wrong URLs,
timeouts, streaming options, upload tuples, callback returns, TLS configuration,
Cookie values, and response return types are covered. The current consumers
include 130 negative markers: async additions reject synchronous pools, incorrect
awaited return types, invalid budgets/iterators, text files and unsupported file tuples.
Synchronous upload calls reject async iterators; async calls accept byte iterators
and async byte iterators. Async multipart paths include `PathLike[str]`.
Eight HPACK cases reject invalid codec inputs, header fields and table/header
limits.
The awaited Cookie-file methods preserve integer results and reject invalid paths,
option types and result assignments in installed consumers.
Prepared-request consumers check `Mapping[str, Union[str, bytes]]` inspection,
byte-value narrowing and header derivation. Preparation preserves byte values
and converts numeric values to strings. HTTP1 transmits bytes unchanged; H2
requires valid UTF-8 bytes. Protocol-specific encoding checks occur at send
after negotiation; shared field syntax checks occur before network/source work.
Temporary files are
removed on exit. The script never sends HTTP requests.

The checker uses `follow_imports = silent`, which loads imported inline types
while withholding diagnostics from implementation bodies. It does **not** use
`follow_imports = skip`, `ignore_errors`, or a global missing-import exemption.
The source gate strictly checks the aliases, top-level facade, retry policy,
HTTP/2 frame values, HPACK header and Huffman codecs, and the ClientHello
inspection schema.
The strict set also includes request-default validation and merging, for fifteen
source modules. Query-pair types preserve existing text-key, byte-key and mixed
list/tuple inputs, including homogeneous typed lists; string-only configured
default pairs keep their separate contract. Installed consumers cover those
query inputs across sync/async and buffered preparation, plus the concrete
string/byte dictionary return types of the header helpers.
Async phase-budget helpers and request exceptions are also strictly checked.
The internal task factory preserves coroutine result types and accepts coroutine
objects, matching `loop.create_task`; phase waits retain awaited result types.
Exception keyword metadata remains dynamic for existing sync/async and custom
request/response objects. The `phase` annotation describes the field attached
by async phase helpers; it does not add a value to manually constructed or
synchronous timeout exceptions. Internal helper examples verify these installed
annotations without establishing a new public helper API.
The utility module is now strictly checked too. Header helpers accept explicit
`None` options and retain byte-valued User-Agent and encoding-fallback inputs.
Basic/proxy credentials and encoding lists require text: nonempty byte
credentials already fail when encoded, and byte lists already fail at joining.
This corrects their earlier `AnyStr` signatures without introducing coercion.
Cookie conversions preserve nullable Cookie values and the supplied jar subtype.
Legacy retry callbacks retain their result type together with the existing
integer-zero failure sentinel; forwarded callback argument types are not checked.
TLS session-cache entries and both ticket types are strictly checked. Cache
lookups retain their distinct optional entry types, binary session/secret
fields remain bytes, and expiry/age methods return bool/int. Empty or `None`
identities rejected by existing cache insertion guards remain accepted inputs.
TLS 1.2 ticket keyword metadata uses a checker-only schema; no optional typing
dependency is imported at runtime. This migration does not add persistence or
alter cache capacity, locking, expiry or authenticated resumption policy.
Cookie-file persistence is strictly checked too, preserving CookieJar and
text/PathLike paths, boolean options and integer counts. Checker-only views
describe existing stdlib private storage/locks and the floating-point expiry
clock; the narrow casts run only during type checking. Dynamic JSON records
still pass through the existing complete validation before Cookie construction.
Installed consumers check these internal helpers without establishing a public
API; eight negative cases reject invalid jars, paths, options and result types.
File format, atomic replacement and all-or-nothing loading are unchanged.
TLS crypto helpers and their logging dependency are strictly checked. Cipher
metadata and parsed ECDHE parameters use checker-only field schemas, including
the existing optional parse result. Key pairs retain EC/X25519 private-key
unions and byte-valued public keys/secrets. PRF digest inputs retain the stdlib
HMAC name, factory and module forms; selected suite hashes remain callable.
Checker-only casts describe the existing RSA input and curve/key relationships;
they add no runtime key validation or algorithm changes. Twelve negative
consumer cases cover bytes, suite IDs, keys, parsed fields, digest and log inputs.
The protocol modules are an incremental internal migration, not a claim that
the full connection and TLS implementation is type-clean. Installed consumers
also check precise protocol-value return types and eleven invalid protocol uses.
HPACK consumers preserve iterable string/bytes header inputs, distinct encoder
value representations, and the decoder's string-pair results without widening
those boundaries to `Any`.
The header encoder accepts UTF-8 text: byte-valued names and values must decode
as UTF-8, and strings must be UTF-8 encodable. Invalid text raises `ValueError`
before any table state changes. This is a text-header API restriction, not an
HPACK wire-format requirement; the lower-level `encode_string`/`decode_string`
primitives continue to preserve arbitrary bytes.
To inspect the non-gating internal migration backlog explicitly:

```sh
python -m mypy ja3requests/
```

That command can report existing dynamic-state, optional-value, and override
diagnostics in protocol internals and mutable compatibility classes. The Public
typing workflow also runs it in a separate `continue-on-error: true` step, so
existing internal diagnostics remain visible without blocking the job. The
configured strict source check and installed positive/negative consumer checks
remain required; a successful job does not mean the full package is type-clean.
JSON results intentionally remain `Any`;
request JSON input matches the current `dict`/`str`/`bytes` implementation. Upload
values in the synchronous API are paths or binary file objects (optionally lists),
not the filename/file tuple convention of other HTTP clients. Raw `data=` uploads
accept binary files and byte iterators in both APIs, with async iterators also
supported by AsyncSession. Async `files=` has the same
mapping convention and also accepts `PathLike[str]` values.
