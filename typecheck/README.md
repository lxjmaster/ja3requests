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
include 70 negative markers: async additions reject synchronous pools, incorrect
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
python -m mypy ja3requests
```

That command can report existing dynamic-state, optional-value, and override
diagnostics in protocol internals and mutable compatibility classes. It is not
the public-consumer acceptance gate. JSON results intentionally remain `Any`;
request JSON input matches the current `dict`/`str`/`bytes` implementation. Upload
values in the synchronous API are paths or binary file objects (optionally lists),
not the filename/file tuple convention of other HTTP clients. Raw `data=` uploads
accept binary files and byte iterators in both APIs, with async iterators also
supported by AsyncSession. Async `files=` has the same
mapping convention and also accepts `PathLike[str]` values.
