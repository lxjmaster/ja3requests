# Local artifact verification

`verify_release.py` verifies ja3requests locally. It does not commit, stash,
change refs, push, upload, read publishing credentials, or deploy anything.
Use a Python **3.12+ tooling environment**; the library still supports Python
>=3.7. Install the tools there:

```sh
python -m pip install build twine -r requirements-typing.txt
```

## Explicit source identity

Verify a committed revision (a ref is resolved once to its exact full SHA):

```sh
python tools/verify_release.py --repo . --ref HEAD --output dist/verify-commit
```

Verify an uncommitted candidate without creating a commit:

```sh
python tools/verify_release.py --repo . --worktree-snapshot \
  --include tools/verify_release.py \
  --include tools/tests/test_verify_release.py \
  --include tools/README.md \
  --include .github/workflows/docs.yml \
  --output dist/verify-candidate
```

The modes are mutually exclusive. Snapshot mode takes current tracked file
bytes (including stable tracked deletions) and only explicitly named new files.
`--include` is repeatable and takes one repository-relative untracked regular
file, not a directory or glob. Add every new in-scope build/test input. It never
automatically takes untracked files. IDE state, caches/build outputs, local
release records, debug scripts, `.env`/publishing credentials and key files are
excluded; symlinks and submodules are unsupported. The selected paths/hashes,
Git tracked-file list and HEAD are checked before and after copying. Drift fails
the run. Exclusions apply to commit archives too.

Commit inspection disables Git replacement objects. The exported file inventory
and bytes are checked against the original commit tree/blob IDs, independently
of archive attributes. An `export-ignore` or `export-subst` rule that omits or
rewrites a selected file fails verification instead of changing the meaning of
the reported commit SHA. No repository attributes or replacement refs are edited.

Reports label commit mode `source_kind=commit` with `commit`; candidate mode is
`source_kind=worktree-snapshot` with all file hashes and a contextual `base_commit`.
A candidate pass is **not** acceptance of that base commit, a new release, or
permission to publish. A later release must verify its actual committed source
and separately observe exact-commit remote CI.

The output directory must not exist. Every attempt gets fresh owned temporary
staging and fresh retained evidence. `--timeout` bounds each pipeline command
(default 600 seconds); source Git inspection has a separate 60-second bound.
There is no automatic resume or overwrite mode.

## Checks and retained evidence

The common pipeline builds an sdist, then a wheel from that sdist, and performs:

- Strict Twine metadata checking (no upload), source-derived version/metadata,
  unchanged minimum-Python/dependency/license contracts, required source/test/
  fixture/typing files, empty `py.typed`, package inventories and byte equality.
- Wheel RECORD inventory/hash/size validation and every package module's Python
  3.7 grammar. Grammar acceptance is not the Python 3.7-3.13 runtime CI matrix.
- A fresh independent wheel installation from official PyPI dependencies,
  `pip check`, module origin/hash/version checks, secure defaults, async exports
  and HTTP/2 framing smoke checks.
- The frozen `typecheck/check.py` against the installed interpreter, with no
  `--allow-source`. Negative cases are counted from actual `# E:` markers, not
  pinned to a particular release's count.
- Tests copied from the accepted sdist into a directory without package source:
  `pytest test --ignore=test/test_session.py`, with >=85% statement coverage.
  Every copied `test/` file must exist byte-for-byte in the frozen source; extra
  test hooks, configuration or shadow packages in the sdist are rejected.

Source-lookup and pip/pytest/coverage overrides are removed from child command
environments. Runtime package requirements remain `brotli>=1.2.0` and
`cryptography>=42.0.0`; intentional compatibility changes require explicit
verifier-contract review. The verifier is project-specific, not a general
package publishing framework. Only run source/build/test code you trust.

`verification.json` records status, source identity/hashes, artifact SHA-256 and
sizes, inventories, command exit/timeout status, interpreter/tool versions,
installed origin, tests/subtests/skips/warnings and coverage. Command logs,
`source-manifest.json`, `installed.xml`, `coverage.json`, and built artifacts are
retained in the output directory when reached. Failed attempts retain their
available evidence and never become `passed`; unexecuted steps have no passing
entry. Owned staging is removed after evidence is saved, including on failure.
Each command also receives a fresh temporary root under the evidence directory
through `TMPDIR`, `TEMP` and `TMP`. The parent removes that root after reaping the
command, including on timeout or cancellation, so child tools' nested temporary
directories do not escape cleanup. Each command records `temporary_directory`
and the actual `temporary_cleaned` result; logs and artifacts remain retained.
Do not use the output as a source directory or include generated output files.

Documentation is a **separate full-history checkout gate**:

```sh
python -m pip install -e . -r docs/requirements.txt
python -m mkdocs build --strict
python docs/verify.py
```

The docs checker needs historical Git objects and real loopback examples; an
archive/sdist is not a substitute. See [the docs guide](../docs/contributing_docs.md).

## Tool regression tests

```sh
python -m pip install pytest packaging -r requirements.txt -r requirements-capture.txt
python -m pytest tools/tests -q
```

The existing Python 3.12 wheel CI job runs these focused fixture-based tests in
addition to its original wheel smoke. They remain outside the library's `test/`
runtime matrix; they do not build/install the entire project for every negative
case. Full artifact verification is run explicitly for the selected candidate.

## Real TLS and HTTP/2 fingerprint capture

For H2 control acceptance without Chrome, use the exact wheel from the local
verifier and its report. The independent `hpack` decoder checks HEADERS weights
256/183, dependency 0/exclusivity, `/pixel.png` insertion, the retained 20/21
table-entry difference and a third reused stream. Raw/Huffman and empty/excluded
policies run for both installed synchronous and native async clients:

```sh
python -m tools.verify_h2_controls \
  --wheel dist/release-2.4.0/final-candidate/artifacts/ja3requests-2.4.0-py3-none-any.whl \
  --wheel-sha256 <verified-wheel-sha256> \
  --artifact-report dist/release-2.4.0/final-candidate/verification.json \
  --client-profile chrome:154 \
  --output dist/release-2.4.0/h2-controls
```

The output must be new. This reuses the collector's TLS peer, artifact identity,
installed-origin checks and process cleanup. Reports, raw bytes and tool source
hashes are retained; temporary CA keys and installations are removed. The peer
exercises full TLS1.3/H2, not resumption or complete browser identity. Library
runtime dependencies are unchanged; tools use `requirements-capture.txt`.

`capture_fingerprint.py` is Python >=3.12 development tooling for the named
Chrome 155/macOS target. It owns a loopback TLS 1.3 server, while the installed
ja3requests probes use the package's own TLS engine. It neither builds packages
nor publishes them. Install the tool dependencies as above; independent `hpack`
and process observation `psutil` are not library runtime requirements.

Use an explicit released wheel, checked before installation. A fresh checkout
can acquire the baseline without any local release reports:

```sh
python -m pip download --index-url https://pypi.org/simple \
  --only-binary=:all: --no-deps ja3requests==2.3.0 \
  --dest dist/fingerprint-inputs/baseline-2.3.0
python -m tools.capture_fingerprint \
  --chrome "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --wheel dist/fingerprint-inputs/baseline-2.3.0/ja3requests-2.3.0-py3-none-any.whl \
  --wheel-sha256 523fa1d13ebbdd46ba139e6609f3bc955a9ed9a6fb590c13aed7061fc4fc29d4 \
  --client-profile chrome:154 \
  --output dist/fingerprint-2.3.0/capture-local-01
```

The output path must be new. The initial feasibility trial can add
`--browser-only --browser-samples 1`; it cannot replace the default three-browser,
one-sync, one-async acceptance series. The executable's exact version is checked
before every browser case. Chrome 154 is the explicit **client** starting subset;
this does not assert that the installed browser is 154 or that TLS/H2 fully match.
The collector derives SETTINGS/window/pseudo order and equivalent regular header
inputs from the first browser case and records every override. Requests load HTML
and its image on one connection, with both server body and browser DOM/probe checks.

The server uses a short-lived private CA/leaf with localhost/IP SANs, no TLS
tickets, empty server SETTINGS and small fixed bodies. Library certificate
verification stays enabled using process-local `SSL_CERT_FILE`; the session
cache is disabled **after** Session/AsyncSession construction. Chrome uses a
private profile and a generated leaf SPKI exception, recorded as a distinct trust
mode. Machine trust settings are untouched.

Each case has an absolute 30-second request deadline (`--deadline` may select
up to 60 seconds). Dependency preparation has a separate bounded timeout.
Capture directions are limited to 1 MiB and decoded headers to 64 KiB. Failed
attempts retain partial evidence. Owned process groups and observed descendants
are reaped, including detached Chrome processes associated with the private
profile; listeners, peer threads, profiles, keys and the installed-probe venv are
cleaned. Extra queued preconnections are retained separately and excluded from
calibration. A process cleanup failure makes the case fail.

The manifest records wheel/report/module/tool hashes and dependency versions;
`tool-source/` retains the exact parser/collector/test inputs. Case JSON retains
both directions of TLS and plaintext H2 bytes, hashes, independently decoded
ClientHellos, ordered headers, HPACK representations/table state, completion and
cleanup. Comparison uses all browser samples, preserves GREASE slots and lengths,
and distinguishes variability from missing behavior. Three samples establish
observed variation, not a randomized-order distribution.

Optional `--artifact-report PATH` consumes an existing passing verifier report;
its version, wheel and module hashes must agree. For a selected F2/F3 extension,
first run the existing verifier against the final source, then substitute that
report's candidate wheel/hash and supply its report to this same command. Never
reuse the baseline wheel as acceptance for new runtime behavior. The collector
has no source-import fallback. Unknown profiles fail before live capture.

For the selected benefit-based outbound Huffman increment, add `--h2-huffman`
to the final candidate command. It sets the verified public `h2_huffman=True`
option for both probes, including preflight; an older wheel without that public
option is rejected. This mode requires three browser samples and both clients.
The manifest's `huffman_acceptance` must pass: exact first-request HPACK block
agreement under equivalent inputs, and independent Huffman/raw decisions and
literal lengths across both requests. Dynamic indexing and HEADERS priority
remain separate differences. The same CLI without this flag still captures the
released raw baseline. Candidate acceptance requires the passing verifier report
and exact candidate wheel/hash, as described above.

The reviewed [Chrome 155 fixture](../test/fixtures/chrome155_macos_tls_h2.json)
retains the accepted browser/sync/async bytes and compact identities. Runtime
tests check hashes and project decoding without importing capture dependencies;
tool tests independently re-decode raw bytes and check the declared comparison.
See the [received-byte report](../issues/tls_h2_capture_results.md) for actual
matches, remaining differences and conditional follow-up decisions.
