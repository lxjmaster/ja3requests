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
python -m pip install pytest packaging
python -m pytest tools/tests -q
```

The existing Python 3.12 wheel CI job runs these focused fixture-based tests in
addition to its original wheel smoke. They remain outside the library's `test/`
runtime matrix; they do not build/install the entire project for every negative
case. Full artifact verification is run explicitly for the selected candidate.
