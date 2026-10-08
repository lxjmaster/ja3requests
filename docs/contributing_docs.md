# Building these docs

The site uses MkDocs with its default theme and mkdocstrings' Python handler.
The handler extracts public signatures/docstrings directly from this checkout;
there is no hand-maintained duplicate API catalog and no runtime import needed
to build the reference. These are optional development tools, separate from the
package's Python 3.7+ runtime support. Use Python 3.10 or later for the docs tools.

From the repository root, install and validate:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e . -r docs/requirements.txt
.venv/bin/python -m mkdocs build --strict
.venv/bin/python docs/verify.py
```

If `.venv` already exists, use its compatible interpreter without recreating it.
The generated site is under ignored `dist/docs-site/`. Preview it with MkDocs'
local server so directory-based page links resolve correctly:

```sh
.venv/bin/python -m mkdocs serve --dev-addr 127.0.0.1:8000
```

Preview remains local and runs until stopped with Ctrl-C. No deployment,
GitHub Pages configuration, commit or remote write is part of these commands.

`strict: true` treats warnings as build failures. Navigation omissions,
missing targets, unrecognized links and invalid anchors are enabled as warnings.
`docs/verify.py` additionally follows generated HTML links and asset references,
checks required synchronous/async API IDs and Python code-fence syntax, and
executes all three documented local examples. To check an alternate build directory:

```sh
.venv/bin/python -m mkdocs build --strict --site-dir /path/to/task-owned-site
.venv/bin/python docs/verify.py --site-dir /path/to/task-owned-site
```

The checker does not claim availability of external websites. Repository-source
links retained in the three historical guides are pinned to the published
2.0.1 commit so their evidence does not drift with a later default branch.
For every pinned link, it unconditionally runs `git cat-file -e` against the
referenced commit and path. Those historical Git objects must be available:
use a full-history checkout, or fetch the referenced objects before checking.
A shallow checkout that lacks them fails verification; the check is not skipped.
A `git archive` directory or extracted sdist is not a substitute for that checkout.

The documentation workflow uses Python 3.12, a full-history checkout
(`fetch-depth: 0`), and the same strict build and checker commands above. It
installs the project with the separate docs requirements and runs the three local
examples. Its repository permission is `contents: read`; it does not deploy a
site or upload artifacts. A successful local run does not claim that the workflow
has run on GitHub; that requires a later authorized push or workflow run.

Keep guide behavior consistent with the current source, label changes that are
not yet released, and preserve dated acceptance records. A docs build is not a
substitute for the runtime suite or installed-wheel checks. Optional public site
publication can be selected separately after local delivery.

Local verification on 2026-10-04 used MkDocs 1.6.1, mkdocstrings 0.30.1 and
mkdocstrings-python 2.0.9 with package source aggregate SHA-256
`5963161b9673c2004d7c551501265f0cd2c5b151bbe64b512facf7dbe65ca3dd`.
Strict build and the checker passed: 21 HTML pages, 1265 local links/assets,
12 required generated API objects, 32 Python snippets and 12 pinned source paths.
The runnable loopback example also passed JSON, Cookies, retry/hooks, first-chunk
streaming, gzip/deflate/Brotli, line iteration and JA3 checks. This is local docs
evidence for that source snapshot, not a remote publication or runtime CI result.

The native-async documentation extension, including hook cancellation and
application-owned task boundaries, was checked locally on 2026-10-04 against
package source aggregate SHA-256
`7c6ccaa85405c9f8e8444f2aa83dc190e394aade8669c64c2535c87ade17dca6`.
The strict build and checker passed with 23 HTML pages, 1483 local links/assets,
18 required generated API objects, 34 Python snippets and the same 12 pinned
source paths. Both actual loopback examples passed; the async example additionally
exercises awaited body access, an async hook, caller cancellation and borrowed
pool lifetime. These figures describe that docs check during development, not
final installed-package acceptance, supported-runtime CI or public deployment.
