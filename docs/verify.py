"""Validate built documentation links, generated API objects and runnable examples."""

import argparse
import ast
import re
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class Page(HTMLParser):
    """Collect real HTML targets and references without third-party dependencies."""

    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.references = []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(values["id"])
        if tag == "a" and values.get("name"):
            self.ids.add(values["name"])
        for key in ("href", "src"):
            if values.get(key):
                self.references.append(values[key])


def check_html(site):
    """Require all generated local links, assets, fragments and public API IDs."""
    pages = {
        path.resolve(): Page(path.read_text(encoding="utf-8"))
        for path in site.rglob("*.html")
    }
    if not pages:
        raise AssertionError("No HTML pages found; build the docs first")
    checked = 0
    for source, page in pages.items():
        for reference in page.references:
            parsed = urlsplit(reference)
            if parsed.scheme or parsed.netloc:
                continue
            path = unquote(parsed.path)
            if path.startswith("/"):
                target = site / path.lstrip("/")
            elif path:
                target = source.parent / path
            else:
                target = source
            target = target.resolve()
            if target.is_dir():
                target /= "index.html"
            if site != target and site not in target.parents:
                raise AssertionError(
                    "Link escapes site: {} -> {}".format(source, reference)
                )
            if not target.is_file():
                raise AssertionError(
                    "Missing target: {} -> {}".format(source, reference)
                )
            if parsed.fragment and target in pages:
                if unquote(parsed.fragment) not in pages[target].ids:
                    raise AssertionError(
                        "Missing anchor: {} -> {}".format(source, reference)
                    )
            checked += 1

    required = {
        "api/client/index.html": {
            "ja3requests.get",
            "ja3requests.sessions.Session",
            "ja3requests.sessions.Session.request",
            "ja3requests.sessions.Session.save_cookies",
        },
        "api/response/index.html": {
            "ja3requests.response.Response",
            "ja3requests.response.Response.iter_content",
            "ja3requests.exceptions.StreamConsumedError",
        },
        "api/tls/index.html": {
            "ja3requests.protocol.tls.config.TlsConfig",
            "ja3requests.protocol.tls.client_hello_info.inspect_client_hello",
        },
        "api/state/index.html": {
            "ja3requests.pool.ConnectionPool",
            "ja3requests.retry.HTTPRetry",
            "ja3requests.cookies.Ja3RequestsCookieJar",
        },
        "api/async/index.html": {
            "ja3requests.async_sessions.AsyncSession",
            "ja3requests.async_sessions.AsyncSession.request",
            "ja3requests.async_sessions.AsyncSession.prepare_request",
            "ja3requests.async_sessions.AsyncSession.send",
            "ja3requests.async_sessions.AsyncPreparedRequest",
            "ja3requests.async_sessions.AsyncPreparedRequest.with_headers",
            "ja3requests.async_sessions.AsyncSession.save_cookies",
            "ja3requests.async_sessions.AsyncSession.load_cookies",
            "ja3requests.async_response.AsyncResponse",
            "ja3requests.async_response.AsyncResponse.read",
            "ja3requests.async_response.AsyncResponse.aiter_content",
            "ja3requests.async_pool.AsyncConnectionPool",
        },
    }
    for name, ids in required.items():
        page = pages.get(site / name)
        if page is None or not ids.issubset(page.ids):
            raise AssertionError("Missing generated API objects in {}".format(name))
    return len(pages), checked, sum(map(len, required.values()))


def check_markdown(root):
    """Syntax-check snippets and verify pinned repository evidence paths."""
    snippets = 0
    source_links = set()
    for path in (root / "docs").rglob("*.md"):
        source = path.read_text(encoding="utf-8")
        for code in re.findall(
            r"^```python\s*\n(.*?)^```\s*$", source, re.MULTILINE | re.DOTALL
        ):
            ast.parse(code, filename=str(path), feature_version=(3, 7))
            snippets += 1
        source_links.update(
            re.findall(
                r"https://github\.com/lxjmaster/ja3requests/blob/([0-9a-f]{40})/([^\s)#]+)",
                source,
            )
        )
    for commit, path in sorted(source_links):
        subprocess.run(
            ["git", "cat-file", "-e", "{}:{}".format(commit, path)],
            cwd=root,
            check=True,
        )
    return snippets, len(source_links)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent.parent
    parser.add_argument("--site-dir", type=Path, default=root / "dist" / "docs-site")
    args = parser.parse_args()
    pages, links, objects = check_html(args.site_dir.resolve())
    snippets, sources = check_markdown(root)
    for example in (
        "loopback.py",
        "async_client.py",
        "uploads.py",
        "h2_fingerprint.py",
    ):
        subprocess.run(
            [sys.executable, str(root / "docs" / "examples" / example)],
            cwd=root,
            check=True,
            timeout=30,
        )
    print(
        "PASS: {} HTML pages, {} local links/assets, {} API objects, {} Python snippets, {} pinned source paths".format(
            pages, links, objects, snippets, sources
        )
    )


if __name__ == "__main__":
    main()
