"""Exercise documented public APIs against a bounded local HTTP peer."""

import gzip
import json
import tempfile
import threading
import zlib
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import brotli

from ja3requests import HTTPRetry, Session, StreamConsumedError, TlsConfig
from ja3requests.pool import ConnectionPool


class DemoHandler(BaseHTTPRequestHandler):
    """Serve deterministic examples without an Internet dependency."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # pylint: disable=redefined-builtin
        """Keep successful example output concise."""

    def reply(self, status, body, headers=()):
        """Write one complete, length-framed reply."""
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        for key, value in headers:
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def do_POST(self):  # pylint: disable=invalid-name
        """Echo a JSON request and create a Session Cookie."""
        body = self.rfile.read(int(self.headers["Content-Length"]))
        assert json.loads(body) == {"message": "hello"}
        self.reply(
            200,
            body,
            (("Content-Type", "application/json"), ("Set-Cookie", "demo=kept; Path=/")),
        )

    def do_GET(self):  # pylint: disable=invalid-name
        """Serve retries, compression, lines, and a gated streaming response."""
        if self.path == "/retry":
            self.server.retry_calls += 1
            status = 503 if self.server.retry_calls == 1 else 200
            self.reply(status, b"retry complete")
        elif self.path == "/cookie":
            self.reply(200, self.headers.get("Cookie", "").encode("ascii"))
        elif self.path == "/stream":
            self.send_response(200)
            self.send_header("Content-Length", "11")
            self.end_headers()
            self.wfile.write(b"first")
            self.wfile.flush()
            if not self.server.release_tail.wait(5):
                raise RuntimeError("The example did not consume the first chunk")
            self.wfile.write(b"second")
            self.wfile.flush()
        elif self.path == "/lines":
            self.reply(200, b"alpha\r\nbeta\nlast")
        elif self.path in ("/gzip", "/deflate", "/br"):
            encoders = {
                "gzip": gzip.compress,
                "deflate": zlib.compress,
                "br": brotli.compress,
            }
            encoding = self.path[1:]
            body = encoders[encoding](b"decoded content\n" * 100)
            self.reply(200, body, (("Content-Encoding", encoding),))
        else:
            self.reply(404, b"unknown path")


def run_demo():
    """Run public examples, then release the server and temporary Cookie file."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    server.daemon_threads = True
    server.retry_calls = 0
    server.release_tail = threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = "http://127.0.0.1:{}".format(server.server_port)
    events = []

    def before_request(request):
        events.append(("request", request.method))

    def after_request(response):
        events.append(("response", response.status_code))

    try:
        retry = HTTPRetry(total=1, backoff_factor=0, raise_on_status=False)
        with Session(
            pool=ConnectionPool(),
            retry=retry,
            hooks={
                "before_request": [before_request],
                "after_request": [after_request],
            },
        ) as session:
            response = session.post(
                base_url + "/json", json={"message": "hello"}, timeout=3
            )
            response.raise_for_status()
            assert response.json() == {"message": "hello"}
            echoed = SimpleCookie(session.get(base_url + "/cookie", timeout=3).text)
            assert echoed["demo"].value == "kept"
            assert session.get(base_url + "/retry", timeout=3).status_code == 200
            assert server.retry_calls == 2

            with session.get(
                base_url + "/stream", stream=True, timeout=(3, 3)
            ) as response:
                iterator = response.iter_content(chunk_size=5)
                assert next(iterator) == b"first"
                assert not server.release_tail.is_set()
                server.release_tail.set()
                assert b"".join(iterator) == b"second"
                try:
                    response.content
                except StreamConsumedError:
                    pass
                else:
                    raise AssertionError("Uncached streaming content was replayed")

            for encoding in ("gzip", "deflate", "br"):
                with session.get(
                    base_url + "/" + encoding, stream=True, timeout=3
                ) as response:
                    chunks = response.iter_content(chunk_size=17)
                    assert b"".join(chunks) == b"decoded content\n" * 100
            with session.get(base_url + "/lines", stream=True, timeout=3) as response:
                assert list(response.iter_lines(chunk_size=3)) == [
                    b"alpha",
                    b"beta",
                    b"last",
                ]

            with tempfile.TemporaryDirectory(
                prefix="ja3requests-docs-cookies-"
            ) as staging:
                path = Path(staging) / "cookies.json"
                assert session.save_cookies(path, include_session=True) == 1
                with Session(use_pooling=False) as restarted:
                    assert restarted.load_cookies(path, include_session=True) == 1
                    assert restarted.cookies.get("demo") == "kept"

        assert ("request", "POST") in events
        assert ("response", 200) in events
        for config in (
            TlsConfig.secure(),
            TlsConfig.from_browser("chrome", version=154),
        ):
            config.validate(strict=True)
            assert len(config.get_ja3_string(server_name="example.com").split(",")) == 5
        print(
            "PASS: JSON, Cookies, retry/hooks, first-chunk streaming, gzip/deflate/br, lines, JA3"
        )
    finally:
        server.release_tail.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("The loopback server did not stop")


if __name__ == "__main__":
    run_demo()
