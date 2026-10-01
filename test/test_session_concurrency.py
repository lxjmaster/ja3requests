"""Concurrent requests must keep their own prepared request context."""

import threading
from concurrent.futures import ThreadPoolExecutor

from ja3requests import Session
from ja3requests.requests.request import Request


def test_session_request_context_is_thread_local(monkeypatch):
    barrier = threading.Barrier(2)
    original = Request.request

    def prepare_together(request):
        barrier.wait(timeout=2)
        return original(request)

    def inspect_request(session, prepared, **_kwargs):
        return session.Request.url, prepared.url

    monkeypatch.setattr(Request, "request", prepare_together)
    monkeypatch.setattr(Session, "send", inspect_request)
    with Session(use_pooling=False) as session:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(session.get, "http://example.test/first")
            second = executor.submit(session.get, "http://example.test/second")
            assert first.result(timeout=3) == (
                "http://example.test/first",
                "http://example.test/first",
            )
            assert second.result(timeout=3) == (
                "http://example.test/second",
                "http://example.test/second",
            )
