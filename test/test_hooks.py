"""Tests for request/response event hooks (#13)."""

import io
import unittest

from ja3requests.sessions import Session
from ja3requests.response import Response, HTTPResponse


class FakeSocket:
    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)

    def makefile(self, mode):
        return self._buffer


class TestHooksInit(unittest.TestCase):
    """Test hooks initialization on Session."""

    def test_default_hooks_dict(self):
        s = Session(use_pooling=False)
        self.assertIn("before_request", s.hooks)
        self.assertIn("after_request", s.hooks)
        self.assertEqual(s.hooks["before_request"], [])
        self.assertEqual(s.hooks["after_request"], [])

    def test_custom_hooks_on_init(self):
        cb = lambda req: req
        s = Session(use_pooling=False, hooks={"before_request": [cb]})
        self.assertEqual(len(s.hooks["before_request"]), 1)
        self.assertIs(s.hooks["before_request"][0], cb)

    def test_unknown_hook_event_ignored(self):
        s = Session(use_pooling=False, hooks={"unknown_event": [lambda x: x]})
        self.assertNotIn("unknown_event", s.hooks)

    def test_append_hook_after_init(self):
        s = Session(use_pooling=False)
        cb = lambda req: req
        s.hooks["before_request"].append(cb)
        self.assertEqual(len(s.hooks["before_request"]), 1)


class TestHooksDispatch(unittest.TestCase):
    """Test _dispatch_hooks helper."""

    def test_dispatch_calls_all_callbacks(self):
        s = Session(use_pooling=False)
        call_log = []
        s.hooks["after_request"].append(lambda r: call_log.append("cb1"))
        s.hooks["after_request"].append(lambda r: call_log.append("cb2"))
        s._dispatch_hooks("after_request", "data")
        self.assertEqual(call_log, ["cb1", "cb2"])

    def test_dispatch_returns_modified_data(self):
        s = Session(use_pooling=False)
        s.hooks["after_request"].append(lambda r: "modified")
        result = s._dispatch_hooks("after_request", "original")
        self.assertEqual(result, "modified")

    def test_dispatch_chains_modifications(self):
        s = Session(use_pooling=False)
        s.hooks["after_request"].append(lambda r: r + "_a")
        s.hooks["after_request"].append(lambda r: r + "_b")
        result = s._dispatch_hooks("after_request", "start")
        self.assertEqual(result, "start_a_b")

    def test_dispatch_none_return_preserves_data(self):
        s = Session(use_pooling=False)
        s.hooks["after_request"].append(lambda r: None)  # returns None
        result = s._dispatch_hooks("after_request", "preserved")
        self.assertEqual(result, "preserved")

    def test_dispatch_per_request_hooks(self):
        s = Session(use_pooling=False)
        call_log = []
        s.hooks["after_request"].append(lambda r: call_log.append("session"))
        per_req = {"after_request": [lambda r: call_log.append("request")]}
        s._dispatch_hooks("after_request", "data", per_request_hooks=per_req)
        self.assertEqual(call_log, ["session", "request"])

    def test_dispatch_empty_event(self):
        s = Session(use_pooling=False)
        result = s._dispatch_hooks("after_request", "data")
        self.assertEqual(result, "data")

    def test_dispatch_nonexistent_event(self):
        s = Session(use_pooling=False)
        result = s._dispatch_hooks("nonexistent", "data")
        self.assertEqual(result, "data")


class TestHooksOrder(unittest.TestCase):
    """Test that session-level hooks run before per-request hooks."""

    def test_session_hooks_first(self):
        s = Session(use_pooling=False)
        order = []
        s.hooks["before_request"].append(lambda r: order.append("session"))
        per_req = {"before_request": [lambda r: order.append("per_request")]}
        s._dispatch_hooks("before_request", "data", per_request_hooks=per_req)
        self.assertEqual(order, ["session", "per_request"])


if __name__ == "__main__":
    unittest.main()
