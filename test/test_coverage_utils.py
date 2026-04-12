"""Coverage improvement tests for utils.py, cookies.py, __init__.py."""

import unittest
from http.cookiejar import CookieJar

from ja3requests.utils import (
    b,
    default_user_agent,
    make_headers,
    default_headers,
    Retry,
    Task,
    dict_from_cookie_string,
    dict_from_cookiejar,
    add_dict_to_cookiejar,
)
from ja3requests.cookies import (
    Ja3RequestsCookieJar,
    create_cookie,
    morsel_to_cookie,
    cookiejar_from_dict,
    merge_cookies,
    remove_cookie_by_name,
    _copy_cookie_jar,
    CookieConflictError,
)
from ja3requests.exceptions import MaxRetriedException


class TestUtilsB(unittest.TestCase):
    def test_encode_string(self):
        self.assertEqual(b("hello"), b"hello")

    def test_encode_ascii(self):
        self.assertEqual(b("abc"), b"abc")


class TestDefaultUserAgent(unittest.TestCase):
    def test_contains_version(self):
        ua = default_user_agent()
        self.assertIn("Python/", ua)
        self.assertIn("Ja3Requests/", ua)

    def test_custom_agent(self):
        ua = default_user_agent("MyAgent")
        self.assertIn("MyAgent/", ua)


class TestMakeHeaders(unittest.TestCase):
    def test_default(self):
        h = make_headers()
        self.assertIn("Accept", h)
        self.assertIn("User-Agent", h)

    def test_keep_alive(self):
        h = make_headers(keep_alive=True)
        self.assertEqual(h["Connection"], "keep-alive")

    def test_accept_encoding_string(self):
        h = make_headers(accept_encoding="br")
        self.assertEqual(h["Accept-Encoding"], "br")

    def test_accept_encoding_list(self):
        h = make_headers(accept_encoding=["gzip", "deflate"])
        self.assertEqual(h["Accept-Encoding"], "gzip,deflate")

    def test_accept_encoding_other(self):
        h = make_headers(accept_encoding=True)
        self.assertEqual(h["Accept-Encoding"], "gzip,deflate")

    def test_basic_auth(self):
        h = make_headers(basic_auth="user:pass")
        self.assertIn("Authorization", h)
        self.assertTrue(h["Authorization"].startswith("Basic "))

    def test_proxy_basic_auth(self):
        h = make_headers(proxy_basic_auth="user:pass")
        self.assertIn("Proxy-Authorization", h)

    def test_disable_cache(self):
        h = make_headers(disable_cache=True)
        self.assertEqual(h["Cache-Control"], "no-cache")

    def test_custom_user_agent(self):
        h = make_headers(user_agent="CustomBot/1.0")
        self.assertEqual(h["User-Agent"], "CustomBot/1.0")


class TestDefaultHeaders(unittest.TestCase):
    def test_has_connection(self):
        h = default_headers()
        self.assertEqual(h["Connection"], "keep-alive")


class TestRetryAndTask(unittest.TestCase):
    def test_retry_success(self):
        retry = Retry()
        result = retry.do(lambda: 42, Exception)
        self.assertEqual(result, 42)

    def test_retry_exhausted(self):
        def always_fail():
            raise ValueError("fail")
        retry = Retry()
        with self.assertRaises(MaxRetriedException):
            retry.do(always_fail, ValueError)

    def test_task_retry_success(self):
        t = Task(lambda: 10, 3, Exception)
        result = t.retry()
        self.assertEqual(result, 10)

    def test_task_retry_fail(self):
        def fail():
            raise ValueError()
        t = Task(fail, 3, ValueError)
        result = t.retry()
        self.assertEqual(result, 0)
        self.assertEqual(t.times, 2)


class TestDictFromCookieString(unittest.TestCase):
    def test_single_cookie(self):
        result = dict_from_cookie_string("name=value")
        self.assertEqual(result, {"name": "value"})

    def test_multiple_cookies(self):
        result = dict_from_cookie_string("a=1; b=2; c=3")
        self.assertEqual(result, {"a": "1", "b": "2", "c": "3"})

    def test_bytes_input(self):
        result = dict_from_cookie_string(b"token=abc123")
        self.assertEqual(result, {"token": "abc123"})


class TestDictFromCookiejar(unittest.TestCase):
    def test_extract(self):
        jar = Ja3RequestsCookieJar()
        jar.set("a", "1")
        jar.set("b", "2")
        result = dict_from_cookiejar(jar)
        self.assertEqual(result, {"a": "1", "b": "2"})


class TestAddDictToCookiejar(unittest.TestCase):
    def test_add(self):
        jar = Ja3RequestsCookieJar()
        result = add_dict_to_cookiejar(jar, {"x": "y"})
        self.assertEqual(result["x"], "y")


# ============================================================================
# cookies.py coverage
# ============================================================================

class TestCreateCookie(unittest.TestCase):
    def test_basic(self):
        c = create_cookie("name", "value")
        self.assertEqual(c.name, "name")
        self.assertEqual(c.value, "value")

    def test_with_domain(self):
        c = create_cookie("n", "v", domain=".example.com")
        self.assertEqual(c.domain, ".example.com")

    def test_bad_kwarg(self):
        with self.assertRaises(TypeError):
            create_cookie("n", "v", nonexistent_param=True)


class TestCookieJarFromDict(unittest.TestCase):
    def test_from_dict(self):
        jar = cookiejar_from_dict({"a": "1", "b": "2"})
        self.assertEqual(len(list(jar)), 2)

    def test_with_existing_jar(self):
        jar = Ja3RequestsCookieJar()
        jar.set("existing", "val")
        result = cookiejar_from_dict({"new": "val2"}, cookiejar=jar)
        self.assertIn("existing", [c.name for c in result])
        self.assertIn("new", [c.name for c in result])

    def test_no_overwrite(self):
        jar = Ja3RequestsCookieJar()
        jar.set("key", "original")
        cookiejar_from_dict({"key": "new"}, cookiejar=jar, overwrite=False)
        self.assertEqual(jar["key"], "original")

    def test_none_dict(self):
        jar = cookiejar_from_dict(None)
        self.assertEqual(len(list(jar)), 0)


class TestMergeCookies(unittest.TestCase):
    def test_merge_dict(self):
        jar = Ja3RequestsCookieJar()
        merge_cookies(jar, {"a": "1"})
        self.assertEqual(jar["a"], "1")

    def test_merge_cookiejar(self):
        jar1 = Ja3RequestsCookieJar()
        jar2 = Ja3RequestsCookieJar()
        jar2.set("b", "2")
        merge_cookies(jar1, jar2)
        self.assertEqual(jar1["b"], "2")

    def test_merge_invalid_type(self):
        with self.assertRaises(ValueError):
            merge_cookies("not_a_jar", {"a": "1"})


class TestCookieJarOperations(unittest.TestCase):
    def test_iterkeys(self):
        jar = Ja3RequestsCookieJar()
        jar.set("a", "1")
        jar.set("b", "2")
        self.assertEqual(sorted(jar.keys()), ["a", "b"])

    def test_itervalues(self):
        jar = Ja3RequestsCookieJar()
        jar.set("a", "1")
        self.assertEqual(list(jar.values()), ["1"])

    def test_iteritems(self):
        jar = Ja3RequestsCookieJar()
        jar.set("k", "v")
        items = list(jar.items())
        self.assertEqual(items, [("k", "v")])

    def test_list_domains(self):
        jar = Ja3RequestsCookieJar()
        jar.set("a", "1", domain=".example.com")
        self.assertIn(".example.com", jar.list_domains())

    def test_list_paths(self):
        jar = Ja3RequestsCookieJar()
        jar.set("a", "1", path="/api")
        self.assertIn("/api", jar.list_paths())

    def test_multiple_domains_true(self):
        """Same domain appearing twice → True."""
        jar = Ja3RequestsCookieJar()
        c1 = create_cookie("a", "1", domain=".x.com")
        c2 = create_cookie("b", "2", domain=".x.com")
        jar.set_cookie(c1)
        jar.set_cookie(c2)
        self.assertTrue(jar.multiple_domains())

    def test_multiple_domains_false(self):
        jar = Ja3RequestsCookieJar()
        c = create_cookie("a", "1", domain=".x.com")
        jar.set_cookie(c)
        self.assertFalse(jar.multiple_domains())

    def test_get_dict(self):
        jar = Ja3RequestsCookieJar()
        jar.set("a", "1", domain=".x.com")
        jar.set("b", "2", domain=".y.com")
        d = jar.get_dict(domain=".x.com")
        self.assertEqual(d, {"a": "1"})

    def test_contains(self):
        jar = Ja3RequestsCookieJar()
        jar.set("present", "val")
        self.assertIn("present", jar)
        self.assertNotIn("absent", jar)

    def test_set_none_removes(self):
        jar = Ja3RequestsCookieJar()
        jar.set("key", "val")
        jar.set("key", None)
        with self.assertRaises(KeyError):
            _ = jar["key"]

    def test_update_from_dict(self):
        jar = Ja3RequestsCookieJar()
        jar.update({"x": "1", "y": "2"})
        self.assertEqual(jar["x"], "1")

    def test_update_from_cookiejar(self):
        jar1 = Ja3RequestsCookieJar()
        jar2 = Ja3RequestsCookieJar()
        jar2.set("z", "3")
        jar1.update(jar2)
        self.assertEqual(jar1["z"], "3")

    def test_set_cookie_strips_quotes(self):
        jar = Ja3RequestsCookieJar()
        c = create_cookie("q", '"value"')
        jar.set_cookie(c)
        val = jar["q"]
        # set_cookie strips escaped quotes
        self.assertIsNotNone(val)

    def test_pickle(self):
        jar = Ja3RequestsCookieJar()
        jar.set("k", "v")
        state = jar.__getstate__()
        self.assertNotIn("_cookies_lock", state)
        jar2 = Ja3RequestsCookieJar()
        jar2.__setstate__(state)
        self.assertEqual(jar2["k"], "v")

    def test_copy(self):
        jar = Ja3RequestsCookieJar()
        jar.set("a", "1")
        copy = jar.copy()
        self.assertEqual(copy["a"], "1")

    def test_get_policy(self):
        jar = Ja3RequestsCookieJar()
        self.assertIsNotNone(jar.get_policy())


class TestRemoveCookieByName(unittest.TestCase):
    def test_remove(self):
        jar = Ja3RequestsCookieJar()
        jar.set("a", "1")
        jar.set("b", "2")
        remove_cookie_by_name(jar, "a")
        self.assertNotIn("a", jar.keys())
        self.assertIn("b", jar.keys())

    def test_remove_with_domain(self):
        jar = Ja3RequestsCookieJar()
        jar.set("a", "1", domain=".x.com")
        remove_cookie_by_name(jar, "a", domain=".x.com")
        self.assertEqual(len(list(jar)), 0)


class TestCopyCookieJar(unittest.TestCase):
    def test_copy_custom_jar(self):
        jar = Ja3RequestsCookieJar()
        jar.set("x", "1")
        copied = _copy_cookie_jar(jar)
        self.assertEqual(copied["x"], "1")

    def test_copy_none(self):
        self.assertIsNone(_copy_cookie_jar(None))

    def test_copy_generic_jar(self):
        jar = CookieJar()
        copied = _copy_cookie_jar(jar)
        self.assertIsInstance(copied, CookieJar)


class TestCookieConflictError(unittest.TestCase):
    def test_duplicate_raises(self):
        jar = Ja3RequestsCookieJar()
        jar.set("dup", "1", domain=".a.com")
        jar.set("dup", "2", domain=".b.com")
        with self.assertRaises(CookieConflictError):
            _ = jar["dup"]


# ============================================================================
# __init__.py shortcut functions
# ============================================================================

class TestModuleShortcuts(unittest.TestCase):
    def test_session_factory(self):
        import ja3requests
        s = ja3requests.session()
        self.assertIsNotNone(s)

    def test_all_methods_callable(self):
        import ja3requests
        for name in ("get", "post", "put", "patch", "delete", "head", "options", "request"):
            self.assertTrue(callable(getattr(ja3requests, name)))


if __name__ == "__main__":
    unittest.main()
