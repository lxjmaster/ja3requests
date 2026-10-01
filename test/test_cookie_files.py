"""Cookie files preserve request scope without serializing a Session."""

import json
import os
import subprocess
import sys
import time
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy
from pathlib import Path
from types import SimpleNamespace

import pytest

from ja3requests import Session
from ja3requests import _cookie_file
from ja3requests.cookies import Ja3RequestsCookieJar, get_cookie_header


def scoped_cookie(name="sid", value="test-token", **kwargs):
    fields = dict(
        version=0,
        name=name,
        value=value,
        port=None,
        port_specified=False,
        domain="first.example.com",
        domain_specified=False,
        domain_initial_dot=False,
        path="/account",
        path_specified=True,
        secure=True,
        expires=int(time.time()) + 3600,
        discard=False,
        comment=None,
        comment_url=None,
        rest={"HttpOnly": None, "SameSite": "Strict", "Priority": "High"},
        rfc2109=False,
    )
    fields.update(kwargs)
    return Cookie(**fields)


def header(jar, url):
    return get_cookie_header(jar, SimpleNamespace(url=url, headers={}))


def test_file_roundtrip_preserves_scope_in_another_process(tmp_path):
    jar = Ja3RequestsCookieJar()
    for cookie in (
        scoped_cookie(),
        scoped_cookie(
            value="domain-token",
            domain=".example.com",
            domain_specified=True,
            domain_initial_dot=True,
            path="/",
            secure=False,
        ),
        scoped_cookie(value="other-path", path="/other"),
        scoped_cookie("temporary", expires=None, discard=True),
        scoped_cookie("expired", expires=1),
    ):
        jar.set_cookie(cookie)
    path = tmp_path / "cookies.json"
    assert jar.save(path, include_session=True) == 4
    urls = [
        "https://first.example.com/account/profile",
        "https://sub.first.example.com/account/profile",
        "https://second.example.com/",
        "https://first.example.com/other",
        "http://first.example.com/account/profile",
        "https://other.invalid/account/profile",
    ]
    code = """
import json
import sys
from types import SimpleNamespace
from ja3requests.cookies import Ja3RequestsCookieJar, get_cookie_header
jar = Ja3RequestsCookieJar()
assert jar.load(sys.argv[1], include_session=True) == 4
print(json.dumps({
    "cookies": [cookie.__dict__ for cookie in jar],
    "headers": [get_cookie_header(jar, SimpleNamespace(url=url, headers={}))
                for url in json.loads(sys.argv[2])],
}))
"""
    import ja3requests

    env = dict(
        os.environ, PYTHONPATH=str(Path(ja3requests.__file__).resolve().parent.parent)
    )
    child = subprocess.run(
        [sys.executable, "-c", code, str(path), json.dumps(urls)],
        cwd=tmp_path,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    restored = json.loads(child.stdout)
    expected = [cookie.__dict__ for cookie in jar if not cookie.is_expired()]
    assert restored["cookies"] == expected
    assert restored["headers"] == [header(jar, url) for url in urls]
    assert "test-token" in restored["headers"][0]
    assert "test-token" not in restored["headers"][1]
    assert restored["headers"][-1] is None


def test_session_cookies_are_opt_in_on_save_and_load(tmp_path):
    source = Ja3RequestsCookieJar()
    source.set_cookie(scoped_cookie("persistent"))
    source.set_cookie(scoped_cookie("session", expires=None, discard=True))
    source.set_cookie(scoped_cookie("discard", discard=True))
    source.set_cookie(scoped_cookie("expired", expires=1))
    path = tmp_path / "cookies.json"
    assert source.save(path) == 1
    loaded = Ja3RequestsCookieJar()
    assert loaded.load(path, include_session=True) == 1
    assert set(loaded.keys()) == {"persistent"}

    assert source.save(path, include_session=True) == 3
    assert loaded.load(path) == 1
    assert loaded.load(path, include_session=True) == 3
    assert set(loaded.keys()) == {"persistent", "session", "discard"}


def test_load_expired_file_record_without_replacing_jar_partially(tmp_path):
    jar = Ja3RequestsCookieJar()
    jar.set_cookie(scoped_cookie())
    path = tmp_path / "cookies.json"
    jar.save(path)
    data = json.loads(path.read_text())
    data["cookies"][0]["expires"] = 1
    path.write_text(json.dumps(data))
    assert jar.load(path) == 0
    assert len(jar) == 0


@pytest.mark.parametrize("merge", [False, True])
def test_merge_replaces_only_same_identity_and_keeps_policy(tmp_path, merge):
    source = Ja3RequestsCookieJar()
    source.set_cookie(scoped_cookie(value="fresh"))
    source.set_cookie(scoped_cookie(value="other-path", path="/other"))
    path = tmp_path / "cookies.json"
    source.save(path)
    policy = DefaultCookiePolicy(blocked_domains=["blocked.example"])
    target = Ja3RequestsCookieJar(policy=policy)
    target.set_cookie(scoped_cookie(value="stale"))
    target.set_cookie(scoped_cookie("local", domain="local.example"))

    assert target.load(path, merge=merge) == 2
    assert target.get_policy() is policy
    assert target.get("sid", domain="first.example.com", path="/account") == "fresh"
    assert target.get("sid", domain="first.example.com", path="/other") == "other-path"
    assert ("local" in target) is merge


def test_null_value_port_and_extension_metadata_roundtrip(tmp_path):
    jar = Ja3RequestsCookieJar()
    jar.set_cookie(scoped_cookie("flag", value=None))
    jar.set_cookie(
        scoped_cookie(
            "versioned",
            version=1,
            port="443",
            port_specified=True,
            comment="Unicode: \u4e2d\u6587",
            comment_url=False,
            rest={"HttpOnly": None, "SameSite": "Lax", "custom": 7, "enabled": True},
            rfc2109=True,
        )
    )
    path = tmp_path / "cookies.json"
    assert jar.save(path) == 2
    loaded = Ja3RequestsCookieJar()
    assert loaded.load(path) == 2
    assert [cookie.__dict__ for cookie in loaded] == [cookie.__dict__ for cookie in jar]
    url = "https://first.example.com/account/"
    assert header(loaded, url) == header(jar, url)
    assert "flag" in header(loaded, url)


@pytest.mark.parametrize("standard_jar", [False, True])
def test_session_operations_use_stored_jar_and_request_scope(
    tmp_path, monkeypatch, standard_jar
):
    path = tmp_path / "session.json"
    with Session(use_pooling=False) as original:
        jar = CookieJar() if standard_jar else Ja3RequestsCookieJar()
        jar.set_cookie(scoped_cookie())
        original.cookies = jar
        monkeypatch.setattr(original, "send", lambda request, **kwargs: None)
        original.get(
            "https://first.example.com/account/", cookies={"transient": "once"}
        )
        assert "transient" in original.cookies
        assert original.save_cookies(path) == 1

    with Session(use_pooling=False) as restored:
        restored.cookies = CookieJar() if standard_jar else Ja3RequestsCookieJar()
        target = restored._cookies
        assert restored.load_cookies(path) == 1
        assert restored._cookies is target
        captured = []
        monkeypatch.setattr(
            restored, "send", lambda request, **kwargs: captured.append(request)
        )
        restored.get("https://first.example.com/account/profile")
        restored.get("http://first.example.com/account/profile")
        restored.get("https://sub.first.example.com/account/profile")
        restored.get("https://first.example.com/other")
        assert captured[0].cookies == {"sid": "test-token"}
        assert all(not request.cookies for request in captured[1:])


def valid_document(tmp_path):
    jar = Ja3RequestsCookieJar()
    jar.set_cookie(scoped_cookie("first"))
    jar.set_cookie(scoped_cookie("second"))
    path = tmp_path / "cookies.json"
    jar.save(path)
    return path, json.loads(path.read_text())


MALFORMED = [
    "format",
    "schema-version",
    "schema-bool",
    "unknown-field",
    "not-list",
    "missing-field",
    "non-bool",
    "bad-version",
    "expiry-bool",
    "expiry-text",
    "bad-port",
    "newline-value",
    "surrogate",
    "nested-rest",
    "duplicate-cookie",
    "normalized-duplicate",
    "duplicate-json-key",
    "invalid-utf8",
    "truncated",
    "pickle",
    "nan",
    "huge-integer",
    "deep-nesting",
]


@pytest.mark.parametrize("merge", [False, True])
@pytest.mark.parametrize("fault", MALFORMED)
def test_malformed_file_never_partially_changes_jar(tmp_path, merge, fault):
    path, data = valid_document(tmp_path)
    record = data["cookies"][-1]
    if fault == "format":
        data["format"] = "other"
    elif fault == "schema-version":
        data["version"] = 2
    elif fault == "schema-bool":
        data["version"] = True
    elif fault == "unknown-field":
        data["policy"] = {}
    elif fault == "not-list":
        data["cookies"] = {}
    elif fault == "missing-field":
        record.pop("domain_specified")
    elif fault == "non-bool":
        record["secure"] = 1
    elif fault == "bad-version":
        record["version"] = 2
    elif fault == "expiry-bool":
        record["expires"] = True
    elif fault == "expiry-text":
        record["expires"] = "tomorrow"
    elif fault == "bad-port":
        record["port_specified"] = True
    elif fault == "newline-value":
        record["value"] = "value\r\nInjected: yes"
    elif fault == "surrogate":
        record["value"] = "\ud800"
    elif fault == "nested-rest":
        record["rest"] = {"custom": {"nested": True}}
    elif fault in ("duplicate-cookie", "normalized-duplicate"):
        record.update(data["cookies"][0])
        if fault == "normalized-duplicate":
            record["domain"] = record["domain"].upper()
    payload = json.dumps(data).encode()
    if fault == "duplicate-json-key":
        payload = payload.replace(b'"secure": true', b'"secure": true, "secure": false')
    elif fault == "invalid-utf8":
        payload = b"\xff"
    elif fault == "truncated":
        payload = payload[:-1]
    elif fault == "pickle":
        payload = b"\x80\x04pickle is not a cookie JSON file"
    elif fault == "nan":
        payload = payload.replace(b'"expires": ', b'"expires": NaN, "unused": ')
    elif fault == "huge-integer":
        payload = payload.replace(b'"version": 1', b'"version": ' + b"9" * 200)
    elif fault == "deep-nesting":
        payload = b"[" * 1500 + b"0" + b"]" * 1500
    path.write_bytes(payload)
    target = Ja3RequestsCookieJar()
    original = scoped_cookie("unchanged")
    target.set_cookie(original)
    before = target._cookies
    with pytest.raises(ValueError):
        target.load(path, merge=merge, include_session=True)
    assert target._cookies is before
    assert list(target) == [original]


@pytest.mark.parametrize("merge", [False, True])
def test_unreadable_path_leaves_jar_unchanged(tmp_path, merge):
    target = Ja3RequestsCookieJar()
    original = scoped_cookie()
    target.set_cookie(original)
    with pytest.raises(FileNotFoundError):
        target.load(tmp_path / "missing.json", merge=merge)
    assert list(target) == [original]


def test_file_size_bound_on_load_and_save(tmp_path):
    jar = Ja3RequestsCookieJar()
    jar.set_cookie(scoped_cookie())
    path = tmp_path / "cookies.json"
    jar.save(path)
    saved = path.read_bytes()
    jar.set_cookie(scoped_cookie(value="x" * _cookie_file.MAX_FILE_BYTES))
    with pytest.raises(ValueError, match="size limit"):
        jar.save(path)
    assert path.read_bytes() == saved
    path.write_bytes(b" " * (_cookie_file.MAX_FILE_BYTES + 1))
    with pytest.raises(ValueError, match="size limit"):
        jar.load(path)
    assert next(iter(jar)).value == "x" * _cookie_file.MAX_FILE_BYTES


def test_cookie_count_bound_on_load_and_save(tmp_path):
    path, data = valid_document(tmp_path)
    record = data["cookies"][0]
    record.update(domain="", path="/", value="", rest={})
    data["cookies"] = [
        dict(record, name=str(index)) for index in range(_cookie_file.MAX_COOKIES + 1)
    ]
    payload = json.dumps(data, separators=(",", ":")).encode()
    assert len(payload) < _cookie_file.MAX_FILE_BYTES
    path.write_bytes(payload)
    jar = Ja3RequestsCookieJar()
    with pytest.raises(ValueError, match="Too many cookies"):
        jar.load(path)
    assert len(jar) == 0
    for index in range(_cookie_file.MAX_COOKIES + 1):
        jar.set_cookie(scoped_cookie(str(index)))
    with pytest.raises(ValueError, match="Too many cookies"):
        jar.save(path)
    assert path.read_bytes() == payload


@pytest.mark.parametrize("operation", ["fsync", "replace"])
def test_failed_atomic_save_keeps_existing_file_and_cleans_temp(
    tmp_path, monkeypatch, operation
):
    jar = Ja3RequestsCookieJar()
    jar.set_cookie(scoped_cookie())
    path = tmp_path / "cookies.json"
    jar.save(path)
    original = path.read_bytes()
    jar.set_cookie(scoped_cookie(value="updated"))

    def fail(*args):
        if operation == "replace":
            assert Path(args[0]).parent == path.parent
            assert Path(args[1]) == path
        raise OSError("simulated write failure")

    monkeypatch.setattr(_cookie_file.os, operation, fail)
    with pytest.raises(OSError, match="simulated"):
        jar.save(path)
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


def test_invalid_metadata_does_not_replace_existing_file(tmp_path):
    jar = Ja3RequestsCookieJar()
    jar.set_cookie(scoped_cookie())
    path = tmp_path / "cookies.json"
    jar.save(path)
    original = path.read_bytes()
    next(iter(jar)).set_nonstandard_attr("opaque", object())
    with pytest.raises(ValueError, match="metadata"):
        jar.save(path)
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]


@pytest.mark.skipif(os.name != "posix", reason="POSIX file permissions")
def test_saved_file_is_private_even_when_replacing_public_file(tmp_path):
    jar = Ja3RequestsCookieJar()
    jar.set_cookie(scoped_cookie())
    path = tmp_path / "cookies.json"
    path.write_text("old")
    path.chmod(0o644)
    assert jar.save(path) == 1
    assert path.stat().st_mode & 0o777 == 0o600


def test_options_require_explicit_booleans_and_cookiejar(tmp_path):
    jar = Ja3RequestsCookieJar()
    path = tmp_path / "cookies.json"
    with pytest.raises(TypeError, match="include_session"):
        jar.save(path, include_session="false")
    with pytest.raises(TypeError, match="merge"):
        jar.load(path, merge="false")
    with Session(use_pooling=False) as session:
        session.cookies = {"not": "a jar"}
        with pytest.raises(TypeError, match="CookieJar"):
            session.save_cookies(path)
    assert not path.exists()
