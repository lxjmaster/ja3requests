"""Versioned Cookie data files; no Session, policy or executable object state."""

import json
import os
import tempfile
import time
from http.cookiejar import Cookie, CookieJar
from pathlib import Path

MAX_FILE_BYTES = 1024 * 1024
MAX_COOKIES = 3000
FORMAT = "ja3requests.cookies"
FIELDS = (
    "version",
    "name",
    "value",
    "port",
    "port_specified",
    "domain",
    "domain_specified",
    "domain_initial_dot",
    "path",
    "path_specified",
    "secure",
    "expires",
    "discard",
    "comment",
    "comment_url",
    "rfc2109",
)
BOOLEAN_FIELDS = (
    "port_specified",
    "domain_specified",
    "domain_initial_dot",
    "path_specified",
    "secure",
    "discard",
    "rfc2109",
)


def _scalar(value):
    if value is None or type(value) is bool:
        return True
    if type(value) is int:
        return -(2**63) <= value < 2**63
    if isinstance(value, str):
        value.encode("utf-8")
        return True
    return False


def _parse_cookie(record):
    if not isinstance(record, dict) or set(record) != set(FIELDS) | {"rest"}:
        raise ValueError("Invalid cookie record fields")
    for field in BOOLEAN_FIELDS:
        if type(record[field]) is not bool:
            raise ValueError("Invalid cookie boolean field")
    if type(record["version"]) is not int or record["version"] not in (0, 1):
        raise ValueError("Unsupported cookie version")
    expires = record["expires"]
    if expires is not None and (type(expires) is not int or not _scalar(expires)):
        raise ValueError("Invalid cookie expiry")
    for field in ("name", "value", "port", "domain", "path"):
        value = record[field]
        if value is None and field in ("value", "port"):
            continue
        if not isinstance(value, str) or any(c in value for c in "\r\n\x00"):
            raise ValueError("Invalid cookie text field")
        value.encode("utf-8")
    for field in ("comment", "comment_url"):
        if not _scalar(record[field]):
            raise ValueError("Invalid cookie metadata")
    rest = record["rest"]
    if not isinstance(rest, dict) or any(
        not isinstance(key, str) or not _scalar(key) or not _scalar(value)
        for key, value in rest.items()
    ):
        raise ValueError("Invalid cookie extension metadata")
    try:
        return Cookie(**record)
    except (AssertionError, TypeError, ValueError, OverflowError) as error:
        raise ValueError("Invalid cookie record") from error


def _eligible(cookie, include_session, now):
    return not cookie.is_expired(now) and (
        include_session or (not cookie.discard and cookie.expires is not None)
    )


def _check_jar(jar, include_session):
    if not isinstance(jar, CookieJar):
        raise TypeError("Cookie file operations require a CookieJar")
    if type(include_session) is not bool:
        raise TypeError("include_session must be a bool")


def save_cookie_file(jar, path, *, include_session=False):
    """Save an atomic, private JSON snapshot; return the number saved."""
    _check_jar(jar, include_session)
    now = time.time()
    records = []
    with jar._cookies_lock:
        for cookie in jar:
            if not _eligible(cookie, include_session, now):
                continue
            record = {field: getattr(cookie, field) for field in FIELDS}
            record["rest"] = dict(cookie._rest)
            _parse_cookie(record)
            records.append(record)
            if len(records) > MAX_COOKIES:
                raise ValueError("Too many cookies in file")
    payload = (
        json.dumps(
            {"format": FORMAT, "version": 1, "cookies": records},
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > MAX_FILE_BYTES:
        raise ValueError("Cookie file exceeds size limit")
    target = Path(path)
    fd, temporary = tempfile.mkstemp(
        prefix=".ja3requests-cookies-", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
    return len(records)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _integer(value):
    if len(value.lstrip("-")) > 19:
        raise ValueError("Cookie file integer exceeds limit")
    result = int(value)
    if not _scalar(result):
        raise ValueError("Cookie file integer exceeds limit")
    return result


def _constant(_value):
    raise ValueError("Invalid JSON numeric constant")


def load_cookie_file(jar, path, *, merge=False, include_session=False):
    """Validate the whole file before replacing/merging; return the number loaded."""
    _check_jar(jar, include_session)
    if type(merge) is not bool:
        raise TypeError("merge must be a bool")
    with open(path, "rb") as source:
        payload = source.read(MAX_FILE_BYTES + 1)
    if len(payload) > MAX_FILE_BYTES:
        raise ValueError("Cookie file exceeds size limit")
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_object,
            parse_int=_integer,
            parse_constant=_constant,
        )
    except (ValueError, RecursionError) as error:
        raise ValueError("Invalid cookie JSON file") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"format", "version", "cookies"}
        or document["format"] != FORMAT
        or type(document["version"]) is not int
        or document["version"] != 1
        or not isinstance(document["cookies"], list)
    ):
        raise ValueError("Unsupported cookie file schema")
    if len(document["cookies"]) > MAX_COOKIES:
        raise ValueError("Too many cookies in file")
    selected = []
    identities = set()
    now = time.time()
    for record in document["cookies"]:
        cookie = _parse_cookie(record)
        identity = (cookie.domain, cookie.path, cookie.name)
        if identity in identities:
            raise ValueError("Duplicate cookie identity")
        identities.add(identity)
        if _eligible(cookie, include_session, now):
            selected.append(cookie)
    with jar._cookies_lock:
        staged = (
            {
                domain: {path: values.copy() for path, values in paths.items()}
                for domain, paths in jar._cookies.items()
            }
            if merge
            else {}
        )
        for cookie in selected:
            staged.setdefault(cookie.domain, {}).setdefault(cookie.path, {})[
                cookie.name
            ] = cookie
        jar._cookies = staged
    return len(selected)
