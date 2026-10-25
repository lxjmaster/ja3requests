"""Runtime boundaries represented by the utility type contracts."""

from http.cookiejar import CookieJar

import pytest

from ja3requests.cookies import Ja3RequestsCookieJar, create_cookie
from ja3requests.utils import (
    Retry,
    Task,
    add_dict_to_cookiejar,
    default_user_agent,
    dict_from_cookiejar,
    make_headers,
)


def test_optional_header_arguments_and_byte_user_agent():
    headers = make_headers(
        keep_alive=None,
        accept_encoding=None,
        user_agent=None,
        basic_auth=None,
        proxy_basic_auth=None,
        disable_cache=None,
    )
    assert set(headers) == {'Accept', 'User-Agent'}
    assert make_headers(user_agent=b'Agent')['User-Agent'] == b'Agent'
    assert "b'Agent'/" in default_user_agent(b'Agent')


def test_byte_encoding_input_keeps_the_existing_fallback():
    assert make_headers(accept_encoding=b'br')['Accept-Encoding'] == 'gzip,deflate'
    assert 'Accept-Encoding' not in make_headers(accept_encoding=b'')


@pytest.mark.parametrize('keyword', ['basic_auth', 'proxy_basic_auth'])
def test_nonempty_byte_credentials_remain_unsupported(keyword):
    with pytest.raises(AttributeError):
        make_headers(**{keyword: b'user:pass'})


def test_byte_encoding_list_remains_unsupported():
    with pytest.raises(TypeError):
        make_headers(accept_encoding=[b'gzip'])


def test_generic_task_preserves_failure_sentinel_and_forwarded_results():
    calls = []
    value = object()

    def operation(argument, *, result):
        calls.append(argument)
        if len(calls) == 1:
            raise OSError('retry')
        return result

    task = Task(operation, 2, (ValueError, OSError), 'argument', result=value)
    assert task.retry() == 0
    assert task.times == 1
    assert task.retry() is value
    assert task.times == 0
    assert calls == ['argument', 'argument']
    assert Retry().do(lambda *, result: result, ValueError, result=value) is value


def test_cookie_helpers_preserve_null_values_and_jar_identity():
    jar = Ja3RequestsCookieJar()
    jar.set_cookie(create_cookie('flag', None))
    assert dict_from_cookiejar(iter(jar)) == {'flag': None}
    assert add_dict_to_cookiejar(jar, {'name': 'value'}) is jar
    assert jar['name'] == 'value'
    assert isinstance(add_dict_to_cookiejar(None, None), CookieJar)
