"""
Ja3Requests.utils
~~~~~~~~~~~~~~~~~

This module provides utility functions.
"""

import platform
from base64 import b64encode
from typing import Union, AnyStr, List
from .const import DEFAULT_MAX_RETRY_LIMIT
from .exceptions import MaxRetriedException
from .cookies import cookiejar_from_dict
from .__version__ import __version__


ACCEPT_ENCODING = "gzip,deflate"


def b(s: AnyStr):  # pylint: disable=C
    """
    String encode latin1
    :param s:
    :return:
    """
    return s.encode("latin1")


def default_user_agent(agent: AnyStr = "Ja3Requests"):
    """
    Return a string representing the default user agent.
    :param agent:
    :return: str
    """

    return f"Python/{platform.python_version()} ({platform.system()}; {platform.platform()}) {agent}/{__version__}"


def make_headers(
    keep_alive: bool = None,
    accept_encoding: Union[AnyStr, List[AnyStr]] = None,
    user_agent: AnyStr = None,
    basic_auth: AnyStr = None,
    proxy_basic_auth: AnyStr = None,
    disable_cache: bool = None,
):
    """
    Shortcuts for generating request headers.
    :param keep_alive:
    :param accept_encoding:
    :param user_agent:
    :param basic_auth: username:password
    :param proxy_basic_auth: username:password
    :param disable_cache:
    :return: dict
    """
    headers = {"Accept": "*/*"}
    if accept_encoding:
        if isinstance(accept_encoding, str):
            pass
        elif isinstance(accept_encoding, list):
            accept_encoding = ",".join(accept_encoding)
        else:
            accept_encoding = ACCEPT_ENCODING
        headers["Accept-Encoding"] = accept_encoding

    if keep_alive:
        headers["Connection"] = "keep-alive"

    if basic_auth:
        headers["Authorization"] = "Basic " + b64encode(b(basic_auth)).decode("utf-8")

    if proxy_basic_auth:
        headers["Proxy-Authorization"] = "Basic " + b64encode(
            b(proxy_basic_auth)
        ).decode("utf-8")

    if disable_cache:
        headers["Cache-Control"] = "no-cache"

    headers["User-Agent"] = user_agent if user_agent else default_user_agent()

    return headers


def default_headers():
    """
    Return default headers.
    :return:
    """

    return make_headers(keep_alive=True)


class SingletonMeta(type):
    """
    SingletonMeta Class
    """

    _instance = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instance:
            cls._instance[cls] = super(SingletonMeta, cls).__call__(*args, **kwargs)

        return cls._instance[cls]


class Retry(metaclass=SingletonMeta):
    """
    Retry Class
    """

    _tasks = {}

    def do(self, obj, exception, *args, **kwargs):
        """
        Method of run retry task
        :param obj:
        :param exception:
        :param args:
        :param kwargs:
        :return:
        """
        if obj not in self._tasks:
            self._tasks[obj] = Task(
                obj, DEFAULT_MAX_RETRY_LIMIT, exception, *args, **kwargs
            )

        while self._tasks[obj].times > 0:
            result = self._tasks[obj].retry()
            if result != 0:
                return result

        raise MaxRetriedException(f"Max retries exceeded with {obj!r}")


class Task:
    """
    Retry Task
    """

    def __init__(self, task, times, exception, *args, **kwargs):
        self.task = task
        self.times = times
        self.exception = exception
        self.args = args
        self.kwargs = kwargs

    def retry(self):
        """
        retry method
        :return:
        """
        self.times -= 1
        try:
            return self.task(*self.args, **self.kwargs)
        except self.exception:
            return 0


def dict_from_cookie_string(cookie_string: AnyStr):
    """Returns a key/value dictionary from a cookie string like name1=value1;name2=value2;...

    :param cookie_string:
    :return: dict
    """

    cookie_dict = {}
    if isinstance(cookie_string, bytes):
        cookie_string = cookie_string.decode()

    cookie_list = cookie_string.split(";")
    for cookie in cookie_list:
        cookie = cookie.strip()
        name, value = cookie.split("=")
        cookie_dict.setdefault(name, value)

    return cookie_dict


def dict_from_cookiejar(cj):
    """Returns a key/value dictionary from a CookieJar.

    :param cj: CookieJar object to extract cookies from.
    :rtype: dict
    """

    cookie_dict = {}

    for cookie in cj:
        cookie_dict[cookie.name] = cookie.value

    return cookie_dict


def add_dict_to_cookiejar(cj, cookie_dict):
    """Returns a CookieJar from a key/value dictionary.

    :param cj: CookieJar to insert cookies into.
    :param cookie_dict: Dict of key/values to insert into CookieJar.
    :rtype: CookieJar
    """

    return cookiejar_from_dict(cookie_dict, cj)
