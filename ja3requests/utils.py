"""
ja3requests.utils
~~~~~~~~~~~~~~~~~

This module provides utility functions.
"""

import platform
from base64 import b64encode
from typing import Union, AnyStr, List
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

    headers["User-Agent"] = user_agent if user_agent else default_user_agent()

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

    return headers


def default_headers():
    """
    Return default headers.
    :return:
    """

    return make_headers(keep_alive=True)
