"""
ja3Requests.sessions
~~~~~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
ja3Requests.
"""
import sys
import time
from http.cookiejar import CookieJar
from typing import AnyStr, Any, Dict, ByteString, Union, List, Tuple
from ja3requests.base import BaseSession
from .response import Response
from .utils import default_headers
from .const import DEFAULT_REDIRECT_LIMIT
from ja3requests.base import BaseRequest
from ja3requests.requests.request import Request
from urllib.parse import parse_qs

# Preferred clock, based on which one is more accurate on a given system.
if sys.platform == "win32":
    preferred_clock = time.perf_counter
else:
    preferred_clock = time.time


class Session(BaseSession):
    """A Ja3Request session.

    Provides cookie persistence, connection-pooling, and configuration.
    """

    def request(
        self,
        method: AnyStr,
        url: AnyStr,
        params: Union[Dict[AnyStr, Any], ByteString] = None,
        data: Union[Dict[Any, Any], List[Tuple[Any, Any]], Tuple[Tuple[Any, Any]], AnyStr] = None,
        headers: Dict[AnyStr, AnyStr] = None,
        cookies: Union[Dict[AnyStr, AnyStr], CookieJar] = None,
        # files = None,
        auth: Tuple = None,
        timeout: float = None,
        allow_redirects: bool = True,
        proxies: Dict[AnyStr, AnyStr] = None,
        json: Dict[AnyStr, AnyStr] = None,
    ):
        """
        Instantiating a request class<Request> and ready request<ReadyRequest> to send.
        :param method:
        :param url:
        :param params:
        :param data:
        :param headers:
        :param cookies:
        :param auth:
        :param timeout:
        :param allow_redirects:
        :param proxies:
        :param json:
        :return:
        """

        self.Request = Request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
            cookies=cookies,
            auth=auth,
            json=json,
        )

        req = self.Request.request()
        response = self.send(req)

        return response

    def get(self, url, **kwargs):
        """
        Send a GET request.
        :param url:
        :param kwargs:
        :return:
        """

        return self.request("GET", url, **kwargs)

    def options(self, url, **kwargs):
        """
        Send a OPTIONS request.
        :param url:
        :param kwargs:
        :return:
        """

        return self.request("OPTIONS", url, **kwargs)

    def head(self, url, **kwargs):
        """
        Send a HEAD request.
        :param url:
        :param kwargs:
        :return:
        """

        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        """
        Send a POST request.
        :param url:
        :param data:
        :param json:
        :param kwargs:
        :return:
        """

        return self.request("POST", url, data=data, json=json, **kwargs)

    def put(self, url, data=None, **kwargs):
        """
        Send a PUT request.
        :param url:
        :param data:
        :param kwargs:
        :return:
        """

        return self.request("PUT", url, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        """
        Send a PATCH request.
        :param url:
        :param data:
        :param kwargs:
        :return:
        """

        return self.request("PATCH", url, data=data, **kwargs)

    def delete(self, url, data=None, **kwargs):
        """
        Send a DELETE request.
        :param url:
        :param data:
        :param kwargs:
        :return:
        """

        return self.request("DELETE", url, **kwargs)

    def send(self, request: BaseRequest):
        """
        Send request.
        :return:
        """

        rep = request.send()
        response = Response(rep)

        return response
