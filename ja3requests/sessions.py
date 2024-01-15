"""
Ja3Requests.sessions
~~~~~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
ja3Requests.
"""
import sys
import time
from io import IOBase
from http.cookiejar import CookieJar
from typing import AnyStr, Any, Dict, ByteString, Union, List, Tuple
from ja3requests.base import BaseSession
from ja3requests.response import Response
from ja3requests.const import DEFAULT_REDIRECT_LIMIT
from ja3requests.base import BaseRequest
from ja3requests.requests.request import Request
from ja3requests.exceptions import MaxRetriedException

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
        data: Union[
            Dict[Any, Any], List[Tuple[Any, Any]], Tuple[Tuple[Any, Any]], AnyStr
        ] = None,
        headers: Dict[AnyStr, AnyStr] = None,
        cookies: Union[Dict[AnyStr, AnyStr], CookieJar, AnyStr] = None,
        files: Dict[AnyStr, Union[List[Union[AnyStr, IOBase]], IOBase, AnyStr]] = None,
        auth: Tuple = None,
        proxies: Dict[AnyStr, AnyStr] = None,
        json: Union[Dict[AnyStr, AnyStr], AnyStr] = None,
        **kwargs
    ):
        """
        Instantiating a request class<Request> and ready request<ReadyRequest> to send.
        :param method:
        :param url:
        :param params:
        :param data:
        :param headers:
        :param cookies:
        :param files:
        :param auth:
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
            files=files,
            auth=auth,
            json=json,
            proxies=proxies,
        )

        kwargs.setdefault("timeout", None)
        kwargs.setdefault("allow_redirects", True)

        req = self.Request.request()
        response = self.send(req, **kwargs)

        return response

    def get(self, url, params=None, headers=None, **kwargs):
        """
        Send a GET request.
        :param url:
        :param params:
        :param headers:
        :param kwargs:
        :return:
        """

        return self.request("GET", url, params=params, headers=headers, **kwargs)

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

    def post(self, url, data=None, json=None, files=None, headers=None, **kwargs):
        """
        Send a POST request.
        :param url:
        :param data:
        :param json:
        :param files:
        :param headers:
        :param kwargs:
        :return:
        """

        return self.request(
            "POST", url, data=data, json=json, files=files, headers=headers, **kwargs
        )

    def put(self, url, **kwargs):
        """
        Send a PUT request.
        :param url:
        :param kwargs:
        :return:
        """

        return self.request("PUT", url, **kwargs)

    def patch(self, url, **kwargs):
        """
        Send a PATCH request.
        :param url:
        :param kwargs:
        :return:
        """

        return self.request("PATCH", url, **kwargs)

    def delete(self, url, **kwargs):
        """
        Send a DELETE request.
        :param url:
        :param kwargs:
        :return:
        """

        return self.request("DELETE", url, **kwargs)

    def send(self, request: BaseRequest, **kwargs):
        """
        Send request.
        :return:
        """

        if not isinstance(request, BaseRequest):
            raise ValueError("You can only send HttpRequest/HttpsRequest.")

        rep = request.send()
        response = Response(request, rep)
        allow_redirects = kwargs.get("allow_redirects", True)
        if allow_redirects and response.is_redirected:
            response = self.resolve_redirects(response.location, **kwargs)

        self.response = response

        return response

    def resolve_redirects(self, url, **kwargs):
        """
        Handle response redirects
        :param url:
        :param kwargs:
        :return:
        """
        send_kwargs = kwargs

        for _ in range(DEFAULT_REDIRECT_LIMIT):
            req = Request(
                method="GET",
                url=url,
                headers=self.Request.headers,
                cookies=self.Request.cookies,
                proxies=self.Request.proxies,
            ).request()

            response = self.send(req, **send_kwargs)
            if 400 <= response.status_code or response.status_code < 300:
                break
        else:
            raise MaxRetriedException("Too many redirects")

        return response
