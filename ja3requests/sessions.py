"""
Ja3Requests.sessions
~~~~~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
ja3Requests.
"""

import copy
import sys
import time
from io import IOBase
from http.cookiejar import CookieJar
from typing import AnyStr, Any, Dict, Union, List, Tuple, Optional
from ja3requests.base import BaseSession
from ja3requests.response import Response
from ja3requests.const import DEFAULT_REDIRECT_LIMIT
from ja3requests.base import BaseRequest
from ja3requests.requests.request import Request
from ja3requests.exceptions import MaxRetriedException
from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.pool import ConnectionPool, get_default_pool
from ja3requests.cookies import Ja3RequestsCookieJar, merge_cookies

# Preferred clock, based on which one is more accurate on a given system.
if sys.platform == "win32":
    preferred_clock = time.perf_counter
else:
    preferred_clock = time.time


class Session(BaseSession):
    """A Ja3Request session.

    Provides cookie persistence, connection-pooling, and configuration.
    """

    def __init__(
        self,
        tls_config: TlsConfig = None,
        pool: Optional[ConnectionPool] = None,
        use_pooling: bool = True,
    ):
        super().__init__()
        self._tls_config = tls_config or TlsConfig()
        self._use_pooling = use_pooling
        self._pool = (
            pool if pool is not None else (get_default_pool() if use_pooling else None)
        )

    @property
    def tls_config(self) -> TlsConfig:
        """Get TLS configuration"""
        return self._tls_config

    @tls_config.setter
    def tls_config(self, config: TlsConfig):
        """Set TLS configuration"""
        self._tls_config = config

    @property
    def pool(self) -> Optional[ConnectionPool]:
        """Get connection pool"""
        return self._pool

    @pool.setter
    def pool(self, pool: Optional[ConnectionPool]):
        """Set connection pool"""
        self._pool = pool

    def close(self):
        """Close the session and all pooled connections"""
        if self._pool and self._pool is not get_default_pool():
            self._pool.close_all()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def request(  # pylint: disable=too-many-locals
        self,
        method: AnyStr,
        url: AnyStr,
        *,
        params: Union[Dict[AnyStr, Any], bytes] = None,
        data: Union[
            Dict[Any, Any], List[Tuple[Any, Any]], Tuple[Tuple[Any, Any]], AnyStr
        ] = None,
        headers: Dict[AnyStr, AnyStr] = None,
        cookies: Union[Dict[AnyStr, AnyStr], CookieJar, AnyStr] = None,
        files: Dict[AnyStr, Union[List[Union[AnyStr, IOBase]], IOBase, AnyStr]] = None,
        auth: Tuple = None,
        proxies: Dict[AnyStr, AnyStr] = None,
        json: Union[Dict[AnyStr, AnyStr], AnyStr] = None,
        timeout: Optional[float] = None,
        verify: bool = False,
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
        :param auth: Tuple of (username, password) for Basic Auth.
        :param proxies:
        :param json:
        :param timeout: Timeout in seconds for connect and read.
        :param verify: Whether to verify TLS certificates. Default False.
        :return:
        """

        # Apply verify to TLS config (deep copy to avoid mutating session config)
        tls_config = self._tls_config
        if verify != tls_config.verify_cert:
            tls_config = copy.deepcopy(self._tls_config)
            tls_config.verify_cert = verify

        # Merge session-level cookies with per-request cookies
        merged_cookies = Ja3RequestsCookieJar()
        if len(self._cookies) > 0:
            merge_cookies(merged_cookies, self._cookies)
        if cookies is not None:
            merge_cookies(merged_cookies, cookies)

        self.Request = Request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
            cookies=merged_cookies if len(merged_cookies) > 0 else None,
            files=files,
            auth=auth,
            json=json,
            proxies=proxies,
            timeout=timeout,
            tls_config=tls_config,
        )

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
        # Extract tls_config from kwargs if provided
        tls_config = kwargs.pop('tls_config', None)
        if tls_config:
            # Use the provided tls_config for this request
            original_config = self._tls_config
            self._tls_config = tls_config
            try:
                result = self.request(
                    "GET", url, params=params, headers=headers, **kwargs
                )
                return result
            finally:
                # Restore original config
                self._tls_config = original_config
        else:
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

    def post(self, url, *, data=None, json=None, files=None, headers=None, **kwargs):
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

        # Pass connection pool to request
        kwargs['pool'] = self._pool

        stream = kwargs.pop("stream", False)
        rep = request.send(**kwargs)
        response = Response(request, rep, stream=stream)

        # Persist response cookies into the session cookie jar
        if response.cookies:
            merge_cookies(self._cookies, response.cookies)

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
        from urllib.parse import urljoin, urlparse  # pylint: disable=import-outside-toplevel

        send_kwargs = kwargs
        # Get the original URL to resolve relative redirects
        original_url = self.Request.url

        for _ in range(DEFAULT_REDIRECT_LIMIT):
            # Handle relative URLs by joining with the original URL
            if not urlparse(url).scheme:
                url = urljoin(original_url, url)

            req = Request(
                method="GET",
                url=url,
                headers=self.Request.headers,
                cookies=self._cookies,
                proxies=self.Request.proxies,
                tls_config=self._tls_config,
            ).request()

            response = self.send(req, **send_kwargs)
            if 400 <= response.status_code or response.status_code < 300:
                break

            # Update URL for next redirect and original_url for relative resolution
            if response.is_redirected and response.location:
                original_url = url
                url = response.location
        else:
            raise MaxRetriedException("Too many redirects")

        return response
