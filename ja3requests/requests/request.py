"""
Ja3Requests.requests.request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module of Request.
"""

from __future__ import annotations

import os
import warnings
from io import IOBase
from http.cookiejar import CookieJar
from urllib.parse import urlparse, parse_qs
from typing import TYPE_CHECKING, Optional, Tuple, Union
from ja3requests._typing import (
    Auth,
    Cookies,
    Data,
    Files,
    Headers,
    JsonBody,
    Params,
    Proxies,
    Timeout,
)
from ja3requests.requests.https import HttpsRequest
from ja3requests.requests.http import HttpRequest
from ja3requests.exceptions import (
    NotAllowedRequestMethod,
    MissingScheme,
    NotAllowedScheme,
    InvalidParams,
    InvalidData,
)

if TYPE_CHECKING:
    from ja3requests.protocol.tls.config import TlsConfig


class Request:
    """
    Request
    """

    def __init__(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Params] = None,
        data: Optional[Data] = None,
        headers: Optional[Headers] = None,
        cookies: Optional[Cookies] = None,
        files: Optional[Files] = None,
        auth: Optional[Auth] = None,
        json: Optional[JsonBody] = None,
        proxies: Optional[Proxies] = None,
        timeout: Timeout = None,
        tls_config: Optional[TlsConfig] = None,
    ) -> None:
        self.method = method
        self.url = url
        self.params = params
        self.data = data
        self.headers = headers
        self.cookies = cookies
        self.files = files
        self.auth = auth
        self.json = json
        self.proxies = proxies
        self.timeout = timeout
        self.tls_config = tls_config

    def __repr__(self) -> str:
        return f"<Request [{self.method}]>"

    def request(self) -> Union[HttpRequest, HttpsRequest]:
        """
        Make a ready request to send.
        :return:
        """
        method = self.__ready_method()
        schema, url = self.__ready_url()
        params = self.__ready_params()
        data = self.__ready_data()
        _json = self.__ready_json()
        files = self.__ready_files()
        headers = self.__ready_headers()
        headers = self.__ready_auth(headers)
        cookies = self.__ready_cookies()
        proxies = self.__read_proxies()

        if schema == "http":
            req = HttpRequest()
            req.set_payload(
                method=method,
                url=url,
                params=params,
                data=data,
                files=files,
                headers=headers,
                cookies=cookies,
                auth=self.auth,
                json=_json,
                proxy=proxies,
                timeout=self.timeout,
            )
            return req

        if schema == "https":
            req = HttpsRequest()
            req.set_payload(
                method=method,
                url=url,
                params=params,
                data=data,
                files=files,
                headers=headers,
                cookies=cookies,
                auth=self.auth,
                json=_json,
                proxy=proxies,
                timeout=self.timeout,
                tls_config=self.tls_config,
            )
            return req

        raise NotAllowedScheme(f"Schema: {schema} not allowed.")

    def __ready_method(self) -> str:
        """
        Ready request method and check request method whether allow used.
        :return:
        """

        method = self.method.upper()
        if method == "" or method not in [
            "GET",
            "OPTIONS",
            "HEAD",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ]:
            raise NotAllowedRequestMethod(method)

        return method

    def __ready_url(self) -> Tuple[str, str]:
        """
        Ready http url and check url whether valid.
        :return:
        """
        url = self.url

        if not url or url == "":
            raise ValueError("The request url is require.")

        # Remove whitespaces for url
        url = url.strip()

        parse = urlparse(url)

        # Check HTTP scheme
        if parse.scheme == "":
            raise MissingScheme(
                f"Invalid URL {self.url!r}: No scheme supplied. "
                f"Perhaps you meant http://{self.url} or https://{self.url}"
            )

        # Just allow http or https
        if parse.scheme not in ["http", "https"]:
            raise NotAllowedScheme(f"Schema: {parse.scheme} not allowed.")

        return parse.scheme, url

    def __ready_params(self) -> Optional[Params]:
        """
        Ready params.
        :return:
        """
        params = self.params
        if not params:
            return params

        # parse = urlparse(self.url)
        if not isinstance(params, (str, bytes, dict, list, tuple)):
            raise InvalidParams(f"Invalid params: {self.params!r}")

        return params

    def __ready_headers(self) -> Optional[Headers]:
        """
        Ready http headers.
        :return:
        """

        headers = self.headers
        if headers is None:
            return None
        headers = dict(headers)
        if not headers:
            return headers

        # Check duplicate default item
        header_list = []
        for k, _ in headers.items():
            if k.lower() in header_list:
                warnings.warn(
                    f"Duplicate header: {k}, you should check the request headers.",
                    RuntimeWarning,
                )
            header_list.append(k.lower())

        return headers

    def __ready_data(self) -> Optional[Data]:
        """
        Ready form data.
        :return:
        """
        data = self.data
        if not data:
            return data

        if self.json:
            raise InvalidData(
                "Only one of the data and json parameters can be used at the same time"
            )

        if self.method.upper() not in ["POST", "PUT"]:
            warnings.warn(
                f"The {self.method.upper()} method does not process data."
                f"Maybe you request the POST/PUT method?",
                RuntimeWarning,
            )

        if not isinstance(data, (dict, list, tuple, bytes, str)):
            raise InvalidData(f"Invalid data: {data!r}")

        if isinstance(data, (list, tuple)):
            if len(data) < 1:
                raise InvalidData(
                    f"Invalid data: {data!r}. The data parameter of iterable type is empty"
                )

            if not all(list(map(lambda x: isinstance(x, tuple), data))):
                raise InvalidData(
                    f"Invalid data: {data!r}. The data parameter item of iterable type must be a tuple"
                )

        if isinstance(data, (bytes, str)):
            try:
                parse_qs(data)
            except AttributeError as err:
                raise InvalidData(f"Invalid data: {data!r}") from err

        return data

    def __ready_cookies(self) -> Optional[Cookies]:
        """
        :return:
        """

        cookies = self.cookies
        if not cookies:
            return cookies

        if not isinstance(cookies, (dict, CookieJar, bytes, str)):
            raise AttributeError(
                f"Invalid cookies: {cookies!r}."
                "Cookies type only support dict, CookieJar, bytes, str"
            )

        if isinstance(cookies, (dict, bytes, str)):
            if len(cookies) < 1:
                raise AttributeError("Invalid cookies, it's empty.")

        return cookies

    def __ready_auth(self, headers: Optional[Headers]) -> Optional[Headers]:
        """
        Ready HTTP authentication. Supports Basic Auth tuple (username, password).
        Returns headers dict with Authorization header added if auth is set.
        :param headers: Headers dict to modify.
        :return: headers dict (possibly new if input was None)
        """
        auth = self.auth
        if not auth:
            return headers

        if isinstance(auth, tuple) and len(auth) == 2:
            from ja3requests.utils import b  # pylint: disable=import-outside-toplevel
            from base64 import b64encode  # pylint: disable=import-outside-toplevel

            username, password = auth
            credentials = b64encode(b(f"{username}:{password}")).decode("utf-8")
            if headers is None:
                from ja3requests.utils import (
                    default_headers,
                )  # pylint: disable=import-outside-toplevel

                headers = default_headers()
            headers["Authorization"] = f"Basic {credentials}"

        return headers

    def __ready_json(self) -> Optional[JsonBody]:
        """
        Ready post json.
        :return:
        """

        _json = self.json
        if not _json:
            return _json

        if self.data or self.files:
            raise ValueError(
                "Only one of the data/files and json parameters can be used at the same time"
            )

        if self.method.upper() not in ["POST", "PUT"]:
            warnings.warn(
                f"The {self.method.upper()} method does not process data."
                f"Maybe you request the POST/PUT method?",
                RuntimeWarning,
            )

        if not isinstance(self.json, (dict, str, bytes)):
            raise ValueError(f"Invalid json: {self.json!r}")

        if self.headers:
            for name, value in self.headers.items():
                if name.title() == "Content-Type" and value == "multipart/form-data":
                    warnings.warn(
                        "When sending a json data, the Content-Type header should be set to application/json",
                        RuntimeWarning,
                    )
                    break

        return _json

    def __ready_files(self) -> Optional[Files]:
        """
        Ready post file
        :return:
        """
        files = self.files
        if not files:
            return files

        if not isinstance(files, dict):
            raise AttributeError(
                "The files parameter is invalid, reference structure: {'file': FileObject}"
            )

        for _, file in files.items():
            if isinstance(file, list):
                for f in file:
                    if isinstance(f, (str, bytes)) and not os.path.isfile(f):
                        raise AttributeError(f"{f} is not a file")
                    if isinstance(f, IOBase) and not f.readable():
                        raise AttributeError("IO object is not readable")

            if isinstance(file, (str, bytes)) and not os.path.isfile(file):
                raise AttributeError(f"{file} is not a file")

            if isinstance(file, IOBase) and not file.readable():
                raise AttributeError("IO object is not readable")

        if self.headers:
            for name, value in self.headers.items():
                if name.title() == "Content-Type" and value != "multipart/form-data":
                    warnings.warn(
                        "When sending a files data, the Content-Type header should be set to multipart/form-data",
                        RuntimeWarning,
                    )
                break

        return files

    def __read_proxies(self) -> Optional[Proxies]:
        """
        Read proxies.
        Supports http, https, socks4, socks5 schemes.
        Format: {'https': 'socks5://user:pass@host:port'} or {'https': 'host:port'}
        :return:
        """
        proxies = self.proxies
        if not proxies:
            return proxies

        if not isinstance(proxies, dict):
            raise AttributeError(
                f"Invalid proxies attribute: {proxies!r}."
                "The property structure should look like "
                "{'http': 'username:password@host:port', 'https': 'username:password@host:port'}"
            )

        valid_keys = ("http", "https")
        for schema in proxies:
            if schema not in valid_keys:
                raise AttributeError(
                    f"Invalid proxy schema: {schema!r}.",
                    "The schema is only support http or https.",
                )

        return proxies
