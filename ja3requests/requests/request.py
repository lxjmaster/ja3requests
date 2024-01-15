"""
Ja3Requests.requests.request
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module of Request.
"""


import os
import warnings
from io import IOBase
from http.cookiejar import CookieJar
from urllib.parse import urlparse, parse_qs
from typing import Any, AnyStr, List, Dict, Tuple, Union
from ja3requests.requests.https import HttpsRequest
from ja3requests.requests.http import HttpRequest
from ja3requests.exceptions import (
    NotAllowedRequestMethod,
    MissingScheme,
    NotAllowedScheme,
    InvalidParams,
    InvalidData,
)


class Request:
    """
    Request
    """

    def __init__(
        self,
        method: AnyStr,
        url: AnyStr,
        params: Union[
            Dict[AnyStr, Any],
            List[Tuple[Any, Any]],
            Tuple[Tuple[Any, Any]],
            AnyStr,
        ] = None,
        data: Union[Dict[AnyStr, Any], List, Tuple, AnyStr] = None,
        headers: Dict[AnyStr, AnyStr] = None,
        cookies: Union[Dict[AnyStr, AnyStr], CookieJar, AnyStr] = None,
        files: Dict[AnyStr, Union[List[Union[AnyStr, IOBase]], IOBase, AnyStr]] = None,
        auth: Tuple = None,
        json: Dict[AnyStr, AnyStr] = None,
        proxies: Dict[AnyStr, AnyStr] = None,
        timeout: float = None,
    ):
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

    def __repr__(self):
        return f"<Request [{self.method}]>"

    def request(self):
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
        cookies = self.__ready_cookies()
        auth = self.__ready_auth()
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
                auth=auth,
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
                auth=auth,
                json=_json,
                proxies=proxies,
                timeout=self.timeout,
            )
            return req

        raise NotAllowedScheme(f"Schema: {schema} not allowed.")

    def __ready_method(self):
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

    def __ready_url(self):
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

    def __ready_params(self):
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

    def __ready_headers(self):
        """
        Ready http headers.
        :return:
        """

        headers = self.headers
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

    def __ready_data(self):
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

    def __ready_cookies(self):
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

    def __ready_auth(self):
        """
        Todo: Ready http authenticator
        :return:
        """

        auth = self.auth

        return auth

    def __ready_json(self):
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

    def __ready_files(self):
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

    def __read_proxies(self):
        """
        Read proxies
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

        for schema in proxies:
            if schema not in ("http", "https"):
                raise AttributeError(
                    f"Invalid proxy schema: {schema!r}.",
                    "The schema is only support http or https.",
                )

        return proxies
