import warnings
from http.cookiejar import CookieJar
from urllib.parse import urlparse, parse_qs
from ja3requests.utils import default_headers
from ja3requests.exceptions import (
    NotAllowedRequestMethod,
    MissingScheme,
    NotAllowedScheme,
    InvalidParams,
    InvalidData,
)
from .http import HttpRequest
from .https import HttpsRequest
from io import IOBase
from typing import Any, AnyStr, List, Dict, Tuple, Union


class Request:

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
            data: Union[
                Dict[AnyStr, Any],
                List,
                Tuple,
                AnyStr
            ] = None,
            headers: Dict[AnyStr, AnyStr] = None,
            cookies: Union[Dict[AnyStr, AnyStr], CookieJar] = None,
            files: Union[List[IOBase, ...], IOBase] = None,
            auth: Tuple = None,
            json: Dict[AnyStr, AnyStr] = None,
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

        if schema == "http":
            req = HttpRequest()
            req.set_payload(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers,
                cookies=cookies,
                auth=auth,
                json=_json,
                timeout=self.timeout,
            )
            return req
        elif schema == "https":
            req = HttpsRequest()
            req.set_payload(
                method=method,
                url=url,
                params=params,
                data=data,
                headers=headers,
                cookies=cookies,
                auth=auth,
                json=_json
            )
            return req
        else:
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

        if url == "":
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

        if params:
            # parse = urlparse(self.url)
            if type(params) not in [str, bytes, dict, list, tuple]:
                raise InvalidParams(f"Invalid params: {self.params!r}")

        return params

    def __ready_headers(self):
        """
        Ready http headers.
        :return:
        """

        headers = self.headers

        # Check duplicate default item
        if headers:
            header_list = []
            for k, v in headers.items():
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
        if data:
            if self.json:
                raise InvalidData("Only one of the data and json parameters can be used at the same time")

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
                    raise InvalidData(f"Invalid data: {data!r}. The data parameter of iterable type is empty")

                if not all(list(map(lambda x: isinstance(x, tuple), data))):
                    raise InvalidData(
                        f"Invalid data: {data!r}. The data parameter item of iterable type must be a tuple"
                    )

            if isinstance(data, (bytes, str)):
                try:
                    parse_qs(data)
                except AttributeError:
                    raise InvalidData(f"Invalid data: {data!r}")

        return data

    def __ready_cookies(self):
        """
        Todo: Ready http cookies.
        :return:
        """

        cookies = self.cookies

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
        if _json:
            if self.data:
                raise ValueError("Only one of the data and json parameters can be used at the same time")

            if self.method.upper() not in ["POST", "PUT"]:
                warnings.warn(
                    f"The {self.method.upper()} method does not process data."
                    f"Maybe you request the POST/PUT method?",
                    RuntimeWarning,
                )

            if not isinstance(self.json, (dict, str, bytes)):
                raise ValueError(f"Invalid json: {self.json!r}")

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
        if isinstance(files, list):
            for file in files:
                if not isinstance(file, IOBase):
                    raise AttributeError("The files parameter must be an IO object")
                else:
                    if not file.readable():
                        raise AttributeError("IO object is not readable")
        elif isinstance(files, IOBase):
            if not files.readable():
                raise AttributeError("IO object is not readable")
        else:
            raise AttributeError("The files parameter must be an IO object")

        return files
