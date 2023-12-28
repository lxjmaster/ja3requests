import typing
import warnings
from http.cookiejar import CookieJar
from urllib.parse import urlparse, urlencode
from ja3requests.utils import default_headers
from ja3requests.exceptions import (
    NotAllowedRequestMethod,
    MissingScheme,
    NotAllowedScheme,
    InvalidParams,
)
from .http import HttpRequest
from .https import HttpsRequest
from ja3requests.contexts.context import HTTPContext, HTTPSContext


class Request:

    def __init__(
            self,
            method: typing.AnyStr,
            url: typing.AnyStr,
            params: typing.Union[
                typing.Dict[typing.AnyStr, typing.Any],
                typing.List[typing.Tuple[typing.Any, typing.Any]],
                typing.Tuple[typing.Tuple[typing.Any, typing.Any]],
                typing.ByteString,
                typing.AnyStr,
            ] = None,
            data: typing.Union[
                typing.Dict[typing.AnyStr, typing.Any],
                typing.List,
                typing.Tuple,
                typing.ByteString
            ] = None,
            headers: typing.Dict[typing.AnyStr, typing.AnyStr] = None,
            cookies: typing.Union[typing.Dict[typing.AnyStr, typing.AnyStr], CookieJar] = None,
            auth: typing.Tuple = None,
            json: typing.Dict[typing.AnyStr, typing.AnyStr] = None,
    ):
        self.method = method
        self.url = url
        self.params = params
        self.data = data
        self.headers = headers
        self.cookies = cookies
        self.auth = auth
        self.json = json

    def __repr__(self):

        return f"<Request [{self.method}]>"

    def request(self):
        """
        Make a ready request to send.
        :return:
        """
        method = self.ready_method()
        schema, url = self.ready_url()
        params = self.ready_params()
        headers = self.ready_headers()
        data = self.ready_data()
        cookies = self.ready_cookies()
        auth = self.ready_auth()
        _json = self.ready_json()

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
                json=_json
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

    def ready_method(self):
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

    def ready_url(self):
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

    def ready_params(self):
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

    def ready_headers(self):
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

    def ready_data(self):
        """
        Ready form data.
        :return:
        """
        data = self.data

        return data

    def ready_cookies(self):
        """
        Todo: Ready http cookies.
        :return:
        """

        cookies = self.cookies

        return cookies

    def ready_auth(self):
        """
        Todo: Ready http authenticator
        :return:
        """

        auth = self.auth

        return auth

    def ready_json(self):
        """
        Todo: Ready post json.
        :return:
        """

        _json = self.json

        return _json
