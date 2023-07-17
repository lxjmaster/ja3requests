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

        self.scheme = "http"
        self.port = 80

    def __repr__(self):

        return f"<Request [{self.method}]>"

    def request(self):
        """
        Make a ready request to send.
        :return:
        """
        self.ready_method()
        self.ready_url()
        self.ready_params()
        self.ready_headers()
        self.ready_data()
        self.ready_cookies()
        self.ready_auth()
        self.ready_json()

        if self.scheme == "http":
            return HttpRequest()
        elif self.scheme == "https":
            return HttpsRequest()
        else:
            raise NotAllowedScheme(f"Schema: {self.scheme} not allowed.")

    def ready_method(self):
        """
        Ready request method and check request method whether allow used.
        :return:
        """

        self.method = self.method.upper()
        if self.method == "" or self.method not in [
            "GET",
            "OPTIONS",
            "HEAD",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ]:
            raise NotAllowedRequestMethod(self.method)

    def ready_url(self):
        """
        Ready http url and check url whether valid.
        :return:
        """

        if self.url == "":
            raise ValueError("The request url is required.")

        # Remove whitespaces for url
        self.url.strip()

        parse = urlparse(self.url)

        # Check HTTP scheme
        if parse.scheme == "":
            raise MissingScheme(
                f"Invalid URL {self.url!r}: No scheme supplied. "
                f"Perhaps you meant http://{self.url} or https://{self.url}"
            )

        # Just allow http or https
        if parse.scheme not in ["http", "https"]:
            raise NotAllowedScheme(f"Schema: {parse.scheme} not allowed.")

        self.scheme = parse.scheme
        if self.scheme == "https":
            self.port = 443

        if parse.netloc != "" and ":" in parse.netloc:
            port = parse.netloc.split(":")[-1]
            self.port = int(port)
        else:
            self.port = 80

    def ready_params(self):
        """
        Ready params.
        :return:
        """
        if self.params:
            parse = urlparse(self.url)

            if isinstance(self.params, str):
                params = self.params
            elif isinstance(self.params, bytes):
                params = self.params.decode()
            elif isinstance(self.params, (dict, list, tuple)):
                params = urlencode(self.params)
            else:
                raise InvalidParams(f"Invalid params: {self.params!r}")

            if params.startswith("?"):
                params = params.replace("?", "")

            if parse.query != "":
                self.url = "&" + params
            else:
                self.url = "?" + params

    def ready_headers(self):
        """
        Ready http headers.
        :return:
        """

        # Default headers
        if self.headers is None:
            self.headers = default_headers()

        # Check duplicate default item
        new_headers = {}
        header_list = []
        for k, v in self.headers.items():
            header = k.title()
            if header in header_list:
                warnings.warn(
                    f"Duplicate header: {k}, you should check the request headers.",
                    RuntimeWarning,
                )

            header_list.append(header)
            new_headers[header] = v

        self.headers = new_headers
        del new_headers
        del header_list

    def ready_data(self):
        """
        Ready form data.
        :return:
        """
        if self.data:
            if self.headers is not None:
                content_type = self.headers.get("Content-Type", "")
                if content_type == "":
                    self.headers["Content-Type"] = content_type = "application/x-www-form-urlencoded"
            else:
                self.headers = default_headers()
                self.headers["Content-Type"] = content_type = "application/x-www-form-urlencoded"

            if content_type == "application/x-www-form-urlencoded":
                self.data = urlencode(self.data)
                self.headers["Content-Length"] = len(self.data)

        print(self.data)

    def ready_cookies(self):
        """
        Todo: Ready http cookies.
        :return:
        """

    def ready_auth(self):
        """
        Todo: Ready http authenticator
        :return:
        """

    def ready_json(self):
        """
        Todo: Ready post json.
        :return:
        """