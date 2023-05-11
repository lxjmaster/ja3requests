"""
ja3requests.request
~~~~~~~~~~~~~~~~~~~

This module create a request struct and ready request object.
"""
from .base import BaseRequest
from .connections import HTTPConnection
from .exceptions import NotAllowedRequestMethod, MissingScheme, NotAllowedScheme, InvalidParams
from http.cookiejar import CookieJar
from urllib.parse import urlparse, urlencode
from typing import Any, AnyStr, Dict, List, Union, ByteString, Tuple


class ReadyRequest(BaseRequest):

    def __init__(
            self,
            method: AnyStr,
            url: AnyStr,
            params: Union[Dict[Any, Any], List[Tuple[Any, Any]], Tuple[Tuple[Any, Any]], ByteString, AnyStr] = None,
            data: Union[Dict[AnyStr, Any], List, Tuple, ByteString] = None,
            headers: Dict[AnyStr, AnyStr] = None,
            cookies: Union[Dict[AnyStr, AnyStr], CookieJar] = None,
            auth: Tuple = None,
            json: Dict[AnyStr, AnyStr] = None,
    ):
        super().__init__()
        self.method = method
        self.url = url
        self.params = params
        self.data = data
        self.headers = headers
        self.cookies = cookies
        self.auth = auth
        self.json = json

    def __repr__(self):
        return f"<ReadyRequest [{self.method}]>"

    def ready_method(self):
        """
        Ready request method and check request method whether allow used.
        :return:
        """

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

        self.method = self.method.upper()

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
            raise NotAllowedScheme(
                f"Schema: {parse.scheme} not allowed."
            )

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

    def ready_data(self):
        """
        Todo: Ready form data.
        :return:
        """

    def ready_headers(self):
        """
        Todo: Ready http headers.
        :return:
        """

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

    def ready(self):
        """
        Make a ready request to send.
        :return:
        """
        self.ready_method()
        self.ready_url()
        self.ready_params()
        self.ready_data()
        self.ready_headers()
        self.ready_cookies()
        self.ready_auth()
        self.ready_json()

    def request(self):

        req = Request()
        req.clone(self)

        return req


class Request(BaseRequest):

    def __repr__(self):
        return f"<Request [{self.method}]>"

    def clone(self, ready_request: ReadyRequest):

        for k, v in ready_request.__dict__.items():
            setattr(self, k, v)

    def send(self):
        """
        Connection sending.
        :return:
        """

        conn = self.create_connect()
        proxy, proxy_username, proxy_password = self.parse_proxies()
        conn.connect(
            self.scheme,
            self.port,
            self.source,
            self.url,
            self.timeout,
            proxy,
            proxy_username,
            proxy_password
        )
        response = conn.send()

        return response

    def create_connect(self):
        """
        Create http connection or https connection by request scheme.
        :return:
        """

        if self.is_http():
            conn = HTTPConnection()
        elif self.is_https():
            # TODO: HTTPS
            # conn = HTTPSConnection()
            raise NotImplementedError("HTTPSConnection not implemented yet.")
        else:
            raise MissingScheme(f"Scheme: {self.scheme}, parse scheme failed, can't create connection.")

        return conn

    def parse_proxies(self):
        """
        TODO
        Parse proxy, proxy's username and password. if proxies is set.
        :return:
        """
        return None, None, None
