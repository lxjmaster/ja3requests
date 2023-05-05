"""
ja3requests.request
~~~~~~~~~~~~~~~~~~~

This module create a request struct and ready request object.
"""
from .base import BaseRequest
from .exceptions import NotAllowedRequestMethod, MissingScheme, NotAllowedScheme
from urllib.parse import urlparse
from http.cookiejar import CookieJar
from typing import Any, AnyStr, Dict, List, Union, ByteString, Tuple


class ReadyRequest(BaseRequest):

    def __init__(
            self,
            method: AnyStr,
            url: AnyStr,
            params: Union[Dict[AnyStr, Any], List[Tuple[AnyStr, Any]], ByteString] = None,
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

        self.ready_method()

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
        if parse.scheme.lower() not in ["http", "https"]:
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

    def ready(self):
        """
        Make a ready request to send.
        :return:
        """

