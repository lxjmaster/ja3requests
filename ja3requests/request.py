"""
ja3requests.request
~~~~~~~~~~~~~~~~~~~

This module create a request struct and ready request object.
"""
from .base import BaseRequest
from .exceptions import NotAllowRequestMethod, MissingSchema
from urllib.parse import urlparse
from http.cookiejar import CookieJar
from typing import Any, AnyStr, Dict, List, Union, ByteString, Tuple


class ReadyRequest(BaseRequest):

    def __init__(
            self,
            method: AnyStr,
            url: AnyStr,
            params: Union[Dict[AnyStr, Any], ByteString] = None,
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
            raise NotAllowRequestMethod(self.method)

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

        # Check HTTP schemes, just allow http or https
        if parse.scheme == "":
            raise MissingSchema(f"Invalid URL '{self.url}': No scheme supplied. Perhaps you meant http://{parse.netloc} or https://{parse.netloc}")



    def ready(self):
        """
        Make a ready request to send.
        :return:
        """

