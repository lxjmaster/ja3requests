"""
ja3requests.request
~~~~~~~~~~~~~~~~~~~

This module create a request struct and ready request object.
"""
from .base import BaseRequest
from .exceptions import NotAllowRequestMethod
from http.cookiejar import CookieJar
from typing import Any, AnyStr, Dict, List, Union, ByteString, Tuple


class Request(BaseRequest):

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

    def __repr__(self):
        return f"<Request [{self.method}]>"

    def check_method(self):

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
