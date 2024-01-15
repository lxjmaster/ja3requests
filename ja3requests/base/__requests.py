"""
Ja3Requests.base.__requests
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic of Request.
"""


import os
from io import IOBase
from abc import ABC, abstractmethod
from http.cookiejar import CookieJar
from urllib.parse import urlparse, urlencode
from typing import Any, AnyStr, List, Dict, Tuple, Union
from ja3requests.const import DEFAULT_HTTP_SCHEME, DEFAULT_HTTP_PORT
from ja3requests.exceptions import InvalidParams, InvalidData
from ja3requests.utils import (
    default_headers,
    dict_from_cookie_string,
    dict_from_cookiejar,
)


class BaseRequest(ABC):
    """
    Basic of Request
    """

    def __init__(self):
        self._scheme = None
        self._schema = None
        self._port = None
        self._method = None
        self._url = None
        self._params = None
        self._data = None
        self._files = None
        self._headers = None
        self._cookies = None
        self._auth = None
        self._json = None
        self._proxy = None
        self._timeout = None

    @property
    def schema(self) -> AnyStr:
        """
        Request property schema
        :return:
        """
        return self._schema

    @schema.setter
    def schema(self, attr: AnyStr):
        """
        Request property schema set
        :param attr:
        :return:
        """
        self._schema = attr if attr else DEFAULT_HTTP_SCHEME

    @property
    def port(self) -> int:
        """
        Request property port
        :return:
        """
        return self._port

    @port.setter
    def port(self, attr: int):
        """
        Request property port set
        :param attr:
        :return:
        """
        self._port = attr if attr else DEFAULT_HTTP_PORT

    @property
    def method(self) -> AnyStr:
        """
        Request property method
        :return:
        """
        return self._method

    @method.setter
    def method(self, attr: AnyStr):
        """
        Request property method set
        :param attr:
        :return:
        """
        self._method = attr.upper()

    @property
    def url(self) -> AnyStr:
        """
        Request property url
        :return:
        """
        return self._url

    @url.setter
    def url(self, attr: AnyStr):
        """ "
        Request property url set
        """
        self._url = attr
        if self._url:
            parse = urlparse(self._url)
            self.schema = parse.scheme
            if self.schema == "https":
                self.port = 443

            if parse.netloc != "" and ":" in parse.netloc:
                port = parse.netloc.split(":")[-1]
                self.port = int(port)
            else:
                self.port = 80

    @property
    def params(self):
        """
        Request property params
        :return:
        """
        return self._params

    @params.setter
    def params(
        self,
        attr: Union[
            Dict[AnyStr, Any], List[Tuple[Any, Any]], Tuple[Tuple[Any, Any]], AnyStr
        ],
    ):
        """
        Request property params set
        :param attr:
        :return:
        """
        self._params = attr
        if self._params:
            if isinstance(self._params, str):
                self._params = self._params
            elif isinstance(self._params, bytes):
                self._params = self._params.decode()
            else:
                try:
                    self._params = urlencode(self._params)
                except TypeError as err:
                    raise InvalidParams(f"Invalid params: {self._params!r}") from err

            if self._params.startswith("?"):
                self._params = self._params.replace("?", "")

            parse = urlparse(self.url)

            if parse.query != "":
                self.url += "&" + self._params
            else:
                self.url += "?" + self._params

    @property
    def data(self):
        """
        Request property data
        :return:
        """
        return self._data

    @data.setter
    def data(
        self,
        attr: Union[
            Dict[AnyStr, Any],
            List[Tuple[AnyStr, Any]],
            Tuple[Tuple[AnyStr, Any]],
            AnyStr,
        ],
    ):
        """
        Request property data set
        :param attr:
        :return:
        """
        self._data = attr
        if self._data:
            if isinstance(self._data, str):
                self._data = self._data
            elif isinstance(self._data, bytes):
                self._data = self._data.decode()
            else:
                try:
                    self._data = urlencode(self._data)
                except TypeError as err:
                    raise InvalidData(f"Invalid data: {self._data!r}") from err

            if not self.headers:
                self.headers = default_headers()

            content_type = self.headers.get("Content-Type", "")
            if content_type == "":
                self.headers["Content-Type"] = "application/x-www-form-urlencoded"

            self.headers["Content-Length"] = len(self._data)

    @property
    def files(self):
        """
        Request property files
        :return:
        """
        return self._files

    @files.setter
    def files(self, attr):
        """
        Request property files set
        :param attr:
        :return:
        """
        new_files = None
        files = attr
        if files:
            new_files = {}
            for name, file in files.items():
                if not isinstance(file, list):
                    file = [file]

                for f in file:
                    if isinstance(f, (str, bytes)):
                        with open(f, "rb+") as f_obj:
                            item = {
                                "file_name": os.path.basename(f_obj.name),
                                "content": f_obj.read(),
                            }
                    elif isinstance(f, IOBase):
                        item = {
                            "file_name": os.path.basename(
                                f.name if hasattr(f, "name") else ""
                            ),
                            "content": f.read(),
                        }
                    else:
                        continue

                    if not new_files.get(name, None):
                        new_files.update({name: [item]})
                    else:
                        new_files[name].append(item)

        self._files = new_files

    @property
    def headers(self):
        """
        Request property headers
        :return:
        """
        return self._headers if self._headers else default_headers()

    @headers.setter
    def headers(self, attr: Dict[AnyStr, AnyStr]):
        """
        Request property headers set
        :param attr:
        :return:
        """
        self._headers = attr
        if not self._headers:
            self._headers = default_headers()

        headers = {}
        for header, value in self._headers.items():
            header = header.title()
            headers.update({header: value})

        self._headers = headers

    @property
    def cookies(self) -> Dict | None:
        """
        Request property cookies
        :return:
        """
        return self._cookies

    @cookies.setter
    def cookies(self, attr: Union[Dict[AnyStr, AnyStr], CookieJar, AnyStr]):
        """
        Request property cookies set
        :param attr:
        :return:
        """
        cookies = attr
        if cookies:
            if isinstance(cookies, (bytes, str)):
                cookies = dict_from_cookie_string(cookies)
            elif isinstance(cookies, CookieJar):
                cookies = dict_from_cookiejar(cookies)

        self._cookies = cookies

    @property
    def auth(self):
        """
        Request property auth
        :return:
        """
        return self._auth

    @auth.setter
    def auth(self, attr: Tuple):
        """
        Request property auth set
        :param attr:
        :return:
        """
        self._auth = attr

    @property
    def json(self):
        """
        Request property json
        :return:
        """
        return self._json

    @json.setter
    def json(self, attr: Dict[AnyStr, AnyStr]):
        """
        Request property json set
        :param attr:
        :return:
        """
        self._json = attr

    @property
    def proxy(self):
        """
        Request property proxy
        :return:
        """
        return self._proxy

    @proxy.setter
    def proxy(self, attr):
        """
        Request property proxy set
        :param attr:
        :return:
        """
        self._proxy = attr
        if self._proxy:
            proxy = self._proxy.get(self.schema, None)
        else:
            proxy = None

        self._proxy = proxy

    @property
    def timeout(self):
        """
        Request property timeout
        :return:
        """
        return self._timeout

    @timeout.setter
    def timeout(self, attr):
        """
        Request property timeout set
        :param attr:
        :return:
        """
        self._timeout = attr

    def set_payload(self, **kwargs):
        """
        Set request payload
        :param kwargs:
        :return:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)

    def is_http(self):
        """
        Is http
        :return:
        """
        self.schema = (
            self.schema.decode() if isinstance(self.schema, bytes) else self.schema
        )
        return self.schema.lower() == "http"

    def is_https(self):
        """
        Is https
        :return:
        """
        self.schema = (
            self.schema.decode() if isinstance(self.schema, bytes) else self.schema
        )
        return self.schema.lower() == "https"

    @abstractmethod
    def send(self):
        """
        Request send
        :return:
        """
        raise NotImplementedError("send method must be implemented by subclass.")
