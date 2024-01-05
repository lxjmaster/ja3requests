from abc import ABC, abstractmethod
from http.cookiejar import CookieJar
from ja3requests.const import DEFAULT_HTTP_SCHEME, DEFAULT_HTTP_PORT
from urllib.parse import urlparse, urlencode
from ja3requests.exceptions import InvalidParams, InvalidData
from ja3requests.utils import default_headers
from typing import Any, AnyStr, List, Dict, Tuple, Union
from io import IOBase
import os


class BaseRequest(ABC):

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
        self._timeout = None

    @property
    def schema(self) -> AnyStr:
        return self._schema

    @schema.setter
    def schema(self, attr: AnyStr):
        self._schema = attr if attr else DEFAULT_HTTP_SCHEME

    @property
    def port(self) -> int:
        return self._port

    @port.setter
    def port(self, attr: int):
        self._port = attr if attr else DEFAULT_HTTP_PORT

    @property
    def method(self) -> AnyStr:
        return self._method

    @method.setter
    def method(self, attr: AnyStr):
        self._method = attr.upper()

    @property
    def url(self) -> AnyStr:
        return self._url

    @url.setter
    def url(self, attr: AnyStr):
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
        return self._params

    @params.setter
    def params(self, attr: Union[
        Dict[AnyStr, Any],
        List[Tuple[Any, Any]],
        Tuple[Tuple[Any, Any]],
        AnyStr]
    ):
        self._params = attr
        if self._params:
            if isinstance(self._params, str):
                self._params = self._params
            elif isinstance(self._params, bytes):
                self._params = self._params.decode()
            else:
                try:
                    self._params = urlencode(self._params)
                except TypeError:
                    raise InvalidParams(f"Invalid params: {self._params!r}")

            if self._params.startswith("?"):
                self._params = self._params.replace("?", "")

            parse = urlparse(self.url)

            if parse.query != "":
                self.url += "&" + self._params
            else:
                self.url += "?" + self._params

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, attr: Union[
        Dict[AnyStr, Any],
        List[Tuple[AnyStr, Any]],
        Tuple[Tuple[AnyStr, Any]],
        AnyStr]
    ):

        self._data = attr
        if self._data:

            if isinstance(self._data, str):
                self._data = self._data
            elif isinstance(self._data, bytes):
                self._data = self._data.decode()
            else:
                try:
                    self._data = urlencode(self._data)
                except TypeError:
                    raise InvalidData(f"Invalid data: {self._data!r}")

            if not self.headers:
                self.headers = default_headers()

            content_type = self.headers.get("Content-Type", "")
            if content_type == "":
                self.headers["Content-Type"] = "application/x-www-form-urlencoded"

            self.headers["Content-Length"] = len(self._data)

    @property
    def files(self):

        return self._files

    @files.setter
    def files(self, attr):

        new_files = {}
        files = attr
        for name, file in files.items():
            if not isinstance(file, list):
                file = [file]

            for f in file:
                if isinstance(f, (str, bytes)):
                    with open(f, "rb+") as f_obj:
                        item = {
                            "file_name": os.path.basename(f_obj.name),
                            "content": f_obj.read()
                        }
                elif isinstance(f, IOBase):
                    item = {
                        "file_name": os.path.basename(f.name if hasattr(f, "name") else ""),
                        "content": f.read()
                    }
                else:
                    continue

                if not new_files.get(name, None):
                    new_files.update({
                        name: [item]
                    })
                else:
                    new_files[name].append(item)

        self._files = new_files

    @property
    def headers(self):

        return self._headers if self._headers else default_headers()

    @headers.setter
    def headers(self, attr: Dict[AnyStr, AnyStr]):

        self._headers = attr
        if not self._headers:
            self._headers = default_headers()

        headers = dict()
        for header, value in self._headers.items():
            header = header.title()
            headers.update({
                header: value
            })

        self._headers = headers

    @property
    def cookies(self):

        return self._cookies

    @cookies.setter
    def cookies(self, attr: Union[Dict[AnyStr, AnyStr], CookieJar]):

        self._cookies = attr

    @property
    def auth(self):

        return self._auth

    @auth.setter
    def auth(self, attr: Tuple):

        self._auth = attr

    @property
    def json(self):

        return self._json

    @json.setter
    def json(self, attr: Dict[AnyStr, AnyStr]):

        self._json = attr

    @property
    def timeout(self):

        return self._timeout

    @timeout.setter
    def timeout(self, attr):

        self._timeout = attr

    def set_payload(
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
            List[Tuple[AnyStr, Any]],
            Tuple[Tuple[AnyStr, Any]],
            AnyStr
        ] = None,
        files: Dict[AnyStr, Union[List[Union[AnyStr, IOBase]], IOBase, AnyStr]] = None,
        headers: Dict[AnyStr, AnyStr] = None,
        cookies: Union[Dict[AnyStr, AnyStr], CookieJar] = None,
        auth: Tuple = None,
        json: Dict[AnyStr, AnyStr] = None,
        timeout: float = None,
    ):
        self.method = method
        self.url = url
        self.params = params
        self.data = data
        self.files = files
        self.headers = headers
        self.cookies = cookies
        self.auth = auth
        self.json = json
        self.timeout = timeout

    # @staticmethod
    # def parse_proxy(proxy: AnyStr = None):
    #     if proxy is None:
    #         return None, None, None, None
    #
    #     split_result = urlsplit(f'https://{proxy}')
    #     username = split_result.username
    #     password = split_result.password
    #     host = split_result.hostname
    #     port = split_result.port
    #
    #     return username, password, host, port

    def is_http(self):

        self.schema = self.schema.decode() if isinstance(self.schema, bytes) else self.schema
        return self.schema.lower() == "http"

    def is_https(self):

        self.schema = self.schema.decode() if isinstance(self.schema, bytes) else self.schema
        return self.schema.lower() == "https"

    @abstractmethod
    def send(self):
        raise NotImplementedError("send method must be implemented by subclass.")
