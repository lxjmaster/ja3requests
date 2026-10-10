"""
Ja3Requests.base.__requests
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic of Request.
"""

from __future__ import annotations
from ja3requests._upload import UploadSource, is_upload

import os
from io import IOBase
from abc import ABC, abstractmethod
from http.cookiejar import CookieJar
from urllib.parse import urlparse, urlencode, urlsplit, urlunsplit
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from ja3requests._typing import (
    Auth,
    Cookies,
    Data,
    Files,
    Headers,
    HeaderValue,
    JsonBody,
    Params,
    Proxies,
    Timeout,
)
from ja3requests.const import DEFAULT_HTTP_SCHEME, DEFAULT_HTTP_PORT
from ja3requests.exceptions import InvalidParams, InvalidData
from ja3requests.utils import (
    default_headers,
    dict_from_cookie_string,
)
from ja3requests.cookies import _copy_cookie_jar, _refresh_cookie_header

if TYPE_CHECKING:
    from ja3requests.protocol.tls.config import TlsConfig
    from ja3requests.response import HTTPResponse


class BaseRequest(ABC):
    """
    Basic of Request
    """

    def __init__(self) -> None:
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
        self._cookie_jar = None
        self._cookie_view = None
        self._cookie_from_jar = None
        self._cookie_header_managed = True
        self._auth = None
        self._json = None
        self._proxy = None
        self._timeout = None
        self._tls_config = None

    @property
    def schema(self) -> Optional[str]:
        """
        Request property schema
        :return:
        """
        return self._schema

    @schema.setter
    def schema(self, attr: Optional[str]) -> None:
        """
        Request property schema set
        :param attr:
        :return:
        """
        self._schema = attr if attr else DEFAULT_HTTP_SCHEME

    @property
    def port(self) -> Optional[int]:
        """
        Request property port
        :return:
        """
        return self._port

    @port.setter
    def port(self, attr: Optional[int]) -> None:
        """
        Request property port set
        :param attr:
        :return:
        """
        self._port = attr if attr is not None else DEFAULT_HTTP_PORT

    @property
    def method(self) -> Optional[str]:
        """
        Request property method
        :return:
        """
        return self._method

    @method.setter
    def method(self, attr: str) -> None:
        """
        Request property method set
        :param attr:
        :return:
        """
        self._method = attr.upper()

    @property
    def url(self) -> Optional[str]:
        """
        Request property url
        :return:
        """
        return self._url

    @url.setter
    def url(self, attr: str) -> None:
        """ "
        Request property url set
        """
        self._url = attr
        if self._url:
            parse = urlparse(self._url)
            self.schema = parse.scheme
            # ``urlparse().port`` understands bracketed IPv6 authorities and
            # validates explicit ports without splitting colons in the address.
            if parse.port is not None:
                self.port = parse.port
            else:
                # Set default port based on schema.
                self.port = 443 if self.schema == "https" else 80

    @property
    def params(self) -> Optional[Params]:
        """
        Request property params
        :return:
        """
        return self._params

    @params.setter
    def params(
        self,
        attr: Optional[Params],
    ) -> None:
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

            parse = urlsplit(self.url)
            query = "&".join(filter(None, (parse.query, self._params)))
            # Query parameters belong before a URL fragment.  Keep the
            # fragment in the logical URL; BaseContext excludes it from the
            # HTTP request-target when it builds the start line.
            self.url = urlunsplit(parse._replace(query=query))

    @property
    def data(self) -> Optional[Data]:
        """
        Request property data
        :return:
        """
        return self._data

    @data.setter
    def data(
        self,
        attr: Optional[Data],
    ) -> None:
        """
        Request property data set
        :param attr:
        :return:
        """
        self._data = attr
        if isinstance(attr, UploadSource) or is_upload(attr):
            return
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
    def files(self) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        """
        Request property files
        :return:
        """
        return self._files

    @files.setter
    def files(self, attr: Optional[Files]) -> None:
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
    def headers(self) -> Dict[str, HeaderValue]:
        """
        Request property headers
        :return:
        """
        return self._headers if self._headers else default_headers()

    @headers.setter
    def headers(self, attr: Optional[Headers]) -> None:
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
    def cookies(self) -> Optional[Cookies]:
        """
        Request property cookies
        :return:
        """
        # Hooks may introduce another casing of Cookie after preparation. Keep
        # other header spelling/order, and any existing canonical Cookie position.
        headers = self.headers
        cookie_names = [name for name in headers if name.lower() == "cookie"]
        if any(name != "Cookie" for name in cookie_names):
            cookie = headers[cookie_names[-1]]
            if "Cookie" in headers:
                headers["Cookie"] = cookie
                for name in cookie_names:
                    if name != "Cookie":
                        del headers[name]
            else:
                normalized = {
                    ("Cookie" if name.lower() == "cookie" else name): value
                    for name, value in headers.items()
                }
                headers.clear()
                headers.update(normalized)
        if self._cookie_header_managed:
            if headers.get("Cookie") != self._cookie_from_jar:
                # A header removal/replacement takes precedence over dict edits.
                self._cookie_header_managed = False
                self._cookie_from_jar = None
                self._cookies = None
            elif self._cookies != self._cookie_view:
                # The compatibility dict remains mutable in before_request hooks.
                # Let the context serialize that explicit choice, not the old jar.
                headers.pop("Cookie", None)
                self._cookie_header_managed = False
                self._cookie_from_jar = None
        return self._cookies

    @cookies.setter
    def cookies(self, attr: Optional[Cookies]) -> None:
        """
        Request property cookies set
        :param attr:
        :return:
        """
        if self._cookie_from_jar is not None:
            if self.headers.get("Cookie") == self._cookie_from_jar:
                self.headers.pop("Cookie", None)
        self._cookie_from_jar = None
        self._cookie_jar = None
        self._cookie_header_managed = False
        if isinstance(attr, CookieJar):
            self._cookie_jar = _copy_cookie_jar(attr)
            self._cookie_header_managed = "Cookie" not in self.headers
            self._cookies = self._cookie_view = None
            self._refresh_cookies()
        else:
            self._cookies = (
                dict_from_cookie_string(attr)
                if isinstance(attr, (bytes, str))
                else attr
            )
            self._cookie_view = None

    def _refresh_cookies(self) -> None:
        """Keep the ordered jar header and the legacy dict view in sync."""
        # Reading the view first honors changes made by a request hook.
        self.cookies
        if self._cookie_jar is None or not self._cookie_header_managed:
            return
        _refresh_cookie_header(self._cookie_jar, self)
        cookie_header = self._cookie_from_jar
        self._cookies = (
            dict_from_cookie_string(cookie_header) if cookie_header else None
        )
        self._cookie_view = dict(self._cookies) if self._cookies is not None else None

    @property
    def auth(self) -> Optional[Auth]:
        """
        Request property auth
        :return:
        """
        return self._auth

    @auth.setter
    def auth(self, attr: Optional[Auth]) -> None:
        """
        Request property auth set
        :param attr:
        :return:
        """
        self._auth = attr

    @property
    def json(self) -> Optional[JsonBody]:
        """
        Request property json
        :return:
        """
        return self._json

    @json.setter
    def json(self, attr: Optional[JsonBody]) -> None:
        """
        Request property json set
        :param attr:
        :return:
        """
        self._json = attr

    @property
    def proxy(self) -> Optional[str]:
        """
        Request property proxy
        :return:
        """
        return self._proxy

    @proxy.setter
    def proxy(self, attr: Optional[Proxies]) -> None:
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
    def timeout(self) -> Timeout:
        """
        Request property timeout
        :return:
        """
        return self._timeout

    @timeout.setter
    def timeout(self, attr: Timeout) -> None:
        """
        Request property timeout set
        :param attr:
        :return:
        """
        self._timeout = attr

    @property
    def tls_config(self) -> Optional[TlsConfig]:
        """
        Request property tls_config
        :return:
        """
        return self._tls_config

    @tls_config.setter
    def tls_config(self, attr: Optional[TlsConfig]) -> None:
        """
        Request property tls_config set
        :param attr:
        :return:
        """
        self._tls_config = attr

    def set_payload(self, **kwargs: Any) -> None:
        """
        Set request payload
        :param kwargs:
        :return:
        """
        for k, v in kwargs.items():
            setattr(self, k, v)

    def is_http(self) -> bool:
        """
        Is http
        :return:
        """
        self.schema = (
            self.schema.decode() if isinstance(self.schema, bytes) else self.schema
        )
        return self.schema.lower() == "http"

    def is_https(self) -> bool:
        """
        Is https
        :return:
        """
        self.schema = (
            self.schema.decode() if isinstance(self.schema, bytes) else self.schema
        )
        return self.schema.lower() == "https"

    @abstractmethod
    def send(self, *args: Any, **kwargs: Any) -> HTTPResponse:
        """
        Request send
        :return:
        """
        raise NotImplementedError("send method must be implemented by subclass.")
