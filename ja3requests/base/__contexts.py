""" "
Ja3Requests.base.__contexts
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic of Context.
"""

from __future__ import annotations
from ja3requests._upload import UploadSource
from ja3requests.exceptions import InvalidData

from urllib.parse import urlsplit, urlencode, parse_qsl
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Union
from ja3requests._typing import Data, HeaderValue, JsonBody, Timeout
from ja3requests.utils import _encode_http1_headers, _validated_header_items
from json import dumps
import mimetypes


PROTOCOL_VERSION_HTTP_1 = "HTTP/1.1"
PROTOCOL_VERSION_HTTP_2 = "HTTP/2.0"  # h2


class BaseContext(ABC):
    """
    Basic connection context.
    """

    def __init__(self) -> None:
        self._protocol_version = None
        self._method = None
        self._destination_address = None
        self._host_authority = None
        self._path = None
        self._port = None
        self._headers = None
        self._data = None
        self._json = None
        self._files = None
        self._body = None
        self._start_line = None
        self._message = None
        self._source_address = None
        self._timeout = None
        self._proxy = None
        self._cookies = None

    @property
    def protocol_version(self) -> Optional[str]:
        """
        Version
        :return:
        """
        return self._protocol_version

    @protocol_version.setter
    def protocol_version(self, attr: str) -> None:
        """
        Set version
        :param attr:
        :return:
        """
        self._protocol_version = attr

    @property
    def method(self) -> Optional[str]:
        """
        Method
        :return:
        """
        return self._method

    @method.setter
    def method(self, attr: str) -> None:
        """
        Set method
        :param attr:
        :return:
        """
        self._method = attr

    @property
    def destination_address(self) -> Optional[str]:
        """
        Context property destination_address
        :return:
        """
        return self._destination_address

    @destination_address.setter
    def destination_address(self, attr: Optional[str]) -> None:
        """
        Conntext property destination_address set
        :param attr:
        :return:
        """
        self._destination_address = attr

    @property
    def path(self) -> Optional[str]:
        """
        Context property path
        :return:
        """
        return self._path

    @path.setter
    def path(self, attr: str) -> None:
        """
        Context property path set
        :param attr:
        :return:
        """
        self._path = attr

    @property
    def port(self) -> Optional[int]:
        """
        Context property port
        :return:
        """
        return self._port

    @port.setter
    def port(self, attr: int) -> None:
        """
        Context property port set
        :param attr:
        :return:
        """
        self._port = attr

    @property
    def start_line(self) -> str:
        """
        Start line
        :return:
        """
        return (
            self._start_line
            if self._start_line
            else " ".join([self.method, self.path, self.protocol_version])
        )

    @start_line.setter
    def start_line(self, attr: str) -> None:
        """
        Set start line
        :param attr:
        :return:
        """
        if attr:
            parse = urlsplit(attr)
            self.destination_address = parse.hostname
            if parse.port is not None:
                self.port = parse.port
            else:
                self.port = 443 if parse.scheme.lower() == "https" else 80

            host = self.destination_address or ""
            authority = "[%s]" % host if ":" in host else host
            default_port = 443 if parse.scheme.lower() == "https" else 80
            if self.port != default_port:
                authority += ":%d" % self.port
            self._host_authority = authority
            self.path = parse.path
            if self.path == "":
                self.path = "/"

            if parse.query != "":
                self.path += "?" + parse.query

        self._start_line = " ".join([self.method, self.path, self.protocol_version])

    @property
    def headers(self) -> Optional[Dict[str, HeaderValue]]:
        """
        Headers
        :return:
        """
        return self._headers

    @headers.setter
    def headers(self, attr: Optional[Dict[str, HeaderValue]]) -> None:
        """
        Set headers
        :param attr:
        :return:
        """
        headers = attr
        if headers:
            if not any(name.lower() == "host" for name in headers):
                if self._host_authority or self.destination_address:
                    headers.update(
                        {"Host": self._host_authority or self.destination_address}
                    )

            if self.method in ["POST", "PUT"]:
                if isinstance(self.data, UploadSource):
                    self._headers = headers
                    return
                if not headers.get("Content-Type", None):
                    if self.data:
                        headers.update(
                            {"Content-Type": "application/x-www-form-urlencoded"}
                        )

                    if self.json:
                        headers.update({"Content-Type": "application/json"})

                    if self.files:
                        headers.update(
                            {"Content-Type": 'multipart/form-data;boundary="boundary"'}
                        )
                else:
                    content_type = headers["Content-Type"]
                    if "multipart/form-data" in content_type.lower():
                        headers.update(
                            {"Content-Type": 'multipart/form-data;boundary="boundary"'}
                        )

                if not headers.get("Content-Type", None):
                    headers.update(
                        {"Content-Type": "application/x-www-form-urlencoded"}
                    )

        self._headers = headers

    def _validated_header_items(self):
        """Return final header pairs after validating wire-safe text.

        Hooks can edit the request after the normal header setters run, so
        validation belongs immediately before every serialization path.
        Field names use the RFC token grammar; values allow horizontal tab but
        reject all other C0 controls and DEL, including CR, LF and NUL.
        """
        return _validated_header_items(self.headers)

    @property
    def data(self) -> Optional[str]:
        """
        Context property data
        :return:
        """
        return self._data

    @data.setter
    def data(self, attr: Optional[Data]) -> None:
        """
        Context property data set
        :param attr:
        :return:
        """
        data = attr
        if isinstance(data, (dict, list, tuple)):
            data = urlencode(data)
        elif isinstance(data, bytes):
            data = data.decode()

        self._data = data

    @property
    def json(self) -> Optional[str]:
        """
        Context property json
        :return:
        """
        return self._json

    @json.setter
    def json(self, attr: Optional[JsonBody]) -> None:
        """
        Context property json set
        :param attr:
        :return:
        """
        json = attr
        if isinstance(json, dict):
            json = dumps(json)
        elif isinstance(json, bytes):
            json = json.decode()

        self._json = json

    @property
    def files(self) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        """
        Context property files
        :return:
        """
        return self._files

    @files.setter
    def files(self, attr: Optional[Dict[str, List[Dict[str, Any]]]]) -> None:
        """
        Context property files set
        :param attr:
        :return:
        """
        self._files = attr

    @property
    def body(self) -> Optional[Union[str, bytes]]:
        """
        Body
        :return:
        """

        return self._body

    @body.setter
    def body(self, attr: Union[str, bytes]) -> None:
        """
        Set body
        :param attr:
        :return:
        """
        body = attr
        if (
            self.headers.get("Content-Type", "")
            == 'multipart/form-data;boundary="boundary"'
        ):
            body_list = parse_qsl(body)
            form_data = "--boundary"
            for name, value in body_list:
                content = f'\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n--boundary'
                form_data += content

            if self.files:
                for name, file in self.files.items():
                    for f in file:
                        mime_type, _ = mimetypes.guess_type(f["file_name"])
                        file_name = f["file_name"]
                        content = f'\r\nContent-Disposition: form-data; name="{name}"; filename="{file_name}"'.encode()
                        if mime_type:
                            content += f"\r\nContent-Type: {mime_type}".encode()

                        content += b"\r\n\r\n"
                        content += f["content"]
                        content += b"\r\n--boundary"
                        form_data = (
                            form_data.encode()
                            if isinstance(form_data, str)
                            else form_data
                        )
                        form_data += content

            form_data += b"--"
            body = form_data

        self.headers.update({"Content-Length": len(body)})

        self._body = body

    @property
    def message(self) -> bytes:
        """
        Message
        :return:
        """
        if isinstance(self.data, UploadSource):
            raise InvalidData('A streaming upload cannot be assembled as a message')
        if self.data:
            data = self.data
            if isinstance(data, str):
                data = data.encode()
            self.body = data
        if self.json:
            self.headers.update({"Content-Type": "application/json"})
            self.body = self.json.encode()

        message = b""
        if self._message:
            message = self._message
        else:
            if self.start_line:
                message += self.start_line.encode()
            if self.headers:
                message += b"\r\n"
                message += _encode_http1_headers(self.headers)

            message += b"\r\n\r\n"

            if self.body:
                message += self.body

        self._message = message

        return self._message

    @message.setter
    def message(self, attr: bytes) -> None:
        """
        Set message
        :param attr:
        :return:
        """
        self._message = attr

    @property
    def source_address(self) -> Optional[Tuple[str, int]]:
        """
        Context property source_address
        :return:
        """
        return self._source_address

    @source_address.setter
    def source_address(self, attr: Optional[Tuple[str, int]]) -> None:
        """
        Context property source_address setter
        :param attr:
        :return:
        """
        self._source_address = attr

    @property
    def timeout(self) -> Timeout:
        """
        Context property timeout.
        Can be a single float (used for both connect and read)
        or a tuple (connect_timeout, read_timeout).
        :return:
        """
        return self._timeout

    @timeout.setter
    def timeout(self, attr: Timeout) -> None:
        """
        Context property timeout set
        :param attr:
        :return:
        """
        self._timeout = attr

    @property
    def connect_timeout(self) -> Optional[float]:
        """Extract connect timeout from timeout setting."""
        if isinstance(self._timeout, tuple):
            return self._timeout[0]
        return self._timeout

    @property
    def read_timeout(self) -> Optional[float]:
        """Extract read timeout from timeout setting."""
        if isinstance(self._timeout, tuple):
            return self._timeout[1] if len(self._timeout) > 1 else self._timeout[0]
        return self._timeout

    def _strip_proxy_scheme(self, value: str) -> str:
        """Strip socks5://, socks4://, http:// scheme prefix from proxy value."""
        if value and "://" in value:
            return value.split("://", 1)[1]
        return value

    @property
    def proxy_scheme(self) -> Optional[str]:
        """
        Get the proxy scheme (socks5, socks4, http, or None).
        :return:
        """
        if self._proxy and "://" in self._proxy:
            return self._proxy.split("://", 1)[0].lower()
        return None

    @property
    def proxy(self) -> Optional[str]:
        """
        Context property proxy (host:port without scheme).
        :return:
        """
        proxy = None
        if self._proxy:
            raw = self._strip_proxy_scheme(self._proxy)
            if "@" in raw:
                proxy = raw.split("@")[-1]
            else:
                proxy = raw

        return proxy

    @proxy.setter
    def proxy(self, attr: Optional[str]) -> None:
        """
        Context property proxy set
        :param attr:
        :return:
        """
        self._proxy = attr

    @property
    def proxy_auth(self) -> Optional[str]:
        """
        Context property proxy auth
        :return:
        """
        proxy_auth = None
        if self._proxy:
            raw = self._strip_proxy_scheme(self._proxy)
            if "@" in raw:
                proxy_auth = raw.split("@")[0]

        return proxy_auth

    @property
    def cookies(self) -> Optional[str]:
        """
        Context property cookies
        :return:
        """
        return self._cookies

    @cookies.setter
    def cookies(self, attr: Optional[Dict[str, str]]) -> None:
        """
        Context property cookies set
        :param attr:
        :return:
        """
        cookies = attr
        if isinstance(cookies, dict):
            cookies_list = [f"{k}={v};" for k, v in cookies.items()]
            self._cookies = " ".join(cookies_list)
        else:
            self._cookies = None

        if self._cookies:
            self.headers.setdefault("Cookie", self._cookies)

    @abstractmethod
    def set_payload(self, *args: Any, **kwargs: Any) -> None:
        """
        Set context payload
        :return:
        """
        raise NotImplementedError("set_payload method must be implemented by subclass.")
