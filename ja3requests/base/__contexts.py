""""
Ja3Requests.base.__contexts
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic of Context.
"""
from urllib.parse import urlparse, urlencode, parse_qsl
from abc import ABC, abstractmethod
from typing import AnyStr, Dict
from json import dumps
import mimetypes


class BaseContext(ABC):
    """
    Basic connection context.
    """

    def __init__(self):
        self._protocol = None
        self._version = None
        self._method = None
        self._destination_address = None
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
    def protocol(self):
        """
        Protocol
        :return:
        """
        return self._protocol

    @protocol.setter
    def protocol(self, attr):
        """
        Set protocol
        :param attr:
        :return:
        """
        self._protocol = attr

    @property
    def version(self):
        """
        Version
        :return:
        """
        return self._version

    @version.setter
    def version(self, attr):
        """
        Set version
        :param attr:
        :return:
        """
        self._version = attr

    @property
    def method(self) -> AnyStr:
        """
        Method
        :return:
        """
        return self._method

    @method.setter
    def method(self, attr: AnyStr):
        """
        Set method
        :param attr:
        :return:
        """
        self._method = attr

    @property
    def destination_address(self) -> AnyStr:
        """
        Context property destination_address
        :return:
        """
        return self._destination_address

    @destination_address.setter
    def destination_address(self, attr: AnyStr):
        """
        Conntext property destination_address set
        :param attr:
        :return:
        """
        self._destination_address = attr

    @property
    def path(self) -> AnyStr:
        """
        Context property path
        :return:
        """
        return self._path

    @path.setter
    def path(self, attr: AnyStr):
        """
        Context property path set
        :param attr:
        :return:
        """
        self._path = attr

    @property
    def port(self) -> int:
        """
        Context property port
        :return:
        """
        return self._port

    @port.setter
    def port(self, attr: int):
        """
        Context property port set
        :param attr:
        :return:
        """
        self._port = attr

    @property
    def start_line(self) -> AnyStr:
        """
        Start line
        :return:
        """
        return (
            self._start_line
            if self._start_line
            else " ".join([self.method, self.path, self.version])
        )

    @start_line.setter
    def start_line(self, attr: AnyStr):
        """
        Set start line
        :param attr:
        :return:
        """
        if attr:
            parse = urlparse(attr)
            self.destination_address = parse.hostname
            self.path = parse.path
            if self.path == "":
                self.path = "/"

            if parse.query != "":
                self.path += "?" + parse.query

        self._start_line = " ".join([self.method, self.path, self.version])

    @property
    def headers(self) -> Dict:
        """
        Headers
        :return:
        """
        return self._headers

    @headers.setter
    def headers(self, attr: Dict):
        """
        Set headers
        :param attr:
        :return:
        """
        headers = attr
        if headers:
            if not headers.get("Host", None):
                if self.destination_address:
                    headers.update({"Host": self.destination_address})

            if self.method in ["POST", "PUT"]:
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

    @property
    def data(self) -> AnyStr:
        """
        Context property data
        :return:
        """
        return self._data

    @data.setter
    def data(self, attr):
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
    def json(self) -> AnyStr:
        """
        Context property json
        :return:
        """
        return self._json

    @json.setter
    def json(self, attr):
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
    def files(self):
        """
        Context property files
        :return:
        """
        return self._files

    @files.setter
    def files(self, attr):
        """
        Context property files set
        :param attr:
        :return:
        """
        self._files = attr

    @property
    def body(self) -> AnyStr:
        """
        Body
        :return:
        """

        return self._body

    @body.setter
    def body(self, attr):
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
    def message(self) -> AnyStr:
        """
        Message
        :return:
        """
        if self.data:
            self.body = self.data
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
                message += "\r\n".join(
                    [f"{k}: {v}" for k, v in self.headers.items()]
                ).encode()

            message += b"\r\n\r\n"

            if self.body:
                message += self.body

        self._message = message

        return self._message

    @message.setter
    def message(self, attr: AnyStr):
        """
        Set message
        :param attr:
        :return:
        """
        self._message = attr

    @property
    def source_address(self):
        """
        Context property source_address
        :return:
        """
        return self._source_address

    @source_address.setter
    def source_address(self, attr):
        """
        Context property source_address setter
        :param attr:
        :return:
        """
        self._source_address = attr

    @property
    def timeout(self):
        """
        Context property timeout
        :return:
        """
        return self._timeout

    @timeout.setter
    def timeout(self, attr):
        """
        Context property timeout set
        :param attr:
        :return:
        """
        self._timeout = attr

    @property
    def proxy(self):
        """
        Context property proxy
        :return:
        """
        proxy = None
        if self._proxy:
            if "@" in self._proxy:
                proxy = self._proxy.split("@")[-1]
            else:
                proxy = self._proxy

        return proxy

    @proxy.setter
    def proxy(self, attr):
        """
        Context property proxy set
        :param attr:
        :return:
        """
        self._proxy = attr

    @property
    def proxy_auth(self):
        """
        Context property proxy auth
        :return:
        """
        proxy_auth = None
        if self._proxy:
            if "@" in self._proxy:
                proxy_auth = self._proxy.split("@")[0]

        return proxy_auth

    @property
    def cookies(self):
        """
        Context property cookies
        :return:
        """
        return self._cookies

    @cookies.setter
    def cookies(self, attr: Dict):
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
    def set_payload(self, *args, **kwargs):
        """
        Set context payload
        :return:
        """
        raise NotImplementedError("set_payload method must be implemented by subclass.")
