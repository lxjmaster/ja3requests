""""
ja3Requests.contexts.base
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic Context
"""
from abc import ABC, abstractmethod
from urllib.parse import urlparse, urlencode
from typing import AnyStr, Dict
from json import dumps


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
        self._body = None
        self._start_line = None
        self._message = None
        self._source_address = None
        self._timeout = None

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

        return self._destination_address

    @destination_address.setter
    def destination_address(self, attr: AnyStr):

        self._destination_address = attr

    @property
    def path(self) -> AnyStr:

        return self._path

    @path.setter
    def path(self, attr: AnyStr):

        self._path = attr

    @property
    def port(self) -> int:

        return self._port

    @port.setter
    def port(self, attr: int):

        self._port = attr

    @property
    def start_line(self) -> AnyStr:
        """
        Start line
        :return:
        """
        return self._start_line if self._start_line else " ".join([self.method, self.path, self.version])

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
    def headers(self) -> AnyStr:
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
        self._headers = attr
        if self._headers:
            if not self._headers.get("Host", None):
                if self.destination_address:
                    self._headers.update({
                        "Host": self.destination_address
                    })

            if self.method == "POST" or self.method == "PUT":
                if not self._headers.get("Content-Type", None):
                    if self.data:
                        self._headers.update({
                            "Content-Type": "application/x-www-form-urlencoded"
                        })

                    if self.json:
                        self._headers.update({
                            "Content-Type": "application/json"
                        })

                if not self._headers.get("Content-Type", None):
                    self._headers.update({
                        "Content-Type": "application/x-www-form-urlencoded"
                    })

                self._headers.update({
                    "Content-Length": len(self.body)
                })


        headers = "\r\n".join([f"{k}: {v}" for k, v in self._headers.items()])
        self._headers = headers

    @property
    def data(self) -> AnyStr:

        return self._data

    @data.setter
    def data(self, attr):

        data = attr
        if isinstance(data, (dict, list, tuple)):
            data = urlencode(data)
        elif isinstance(data, bytes):
            data = data.decode()

        self._data = data

    @property
    def json(self) -> AnyStr:

        return self._json

    @json.setter
    def json(self, attr):

        json = attr
        if isinstance(json, dict):
            json = dumps(json)
        elif isinstance(json, bytes):
            json = json.decode()

        self._json = json

    @property
    def body(self) -> AnyStr:
        """
        Body
        :return:
        """
        if not self._body:
            if self.data:
                self._body = self.data

            if self.json:
                self._body = self.json

        return self._body

    @body.setter
    def body(self, attr):
        """
        Set body
        :param attr:
        :return:
        """
        self._body = attr

    @property
    def message(self) -> AnyStr:
        """
        Message
        :return:
        """
        message = ""
        if self._message:
            message = self._message
        else:
            if self.start_line:
                message += self.start_line
            if self.headers:
                message += "\r\n"
                message += self.headers

            message += "\r\n\r\n"
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

        return self._source_address

    @source_address.setter
    def source_address(self, attr):

        self._source_address = attr

    @property
    def timeout(self):

        return self._timeout

    @timeout.setter
    def timeout(self, attr):

        self._timeout = attr

    @abstractmethod
    def set_payload(
        self,
        method,
        url,
        port,
        data,
        headers,
        timeout,
        json
    ):
        """
        Set context payload
        :return:
        """
        raise NotImplementedError("set_payload method must be implemented by subclass.")
