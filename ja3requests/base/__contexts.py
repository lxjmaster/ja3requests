""""
ja3Requests.contexts.base
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic Context
"""
from abc import ABC, abstractmethod
from urllib.parse import urlparse
import typing


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
    def method(self) -> typing.AnyStr:
        """
        Method
        :return:
        """
        return self._method

    @method.setter
    def method(self, attr: typing.AnyStr):
        """
        Set method
        :param attr:
        :return:
        """
        self._method = attr

    @property
    def destination_address(self) -> typing.AnyStr:

        return self._destination_address

    @destination_address.setter
    def destination_address(self, attr: typing.AnyStr):

        self._destination_address = attr

    @property
    def path(self) -> typing.AnyStr:

        return self._path

    @path.setter
    def path(self, attr: typing.AnyStr):

        self._path = attr

    @property
    def port(self) -> int:

        return self._port

    @port.setter
    def port(self, attr: int):

        self._port = attr

    @property
    def start_line(self) -> typing.AnyStr:
        """
        Start line
        :return:
        """
        return self._start_line if self._start_line else " ".join([self.method, self.path, self.version])

    @start_line.setter
    def start_line(self, attr: typing.AnyStr):
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
    def headers(self) -> typing.AnyStr:
        """
        Headers
        :return:
        """
        return self._headers

    @headers.setter
    def headers(self, attr: typing.Dict):
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

        headers = "\r\n".join([f"{k}: {v}" for k, v in self._headers.items()])
        self._headers = headers

    @property
    def body(self) -> typing.AnyStr:
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
        self._body = attr

    @property
    def message(self) -> typing.AnyStr:
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
    def message(self, attr: typing.AnyStr):
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
    ):
        """
        Set context payload
        :return:
        """
        raise NotImplementedError("set_payload method must be implemented by subclass.")
