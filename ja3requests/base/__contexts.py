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
        self._host = None
        self._path = None
        self._headers = None
        self._body = None
        self._start_line = None
        self._message = None

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
    def host(self) -> typing.AnyStr:

        return self._host

    @host.setter
    def host(self, attr: typing.AnyStr):

        self._host = attr

    @property
    def path(self) -> typing.AnyStr:

        return self._path

    @path.setter
    def path(self, attr: typing.AnyStr):

        self._path = attr

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
            self.host = parse.hostname
            self.path = parse.path
            if self.path == "":
                self.path = "/"

            if parse.query != "":
                self.path += "?" + parse.query

        self._start_line = " ".join([self.method, self.path, self.version])

    @property
    def headers(self):
        """
        Headers
        :return:
        """
        return self._headers

    @headers.setter
    def headers(self, attr):
        """
        Set headers
        :param attr:
        :return:
        """
        self._headers = attr

    @property
    def body(self):
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
    def message(self):
        """
        Message
        :return:
        """
        return self._message

    @message.setter
    def message(self, attr):
        """
        Set message
        :param attr:
        :return:
        """
        self._message = attr

    @abstractmethod
    def set_payload(
        self,
        method,
        url,
        data,
        headers,
    ):
        """
        Set context payload
        :return:
        """
        raise NotImplementedError("set_payload method must be implemented by subclass.")
