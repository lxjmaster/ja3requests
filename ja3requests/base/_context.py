""""
ja3Requests.base._context
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic Context
"""


class BaseContext:

    def __init__(self):
        self._protocol = None
        self._version = None
        self._start_line = None
        self._method = None
        self._headers = None
        self._body = None
        self._message = None

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, attr):
        self._protocol = attr

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, attr):
        self._version = attr

    @property
    def start_line(self):
        return self._start_line

    @start_line.setter
    def start_line(self, attr):
        self._start_line = attr

    @property
    def method(self):
        return self._method

    @method.setter
    def method(self, attr):
        self._method = attr

    @property
    def headers(self):
        return self._headers

    @headers.setter
    def headers(self, attr):
        self._headers = attr

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, attr):
        self._body = attr

    @property
    def message(self):
        return self._message

    @message.setter
    def message(self, attr):
        self._message = attr
