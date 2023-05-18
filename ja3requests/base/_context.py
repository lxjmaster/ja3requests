""""
ja3Requests.base._context
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic Context
"""


class BaseContext:
    """
    Basic connection context.
    """

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
    def start_line(self):
        """
        Start line
        :return:
        """
        return self._start_line

    @start_line.setter
    def start_line(self, attr):
        """
        Set start line
        :param attr:
        :return:
        """
        self._start_line = attr

    @property
    def method(self):
        """
        Method
        :return:
        """
        return self._method

    @method.setter
    def method(self, attr):
        """
        Set method
        :param attr:
        :return:
        """
        self._method = attr

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
