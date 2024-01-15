"""
Ja3Requests.base.__response
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic of Response.
"""


class BaseResponse:
    """
    The basic response.
    """

    def __init__(self):
        self._raw = None
        self._protocol_version = None
        self._status_code = None
        self._status_text = None
        self._headers = None
        self._body = None

    @property
    def raw(self):
        """Raw Response
        Receive from remote connection.
        >>> b"HTTP/1.1 200 OK..."
        :return:
        """
        return self._raw

    @raw.setter
    def raw(self, attr):
        """
        Set raw response.
        :param attr:
        :return:
        """
        self._raw = attr

    @property
    def protocol_version(self):
        """
        Protocol Version
        >>> b"HTTP/1.1"
        :return:
        """
        return self._protocol_version

    @protocol_version.setter
    def protocol_version(self, attr):
        """
        Set protocol version
        :param attr:
        :return:
        """
        self._protocol_version = attr

    @property
    def status_code(self):
        """STATUS CODE
        The response status code, e.g(200, 203, 400, 404...)
        >>> b"200"
        :return:
        """
        return self._status_code

    @status_code.setter
    def status_code(self, attr):
        """
        Set response status code.
        :param attr:
        :return:
        """
        self._status_code = attr

    @property
    def status_text(self):
        """
        Response status text. eg. HTTP/1.1 200 OK
        >>> b"OK"
        :return:
        """
        return self._status_text

    @status_text.setter
    def status_text(self, attr):
        """
        Set response status text.
        :param attr:
        :return:
        """
        self._status_text = attr

    @property
    def headers(self):
        """Headers
        Response headers
        :return:
        """
        return self._headers

    @headers.setter
    def headers(self, attr):
        """
        Set response headers.
        :param attr:
        :return:
        """
        self._headers = attr

    @property
    def body(self):
        """
        Response Body
        :return:
        """
        return self._body

    @body.setter
    def body(self, attr):
        """
        Set response body.
        :param attr:
        :return:
        """
        self._body = attr
