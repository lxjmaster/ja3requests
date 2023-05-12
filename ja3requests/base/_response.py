"""
ja3Requests.base._response
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic Response
"""


class BaseResponse:

    def __init__(self):

        self._raw = None
        self._protocol_version = None
        self._status_code = None
        self._status_text = None
        self._headers = None
        self._body = None

    @property
    def raw(self):
        return self._raw

    @raw.setter
    def raw(self, attr):
        self._raw = attr

    @property
    def protocol_version(self):
        return self._protocol_version

    @protocol_version.setter
    def protocol_version(self, attr):
        self._protocol_version = attr

    @property
    def status_code(self):
        return self._status_code

    @status_code.setter
    def status_code(self, attr):
        self._status_code = attr

    @property
    def status_text(self):
        return self._status_text

    @status_text.setter
    def status_text(self, attr):
        self._status_text = attr

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
