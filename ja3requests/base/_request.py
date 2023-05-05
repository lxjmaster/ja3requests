"""
ja3Requests.base._request
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic Request
"""


class BaseRequest:

    def __init__(self):

        self._method = None
        self._url = None
        self._scheme = None
        self._port = None
        self._headers = None
        self._params = None
        self._data = None
        self._cookies = None
        self._files = None
        self._auth = None
        self._json = None

    @property
    def method(self):
        return self._method

    @method.setter
    def method(self, attr):
        self._method = attr

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, attr):
        self._url = attr

    @property
    def scheme(self):
        return self._scheme

    @scheme.setter
    def scheme(self, attr):
        self._scheme = attr

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, attr):
        self._port = attr

    @property
    def headers(self):
        return self._headers

    @headers.setter
    def headers(self, attr):
        self._headers = attr

    @property
    def params(self):
        return self._params

    @params.setter
    def params(self, attr):
        self._params = attr

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, attr):
        self._data = attr

    @property
    def cookies(self):
        return self._cookies

    @cookies.setter
    def cookies(self, attr):
        self._cookies = attr

    @property
    def files(self):
        return self._files

    @files.setter
    def files(self, attr):
        self._files = attr

    @property
    def auth(self):
        return self._auth

    @auth.setter
    def auth(self, attr):
        self._auth = attr

    @property
    def json(self):
        return self._json

    @json.setter
    def json(self, attr):
        self._json = attr
