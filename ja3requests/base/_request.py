"""
ja3Requests.base._request
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic Request
"""


class BaseRequest:
    """
    The basic request.
    """

    def __init__(self):
        self._method = None
        self._source = None
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
        self._timeout = None
        self._proxies = None

    @property
    def method(self):
        """
        Request method
        >>> "GET"
        :return:
        """
        return self._method

    @method.setter
    def method(self, attr):
        """
        Set request method.
        :param attr:
        :return:
        """
        self._method = attr

    @property
    def source(self):
        """
        Source Address.
        :return:
        """
        return self._source

    @source.setter
    def source(self, attr):
        """
        Set source address.
        :param attr:
        :return:
        """
        self._source = attr

    @property
    def url(self):
        """
        Request url.
        :return:
        """
        return self._url

    @url.setter
    def url(self, attr):
        """
        Set request url.
        :param attr:
        :return:
        """
        self._url = attr

    @property
    def scheme(self):
        """
        Request Scheme. eg. HTTP, HTTPS
        :return:
        """
        return self._scheme

    @scheme.setter
    def scheme(self, attr):
        """
        Set scheme.
        :param attr:
        :return:
        """
        self._scheme = attr

    @property
    def port(self):
        """
        Remote address port.
        :return:
        """
        return self._port

    @port.setter
    def port(self, attr):
        """
        Set port.
        :param attr:
        :return:
        """
        self._port = attr

    @property
    def headers(self):
        """Headers
        Request headers.
        >>> {"Host": "www.example.com", "Accept": "*/*"}
        :return:
        """
        return self._headers

    @headers.setter
    def headers(self, attr):
        """
        Set request headers.
        :param attr:
        :return:
        """
        self._headers = attr

    @property
    def params(self):
        """
        Request params. eg. ?page=1&page_size=10&desc=1
        >>> [("page", 1), ("page_size", 10),]
        :return:
        """
        return self._params

    @params.setter
    def params(self, attr):
        """
        Set params.
        :param attr:
        :return:
        """
        self._params = attr

    @property
    def data(self):
        """
        Post request data.
        >>> {"username": "admin", "password": "admin"}
        :return:
        """
        return self._data

    @data.setter
    def data(self, attr):
        """
        Set post request data.
        :param attr:
        :return:
        """
        self._data = attr

    @property
    def cookies(self):
        """
        Request cookies.
        >>> {"UUID": "xxxxxxx"}
        :return:
        """
        return self._cookies

    @cookies.setter
    def cookies(self, attr):
        """
        Set request cookies.
        :param attr:
        :return:
        """
        self._cookies = attr

    @property
    def files(self):
        """
        Request files.
        :return:
        """
        return self._files

    @files.setter
    def files(self, attr):
        """
        Set files.
        :param attr:
        :return:
        """
        self._files = attr

    @property
    def auth(self):
        """
        Request Authorization.
        >>> {"username": "admin", "password": "admin"}
        :return:
        """
        return self._auth

    @auth.setter
    def auth(self, attr):
        """
        Set authorization.
        :param attr:
        :return:
        """
        self._auth = attr

    @property
    def json(self):
        """
        Post json.
        :return:
        """
        return self._json

    @json.setter
    def json(self, attr):
        """
        Set json for post request.
        :param attr:
        :return:
        """
        self._json = attr

    @property
    def timeout(self):
        """
        Request timeout.
        :return:
        """
        return self._timeout

    @timeout.setter
    def timeout(self, attr):
        """
        Set request timeout.
        :param attr:
        :return:
        """
        self._timeout = attr

    @property
    def proxies(self):
        """
        Request proxies.
        >>> {"http": "username:password@host:port", "https": "username:password@host:port"}
        :return:
        """
        return self._proxies

    @proxies.setter
    def proxies(self, attr):
        """
        Set proxies.
        :param attr:
        :return:
        """
        self._proxies = attr

    def is_http(self):
        """
        Is http request.
        :return:
        """
        return self._scheme == "http"

    def is_https(self):
        """
        Is https request.
        :return:
        """
        return self._scheme == "https"
