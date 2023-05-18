"""
ja3Requests.base._sessions
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic Session
"""


class BaseSession:
    """
    The basic request session.
    """

    def __init__(self):
        self._headers = None
        self._cookies = None
        self._auth = None
        self._proxies = None
        self._params = None
        self._max_redirects = None
        self._allow_redirect = None
        self._ja3_text = None
        self._h2_settings = None
        self._h2_window_update = None
        self._h2_headers = None

    @property
    def headers(self):
        """Headers
        Http headers.
        >>> {'Accept': '*/*', 'Accept-Encoding': 'gzip,deflate'}
        :return:
        """
        return self._headers

    @headers.setter
    def headers(self, attr):
        """
        Set Headers
        :param attr:
        :return:
        """
        self._headers = attr

    @property
    def cookies(self):
        """Cookies
        Http cookies.
        >>> CookieJar({})
        :return:
        """
        return self._cookies

    @cookies.setter
    def cookies(self, attr):
        """
        Set Cookies
        :param attr:
        :return:
        """
        self.cookies = attr

    @property
    def auth(self):
        """Auth
        >>> {'user': 'xxx', 'password': 'xxx'}
        :return:
        """
        return self._auth

    @auth.setter
    def auth(self, attr):
        """
        Set Auth
        :param attr:
        :return:
        """
        self._auth = attr

    @property
    def proxies(self):
        """Proxies
        Http proxy server.
        >>> {'http': 'user:password@host:port', 'https': 'user:password@host:port'}
        :return:
        """
        return self._cookies

    @proxies.setter
    def proxies(self, attr):
        """
        Set Proxies
        :param attr:
        :return:
        """
        self._proxies = attr

    @property
    def params(self):
        """Params.
        Request Params. ?page=1&per_page=10
        >>> {'page': 1, 'per_page': 10}
        :return:
        """
        return self._params

    @params.setter
    def params(self, attr):
        """
        Set Params
        :param attr:
        :return:
        """
        self._params = attr

    @property
    def max_redirects(self):
        """Max Redirects.
        The max for redirect times.
        >>> 5
        :return:
        """
        return self._max_redirects

    @max_redirects.setter
    def max_redirects(self, attr):
        """
        Set Max Redirects
        :param attr:
        :return:
        """
        self._max_redirects = attr

    @property
    def allow_redirect(self):
        """Allow Redirect.
        Whether allow redirect.
        >>> True or False.
        :return:
        """
        return self._allow_redirect

    @allow_redirect.setter
    def allow_redirect(self, attr):
        """
        Set Allow Redirect
        :param attr:
        :return:
        """
        self._allow_redirect = attr

    @property
    def ja3_text(self):
        """Ja3 Text.
        The TLS fingerprint ja3 text.
        >>> "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17513-27-0-13-35-43-65281-23-51-5-45-11-16-10-18-21,29-23-24,0"
        :return:
        """
        return self._ja3_text

    @ja3_text.setter
    def ja3_text(self, attr):
        """
        Set Ja3 Text
        :param attr:
        :return:
        """
        self._ja3_text = attr

    @property
    def h2_settings(self):
        """H2 Settings.
        The htp2 fingerprint SETTINGS.
        >>> {"1": "65535", "2": "0", "3": "1000", "4": "6291456", "6": "262144"}
        :return:
        """
        return self._h2_settings

    @h2_settings.setter
    def h2_settings(self, attr):
        """
        Set H2 Settings
        :param attr:
        :return:
        """
        self._h2_settings = attr

    @property
    def h2_window_update(self):
        """H2 Window Update.
        The http2 fingerprint WINDOW_UPDATE.
        >>> "15663105"
        :return:
        """
        return self._h2_window_update

    @h2_window_update.setter
    def h2_window_update(self, attr):
        """
        Set Window Update
        :param attr:
        :return:
        """
        self._h2_window_update = attr

    @property
    def h2_headers(self):
        """H2 Headers.
        The http2 fingerprint HEADERS.
        :method
        :authority
        :scheme
        :path
        >>> "m,a,s,p"
        :return:
        """
        return self._h2_headers

    @h2_headers.setter
    def h2_headers(self, attr):
        """
        Set H2 Headers
        :param attr:
        :return:
        """
        self._h2_headers = attr

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.close(*args, **kwargs)

    def close(self, *args, **kwargs):
        """
        Close session.
        :param args:
        :param kwargs:
        :return:
        """

    def request(self, *args, **kwargs):
        """
        Request
        :return:
        """

    def get(self, *args, **kwargs):
        """
        GET Method.
        :return:
        """

    def options(self, *args, **kwargs):
        """
        OPTIONS Method.
        :return:
        """

    def head(self, *args, **kwargs):
        """
        HEAD Method.
        :return:
        """

    def post(self, *args, **kwargs):
        """
        POST Method.
        :return:
        """

    def put(self, *args, **kwargs):
        """
        PUT Method.
        :return:
        """

    def patch(self, *args, **kwargs):
        """
        PATCH Method.
        :return:
        """

    def delete(self, *args, **kwargs):
        """
        DELETE Method.
        :return:
        """

    def send(self, *args, **kwargs):
        """
        Send
        :return:
        """
