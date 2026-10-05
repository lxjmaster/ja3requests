"""
Ja3Requests.base.__sessions
~~~~~~~~~~~~~~~~~~~~~~~~~~

Basic of Session.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional
from ja3requests._typing import Auth, Cookies, Headers, Params, Proxies
from ja3requests.const import DEFAULT_REDIRECT_LIMIT
from ja3requests.cookies import Ja3RequestsCookieJar, CookieJar
from ja3requests.utils import dict_from_cookie_string, add_dict_to_cookiejar

if TYPE_CHECKING:
    from ja3requests.requests.request import Request
    from ja3requests.response import Response


class BaseSession:
    """
    The basic request session.
    """

    def __init__(self) -> None:
        self._request: Optional[Request] = None
        self._response: Optional[Response] = None
        self._headers: Optional[Headers] = None
        self._cookies: Cookies = Ja3RequestsCookieJar()
        self._auth: Optional[Auth] = None
        self._proxies: Optional[Proxies] = None
        self._params: Optional[Params] = None
        self._max_redirects: Optional[int] = None
        self._allow_redirect: Optional[bool] = None
        self._ja3_text: Optional[str] = None
        self._h2_settings: Optional[Dict[int, int]] = None
        self._h2_window_update: Optional[int] = None
        self._h2_headers: Optional[List[str]] = None

    @property
    def Request(self) -> Optional[Request]:
        """
        Session property Request
        :return:
        """
        return self._request

    @Request.setter
    def Request(self, attr: Optional[Request]) -> None:
        self._request = attr

    @property
    def response(self) -> Optional[Response]:
        """
        Session property response
        :return:
        """
        return self._response

    @response.setter
    def response(self, attr: Optional[Response]) -> None:
        self._response = attr

    @property
    def headers(self) -> Optional[Headers]:
        """Headers
        Http headers.
        >>> {'Accept': '*/*', 'Accept-Encoding': 'gzip,deflate'}
        :return:
        """
        if not self._headers:
            if self.Request:
                self._headers = self.Request.headers

        return self._headers

    @headers.setter
    def headers(self, attr: Optional[Headers]) -> None:
        """
        Set Headers
        :param attr:
        :return:
        """
        self._headers = attr

    @staticmethod
    def resolve_cookies(
        cj: Ja3RequestsCookieJar, cookie: Cookies
    ) -> Ja3RequestsCookieJar:
        """
        Collection session cookies
        :param cj:
        :param cookie:
        :return:
        """
        if isinstance(cookie, (bytes, str)):
            cookies_dict = dict_from_cookie_string(cookie)
            cj = add_dict_to_cookiejar(cj, cookies_dict)
        elif isinstance(cookie, dict):
            cj = add_dict_to_cookiejar(cj, cookie)
        elif isinstance(cookie, CookieJar):
            cj.update(cookie)

        return cj

    @property
    def cookies(self) -> Ja3RequestsCookieJar:
        """Cookies
        Http cookies.
        >>> <Ja3RequestsCookieJar[]>
        :return:
        """
        cookies = Ja3RequestsCookieJar()
        if len(self._cookies) > 0:
            cookies = self.resolve_cookies(cookies, self._cookies)

        if self._request is not None and getattr(self._request, 'cookies', None):
            cookies = self.resolve_cookies(cookies, self._request.cookies)

        if self._response is not None and getattr(self._response, 'cookies', None):
            cookies = self.resolve_cookies(cookies, self._response.cookies)

        return cookies

    @cookies.setter
    def cookies(self, attr: Cookies) -> None:
        """
        Set Cookies
        :param attr:
        :return:
        """
        self._cookies = attr

    @property
    def auth(self) -> Optional[Auth]:
        """Auth
        >>> {'user': 'xxx', 'password': 'xxx'}
        :return:
        """
        if not self._auth:
            if self.Request:
                self._auth = self.Request.auth

        return self._auth

    @auth.setter
    def auth(self, attr: Optional[Auth]) -> None:
        """
        Set Auth
        :param attr:
        :return:
        """
        self._auth = attr

    @property
    def proxies(self) -> Optional[Proxies]:
        """Proxies
        Http proxy server.
        >>> {'http': 'user:password@host:port', 'https': 'user:password@host:port'}
        :return:
        """
        if not self._proxies:
            if self.Request:
                self._proxies = self.Request.proxies

        return self._proxies

    @proxies.setter
    def proxies(self, attr: Optional[Proxies]) -> None:
        """
        Set Proxies
        :param attr:
        :return:
        """
        self._proxies = attr

    @property
    def params(self) -> Optional[Params]:
        """Params.
        Request Params. ?page=1&per_page=10
        >>> {'page': 1, 'per_page': 10}
        :return:
        """
        if not self._params:
            if self.Request:
                self._params = self.Request.params

        return self._params

    @params.setter
    def params(self, attr: Optional[Params]) -> None:
        """
        Set Params
        :param attr:
        :return:
        """
        self._params = attr

    @property
    def max_redirects(self) -> int:
        """Max Redirects.
        The max for redirect times.
        >>> 5
        :return:
        """
        if not self._max_redirects:
            if self.Request:
                self._max_redirects = self.Request.max_redirects

        if not self._max_redirects:
            self._max_redirects = DEFAULT_REDIRECT_LIMIT

        return self._max_redirects

    @max_redirects.setter
    def max_redirects(self, attr: Optional[int]) -> None:
        """
        Set Max Redirects
        :param attr:
        :return:
        """
        self._max_redirects = attr

    @property
    def allow_redirect(self) -> bool:
        """Allow Redirect.
        Whether allow redirect.
        >>> True or False.
        :return:
        """
        if not self._allow_redirect:
            if self.Request:
                self._allow_redirect = self.Request.allow_redirect

        if not self._allow_redirect:
            self._allow_redirect = True

        return self._allow_redirect

    @allow_redirect.setter
    def allow_redirect(self, attr: Optional[bool]) -> None:
        """
        Set Allow Redirect
        :param attr:
        :return:
        """
        self._allow_redirect = attr

    @property
    def ja3_text(self) -> Optional[str]:
        """Ja3 Text.
        The TLS fingerprint ja3 text.
        >>> "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,17513-27-0-13-35-43-65281-23-51-5-45-11-16-10-18-21,29-23-24,0"
        :return:
        """
        return self._ja3_text

    @ja3_text.setter
    def ja3_text(self, attr: Optional[str]) -> None:
        """
        Set Ja3 Text
        :param attr:
        :return:
        """
        self._ja3_text = attr

    @property
    def h2_settings(self) -> Optional[Dict[int, int]]:
        """H2 Settings.
        The htp2 fingerprint SETTINGS.
        >>> {"1": "65535", "2": "0", "3": "1000", "4": "6291456", "6": "262144"}
        :return:
        """
        return self._h2_settings

    @h2_settings.setter
    def h2_settings(self, attr: Optional[Dict[int, int]]) -> None:
        """
        Set H2 Settings
        :param attr:
        :return:
        """
        self._h2_settings = attr

    @property
    def h2_window_update(self) -> Optional[int]:
        """H2 Window Update.
        The http2 fingerprint WINDOW_UPDATE.
        >>> "15663105"
        :return:
        """
        return self._h2_window_update

    @h2_window_update.setter
    def h2_window_update(self, attr: Optional[int]) -> None:
        """
        Set Window Update
        :param attr:
        :return:
        """
        self._h2_window_update = attr

    @property
    def h2_headers(self) -> Optional[List[str]]:
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
    def h2_headers(self, attr: Optional[List[str]]) -> None:
        """
        Set H2 Headers
        :param attr:
        :return:
        """
        self._h2_headers = attr

    def __enter__(self) -> BaseSession:
        return self

    def __exit__(self, *args: Any, **kwargs: Any) -> Optional[bool]:
        self.close(*args, **kwargs)

    def close(self, *args: Any, **kwargs: Any) -> None:
        """
        Close session.
        :param args:
        :param kwargs:
        :return:
        """

    def request(self, *args: Any, **kwargs: Any) -> Optional[Response]:
        """
        Request
        :return:
        """

    def get(self, *args: Any, **kwargs: Any) -> Optional[Response]:
        """
        GET Method.
        :return:
        """

    def options(self, *args: Any, **kwargs: Any) -> Optional[Response]:
        """
        OPTIONS Method.
        :return:
        """

    def head(self, *args: Any, **kwargs: Any) -> Optional[Response]:
        """
        HEAD Method.
        :return:
        """

    def post(self, *args: Any, **kwargs: Any) -> Optional[Response]:
        """
        POST Method.
        :return:
        """

    def put(self, *args: Any, **kwargs: Any) -> Optional[Response]:
        """
        PUT Method.
        :return:
        """

    def patch(self, *args: Any, **kwargs: Any) -> Optional[Response]:
        """
        PATCH Method.
        :return:
        """

    def delete(self, *args: Any, **kwargs: Any) -> Optional[Response]:
        """
        DELETE Method.
        :return:
        """

    def send(self, *args: Any, **kwargs: Any) -> Optional[Response]:
        """
        Send
        :return:
        """
