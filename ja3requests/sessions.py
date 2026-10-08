"""
Ja3Requests.sessions
~~~~~~~~~~~~~~~~~~~~

This module provides a Session object to manage and persist settings across
ja3Requests.
"""

from __future__ import annotations

import copy
from http.cookiejar import CookieJar
import sys
import threading
import time
from types import TracebackType
from typing import TYPE_CHECKING, Any, Dict, Optional, Type, TypeVar
from ja3requests.base import BaseSession
from ja3requests.response import Response
from ja3requests.const import DEFAULT_REDIRECT_LIMIT
from ja3requests.base import BaseRequest
from ja3requests.requests.request import Request
from ja3requests.exceptions import MaxRetriedException
from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.pool import ConnectionPool, get_default_pool
from ja3requests.cookies import (
    Ja3RequestsCookieJar,
    extract_cookies_to_jar,
    merge_cookies,
)
from ja3requests.protocol.tls.session_cache import TLSSessionCache
from ja3requests.retry import HTTPRetry
from ja3requests._cookie_file import load_cookie_file, save_cookie_file
from ja3requests._upload import UploadSource, is_upload
from ja3requests.sockets._upload import upload_length
from ja3requests.exceptions import InvalidData, StreamConsumedError
from ja3requests._typing import (
    Auth,
    Cookies,
    Data,
    Files,
    Headers,
    JsonBody,
    Params,
    PathInput,
    Proxies,
    Timeout,
)

if TYPE_CHECKING:
    from typing_extensions import Literal, Unpack
    from ja3requests._typing import (
        GetOptions,
        Hooks,
        PostOptions,
        RequestOptions,
        SendOptions,
    )

_HookValue = TypeVar('_HookValue', BaseRequest, Response)

# Preferred clock, based on which one is more accurate on a given system.
if sys.platform == "win32":
    preferred_clock = time.perf_counter
else:
    preferred_clock = time.time


class Session(BaseSession):
    """A Ja3Request session.

    Provides cookie persistence, connection-pooling, and configuration.
    """

    def __init__(
        self,
        tls_config: Optional[TlsConfig] = None,
        pool: Optional[ConnectionPool] = None,
        use_pooling: bool = True,
        hooks: Optional[Hooks] = None,
        retry: Optional[HTTPRetry] = None,
    ) -> None:
        super().__init__()
        self._request_local = threading.local()
        self._cookie_lock = threading.RLock()
        self._cookie_view = None
        self._uploads = set()
        self._tls_config = tls_config or TlsConfig()
        # Enable session resumption by default
        if self._tls_config.session_cache is None:
            self._tls_config.session_cache = TLSSessionCache()
        self._use_pooling = use_pooling
        self._pool = (
            pool if pool is not None else (get_default_pool() if use_pooling else None)
        )
        self.hooks = {
            "before_request": [],
            "after_request": [],
        }
        if hooks:
            for event, callbacks in hooks.items():
                if event in self.hooks:
                    self.hooks[event].extend(callbacks)
        self._retry = retry

    @property
    def Request(self) -> Optional[Request]:
        return getattr(self._request_local, 'value', self._request)

    @Request.setter
    def Request(self, request: Optional[Request]) -> None:
        self._request_local.value = request
        self._request = request

    @property
    def tls_config(self) -> TlsConfig:
        """Get TLS configuration"""
        return self._tls_config

    @tls_config.setter
    def tls_config(self, config: TlsConfig) -> None:
        """Set TLS configuration"""
        self._tls_config = config

    @property
    def pool(self) -> Optional[ConnectionPool]:
        """Get connection pool"""
        return self._pool

    @pool.setter
    def pool(self, pool: Optional[ConnectionPool]) -> None:
        """Set connection pool"""
        self._pool = pool

    @property
    def cookies(self) -> Ja3RequestsCookieJar:
        """Return a detached snapshot, including the latest request's cookies."""
        with self._cookie_lock:
            if self._cookie_view is not None:
                return self._cookie_view.copy()
            return self.resolve_cookies(Ja3RequestsCookieJar(), self._cookies)

    @cookies.setter
    def cookies(self, attr: Cookies) -> None:
        with self._cookie_lock:
            self._cookies = attr
            self._cookie_view = None

    def close(self) -> None:
        """Close an explicitly supplied pool; preserve the shared default pool."""
        with self._cookie_lock:
            uploads = tuple(self._uploads)
        error = None
        for upload in uploads:
            try:
                upload.close()
            except Exception as failure:
                error = failure
        if self._pool and self._pool is not get_default_pool():
            self._pool.close_all()
        if error is not None:
            raise error

    def _register_upload(self, upload):
        with self._cookie_lock:
            self._uploads.add(upload)

        def unregister():
            with self._cookie_lock:
                self._uploads.discard(upload)

        return unregister

    def save_cookies(self, path: PathInput, *, include_session: bool = False) -> int:
        """Save the stored Session Cookies; return the count written.

        This explicit operation does not include transient request Cookies.
        """
        with self._cookie_lock:
            return save_cookie_file(
                self._cookies, path, include_session=include_session
            )

    def load_cookies(
        self, path: PathInput, *, merge: bool = False, include_session: bool = False
    ) -> int:
        """Load stored Cookies atomically, replacing them unless merge=True."""
        with self._cookie_lock:
            count = load_cookie_file(
                self._cookies, path, merge=merge, include_session=include_session
            )
            self._cookie_view = None
            return count

    def __enter__(self) -> Session:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Literal[False]:
        self.close()
        return False

    def request(  # pylint: disable=too-many-locals
        self,
        method: str,
        url: str,
        *,
        params: Optional[Params] = None,
        data: Optional[Data] = None,
        headers: Optional[Headers] = None,
        cookies: Optional[Cookies] = None,
        files: Optional[Files] = None,
        auth: Optional[Auth] = None,
        proxies: Optional[Proxies] = None,
        json: Optional[JsonBody] = None,
        timeout: Timeout = None,
        verify: Optional[bool] = None,
        tls_config: Optional[TlsConfig] = None,
        **kwargs: Unpack[SendOptions],
    ) -> Response:
        """
        Instantiating a request class<Request> and ready request<ReadyRequest> to send.
        :param method:
        :param url:
        :param params:
        :param data:
        :param headers:
        :param cookies:
        :param files:
        :param auth: Tuple of (username, password) for Basic Auth.
        :param proxies:
        :param json:
        :param timeout: Timeout in seconds for connect and read.
        :param verify: Override TLS certificate verification for this request.
                       If omitted, use the session TLS configuration.
        :return:
        """

        # Apply verify to TLS config (deep copy to avoid mutating session config)
        tls_config = tls_config or self._tls_config
        if verify is not None and verify != tls_config.verify_cert:
            # The thread-safe cache belongs to the session, not the request.
            cache = tls_config.session_cache
            tls_config = copy.deepcopy(tls_config, {id(cache): cache})
            tls_config.verify_cert = verify

        # Merge session-level cookies with per-request cookies
        merged_cookies = Ja3RequestsCookieJar()
        with self._cookie_lock:
            if not isinstance(self._cookies, CookieJar):
                self._cookies = self.resolve_cookies(
                    Ja3RequestsCookieJar(), self._cookies
                )
            if len(self._cookies) > 0:
                merge_cookies(merged_cookies, self._cookies)
            if cookies is not None:
                merge_cookies(merged_cookies, cookies)
            # This compatibility view never aliases any in-flight sending jar.
            self._cookie_view = merged_cookies.copy()

        self.Request = Request(
            method=method,
            url=url,
            params=params,
            data=data,
            headers=headers,
            cookies=merged_cookies,
            files=files,
            auth=auth,
            json=json,
            proxies=proxies,
            timeout=timeout,
            tls_config=tls_config,
        )

        kwargs.setdefault("allow_redirects", True)

        req = self.Request.request()
        response = self.send(req, **kwargs)

        return response

    def get(
        self,
        url: str,
        params: Optional[Params] = None,
        headers: Optional[Headers] = None,
        **kwargs: Unpack[GetOptions],
    ) -> Response:
        """
        Send a GET request.
        :param url:
        :param params:
        :param headers:
        :param kwargs:
        :return:
        """
        # Extract tls_config from kwargs if provided
        tls_config = kwargs.pop('tls_config', None)
        if tls_config:
            return self.request(
                "GET",
                url,
                params=params,
                headers=headers,
                tls_config=tls_config,
                **kwargs,
            )
        else:
            return self.request("GET", url, params=params, headers=headers, **kwargs)

    def options(self, url: str, **kwargs: Unpack[RequestOptions]) -> Response:
        """
        Send a OPTIONS request.
        :param url:
        :param kwargs:
        :return:
        """

        return self.request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs: Unpack[RequestOptions]) -> Response:
        """
        Send a HEAD request.
        :param url:
        :param kwargs:
        :return:
        """

        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)

    def post(
        self,
        url: str,
        *,
        data: Optional[Data] = None,
        json: Optional[JsonBody] = None,
        files: Optional[Files] = None,
        headers: Optional[Headers] = None,
        **kwargs: Unpack[PostOptions],
    ) -> Response:
        """
        Send a POST request.
        :param url:
        :param data:
        :param json:
        :param files:
        :param headers:
        :param kwargs:
        :return:
        """

        return self.request(
            "POST", url, data=data, json=json, files=files, headers=headers, **kwargs
        )

    def put(self, url: str, **kwargs: Unpack[RequestOptions]) -> Response:
        """
        Send a PUT request.
        :param url:
        :param kwargs:
        :return:
        """

        return self.request("PUT", url, **kwargs)

    def patch(self, url: str, **kwargs: Unpack[RequestOptions]) -> Response:
        """
        Send a PATCH request.
        :param url:
        :param kwargs:
        :return:
        """

        return self.request("PATCH", url, **kwargs)

    def delete(self, url: str, **kwargs: Unpack[RequestOptions]) -> Response:
        """
        Send a DELETE request.
        :param url:
        :param kwargs:
        :return:
        """

        return self.request("DELETE", url, **kwargs)

    def _dispatch_hooks(
        self,
        event: str,
        hook_data: _HookValue,
        per_request_hooks: Optional[Hooks] = None,
    ) -> _HookValue:
        """
        Call all registered hooks for a given event.
        :param event: Hook event name (e.g., 'before_request', 'after_request')
        :param hook_data: The object passed to each hook callback.
        :param per_request_hooks: Optional per-request hooks dict.
        :return: The hook_data (possibly modified by callbacks).
        """
        callbacks = list(self.hooks.get(event, []))
        if per_request_hooks and event in per_request_hooks:
            callbacks.extend(per_request_hooks[event])
        for callback in callbacks:
            result = callback(hook_data)
            if result is not None:
                hook_data = result
        return hook_data

    def _dispatch_response_hooks(
        self, response: Response, hooks: Optional[Hooks]
    ) -> Response:
        """Transfer ownership across replacements and release failed hook chains."""
        callbacks = list(self.hooks.get("after_request", []))
        if hooks:
            callbacks.extend(hooks.get("after_request", []))
        try:
            for callback in callbacks:
                replacement = callback(response)
                if replacement is None or replacement is response:
                    continue
                if not isinstance(replacement, Response):
                    raise TypeError("after_request hooks must return Response or None")
                previous, response = response, replacement
                if (
                    previous.response is not None
                    and previous.response is response.response
                ):
                    # A new wrapper may take over the same live body. Detach
                    # the old wrapper before closing it so later cleanup cannot
                    # close the newly returned response's transport.
                    previous.response = None
                previous.close()
            return response
        except BaseException:
            response.close()
            raise

    def send(self, request: BaseRequest, **kwargs: Unpack[SendOptions]) -> Response:
        """
        Send request with optional HTTP-level retry.
        :return:
        """

        if not isinstance(request, BaseRequest):
            raise ValueError("You can only send HttpRequest/HttpsRequest.")

        per_request_hooks = kwargs.pop("hooks", None)

        # Dispatch before_request hooks
        request = self._dispatch_hooks("before_request", request, per_request_hooks)
        request._refresh_cookies()
        source = request.data
        if is_upload(source) or isinstance(source, UploadSource):
            if request.json is not None or request.files:
                raise InvalidData(
                    'Streaming data cannot be combined with json or files'
                )
            length = upload_length(request.headers)
            if not isinstance(source, UploadSource):
                source = UploadSource(source, length=length)
            try:
                source.prepare()
            except BaseException:
                source.close_owned()
                raise
            request.data = source
            kwargs['_upload_register'] = self._register_upload
        else:
            source = None

        # Pass connection pool to request
        kwargs['pool'] = self._pool

        stream = kwargs.pop("stream", False)
        kwargs['stream'] = stream
        retry = self._retry
        method = getattr(request, 'method', 'GET')
        max_attempts = 1 + (
            retry.total if retry and retry.is_retryable_method(method) else 0
        )

        last_response = None
        last_error = None

        for attempt in range(max_attempts):
            response = None
            upload_owner = None
            retrying = False
            dispatching_hooks = False
            try:
                if attempt and source is not None:
                    try:
                        source.rewind()
                    except StreamConsumedError as error:
                        error.response = last_response
                        if last_error is not None:
                            raise error from last_error
                        raise
                rep = request.send(**kwargs)
                upload_owner = getattr(rep, '_upload_owner', None)
                response = Response(request, rep, stream=stream)

                # Apply Set-Cookie to existing jars so expiry/deletion is retained.
                with self._cookie_lock:
                    if not isinstance(self._cookies, CookieJar):
                        self._cookies = self.resolve_cookies(
                            Ja3RequestsCookieJar(), self._cookies
                        )
                    extract_cookies_to_jar(self._cookies, request, response)
                    if self._cookie_view is not None:
                        extract_cookies_to_jar(self._cookie_view, request, response)
                if request._cookie_jar is not None:
                    extract_cookies_to_jar(request._cookie_jar, request, response)

                # Route the final retryable response through exhaustion handling.
                if (
                    retry
                    and retry.is_retryable_method(method)
                    and retry.is_retryable_status(response.status_code)
                ):
                    last_response = response
                    if attempt < max_attempts - 1:
                        response.close()
                        retry.sleep_for_retry(response, attempt + 1)
                        request._refresh_cookies()
                        retrying = True
                        continue
                    break

                allow_redirects = kwargs.get("allow_redirects", True)
                if allow_redirects and response.is_redirected:
                    location = response.location
                    response.close()
                    response = self.resolve_redirects(location, request, **kwargs)

                # Dispatch after_request hooks
                dispatching_hooks = True
                response = self._dispatch_response_hooks(response, per_request_hooks)

                self.response = response
                return response

            except (ConnectionError, OSError) as err:
                if response is not None:
                    response.close()
                if dispatching_hooks:
                    raise
                if isinstance(err, (InvalidData, StreamConsumedError)):
                    raise
                last_error = err
                if (
                    retry
                    and attempt < max_attempts - 1
                    and retry.is_retryable_method(method)
                ):
                    retry.sleep_for_retry(None, attempt + 1)
                    retrying = True
                    continue
                raise
            except BaseException:
                if response is not None:
                    response.close()
                raise
            finally:
                # Intermediate attempts keep replay state. A final streaming
                # response owns cleanup until its upload worker has stopped.
                if source is not None and not retrying:
                    if upload_owner is not None:
                        upload_owner.finalize_source()
                    else:
                        source.close_owned()

        # All retries exhausted
        if last_response is not None:
            # Return the last response even if status was retryable
            allow_redirects = kwargs.get("allow_redirects", True)
            if allow_redirects and last_response.is_redirected:
                location = last_response.location
                last_response.close()
                last_response = self.resolve_redirects(location, request, **kwargs)
            last_response = self._dispatch_response_hooks(
                last_response, per_request_hooks
            )
            self.response = last_response
            if (
                retry
                and retry.raise_on_status
                and retry.is_retryable_status(last_response.status_code)
            ):
                last_response.close()
                raise MaxRetriedException(
                    f"Max retries ({retry.total}) exceeded, last status: {last_response.status_code}"
                )
            return last_response

        if last_error is not None:
            raise MaxRetriedException(
                f"Max retries ({retry.total}) exceeded"
            ) from last_error

        raise MaxRetriedException("Max retries exceeded")

    def resolve_redirects(
        self,
        url: str,
        request: Optional[BaseRequest] = None,
        **kwargs: Unpack[SendOptions],
    ) -> Response:
        """
        Handle response redirects
        :param url:
        :param kwargs:
        :return:
        """
        from urllib.parse import (
            urljoin,
            urlparse,
        )  # pylint: disable=import-outside-toplevel

        send_kwargs = dict(kwargs, allow_redirects=False)
        # Get the original URL to resolve relative redirects
        request = request if request is not None else self.Request.request()
        original_url = request.url

        for _ in range(DEFAULT_REDIRECT_LIMIT):
            # Handle relative URLs by joining with the original URL
            if not urlparse(url).scheme:
                url = urljoin(original_url, url)

            target = urlparse(url)
            target_origin = (
                target.scheme.lower(),
                (target.hostname or '').lower(),
                target.port or (443 if target.scheme == 'https' else 80),
            )
            source = urlparse(original_url)
            source_origin = (
                source.scheme.lower(),
                (source.hostname or '').lower(),
                source.port or (443 if source.scheme == 'https' else 80),
            )
            # Sync redirects become bodyless GETs, so drop the old entity headers.
            body_headers = {'content-length', 'content-type', 'transfer-encoding'}
            headers = {
                k: v
                for k, v in request.headers.items()
                if k.lower() not in body_headers
            }
            # Automatic cookies must be selected again for the next path/origin.
            if request._cookie_header_managed:
                headers.pop('Cookie', None)
            with self._cookie_lock:
                cookies = Ja3RequestsCookieJar()
                merge_cookies(cookies, self._cookies)
            if target_origin != source_origin:
                sensitive = {'authorization', 'proxy-authorization', 'cookie', 'host'}
                headers = {
                    k: v for k, v in headers.items() if k.lower() not in sensitive
                }
            elif not request._cookie_header_managed:
                # Preserve an explicit header removal, as well as replacement.
                cookies = None

            req = Request(
                method="GET",
                url=url,
                headers=headers,
                cookies=cookies,
                proxies=self.Request.proxies,
                timeout=self.Request.timeout,
                tls_config=self.Request.tls_config,
            ).request()

            response = self.send(req, **send_kwargs)
            if 400 <= response.status_code or response.status_code < 300:
                break

            # Update URL for next redirect and original_url for relative resolution
            if response.is_redirected and response.location:
                request = response.request
                original_url = url
                url = response.location
                response.close()
        else:
            raise MaxRetriedException("Too many redirects")

        return response
