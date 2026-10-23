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
from ja3requests.protocol.tls.config import TlsConfig, _validate_http_alpn
from ja3requests.protocol.h2.hpack import normalize_indexing_exclusions
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
from ja3requests._request_defaults import (
    merge_default_headers,
    merge_default_params,
    normalize_request_defaults,
    request_defaults_snapshot,
)
from ja3requests.sockets._upload import upload_length
from ja3requests.utils import _validated_header_items
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
        RequestDefaults,
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
        self._request_defaults: Optional[Dict[str, Any]] = None
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
    def request_defaults(self) -> Optional[RequestDefaults]:
        """Return a detached opt-in snapshot of default headers and params."""
        return request_defaults_snapshot(self._request_defaults)

    @request_defaults.setter
    def request_defaults(self, value: Optional[RequestDefaults]) -> None:
        """Atomically replace opt-in default headers and query parameters."""
        self._request_defaults = normalize_request_defaults(value)

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

        # Capture and merge the opt-in defaults before creating the prepared
        # request. The private value is replaced atomically by the setter.
        defaults = self._request_defaults
        headers = merge_default_headers(
            defaults.get('headers') if defaults else None, headers
        )
        params = merge_default_params(
            defaults.get('params') if defaults else None, params
        )

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
            h2_headers_priority=kwargs.pop('h2_headers_priority', None),
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
        if 'h2_headers_priority' in kwargs:
            request.h2_headers_priority = kwargs.pop('h2_headers_priority')
        redirect_chain = kwargs.pop('_redirect_chain', False)
        replay_source = kwargs.pop('_redirect_replay', None)

        # Dispatch before_request hooks
        redirect_request = request
        request = self._dispatch_hooks("before_request", request, per_request_hooks)
        if not isinstance(request, BaseRequest):
            raise TypeError(
                'before_request hooks must return HttpRequest/HttpsRequest or None'
            )
        request._validate_send()
        request.h2_headers_priority = request.h2_headers_priority
        if replay_source is not None and request.data is not replay_source:
            replay_source.close_owned()
            if request is redirect_request and replay_source.length is not None:
                request._remove_inherited_length(replay_source.length)
        request._refresh_cookies()
        # Caller input errors must not open a connection or enter HTTP retries.
        # Keep raw bytes intact: the chosen transport owns their encoding.
        _validated_header_items(request.headers)
        if request.schema == 'https':
            # Resolve after hooks so replacements and cleared configurations
            # inherit the Session policy before validation or upload preparation.
            if request.tls_config is None:
                request.tls_config = self._tls_config
            _validate_http_alpn(request.tls_config.alpn_protocols)
            normalize_indexing_exclusions(request.tls_config.h2_indexing_exclusions)
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
                if source is replay_source:
                    source.rewind()
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
            keep_redirect_source = False
            exhausted_status = False
            dispatching_hooks = False
            following_redirects = False
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
                        request._refresh_cookies()
                        _validated_header_items(request.headers)
                        retry.sleep_for_retry(response, attempt + 1)
                        retrying = True
                        continue
                    exhausted_status = True

                allow_redirects = kwargs.get("allow_redirects", True)
                if allow_redirects and response.is_redirected:
                    # The redirect chain takes responsibility for the source;
                    # the completed hop must not finalize a surviving producer.
                    following_redirects = True
                    source = None
                    response = self._follow_redirect(
                        response, request, hooks=per_request_hooks, **kwargs
                    )

                # Dispatch after_request hooks
                dispatching_hooks = True
                response = self._dispatch_response_hooks(response, per_request_hooks)

                self.response = response
                if (
                    exhausted_status
                    and not following_redirects
                    and retry.raise_on_status
                    and retry.is_retryable_status(response.status_code)
                ):
                    response.close()
                    raise MaxRetriedException(
                        f"Max retries ({retry.total}) exceeded, last status: {response.status_code}"
                    )
                keep_redirect_source = redirect_chain and response.is_redirected
                return response

            except (ConnectionError, OSError) as err:
                if response is not None:
                    response.close()
                # Each redirect destination owns its retries; this hop is done.
                if dispatching_hooks or following_redirects:
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
                if source is not None and not retrying and not keep_redirect_source:
                    if upload_owner is not None:
                        upload_owner.finalize_source()
                    else:
                        source.close_owned()

        if last_error is not None:
            raise MaxRetriedException(
                f"Max retries ({retry.total}) exceeded"
            ) from last_error

        raise MaxRetriedException("Max retries exceeded")

    def _follow_redirect(self, response, request, **kwargs):
        """Stop the completed upload before handing its source to the next hop."""
        source = request.data if isinstance(request.data, UploadSource) else None
        try:
            response.close()
            return self.resolve_redirects(
                response.location, request, status_code=response.status_code, **kwargs
            )
        except BaseException:
            if source is not None:
                source.close_owned()
            raise

    def resolve_redirects(
        self,
        url: str,
        request: Optional[BaseRequest] = None,
        status_code: Optional[int] = None,
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

        send_kwargs = dict(kwargs, allow_redirects=False, _redirect_chain=True)
        # Get the original URL to resolve relative redirects
        request = request if request is not None else self.Request.request()
        original_url = request.url

        try:
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
                preserve_body = (
                    status_code in (307, 308)
                    or (status_code in (301, 302) and request.method != 'POST')
                    or (status_code == 303 and request.method == 'HEAD')
                )
                upload_source = (
                    request.data if isinstance(request.data, UploadSource) else None
                )
                body_headers = {'content-length', 'content-type', 'transfer-encoding'}
                headers = {
                    k: v
                    for k, v in request.headers.items()
                    if (preserve_body or k.lower() not in body_headers)
                    and not (
                        upload_source is not None and k.lower() == 'transfer-encoding'
                    )
                }
                if request._cookie_header_managed:
                    headers.pop('Cookie', None)
                with self._cookie_lock:
                    cookies = Ja3RequestsCookieJar()
                    merge_cookies(cookies, self._cookies)
                if target_origin != source_origin:
                    sensitive = {
                        'authorization',
                        'proxy-authorization',
                        'cookie',
                        'host',
                    }
                    headers = {
                        k: v for k, v in headers.items() if k.lower() not in sensitive
                    }
                elif not request._cookie_header_managed:
                    cookies = None

                req = Request(
                    method=request.method if preserve_body else "GET",
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    proxies=request._proxy_routes,
                    timeout=request.timeout,
                    tls_config=request.tls_config,
                    h2_headers_priority=request.h2_headers_priority,
                ).request()

                if preserve_body:
                    # Prepared buffered values never reread borrowed multipart files.
                    req._data, req._json, req._files = (
                        request.data,
                        request.json,
                        request.files,
                    )
                    req._redirect_body = request._redirect_body
                    req._redirect_body_inputs = request._redirect_body_inputs
                elif upload_source is not None:
                    upload_source.close_owned()
                response = self.send(
                    req,
                    _redirect_replay=upload_source if preserve_body else None,
                    **send_kwargs,
                )
                if not getattr(response, 'is_redirected', False):
                    break

                if response.location:
                    request = response.request
                    original_url = request.url
                    url = response.location
                    status_code = response.status_code
                    response.close()
            else:
                raise MaxRetriedException("Too many redirects")
        except BaseException:
            # A hook may have selected a different source on a completed hop.
            # Parsing/constructing the next hop must finalize that current source.
            if isinstance(request.data, UploadSource):
                request.data.close_owned()
            raise

        return response
