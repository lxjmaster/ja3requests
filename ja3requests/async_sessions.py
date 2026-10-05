"""Native async requests with project-owned TLS and response leases."""

from __future__ import annotations

import asyncio
import base64
import copy
import inspect
import json as json_module
import math
import weakref
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple
from urllib.parse import urldefrag, urlencode, urljoin, urlsplit, urlunsplit

from ja3requests._async_utils import owner_task, phase_wait, timeout_pair
from ja3requests._typing import Auth, Cookies, Data, Headers, JsonBody, Params, Proxies
from ja3requests._typing import Timeout as TimeoutInput
from ja3requests.async_pool import AsyncConnectionPool, _Entry
from ja3requests.async_response import AsyncResponse
from ja3requests.async_transport import open_transport
from ja3requests.const import DEFAULT_REDIRECT_LIMIT
from ja3requests.cookies import (
    Ja3RequestsCookieJar,
    _refresh_cookie_header,
    extract_cookies_to_jar,
    merge_cookies,
)
from ja3requests.exceptions import (
    ContentDecodingError,
    InvalidHost,
    MaxRetriedException,
    MissingScheme,
    NotAllowedRequestMethod,
    NotAllowedScheme,
    RequestException,
    TLSError,
    Timeout,
)
from ja3requests.protocol.exceptions import ProxyError
from ja3requests.protocol.h2.async_connection import AsyncH2Connection
from ja3requests.protocol.tls.config import TlsConfig
from ja3requests.protocol.tls.session_cache import TLSSessionCache
from ja3requests.retry import HTTPRetry
from ja3requests.sockets.https import HttpsSocket
from ja3requests.utils import default_headers

if TYPE_CHECKING:
    from typing_extensions import Unpack
    from ja3requests._typing import AsyncHooks, AsyncRequestOptions


@dataclass
class _RequestMetadata:
    """Hook/response metadata with no synchronous sender or transport handle."""

    method: str
    url: str
    headers: Dict[str, str]
    body: bytes
    _cookie_from_jar: Optional[str] = None
    _cookie_header_managed: bool = True


def _origin(url: str) -> Tuple[str, str, int]:
    parsed = urlsplit(url)
    if not parsed.scheme:
        raise MissingScheme('URL requires http:// or https://')
    if parsed.scheme not in ('http', 'https'):
        raise NotAllowedScheme('Only http and https URLs are supported')
    if not parsed.hostname or parsed.username is not None:
        raise InvalidHost('URL requires a host; use auth for credentials')
    return (
        parsed.scheme,
        parsed.hostname,
        parsed.port or (443 if parsed.scheme == 'https' else 80),
    )


def _headers(headers: Optional[Headers]) -> Dict[str, str]:
    values = default_headers() if headers is None else headers
    result = {}
    for name, value in values.items():
        if not isinstance(name, str) or not name or any(c in name for c in '\r\n :\t'):
            raise ValueError('Invalid HTTP header name')
        value = value.decode('latin1') if isinstance(value, bytes) else str(value)
        if '\r' in value or '\n' in value:
            raise ValueError('Invalid HTTP header value')
        result[name.title()] = value
    return result


def _freeze(request: _RequestMetadata) -> _RequestMetadata:
    if not isinstance(request, _RequestMetadata):
        raise TypeError('before_request hooks must return request metadata or None')
    method = request.method.upper()
    if method not in ('GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'):
        raise NotAllowedRequestMethod(method)
    scheme, host, port = _origin(request.url)
    url = urldefrag(request.url)[0]
    if any(c in url for c in '\r\n\t '):
        raise ValueError('URL must not contain whitespace')
    if not isinstance(request.body, bytes):
        raise TypeError('Request body must be replayable bytes')
    headers = _headers(request.headers)
    authority = '[' + host + ']' if ':' in host else host.encode('idna').decode('ascii')
    if port != (443 if scheme == 'https' else 80):
        authority += ':' + str(port)
    headers.setdefault('Host', authority)
    if 'Transfer-Encoding' in headers:
        raise ValueError('Streaming/chunked request uploads are not supported')
    if request.body or method in ('POST', 'PUT', 'PATCH'):
        headers['Content-Length'] = str(len(request.body))
    elif 'Content-Length' in headers:
        headers['Content-Length'] = '0'
    generated_cookie = request._cookie_from_jar
    managed_cookie = request._cookie_header_managed
    if headers.get('Cookie') != generated_cookie:
        # A hook replacing a generated value has supplied an explicit header.
        generated_cookie = None
        managed_cookie = False
    return _RequestMetadata(
        method, url, headers, request.body, generated_cookie, managed_cookie
    )


def _prepare(
    method: str,
    url: str,
    params: Optional[Params],
    data: Optional[Data],
    json: Optional[JsonBody],
    headers: Optional[Headers],
    auth: Optional[Auth],
    cookies: Ja3RequestsCookieJar,
) -> _RequestMetadata:
    _origin(url)
    values = _headers(headers)
    if params:
        query = params.decode() if isinstance(params, bytes) else params
        if not isinstance(query, str):
            query = urlencode(query, doseq=True)
        parsed = urlsplit(url)
        url = urlunsplit(
            parsed._replace(
                query='&'.join(filter(None, (parsed.query, query.lstrip('?'))))
            )
        )
    if json is not None and data is not None:
        raise ValueError('Only one of data and json may be supplied')
    body = b''
    if json is not None:
        body = (
            json
            if isinstance(json, bytes)
            else (
                json.encode()
                if isinstance(json, str)
                else json_module.dumps(json).encode()
            )
        )
        values['Content-Type'] = 'application/json'
    elif data is not None:
        if isinstance(data, bytes):
            body = data
        elif isinstance(data, str):
            body = data.encode()
        elif isinstance(data, (dict, list, tuple)):
            body = urlencode(data, doseq=True).encode()
            values.setdefault('Content-Type', 'application/x-www-form-urlencoded')
        else:
            raise TypeError('data must be in-memory bytes, text or form fields')
    if auth is not None:
        if not isinstance(auth, tuple) or len(auth) != 2:
            raise ValueError('auth must be a (username, password) pair')
        values['Authorization'] = 'Basic ' + base64.b64encode(
            ('%s:%s' % auth).encode('latin1')
        ).decode('ascii')
    request = _freeze(_RequestMetadata(method, url, values, body))
    _refresh_cookie_header(cookies, request)
    return request


class AsyncSession:
    """Native asynchronous session with a private or explicitly borrowed pool.

    Use ``async with`` or await ``aclose()``. A session is terminal after close
    and can be used by concurrent tasks on one event loop only.
    """

    def __init__(
        self,
        tls_config: Optional[TlsConfig] = None,
        pool: Optional[AsyncConnectionPool] = None,
        use_pooling: bool = True,
        hooks: Optional[AsyncHooks] = None,
        retry: Optional[HTTPRetry] = None,
    ) -> None:
        if pool is not None and not use_pooling:
            raise ValueError('An explicit pool requires use_pooling=True')
        self._tls_config = tls_config or TlsConfig()
        if self._tls_config.session_cache is None:
            self._tls_config.session_cache = TLSSessionCache()
        self._pool = pool if pool is not None else AsyncConnectionPool()
        self._owns_pool = pool is None
        self._use_pooling = use_pooling
        self.hooks = {
            name: list((hooks or {}).get(name, []))
            for name in ('before_request', 'after_request')
        }
        self._retry = retry
        self.cookies = Ja3RequestsCookieJar()
        self._loop = None
        self._closed = False
        self._requests: set = set()
        self._hook_tasks: set = set()
        self._responses: set = set()
        self._close_task = None

    @property
    def tls_config(self) -> TlsConfig:
        return self._tls_config

    @tls_config.setter
    def tls_config(self, config: TlsConfig) -> None:
        self._tls_config = config

    @property
    def pool(self) -> AsyncConnectionPool:
        return self._pool

    def _bind(self) -> None:
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise RuntimeError('AsyncSession cannot be used across event loops')
        self._pool._bind()

    def _adopt_response(self, response: AsyncResponse) -> None:
        previous = response._session_owner
        previous_session = previous() if previous is not None else None
        if previous_session is not None:
            if previous_session is not self and response._pool_lease is not None:
                response._pool_lease.transfer()
            previous_session._responses.discard(response)
        response._session_owner = None
        if not response._released or (
            response._cleanup_task is not None and not response._cleanup_task.done()
        ):
            response._session_owner = weakref.ref(self)
            self._responses.add(response)

    async def _close_owned_response(self, response: AsyncResponse) -> None:
        # Hooks can transfer a response while its original request or a
        # scheduled shutdown still holds a reference. Check at execution time.
        owner = response._session_owner
        if owner is not None and owner() is self:
            await response.aclose()

    async def _run_hook(self, callback: Any, value: Any) -> Any:
        result = callback(value)
        if not inspect.isawaitable(result):
            return result
        if asyncio.isfuture(result):
            # A hook may lend an application-owned task/future. Its lifetime
            # is independent of this request and must not be cancelled here.
            return await asyncio.shield(result)

        async def invoke() -> Any:
            return await result

        task = self._loop.create_task(invoke())
        self._hook_tasks.add(task)
        task.add_done_callback(self._hook_done)
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # A user hook may await session shutdown in its finally block or
            # suppress cancellation. Library resource cleanup cannot join it.
            task.cancel()
            raise

    def _hook_done(self, task: asyncio.Task) -> None:
        self._hook_tasks.discard(task)
        if not task.cancelled():
            task.exception()

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Params] = None,
        data: Optional[Data] = None,
        headers: Optional[Headers] = None,
        cookies: Optional[Cookies] = None,
        auth: Optional[Auth] = None,
        proxies: Optional[Proxies] = None,
        json: Optional[JsonBody] = None,
        timeout: TimeoutInput = None,
        verify: Optional[bool] = None,
        tls_config: Optional[TlsConfig] = None,
        stream: bool = False,
        allow_redirects: bool = True,
        hooks: Optional[AsyncHooks] = None,
        h1: bool = False,
    ) -> AsyncResponse:
        """Return headers for stream=True; otherwise await and cache the body."""
        self._bind()
        if self._closed:
            raise RuntimeError('AsyncSession is closed')
        budgets = timeout_pair(timeout)
        config = tls_config or self._tls_config
        cache = config.session_cache
        config = copy.deepcopy(config, {id(cache): cache})
        if verify is not None:
            config.verify_cert = verify
        if h1:
            config.alpn_protocols = ['http/1.1']
        session_jar = Ja3RequestsCookieJar()
        merge_cookies(session_jar, self.cookies)
        jar = session_jar.copy()
        if cookies is not None:
            merge_cookies(jar, cookies)
        request = _prepare(method, url, params, data, json, headers, auth, jar)
        callbacks = {
            name: list(self.hooks.get(name, [])) + list((hooks or {}).get(name, []))
            for name in ('before_request', 'after_request')
        }
        policy = copy.deepcopy(self._retry)
        if policy is not None and (
            isinstance(policy.total, bool)
            or not isinstance(policy.total, int)
            or policy.total < 0
        ):
            raise ValueError('retry.total must be a non-negative integer')
        routes = dict(proxies or {})
        if any(k not in ('http', 'https') for k in routes):
            raise ValueError('proxies keys must be http or https')
        # Only library-owned request tasks are cancelled by session shutdown.
        task = self._loop.create_task(
            self._request(
                request,
                config,
                routes,
                budgets,
                stream,
                allow_redirects,
                callbacks,
                policy,
                jar,
                session_jar,
            )
        )
        self._requests.add(task)
        try:
            return await task
        finally:
            self._requests.discard(task)

    async def _request(
        self,
        request,
        config,
        proxies,
        budgets,
        stream,
        allow_redirects,
        callbacks,
        retry,
        jar,
        session_jar,
    ):
        response = None
        try:
            for hop in range(DEFAULT_REDIRECT_LIMIT + 1):
                for callback in callbacks['before_request']:
                    result = await self._run_hook(callback, request)
                    if result is not None:
                        request = result
                    request = _freeze(request)
                request = _freeze(request)
                _refresh_cookie_header(jar, request)
                attempts = 1 + (
                    retry.total
                    if retry and retry.is_retryable_method(request.method)
                    else 0
                )
                for attempt in range(attempts):
                    try:
                        response = await self._attempt(
                            request, config, proxies, budgets
                        )
                    except asyncio.CancelledError:
                        raise
                    except (TLSError, ContentDecodingError, ProxyError):
                        raise
                    except OSError as error:
                        if isinstance(error, RequestException) and not isinstance(
                            error, Timeout
                        ):
                            raise
                        if attempt + 1 == attempts:
                            raise
                        await self._backoff(retry, None, attempt + 1)
                        continue
                    self._adopt_response(response)
                    extract_cookies_to_jar(self.cookies, request, response)
                    extract_cookies_to_jar(session_jar, request, response)
                    extract_cookies_to_jar(jar, request, response)
                    retryable = (
                        retry
                        and retry.is_retryable_method(request.method)
                        and retry.is_retryable_status(response.status_code)
                    )
                    if retryable and attempt + 1 < attempts:
                        await self._close_owned_response(response)
                        await self._backoff(retry, response, attempt + 1)
                        _refresh_cookie_header(jar, request)
                        response = None
                        continue
                    break
                if (
                    allow_redirects
                    and response.status_code in (301, 302, 303, 307, 308)
                    and response.location
                ):
                    if hop == DEFAULT_REDIRECT_LIMIT:
                        raise MaxRetriedException('Too many redirects')
                    target = urljoin(request.url, response.location)
                    values = dict(request.headers)
                    values.pop('Host', None)
                    managed_cookie = request._cookie_header_managed
                    if _origin(target) != _origin(request.url):
                        for name in ('Authorization', 'Proxy-Authorization', 'Cookie'):
                            values.pop(name, None)
                        # Drop per-request cookies without reading another
                        # concurrent request's updates from the shared jar.
                        jar = session_jar.copy()
                        managed_cookie = True
                    elif managed_cookie:
                        values.pop('Cookie', None)
                    method, body = request.method, request.body
                    if (response.status_code in (301, 302) and method == 'POST') or (
                        response.status_code == 303 and method != 'HEAD'
                    ):
                        method, body = 'GET', b''
                        for name in (
                            'Content-Length',
                            'Content-Type',
                            'Transfer-Encoding',
                        ):
                            values.pop(name, None)
                    await self._close_owned_response(response)
                    response = None
                    request = _freeze(
                        _RequestMetadata(
                            method,
                            target,
                            values,
                            body,
                            _cookie_header_managed=managed_cookie,
                        )
                    )
                    _refresh_cookie_header(jar, request)
                    continue
                if not stream:
                    await response.read()
                for callback in callbacks['after_request']:
                    replacement = await self._run_hook(callback, response)
                    if replacement is None or replacement is response:
                        continue
                    if not isinstance(replacement, AsyncResponse):
                        raise TypeError(
                            'after_request hooks must return AsyncResponse or None'
                        )
                    if replacement._loop is not self._loop:
                        raise RuntimeError(
                            'Replacement response belongs to another event loop'
                        )
                    previous, response = response, replacement
                    self._adopt_response(response)
                    await self._close_owned_response(previous)
                if not stream:
                    await response.read()
                if (
                    retry
                    and retry.raise_on_status
                    and retry.is_retryable_method(request.method)
                    and retry.is_retryable_status(response.status_code)
                ):
                    error = MaxRetriedException(
                        'Max retries (%d) exceeded, last status: %d'
                        % (retry.total, response.status_code)
                    )
                    error.response = response
                    raise error
                if self._closed:
                    raise RuntimeError('AsyncSession closed during request')
                return response
            raise MaxRetriedException('Too many redirects')
        except BaseException:
            if response is not None:
                await self._close_owned_response(response)
            raise

    @staticmethod
    async def _backoff(retry, response, number):
        delay = retry.get_retry_after(response) if response is not None else None
        if delay is None or not math.isfinite(delay) or delay < 0:
            delay = retry.get_backoff_time(number)
        await asyncio.sleep(max(0, delay))

    async def _attempt(self, request, config, proxies, budgets):
        scheme, host, port = _origin(request.url)
        proxy = proxies.get(scheme)
        policy = (
            HttpsSocket._tls_policy_key(config, host) if scheme == 'https' else None
        )
        key = (host, port, scheme, proxy, policy)
        connect_timeout, read_timeout = budgets
        deadline = (
            None if connect_timeout is None else self._loop.time() + connect_timeout
        )

        async def factory():
            remaining = (
                None if deadline is None else max(0, deadline - self._loop.time())
            )
            transport = await open_transport(
                host,
                port,
                tls_config=config if scheme == 'https' else None,
                proxy=proxy,
                timeout=remaining,
            )
            h2 = None
            try:
                if transport.negotiated_protocol == 'h2':
                    h2 = AsyncH2Connection(
                        transport.write, transport.read, settings=config.h2_settings
                    )
                    await h2.initiate(config.h2_window_update)
                    remaining = (
                        None
                        if deadline is None
                        else max(0, deadline - self._loop.time())
                    )
                    await h2._wait_for(
                        lambda: h2.capacity_available or h2._goaway_received,
                        remaining,
                        phase='connect',
                    )
                    h2._check_connection()
                    if h2._goaway_received:
                        raise ConnectionError(
                            'HTTP/2 peer rejected connection admission'
                        )
                return _Entry(key, transport, h2, reusable=self._use_pooling)
            except BaseException:
                transport.close()
                if h2 is not None:
                    await h2.aclose()
                await transport.aclose()
                raise

        lease = await phase_wait(
            self._pool._acquire(key, factory, share_h2=self._use_pooling),
            connect_timeout,
            'connect',
        )
        entry = lease.entry
        stream_id = None
        parsed = urlsplit(request.url)
        path = urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
        try:
            if entry.h2 is not None:
                stream_id = await entry.h2.send_request(
                    request.method,
                    request.headers['Host'],
                    path,
                    headers=list(request.headers.items()),
                    body=request.body,
                    scheme=scheme,
                    timeout=read_timeout,
                )
                headers = await entry.h2.receive_headers(
                    stream_id, timeout=read_timeout
                )
                response = await AsyncResponse.from_http2(
                    entry.h2,
                    stream_id,
                    headers,
                    method=request.method,
                    url=request.url,
                    request=request,
                    release=lease.release,
                    timeout=read_timeout,
                )
                if not response._released:
                    response._pool_lease = lease
                return response
            wire = ('%s %s HTTP/1.1\r\n' % (request.method, path)).encode('ascii')
            wire += ''.join(
                '%s: %s\r\n' % item for item in request.headers.items()
            ).encode('latin1')
            await phase_wait(
                entry.transport.write(wire + b'\r\n' + request.body),
                read_timeout,
                'write',
            )
            response = await AsyncResponse.from_http1(
                entry.transport,
                method=request.method,
                url=request.url,
                request=request,
                release=lease.release,
                timeout=read_timeout,
            )
            if not response._released:
                response._pool_lease = lease
            return response
        except BaseException:
            if stream_id is not None:
                await entry.h2.cancel_stream(stream_id)
            await lease.release(False)
            raise

    async def aclose(self) -> None:
        """Stop this session's requests and leases; borrowed pools stay open."""
        self._bind()
        if self._close_task is None:
            self._closed = True
            current = asyncio.current_task()
            requests = [task for task in self._requests if task is not current]
            for task in requests:
                task.cancel()
            self._close_task = owner_task(self._finish_close(requests))
        await asyncio.shield(self._close_task)

    async def _finish_close(self, requests):
        await asyncio.gather(*requests, return_exceptions=True)
        await asyncio.gather(
            *(self._close_owned_response(r) for r in tuple(self._responses)),
            return_exceptions=True,
        )
        if self._owns_pool:
            await self._pool._close_from_session()

    async def __aenter__(self) -> AsyncSession:
        self._bind()
        if self._closed:
            raise RuntimeError('AsyncSession is closed')
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    async def get(
        self, url: str, **kwargs: Unpack[AsyncRequestOptions]
    ) -> AsyncResponse:
        return await self.request('GET', url, **kwargs)

    async def post(
        self, url: str, **kwargs: Unpack[AsyncRequestOptions]
    ) -> AsyncResponse:
        return await self.request('POST', url, **kwargs)

    async def put(
        self, url: str, **kwargs: Unpack[AsyncRequestOptions]
    ) -> AsyncResponse:
        return await self.request('PUT', url, **kwargs)

    async def patch(
        self, url: str, **kwargs: Unpack[AsyncRequestOptions]
    ) -> AsyncResponse:
        return await self.request('PATCH', url, **kwargs)

    async def delete(
        self, url: str, **kwargs: Unpack[AsyncRequestOptions]
    ) -> AsyncResponse:
        return await self.request('DELETE', url, **kwargs)

    async def head(
        self, url: str, **kwargs: Unpack[AsyncRequestOptions]
    ) -> AsyncResponse:
        kwargs.setdefault('allow_redirects', False)
        return await self.request('HEAD', url, **kwargs)

    async def options(
        self, url: str, **kwargs: Unpack[AsyncRequestOptions]
    ) -> AsyncResponse:
        return await self.request('OPTIONS', url, **kwargs)
