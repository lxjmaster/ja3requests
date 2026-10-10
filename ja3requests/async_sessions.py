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
from functools import partial
from http.cookiejar import CookieJar
from types import MappingProxyType
from typing import (
    TYPE_CHECKING,
    Any,
    AsyncIterator,
    BinaryIO,
    Dict,
    Iterator,
    Mapping,
    Optional,
    Tuple,
    Union,
)
from urllib.parse import urldefrag, urlencode, urljoin, urlsplit, urlunsplit

from ja3requests._async_utils import owner_task, phase_wait, timeout_pair
from ja3requests._async_upload import HTTP1Upload
from ja3requests._multipart import MultipartSource
from ja3requests._upload import UploadSource, is_upload
from ja3requests._cookie_file import (
    _check_jar,
    load_cookie_file,
    save_cookie_file,
)
from ja3requests._typing import (
    Auth,
    AsyncData,
    Cookies,
    Headers,
    JsonBody,
    Params,
    PathInput,
    Proxies,
)
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
    InvalidData,
    MaxRetriedException,
    MissingScheme,
    NotAllowedRequestMethod,
    NotAllowedScheme,
    RequestException,
    StreamConsumedError,
    TLSError,
    Timeout,
)
from ja3requests.protocol.exceptions import ProxyError
from ja3requests.protocol.h2.async_connection import AsyncH2Connection
from ja3requests.protocol.tls.config import TlsConfig, _validate_http_alpn
from ja3requests.protocol.tls.session_cache import TLSSessionCache
from ja3requests.retry import HTTPRetry
from ja3requests.sockets.https import HttpsSocket
from ja3requests.utils import (
    _encode_http1_headers,
    _validated_header_items,
    default_headers,
)

if TYPE_CHECKING:
    from typing_extensions import Unpack
    from ja3requests._typing import AsyncFiles, AsyncHooks, AsyncRequestOptions


_UploadBody = Union[
    bytes, BinaryIO, Iterator[bytes], AsyncIterator[bytes], UploadSource
]
_HeaderText = Union[str, bytes]


@dataclass
class _RequestMetadata:
    """Hook/response metadata with no synchronous sender or transport handle."""

    method: str
    url: str
    headers: Dict[str, _HeaderText]
    body: _UploadBody
    _cookie_from_jar: Optional[str] = None
    _cookie_header_managed: bool = True
    _auto_length: Optional[str] = None


@dataclass(frozen=True)
class _PreparedContext:
    session: AsyncSession
    config: TlsConfig
    proxies: Dict[str, str]
    jar: Ja3RequestsCookieJar
    session_jar: Ja3RequestsCookieJar


class AsyncPreparedRequest:
    """Read-only buffered request created by ``AsyncSession.prepare_request()``.

    Inspect ``method``, ``url``, ``headers`` and ``body`` before sending. Use
    ``with_headers()`` to derive a signed copy; send with the preparing Session
    on its event loop. Preparation owns no connection or upload handle.
    """

    __slots__ = ('_request', '_context')

    def __init__(self) -> None:
        raise TypeError('Use AsyncSession.prepare_request()')

    @classmethod
    def _create(
        cls, request: _RequestMetadata, context: _PreparedContext
    ) -> AsyncPreparedRequest:
        instance = object.__new__(cls)
        instance._request = request
        instance._context = context
        return instance

    def __repr__(self) -> str:
        return '<AsyncPreparedRequest [%s]>' % self.method

    @property
    def method(self) -> str:
        """Normalized HTTP method."""
        return self._request.method

    @property
    def url(self) -> str:
        """Normalized destination URL with query parameters and no fragment."""
        return self._request.url

    @property
    def headers(self) -> Mapping[str, _HeaderText]:
        """Read-only normalized headers; supplied byte values remain bytes."""
        return MappingProxyType(self._request.headers)

    @property
    def body(self) -> bytes:
        """Encoded buffered request body."""
        assert isinstance(self._request.body, bytes)
        return self._request.body

    def with_headers(self, headers: Headers) -> AsyncPreparedRequest:
        """Derive a copy with replacement headers, preserving URL/body/context.

        To add a signature, pass ``dict(self.headers, Authorization=signature)``.
        Headers are validated again; no hooks or network I/O run here.
        """
        request = copy.copy(self._request)
        request.headers = _headers(headers)
        if any(
            isinstance(name, str) and name.lower() == 'cookie'
            for name in request.headers
        ):
            # A replacement mapping is caller-supplied, even if it copies the
            # generated value exactly. Retrying must not rewrite a signed Cookie.
            request._cookie_from_jar = None
            request._cookie_header_managed = False
        return self._create(_freeze(request), self._context)


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


def _authority(scheme: str, host: str, port: int) -> str:
    authority = '[' + host + ']' if ':' in host else host.encode('idna').decode('ascii')
    if port != (443 if scheme == 'https' else 80):
        authority += ':' + str(port)
    return authority


def _headers(headers: Optional[Headers]) -> Dict[str, _HeaderText]:
    values = default_headers() if headers is None else headers
    result = {}
    for name, value in _validated_header_items(values):
        original = values[name]
        result[name.title()] = original if isinstance(original, bytes) else value
    return result


def _upload_length(headers):
    lengths = []
    for name, value in headers.items():
        if not isinstance(name, str):
            continue
        if name.lower() == 'transfer-encoding':
            raise InvalidData(
                'Streaming Transfer-Encoding is selected by the transport'
            )
        if name.lower() == 'content-length':
            value = value.decode('latin1') if isinstance(value, bytes) else str(value)
            if not value or any(char not in '0123456789' for char in value):
                raise InvalidData('Invalid streaming Content-Length')
            lengths.append(int(value))
    if len(lengths) > 1:
        raise InvalidData('Duplicate streaming Content-Length headers')
    return lengths[0] if lengths else None


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
    streaming = isinstance(request.body, UploadSource) or is_upload(
        request.body, allow_async=True
    )
    if not streaming and not isinstance(request.body, bytes):
        raise TypeError('Request body must be bytes or a binary upload source')
    if streaming:
        _upload_length(request.headers)
    headers = _headers(request.headers)
    headers.setdefault('Host', _authority(scheme, host, port))
    if 'Transfer-Encoding' in headers:
        raise ValueError('Streaming/chunked request uploads are not supported')
    auto_length = request._auto_length
    if not streaming and (request.body or method in ('POST', 'PUT', 'PATCH')):
        headers['Content-Length'] = str(len(request.body))
        auto_length = headers['Content-Length']
    elif not streaming and 'Content-Length' in headers:
        headers['Content-Length'] = '0'
        auto_length = '0'
    generated_cookie = request._cookie_from_jar
    managed_cookie = request._cookie_header_managed
    if headers.get('Cookie') != generated_cookie:
        # A hook replacing a generated value has supplied an explicit header.
        generated_cookie = None
        managed_cookie = False
    return _RequestMetadata(
        method,
        url,
        headers,
        request.body,
        generated_cookie,
        managed_cookie,
        auto_length,
    )


def _prepare(
    method: str,
    url: str,
    params: Optional[Params],
    data: Optional[AsyncData],
    json: Optional[JsonBody],
    headers: Optional[Headers],
    auth: Optional[Auth],
    cookies: Ja3RequestsCookieJar,
    files: Optional[AsyncFiles] = None,
) -> _RequestMetadata:
    _origin(url)
    if (
        files is not None
        or is_upload(data, allow_async=True)
        or isinstance(data, UploadSource)
    ):
        _upload_length(headers or {})
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
    if json is not None and files is not None:
        raise InvalidData('json and files cannot be combined')
    if json is not None and data is not None:
        raise ValueError('Only one of data and json may be supplied')
    body: _UploadBody = b''
    if files is not None:
        body = MultipartSource(
            data,
            files,
            content_type=values.get('Content-Type'),
            length=_upload_length(values),
        )
        values['Content-Type'] = body.content_type
    elif json is not None:
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
        elif isinstance(data, UploadSource) or is_upload(data, allow_async=True):
            body = data
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
    _validated_header_items(request.headers)
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
        self._cookie_tasks: set = set()
        self._cookie_file_lock = None
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

    async def save_cookies(
        self, path: PathInput, *, include_session: bool = False
    ) -> int:
        """Save a detached Cookie snapshot without blocking the event loop.

        Operations on this Session run in order. Once file I/O starts,
        cancellation waits for its cleanup; an atomic replacement may finish.
        """
        return await self._cookie_file(
            path, save=True, merge=False, include_session=include_session
        )

    async def load_cookies(
        self, path: PathInput, *, merge: bool = False, include_session: bool = False
    ) -> int:
        """Validate off-loop, then replace or merge the current Cookie jar.

        A cancelled load never commits later. The destination jar and its
        policy are retained, including when merge=True uses newer live Cookies.
        """
        return await self._cookie_file(
            path, save=False, merge=merge, include_session=include_session
        )

    async def _cookie_file(self, path, *, save, merge, include_session):
        self._bind()
        if self._closed:
            raise RuntimeError('AsyncSession is closed')
        _check_jar(self.cookies, include_session)
        if type(merge) is not bool:
            raise TypeError('merge must be a bool')
        if self._cookie_file_lock is None:
            # Construct on the bound loop, including on Python 3.7.
            self._cookie_file_lock = asyncio.Lock()
        task = owner_task(
            self._run_cookie_file(
                path, save=save, merge=merge, include_session=include_session
            )
        )
        self._cookie_tasks.add(task)
        task.add_done_callback(self._cookie_file_done)
        # Forward cancellation to the owner immediately, including when its
        # worker result is ready but a load has not yet committed. The owner
        # shields and joins the worker before propagating cancellation.
        return await task

    def _cookie_file_done(self, task):
        self._cookie_tasks.discard(task)
        if not task.cancelled():
            task.exception()

    @staticmethod
    async def _drain_cookie_work(work):
        # Both the worker and its library-owned task outlive cancellation of
        # a public waiter. Repeated cancellation cannot detach either cleanup.
        while not work.done():
            try:
                await asyncio.shield(work)
            except BaseException:
                pass
        if not work.cancelled():
            work.exception()

    async def _run_cookie_file(self, path, *, save, merge, include_session):
        async with self._cookie_file_lock:
            if self._closed:
                raise RuntimeError('AsyncSession is closed')
            _check_jar(self.cookies, include_session)
            detached = CookieJar()
            if save:
                # No await or blocking live-jar lock: Session Cookies belong
                # to this loop. CookieJar.copy() shares extension dictionaries.
                for cookie in self.cookies:
                    snapshot = copy.copy(cookie)
                    # The file schema accepts only scalar extension values.
                    # Leave validation and filtering to the shared writer;
                    # unrelated application attributes need no recursive copy.
                    snapshot._rest = dict(cookie._rest)
                    detached.set_cookie(snapshot)
            operation = save_cookie_file if save else load_cookie_file
            worker = self._loop.run_in_executor(
                None,
                partial(operation, detached, path, include_session=include_session),
            )
            try:
                count = await asyncio.shield(worker)
            except asyncio.CancelledError:
                await self._drain_cookie_work(worker)
                raise
            if not save:
                target = self.cookies
                _check_jar(target, include_session)
                staged = (
                    {
                        domain: {path: values.copy() for path, values in paths.items()}
                        for domain, paths in target._cookies.items()
                    }
                    if merge
                    else {}
                )
                for cookie in detached:
                    staged.setdefault(cookie.domain, {}).setdefault(cookie.path, {})[
                        cookie.name
                    ] = cookie
                # Publish once on the loop, preserving jar/policy identity.
                target._cookies = staged
            return count

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Params] = None,
        data: Optional[AsyncData] = None,
        files: Optional[AsyncFiles] = None,
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
        request = _prepare(
            method, url, params, data, json, headers, auth, jar, files=files
        )
        return await self._submit(
            request,
            config,
            dict(proxies or {}),
            budgets,
            stream,
            allow_redirects,
            hooks,
            jar,
            session_jar,
        )

    async def prepare_request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Params] = None,
        data: Optional[Params] = None,
        headers: Optional[Headers] = None,
        cookies: Optional[Cookies] = None,
        auth: Optional[Auth] = None,
        proxies: Optional[Proxies] = None,
        json: Optional[JsonBody] = None,
        verify: Optional[bool] = None,
        tls_config: Optional[TlsConfig] = None,
        h1: bool = False,
    ) -> AsyncPreparedRequest:
        """Encode a buffered request for inspection/signing without network I/O.

        Snapshot TLS, proxy and Cookie configuration when awaited. Binary files,
        iterators and multipart ``files=`` are excluded from this prepared API;
        use ``request()`` for streaming uploads. Hooks run when ``send()`` runs.
        """
        self._bind()
        if self._closed:
            raise RuntimeError('AsyncSession is closed')
        if isinstance(data, UploadSource) or is_upload(data, allow_async=True):
            raise InvalidData('Prepared requests require a buffered body')
        config = tls_config or self._tls_config
        cache = config.session_cache
        config = copy.deepcopy(config, {id(cache): cache})
        if verify is not None:
            config.verify_cert = verify
        if h1:
            config.alpn_protocols = ['http/1.1']
        routes = dict(proxies or {})
        if any(k not in ('http', 'https') for k in routes):
            raise ValueError('proxies keys must be http or https')
        session_jar = Ja3RequestsCookieJar()
        merge_cookies(session_jar, self.cookies)
        jar = session_jar.copy()
        if cookies is not None:
            merge_cookies(jar, cookies)
        request = _prepare(method, url, params, data, json, headers, auth, jar)
        parsed = urlsplit(request.url)
        scheme, host, port = _origin(request.url)
        if scheme == 'https':
            _validate_http_alpn(config.alpn_protocols)
        # Match the transport's scheme/authority/target before callers sign.
        request.url = urlunsplit(
            (
                scheme,
                _authority(scheme, host, port),
                parsed.path or '/',
                parsed.query,
                '',
            )
        )
        _refresh_cookie_header(jar, request)
        _validated_header_items(request.headers)
        return AsyncPreparedRequest._create(
            request, _PreparedContext(self, config, routes, jar, session_jar)
        )

    async def send(
        self,
        request: AsyncPreparedRequest,
        *,
        timeout: TimeoutInput = None,
        stream: bool = False,
        allow_redirects: bool = True,
        hooks: Optional[AsyncHooks] = None,
    ) -> AsyncResponse:
        """Send a prepared buffered request on its preparing Session and loop.

        Each send gets independent metadata and Cookie/TLS/proxy copies. Session
        hooks and retry policy are selected at send time. A streaming response
        stays owned by this Session until consumed, closed or adopted elsewhere.
        """
        self._bind()
        if self._closed:
            raise RuntimeError('AsyncSession is closed')
        if not isinstance(request, AsyncPreparedRequest):
            raise TypeError('send() requires AsyncPreparedRequest')
        context = request._context
        if context.session is not self:
            raise ValueError('Prepared request belongs to another AsyncSession')
        budgets = timeout_pair(timeout)
        metadata = _freeze(request._request)
        config = context.config
        cache = config.session_cache
        config = copy.deepcopy(config, {id(cache): cache})
        return await self._submit(
            metadata,
            config,
            dict(context.proxies),
            budgets,
            stream,
            allow_redirects,
            hooks,
            context.jar.copy(),
            context.session_jar.copy(),
            buffered_only=True,
        )

    async def _submit(
        self,
        request,
        config,
        routes,
        budgets,
        stream,
        allow_redirects,
        hooks,
        jar,
        session_jar,
        buffered_only=False,
    ):
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
                buffered_only=buffered_only,
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
        buffered_only=False,
    ):
        response = None
        sources = set()
        source_responses = {}
        redirect_body = redirect_response = None
        try:
            for hop in range(DEFAULT_REDIRECT_LIMIT + 1):
                for callback in callbacks['before_request']:
                    previous_body = request.body
                    previous_length = request._auto_length
                    result = await self._run_hook(callback, request)
                    if result is not None:
                        request = result
                    if (
                        isinstance(request, _RequestMetadata)
                        and request.body is not previous_body
                    ):
                        if request.headers.get('Content-Length') == previous_length:
                            request.headers.pop('Content-Length', None)
                        request._auto_length = None
                        if isinstance(previous_body, UploadSource):
                            await previous_body.aclose_owned()
                    request = _freeze(request)
                    if buffered_only and not isinstance(request.body, bytes):
                        raise InvalidData('Prepared requests require a buffered body')
                request = _freeze(request)
                _refresh_cookie_header(jar, request)
                _validated_header_items(request.headers)
                if _origin(request.url)[0] == 'https':
                    _validate_http_alpn(config.alpn_protocols)
                if not isinstance(request.body, bytes):
                    length = _upload_length(request.headers)
                    if not isinstance(request.body, UploadSource):
                        request.body = UploadSource(request.body, length=length)
                    sources.add(request.body)
                    if isinstance(request.body, MultipartSource) and (
                        request.headers.get('Content-Type') != request.body.content_type
                    ):
                        raise InvalidData(
                            'Multipart Content-Type conflicts with its boundary'
                        )
                    await phase_wait(request.body.aprepare(), budgets[1], 'write')
                    if length is not None and request.body.length != length:
                        raise InvalidData('Content-Length changed during upload replay')
                    if request.body.length is not None:
                        request.headers['Content-Length'] = str(request.body.length)
                        if length is None:
                            request._auto_length = request.headers['Content-Length']
                if request.body is redirect_body:
                    await self._rewind_upload(
                        request.body, budgets[1], response=redirect_response
                    )
                redirect_body = redirect_response = None
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
                        await self._rewind_upload(request.body, budgets[1], cause=error)
                        await self._backoff(retry, None, attempt + 1)
                        continue
                    self._adopt_response(response)
                    if (
                        isinstance(request.body, UploadSource)
                        and not response._released
                    ):
                        response._upload_sources.append(request.body)
                        source_responses[request.body] = response
                    extract_cookies_to_jar(self.cookies, request, response)
                    extract_cookies_to_jar(session_jar, request, response)
                    extract_cookies_to_jar(jar, request, response)
                    retryable = (
                        retry
                        and retry.is_retryable_method(request.method)
                        and retry.is_retryable_status(response.status_code)
                    )
                    if retryable and attempt + 1 < attempts:
                        _refresh_cookie_header(jar, request)
                        _validated_header_items(request.headers)
                        if isinstance(request.body, UploadSource):
                            if request.body in response._upload_sources:
                                response._upload_sources.remove(request.body)
                            source_responses.pop(request.body, None)
                        await self._close_owned_response(response)
                        await self._rewind_upload(
                            request.body, budgets[1], response=response
                        )
                        await self._backoff(retry, response, attempt + 1)
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
                    if body is request.body and isinstance(body, UploadSource):
                        if body in response._upload_sources:
                            response._upload_sources.remove(body)
                        source_responses.pop(body, None)
                    await self._close_owned_response(response)
                    if body is request.body and isinstance(body, UploadSource):
                        # Hooks run on every redirect hop and may choose a new
                        # body. Rewind only the source that survives those hooks.
                        redirect_body, redirect_response = body, response
                    elif isinstance(request.body, UploadSource):
                        await request.body.aclose_owned()
                    response = None
                    request = _freeze(
                        _RequestMetadata(
                            method,
                            target,
                            values,
                            body,
                            _cookie_header_managed=managed_cookie,
                            _auto_length=(
                                request._auto_length if body is request.body else None
                            ),
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
        finally:
            for source in sources:
                owner = source_responses.get(source)
                if owner is None or source not in owner._upload_sources:
                    await source.aclose_owned()

    @staticmethod
    async def _rewind_upload(body, timeout, response=None, cause=None):
        if isinstance(body, UploadSource):
            try:
                await phase_wait(body.arewind(), timeout, 'write')
            except StreamConsumedError as error:
                if response is not None:
                    error.response = response
                raise error from cause

    @staticmethod
    async def _backoff(retry, response, number):
        delay = retry.get_retry_after(response) if response is not None else None
        if delay is None or not math.isfinite(delay) or delay < 0:
            delay = retry.get_backoff_time(number)
        await asyncio.sleep(max(0, delay))

    async def _attempt(self, request, config, proxies, budgets):
        scheme, host, port = _origin(request.url)
        proxy = proxies.get(scheme)
        headers = dict(request.headers)
        proxy_auth = headers.pop('Proxy-Authorization', None)
        if proxy is None or urlsplit(proxy).scheme != 'http':
            proxy_auth = None
        elif proxy_auth and len(proxy_auth.split(None, 1)) == 1:
            proxy_auth = (
                b'Basic ' if isinstance(proxy_auth, bytes) else 'Basic '
            ) + proxy_auth
        policy = (
            HttpsSocket._tls_policy_key(config, host) if scheme == 'https' else None
        )
        key = (host, port, scheme, proxy, proxy_auth, policy)
        connect_timeout, read_timeout = budgets
        deadline = (
            None if connect_timeout is None else self._loop.time() + connect_timeout
        )

        async def factory():
            remaining = (
                None if deadline is None else max(0, deadline - self._loop.time())
            )
            transport_options = {'proxy_auth': proxy_auth} if proxy_auth else {}
            transport = await open_transport(
                host,
                port,
                tls_config=config if scheme == 'https' else None,
                proxy=proxy,
                timeout=remaining,
                **transport_options,
            )
            h2 = None
            try:
                HttpsSocket._validate_negotiated_protocol(transport.negotiated_protocol)
                if transport.negotiated_protocol == 'h2':
                    h2 = AsyncH2Connection(
                        transport.write,
                        transport.read,
                        settings=config.h2_settings,
                        pseudo_header_order=config.h2_pseudo_header_order,
                        priority_frames=config.h2_priority_frames,
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
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        try:
            try:
                HttpsSocket._validate_negotiated_protocol(
                    entry.transport.negotiated_protocol
                )
            except TLSError:
                # This invalidates the entire connection, including shared H2
                # leases; ordinary stream errors may otherwise leave H2 reusable.
                entry.reusable = False
                raise
            if entry.h2 is not None:
                send = (
                    entry.h2.begin_upload
                    if isinstance(request.body, UploadSource)
                    else entry.h2.send_request
                )
                stream_id = await send(
                    request.method,
                    request.headers['Host'],
                    path,
                    headers=list(headers.items()),
                    body=request.body,
                    scheme=scheme,
                    timeout=read_timeout,
                )
                headers = await entry.h2.receive_headers(
                    stream_id, timeout=read_timeout
                )
                release = lease.release
                if isinstance(request.body, UploadSource):

                    async def release_upload(reusable):
                        try:
                            await entry.h2.cancel_stream(stream_id)
                        finally:
                            await lease.release(reusable)

                    release = release_upload

                response = await AsyncResponse.from_http2(
                    entry.h2,
                    stream_id,
                    headers,
                    method=request.method,
                    url=request.url,
                    request=request,
                    release=release,
                    timeout=read_timeout,
                )
                if not response._released:
                    response._pool_lease = lease
                return response
            wire = ('%s %s HTTP/1.1\r\n' % (request.method, path)).encode('ascii')
            if isinstance(request.body, UploadSource) and request.body.length is None:
                headers['Transfer-Encoding'] = 'chunked'
            wire += _encode_http1_headers(headers, 'latin1') + b'\r\n'
            if isinstance(request.body, UploadSource):
                exchange = HTTP1Upload(lease, request.body, read_timeout)
                response = await exchange.response(wire + b'\r\n', request)
                if not response._released:
                    response._pool_lease = lease
                return response
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
        """Stop requests, leases and Cookie file work; borrowed pools stay open."""
        self._bind()
        if self._close_task is None:
            self._closed = True
            current = asyncio.current_task()
            requests = [task for task in self._requests if task is not current]
            cookie_tasks = list(self._cookie_tasks)
            for task in requests + cookie_tasks:
                task.cancel()
            self._close_task = owner_task(self._finish_close(requests, cookie_tasks))
        await asyncio.shield(self._close_task)

    async def _finish_close(self, requests, cookie_tasks):
        await asyncio.gather(*requests, *cookie_tasks, return_exceptions=True)
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
