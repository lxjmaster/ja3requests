"""Shared public-interface types; no optional typing dependency at runtime.

The keyword dictionaries are consumed only by static type checkers. All library
annotations that use them are postponed, preserving the Python 3.7 runtime.
"""

from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Awaitable,
    Dict,
    BinaryIO,
    Iterator,
    AsyncIterator,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
)
from http.cookiejar import CookieJar


Timeout = Optional[Union[float, Tuple[Optional[float], Optional[float]]]]
Params = Union[
    str,
    bytes,
    Dict[str, Any],
    Dict[bytes, Any],
    List[Tuple[str, Any]],
    Tuple[Tuple[str, Any], ...],
]
Data = Union[Params, BinaryIO, Iterator[bytes]]
AsyncData = Union[Data, AsyncIterator[bytes]]
JsonBody = Union[Dict[str, Any], str, bytes]
HeaderValue = Union[str, bytes, int, float]
Headers = Mapping[str, HeaderValue]
Cookies = Union[Dict[str, str], CookieJar, str, bytes]
Auth = Tuple[str, str]
Proxies = Dict[str, str]
FileValue = Union[str, bytes, BinaryIO]
Files = Dict[str, Union[FileValue, List[FileValue]]]
AsyncFileValue = Union[FileValue, "os.PathLike[str]"]
AsyncFiles = Mapping[str, Union[AsyncFileValue, List[AsyncFileValue]]]
PathInput = Union[str, "os.PathLike[str]"]
RequestHook = Callable[["BaseRequest"], Optional["BaseRequest"]]
ResponseHook = Callable[["Response"], Optional["Response"]]


if TYPE_CHECKING:
    import os
    from typing_extensions import TypedDict

    from ja3requests.base import BaseRequest
    from ja3requests.pool import ConnectionPool
    from ja3requests.protocol.tls.config import TlsConfig
    from ja3requests.response import Response
    from ja3requests.retry import HTTPRetry
    from ja3requests.async_sessions import _RequestMetadata
    from ja3requests.async_response import AsyncResponse

    AsyncRequestHook = Callable[
        [_RequestMetadata],
        Union[None, _RequestMetadata, Awaitable[Optional[_RequestMetadata]]],
    ]
    AsyncResponseHook = Callable[
        [AsyncResponse], Union[None, AsyncResponse, Awaitable[Optional[AsyncResponse]]]
    ]

    class AsyncHooks(TypedDict, total=False):
        before_request: List[AsyncRequestHook]
        after_request: List[AsyncResponseHook]

    class AsyncRequestOptions(TypedDict, total=False):
        params: Optional[Params]
        data: Optional[AsyncData]
        files: Optional[AsyncFiles]
        json: Optional[JsonBody]
        headers: Optional[Headers]
        cookies: Optional[Cookies]
        auth: Optional[Auth]
        proxies: Optional[Proxies]
        timeout: Timeout
        verify: Optional[bool]
        tls_config: Optional[TlsConfig]
        stream: bool
        allow_redirects: bool
        hooks: Optional[AsyncHooks]
        h1: bool

    class Hooks(TypedDict, total=False):
        before_request: List[RequestHook]
        after_request: List[ResponseHook]

    class SendOptions(TypedDict, total=False):
        stream: bool
        allow_redirects: bool
        hooks: Optional[Hooks]
        h1: bool

    class CommonOptions(SendOptions, total=False):
        cookies: Optional[Cookies]
        auth: Optional[Auth]
        proxies: Optional[Proxies]
        timeout: Timeout
        verify: Optional[bool]
        tls_config: Optional[TlsConfig]

    class GetOptions(CommonOptions, total=False):
        data: Optional[Data]
        files: Optional[Files]
        json: Optional[JsonBody]

    class GetRequestOptions(GetOptions, total=False):
        headers: Optional[Headers]

    class PostOptions(CommonOptions, total=False):
        params: Optional[Params]

    class PostRequestOptions(PostOptions, total=False):
        files: Optional[Files]
        headers: Optional[Headers]

    class DataOptions(PostRequestOptions, total=False):
        json: Optional[JsonBody]

    class RequestOptions(DataOptions, total=False):
        data: Optional[Data]

    class SessionOptions(TypedDict, total=False):
        tls_config: Optional[TlsConfig]
        pool: Optional[ConnectionPool]
        use_pooling: bool
        hooks: Optional[Hooks]
        retry: Optional[HTTPRetry]

    class H2HostStats(TypedDict):
        connections: int
        active_streams: int

    class PoolStats(TypedDict):
        total_connections: int
        pools: int
        h2_pools: int
        max_per_host: int
        idle_timeout: float
        hosts: Dict[str, int]
        h2_hosts: Dict[str, H2HostStats]
