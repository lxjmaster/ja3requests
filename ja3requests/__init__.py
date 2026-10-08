"""
Ja3Requests.__init__
~~~~~~~~~~~~~~~~~~~~~~~~~~

Ja3Request
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from ._typing import Data, JsonBody, Params
from .sessions import Session
from .async_sessions import AsyncSession
from .async_response import AsyncResponse
from .async_pool import AsyncConnectionPool
from .protocol.tls.config import TlsConfig
from .response import Response
from .retry import HTTPRetry
from .exceptions import (
    RequestException,
    HTTPError,
    ConnectionException,
    Timeout,
    StreamConsumedError,
    ContentDecodingError,
    NotAllowedRequestMethod,
    MissingScheme,
    NotAllowedScheme,
    InvalidParams,
    InvalidData,
    InvalidHost,
    MaxRetriedException,
    TLSError,
    TLSHandshakeError,
)

if TYPE_CHECKING:
    from typing_extensions import Unpack
    from ._typing import (
        DataOptions,
        GetRequestOptions,
        PostRequestOptions,
        RequestOptions,
        SessionOptions,
    )

__all__ = [
    'Session',
    'AsyncSession',
    'AsyncResponse',
    'AsyncConnectionPool',
    'TlsConfig',
    'Response',
    'HTTPRetry',
    'RequestException',
    'HTTPError',
    'ConnectionException',
    'Timeout',
    'StreamConsumedError',
    'ContentDecodingError',
    'NotAllowedRequestMethod',
    'MissingScheme',
    'NotAllowedScheme',
    'InvalidParams',
    'InvalidData',
    'InvalidHost',
    'MaxRetriedException',
    'TLSError',
    'TLSHandshakeError',
    'session',
    'request',
    'get',
    'post',
    'put',
    'patch',
    'delete',
    'head',
    'options',
]


def session(**kwargs: Unpack[SessionOptions]) -> Session:
    """
    Return a Session object.
    :param kwargs: Arguments passed to Session constructor (tls_config, pool, use_pooling).
    :return: Session
    """
    return Session(**kwargs)


def request(method: str, url: str, **kwargs: Unpack[RequestOptions]) -> Response:
    """
    Send a request.

    :param method: HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
    :param url: URL for the request.
    :param kwargs: Arguments passed to Session.request().
    :return: Response
    """
    s = Session()
    try:
        response = s.request(method, url, **kwargs)
    except BaseException:
        s.close()
        raise

    raw = response.response
    if kwargs.get('stream', False) and raw is not None and not raw._finished:
        release = raw._release

        def release_session(reusable: bool) -> None:
            try:
                if release is not None:
                    release(reusable)
            finally:
                s.close()

        raw._release = release_session
    else:
        s.close()
    return response


def get(
    url: str, params: Optional[Params] = None, **kwargs: Unpack[GetRequestOptions]
) -> Response:
    """Send a GET request."""
    return request("GET", url, params=params, **kwargs)


def post(
    url: str,
    data: Optional[Data] = None,
    json: Optional[JsonBody] = None,
    **kwargs: Unpack[PostRequestOptions],
) -> Response:
    """Send a POST request."""
    return request("POST", url, data=data, json=json, **kwargs)


def put(
    url: str, data: Optional[Data] = None, **kwargs: Unpack[DataOptions]
) -> Response:
    """Send a PUT request."""
    return request("PUT", url, data=data, **kwargs)


def patch(
    url: str, data: Optional[Data] = None, **kwargs: Unpack[DataOptions]
) -> Response:
    """Send a PATCH request."""
    return request("PATCH", url, data=data, **kwargs)


def delete(url: str, **kwargs: Unpack[RequestOptions]) -> Response:
    """Send a DELETE request."""
    return request("DELETE", url, **kwargs)


def head(url: str, **kwargs: Unpack[RequestOptions]) -> Response:
    """Send a HEAD request."""
    kwargs.setdefault("allow_redirects", False)
    return request("HEAD", url, **kwargs)


def options(url: str, **kwargs: Unpack[RequestOptions]) -> Response:
    """Send an OPTIONS request."""
    return request("OPTIONS", url, **kwargs)
