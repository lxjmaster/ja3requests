"""
Ja3Requests.__init__
~~~~~~~~~~~~~~~~~~~~~~~~~~

Ja3Request
"""

from .sessions import Session
from .protocol.tls.config import TlsConfig
from .response import Response
from .exceptions import (
    RequestException,
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


def session(**kwargs):
    """
    Return a Session object.
    :param kwargs: Arguments passed to Session constructor (tls_config, pool, use_pooling).
    :return: Session
    """
    return Session(**kwargs)


def request(method, url, **kwargs):
    """
    Send a request.

    :param method: HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS).
    :param url: URL for the request.
    :param kwargs: Arguments passed to Session.request().
    :return: Response
    """
    with Session() as s:
        return s.request(method, url, **kwargs)


def get(url, params=None, **kwargs):
    """Send a GET request."""
    return request("GET", url, params=params, **kwargs)


def post(url, data=None, json=None, **kwargs):
    """Send a POST request."""
    return request("POST", url, data=data, json=json, **kwargs)


def put(url, data=None, **kwargs):
    """Send a PUT request."""
    return request("PUT", url, data=data, **kwargs)


def patch(url, data=None, **kwargs):
    """Send a PATCH request."""
    return request("PATCH", url, data=data, **kwargs)


def delete(url, **kwargs):
    """Send a DELETE request."""
    return request("DELETE", url, **kwargs)


def head(url, **kwargs):
    """Send a HEAD request."""
    kwargs.setdefault("allow_redirects", False)
    return request("HEAD", url, **kwargs)


def options(url, **kwargs):
    """Send an OPTIONS request."""
    return request("OPTIONS", url, **kwargs)
