"""
Ja3Requests.requests.http
~~~~~~~~~~~~~~~~~~~~~~~~~

This module of HTTP Request.
"""

from __future__ import annotations

from typing import Any, Optional, Union
from ja3requests.base import BaseRequest
from ja3requests.contexts.context import HTTPContext
from ja3requests.sockets.http import HttpSocket
from ja3requests.sockets.proxy import ProxySocket
from ja3requests.sockets.socks import SocksProxySocket
from ja3requests.const import DEFAULT_HTTP_SCHEME, DEFAULT_HTTP_PORT
from ja3requests.response import HTTPResponse
from ja3requests.pool import ConnectionPool


class HttpRequest(BaseRequest):
    """
    HTTP Request
    """

    def __init__(self) -> None:
        super().__init__()
        self.scheme = DEFAULT_HTTP_SCHEME
        self.port = DEFAULT_HTTP_PORT

    @staticmethod
    def create_connection(
        context: HTTPContext, pool: Optional[ConnectionPool] = None
    ) -> Union[HttpSocket, ProxySocket, SocksProxySocket]:
        """
        create a new connection by context
        :param context:
        :param pool: Connection pool for reuse
        :return:
        """
        if context.proxy:
            scheme = getattr(context, 'proxy_scheme', None)
            if scheme in ('socks5', 'socks4'):
                socks_ver = 5 if scheme == 'socks5' else 4
                sock = SocksProxySocket(context, socks_version=socks_ver)
            else:
                sock = ProxySocket(context)
        else:
            sock = HttpSocket(context, pool=pool)

        return sock.new_conn()

    def send(self, **kwargs: Any) -> HTTPResponse:
        pool = kwargs.pop('pool', None)

        context = HTTPContext()
        context._upload_register = kwargs.pop('_upload_register', None)
        context.set_payload(
            method=self.method,
            start_line=self.url,
            port=self.port,
            data=self.data,
            files=self.files,
            headers=self.headers,
            timeout=self.timeout,
            json=self.json,
            proxy=self.proxy,
            cookies=self.cookies,
        )
        sock = self.create_connection(context, pool=pool)
        try:
            conn = sock.send()
            response = HTTPResponse(
                conn, method=self.method, release=sock.release_response
            )
            response._upload_owner = conn if hasattr(conn, 'finalize_source') else None
            response.handle()
            if hasattr(conn, 'upload_headers_received'):
                conn.upload_headers_received()
        except Exception:
            if 'conn' in locals() and hasattr(conn, 'release_response'):
                conn.release_response(False)
            else:
                sock.close()
            raise

        return response
