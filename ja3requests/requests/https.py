"""
Ja3Requests.requests.https
~~~~~~~~~~~~~~~~~~~~~~~~~~

This module of HTTPS Request.
"""

from __future__ import annotations

from typing import Any, Optional, Union
from ja3requests.const import DEFAULT_HTTPS_SCHEME, DEFAULT_HTTPS_PORT
from ja3requests.base import BaseRequest
from ja3requests.contexts.context import HTTPSContext
from ja3requests.sockets.https import HttpsSocket
from ja3requests.sockets.proxy import ProxySocket
from ja3requests.sockets.socks import SocksProxySocket
from ja3requests.response import HTTPSResponse
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls.config import _validate_http_alpn


class HttpsRequest(BaseRequest):
    """
    HTTPS Request
    """

    def __init__(self) -> None:
        super().__init__()
        self.scheme = DEFAULT_HTTPS_SCHEME
        self.port = DEFAULT_HTTPS_PORT

    @staticmethod
    def create_connection(
        context: HTTPSContext, pool: Optional[ConnectionPool] = None
    ) -> Union[HttpsSocket, ProxySocket, SocksProxySocket]:
        """
        create a new connection by context
        :param context:
        :param pool: Connection pool for reuse
        :return:
        """
        config = getattr(context, 'tls_config', None)
        if config is not None:
            _validate_http_alpn(config.alpn_protocols)
        if context.proxy:
            scheme = getattr(context, 'proxy_scheme', None)
            if scheme in ('socks5', 'socks4'):
                socks_ver = 5 if scheme == 'socks5' else 4
                sock = SocksProxySocket(context, socks_version=socks_ver)
            else:
                sock = ProxySocket(context)
        else:
            sock = HttpsSocket(context, pool=pool)

        return sock.new_conn()

    def send(self, **kwargs: Any) -> HTTPSResponse:
        pool = kwargs.pop('pool', None)

        if kwargs.get("h1", False) is True:
            context = HTTPSContext(protocol="HTTP/1.1")
        else:
            context = HTTPSContext()

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
            tls_config=self.tls_config,
        )
        sock = self.create_connection(context, pool=pool)
        try:
            conn = sock.send()
        except Exception:
            # HttpsSocket releases a failed H2 stream itself. Proxy tunnels
            # have no shared pool and still need closing on handshake failure.
            if not isinstance(sock, HttpsSocket):
                sock.close()
            raise
        response = None
        try:
            response = HTTPSResponse(
                conn, method=self.method, release=sock.release_response
            )
            response._upload_owner = (
                conn
                if hasattr(conn, 'finalize_source')
                else getattr(conn, 'upload_owner', None)
            )
            response.handle()
            if hasattr(conn, 'upload_headers_received'):
                conn.upload_headers_received()
        except Exception:
            # The response adapter owns an individual H2 stream. Its error
            # cleanup must not close another stream's shared TLS connection.
            if response is None or hasattr(conn, 'upload_headers_received'):
                release = getattr(conn, 'release_response', sock.release_response)
                release(False)
            raise

        return response
