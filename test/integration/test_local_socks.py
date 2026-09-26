"""Exercise SOCKS handshakes and tunnel data over real loopback TCP."""

from types import SimpleNamespace

import pytest

from ja3requests.protocol.exceptions import ProxyError
from ja3requests.sockets.socks import SocksProxySocket
from test.mock_servers.local import LocalServer, read_exact, serve_socks


@pytest.mark.parametrize(
    "version,host,auth",
    [
        (4, "127.0.0.1", False),
        (4, "target.invalid", True),
        (5, "target.invalid", False),
        (5, "target.invalid", True),
    ],
)
@pytest.mark.parametrize("reject", [False, True])
def test_socks_connect(version, host, auth, reject):
    observed = {}

    def handler(conn):
        serve_socks(conn, observed, version=version, auth=auth, reject=reject)

    with LocalServer(handler) as server:
        context = SimpleNamespace(
            proxy=f"127.0.0.1:{server.port}",
            proxy_auth="alice:secret" if auth else None,
            destination_address=host,
            port=8443,
            connect_timeout=2,
            source_address=None,
            message=b"ping",
        )
        client = SocksProxySocket(context, socks_version=version)
        try:
            if reject:
                with pytest.raises(ProxyError):
                    client.new_conn()
            else:
                client.new_conn()
                client.conn.settimeout(2)
                assert read_exact(client.send(), 4) == b"ping"
        finally:
            if client.conn is not None:
                client.conn.close()
    assert observed["host"] == host.encode()
    assert observed["port"] == 8443
    if auth and version == 5:
        assert observed["credentials"] == (b"alice", b"secret")
    if version == 4:
        assert observed["user"] == (b"alice" if auth else b"")
