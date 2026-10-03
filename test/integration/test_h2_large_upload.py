"""Large HTTP/2 DATA frames must span valid TLS records."""

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    tls12_context,
    tls13_context,
)


@pytest.mark.parametrize("version", [12, 13])
@pytest.mark.parametrize("pooled", [False, True])
def test_h2_large_upload_with_default_peer_windows(local_certificate, version, pooled):
    config = TlsConfig.secure()
    config.verify_cert = False
    config.tls_version = 0x0303 if version == 12 else 0x0304
    config.alpn_protocols = ["h2"]
    context = (
        tls12_context(
            *local_certificate, alpn="h2", cipher="ECDHE-RSA-AES128-GCM-SHA256"
        )
        if version == 12
        else tls13_context(*local_certificate, alpn="h2")
    )
    body = b"x" * 20000
    received = bytearray()
    lengths = []

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while True:
            header = read_exact(conn, 9)
            size = int.from_bytes(header[:3], "big")
            payload = read_exact(conn, size)
            if header[3] == 0:
                lengths.append(size)
                received.extend(payload)
                if header[4] & 1:
                    stream = int.from_bytes(header[5:9], "big")
                    conn.sendall(
                        h2_frame(1, 4, stream, b"\x88") + h2_frame(0, 1, stream, b"ok")
                    )
                    return

    with LocalServer(handler, context) as server:
        with Session(
            tls_config=config,
            pool=ConnectionPool() if pooled else None,
            use_pooling=pooled,
        ) as session:
            response = session.post(
                f"https://127.0.0.1:{server.port}/", data=body, timeout=2
            )
            assert response.content == b"ok"
    assert bytes(received) == body
    assert lengths == [16384, 3616]
