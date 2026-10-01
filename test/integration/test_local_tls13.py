"""TLS 1.3 interoperability through the existing public Session API."""

import json
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.tls13 import TLS13Handshake
from ja3requests.sockets.https import HttpsSocket
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    read_headers,
    recv_with_ragged_eof,
    serve_h2,
    serve_h2_serial,
    tls13_context,
)
from test.mock_servers.local import tls12_context


def tls13_config(cipher=0x1301):
    config = TlsConfig()
    config.tls_version = 0x0304
    config.cipher_suites = [cipher]
    config.supported_groups = [29]
    config.signature_algorithms = [0x0804]
    config.alpn_protocols = ["http/1.1"]
    return config


@pytest.fixture(params=[False, True], ids=["normal-reads", "fragmented-reads"])
def fragmented_reads(request, monkeypatch):
    if not request.param:
        return
    original = HttpsSocket._new_conn

    class FragmentedSocket:
        def __init__(self, conn):
            self.conn = conn

        def recv(self, size, *args):
            return self.conn.recv(min(size, 7), *args)

        def __getattr__(self, name):
            return getattr(self.conn, name)

    def connect(transport, host, port):
        return FragmentedSocket(original(transport, host, port))

    monkeypatch.setattr(HttpsSocket, "_new_conn", connect)


@pytest.mark.parametrize("cipher", [0x1301, 0x1302, 0x1303])
def test_tls13_http_and_pool_reuse(local_certificate, fragmented_reads, cipher):
    requests = []

    def handler(conn):
        assert conn.version() == "TLSv1.3"
        assert conn.selected_alpn_protocol() == "http/1.1"
        for _ in range(2):
            requests.append(read_headers(conn))
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")

    with LocalServer(handler, tls13_context(*local_certificate)) as server:
        with Session(tls_config=tls13_config(cipher), pool=ConnectionPool()) as session:
            for path in ("/first", "/second"):
                response = session.get(
                    f"https://127.0.0.1:{server.port}{path}", timeout=2
                )
                assert response.status_code == 200
                assert response.content == b"hello"
    assert requests[0].startswith(b"GET /first HTTP/1.1\r\n")
    assert requests[1].startswith(b"GET /second HTTP/1.1\r\n")


@pytest.mark.parametrize("cipher", [0x1301, 0x1302, 0x1303])
def test_tls13_h2_alpn_and_session_tickets(local_certificate, fragmented_reads, cipher):
    observed = {}
    config = tls13_config(cipher)
    config.alpn_protocols = ["h2", "http/1.1"]
    config.h2_settings = {1: 12345}
    config.h2_window_update = 65536
    context = tls13_context(*local_certificate, alpn="h2")
    # OpenSSL emits tickets before application data. They must not look like EOF.
    context.num_tickets = 2
    with LocalServer(lambda conn: serve_h2(conn, observed), context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert response.status_code == 200
            assert response.content == b"hello h2"
    assert observed["settings"][1] == 12345
    assert observed["window"] == 65536


@pytest.mark.parametrize("cipher", [0x1301, 0x1302, 0x1303])
def test_tls13_h2_sequential_requests_reuse_connection(
    local_certificate, fragmented_reads, cipher
):
    observed = {}
    config = tls13_config(cipher)
    config.alpn_protocols = ["h2", "http/1.1"]
    with LocalServer(
        lambda conn: serve_h2_serial(conn, observed, fragment_ack=True),
        tls13_context(*local_certificate, alpn="h2"),
    ) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            for index, path in enumerate(("/first", "/second")):
                response = session.get(
                    f"https://127.0.0.1:{server.port}{path}", timeout=3
                )
                assert response.status_code == 200
                assert response.content == b"ok"
                if index == 0:
                    assert session.pool.get_stats()["total_connections"] == 1
    assert observed["settings"] == 1
    assert observed["streams"] == [1, 3]


def test_tls13_h2_reuse_replenishes_window_and_tracks_table_size(local_certificate):
    observed = {}
    body = b"x" * 40000
    config = tls13_config()
    config.alpn_protocols = ["h2", "http/1.1"]
    with LocalServer(
        lambda conn: serve_h2_serial(conn, observed, body=body, table_size=0),
        tls13_context(*local_certificate, alpn="h2"),
    ) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            assert session.get(url, timeout=3).content == body
            assert session.get(url, timeout=3).content == body
    assert observed["streams"] == [1, 3]
    assert observed["header_blocks"][0].startswith(b"\x20")
    assert any(stream == 0 for stream, _ in observed["window_updates"])


def test_tls13_h2_post_reuse_obeys_send_windows(local_certificate):
    observed = {"streams": [], "bodies": [], "data_sizes": [], "connection_updates": 0}
    config = tls13_config()
    config.alpn_protocols = ["h2", "http/1.1"]
    raw_body = b"x" * 70000

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0, b"\x00\x04\x00\x00\x10\x00"))
        connection_window = 65535
        stream_window = 0
        body = bytearray()
        while len(observed["bodies"]) < 2:
            header = read_exact(conn, 9)
            length = int.from_bytes(header[:3], "big")
            kind = header[3]
            flags = header[4]
            stream = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            payload = read_exact(conn, length)
            if kind == 1:
                assert flags & 4
                observed["streams"].append(stream)
                stream_window = 4096
                body = bytearray()
                # Response headers can arrive while the client is waiting to send DATA.
                conn.sendall(
                    h2_frame(1, 4, stream, b"\x88") + h2_frame(0, 0, stream, b"pre")
                )
            elif kind == 0:
                assert stream == observed["streams"][-1]
                assert length <= min(16384, stream_window, connection_window)
                stream_window -= length
                connection_window -= length
                observed["data_sizes"].append(length)
                body.extend(payload)
                if connection_window == 0:
                    conn.sendall(h2_frame(8, 0, 0, (65535).to_bytes(4, "big")))
                    connection_window = 65535
                    observed["connection_updates"] += 1
                if flags & 1:
                    observed["bodies"].append(bytes(body))
                    conn.sendall(h2_frame(0, 1, stream, b"ok"))
                else:
                    conn.sendall(h2_frame(8, 0, stream, length.to_bytes(4, "big")))
                    stream_window += length

    with LocalServer(handler, tls13_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/upload"
            for index, kwargs in enumerate(
                ({"data": raw_body}, {"json": {"kind": "json", "n": 2}})
            ):
                response = session.post(url, timeout=3, **kwargs)
                assert response.status_code == 200
                assert response.content == b"preok"
                if index == 0:
                    assert session.pool.get_stats()["total_connections"] == 1

    assert observed["streams"] == [1, 3]
    assert observed["bodies"][0] == raw_body
    assert json.loads(observed["bodies"][1]) == {"kind": "json", "n": 2}
    assert max(observed["data_sizes"]) <= 4096
    assert observed["connection_updates"] >= 1


@pytest.mark.parametrize("version", ["TLSv1.2", "TLSv1.3"])
def test_h2_concurrent_streams_share_connection(local_certificate, version):
    first_seen = threading.Event()
    both_seen = threading.Event()
    allow_responses = threading.Event()
    streams = []
    paths = []
    config = tls13_config() if version == "TLSv1.3" else TlsConfig()
    config.alpn_protocols = ["h2", "http/1.1"]

    def handler(conn):
        assert conn.version() == version
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0, b"\x00\x03\x00\x00\x00\x02"))
        while len(streams) < 2:
            header = read_exact(conn, 9)
            length = int.from_bytes(header[:3], "big")
            payload = read_exact(conn, length)
            if header[3] != 1:
                continue
            assert header[4] & 5 == 5  # END_HEADERS and END_STREAM
            streams.append(int.from_bytes(header[5:9], "big") & 0x7FFFFFFF)
            paths.append("/first" if b"/first" in payload else "/second")
            if len(streams) == 1:
                first_seen.set()
        both_seen.set()
        assert allow_responses.wait(3)
        conn.sendall(
            h2_frame(1, 0, streams[1])
            + h2_frame(9, 4, streams[1], b"\x88")
            + h2_frame(0, 1, streams[1], b"second")
        )
        conn.sendall(
            h2_frame(1, 4, streams[0], b"\x88") + h2_frame(0, 1, streams[0], b"first")
        )

    context = (
        tls13_context(*local_certificate, alpn="h2")
        if version == "TLSv1.3"
        else tls12_context(*local_certificate, alpn="h2")
    )
    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}"
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(session.get, url + "/first", timeout=3)
                assert first_seen.wait(3)
                second = executor.submit(session.get, url + "/second", timeout=3)
                assert both_seen.wait(3)
                stats = session.pool.get_stats()
                assert stats["total_connections"] == 1
                assert next(iter(stats["h2_hosts"].values()))["active_streams"] == 2
                allow_responses.set()
                assert second.result(timeout=4).content == b"second"
                assert first.result(timeout=4).content == b"first"
    assert streams == [1, 3]
    assert paths == ["/first", "/second"]


def test_tls13_h2_concurrent_posts_have_separate_send_windows(local_certificate):
    first_seen = threading.Event()
    bodies = {}
    streams = []
    config = tls13_config()
    config.alpn_protocols = ["h2", "http/1.1"]

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0, b"\x00\x04\x00\x00\x00\x02"))
        deferred = []
        while len(bodies) < 2 or not all(len(value) == 4 for value in bodies.values()):
            header = read_exact(conn, 9)
            length = int.from_bytes(header[:3], "big")
            payload = read_exact(conn, length)
            stream = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            if header[3] == 1:
                streams.append(stream)
                bodies[stream] = bytearray()
                if len(streams) == 1:
                    first_seen.set()
                else:
                    for pending in deferred:
                        conn.sendall(h2_frame(8, 0, pending, (2).to_bytes(4, "big")))
                    deferred.clear()
            elif header[3] == 0:
                assert length <= 2
                bodies[stream].extend(payload)
                if not header[4] & 1:
                    if len(streams) == 1:
                        deferred.append(stream)
                    else:
                        conn.sendall(h2_frame(8, 0, stream, length.to_bytes(4, "big")))
        for stream in reversed(streams):
            conn.sendall(
                h2_frame(1, 4, stream, b"\x88") + h2_frame(0, 1, stream, b"ok")
            )

    with LocalServer(handler, tls13_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/upload"
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(session.post, url, data=b"aaaa", timeout=3)
                assert first_seen.wait(3)
                second = executor.submit(session.post, url, data=b"bbbb", timeout=3)
                assert first.result(timeout=4).content == b"ok"
                assert second.result(timeout=4).content == b"ok"
    assert streams == [1, 3]
    assert bodies[1] == b"aaaa"
    assert bodies[3] == b"bbbb"


def test_tls13_h2_reset_isolated_from_other_streams(local_certificate):
    first_seen = threading.Event()
    streams = []
    config = tls13_config()
    config.alpn_protocols = ["h2", "http/1.1"]

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while len(streams) < 3:
            header = read_exact(conn, 9)
            length = int.from_bytes(header[:3], "big")
            read_exact(conn, length)
            if header[3] != 1:
                continue
            stream = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            streams.append(stream)
            if len(streams) == 1:
                first_seen.set()
            elif len(streams) == 2:
                conn.sendall(h2_frame(3, 0, stream, b"\x00\x00\x00\x02"))
                conn.sendall(
                    h2_frame(1, 4, streams[0], b"\x88")
                    + h2_frame(0, 1, streams[0], b"ok")
                )
            else:
                conn.sendall(
                    h2_frame(1, 4, stream, b"\x88") + h2_frame(0, 1, stream, b"ok")
                )

    with LocalServer(handler, tls13_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(session.get, url + "first", timeout=3)
                assert first_seen.wait(3)
                second = executor.submit(session.get, url + "reset", timeout=3)
                with pytest.raises(ConnectionError, match="reset by peer"):
                    second.result(timeout=4)
                assert first.result(timeout=4).content == b"ok"
            assert session.get(url + "third", timeout=3).content == b"ok"
    assert streams == [1, 3, 5]


def test_tls13_h2_stream_timeout_sends_reset_and_keeps_connection(local_certificate):
    streams = []
    resets = []
    config = tls13_config()
    config.alpn_protocols = ["h2", "http/1.1"]

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while len(streams) < 2:
            header = read_exact(conn, 9)
            length = int.from_bytes(header[:3], "big")
            payload = read_exact(conn, length)
            stream = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            if header[3] == 1:
                streams.append(stream)
                if len(streams) == 2:
                    assert resets == [1]
                    conn.sendall(
                        h2_frame(1, 4, stream, b"\x88") + h2_frame(0, 1, stream, b"ok")
                    )
            elif header[3] == 3:
                resets.append(stream)
                assert payload == b"\x00\x00\x00\x08"

    with LocalServer(handler, tls13_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            with pytest.raises(ConnectionError, match="timed out"):
                session.get(url + "slow", timeout=0.2)
            assert session.pool.get_stats()["total_connections"] == 1
            assert session.get(url + "next", timeout=3).content == b"ok"
    assert streams == [1, 3]


def test_tls13_h2_disconnect_fails_all_active_streams(local_certificate):
    first_seen = threading.Event()
    streams = []
    config = tls13_config()
    config.alpn_protocols = ["h2", "http/1.1"]

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while len(streams) < 2:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            if header[3] == 1:
                streams.append(int.from_bytes(header[5:9], "big") & 0x7FFFFFFF)
                if len(streams) == 1:
                    first_seen.set()

    with LocalServer(handler, tls13_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(session.get, url + "first", timeout=3)
                assert first_seen.wait(3)
                second = executor.submit(session.get, url + "second", timeout=3)
                with pytest.raises(
                    ConnectionError, match="HTTP/2 communication failed"
                ):
                    first.result(timeout=4)
                with pytest.raises(
                    ConnectionError, match="HTTP/2 communication failed"
                ):
                    second.result(timeout=4)
            assert session.pool.get_stats()["total_connections"] == 0
    assert streams == [1, 3]


def test_tls13_h2_goaway_keeps_accepted_stream_and_reconnects(local_certificate):
    first_seen = threading.Event()
    connections = []
    config = tls13_config()
    config.alpn_protocols = ["h2", "http/1.1"]

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        streams = []
        connections.append(streams)
        expected = 2 if len(connections) == 1 else 1
        while len(streams) < expected:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            if header[3] == 1:
                streams.append(int.from_bytes(header[5:9], "big") & 0x7FFFFFFF)
                if len(connections) == 1 and len(streams) == 1:
                    first_seen.set()
        if expected == 2:
            conn.sendall(h2_frame(7, 0, 0, b"\x00\x00\x00\x01" + b"\x00" * 4))
        conn.sendall(
            h2_frame(1, 4, streams[0], b"\x88") + h2_frame(0, 1, streams[0], b"ok")
        )

    with LocalServer(
        handler, tls13_context(*local_certificate, alpn="h2"), connections=2
    ) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            with ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(session.get, url + "first", timeout=3)
                assert first_seen.wait(3)
                second = executor.submit(session.get, url + "second", timeout=3)
                with pytest.raises(ConnectionError, match="rejected by GOAWAY"):
                    second.result(timeout=4)
                assert first.result(timeout=4).content == b"ok"
            assert session.get(url + "third", timeout=3).content == b"ok"
    assert connections == [[1, 3], [1]]


def test_tls13_h2_goaway_opens_new_connection(local_certificate):
    observed = []
    config = tls13_config()
    config.alpn_protocols = ["h2", "http/1.1"]

    def handler(conn):
        exchange = {}
        serve_h2_serial(conn, exchange, count=1, goaway=True)
        observed.append(exchange)

    with LocalServer(
        handler, tls13_context(*local_certificate, alpn="h2"), connections=2
    ) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            for _ in range(2):
                assert (
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=3).content
                    == b"ok"
                )
                assert session.pool.get_stats()["total_connections"] == 0
    assert [exchange["streams"] for exchange in observed] == [[1], [1]]


def test_h2_settings_change_pool_policy():
    config = tls13_config()
    config.h2_settings = {1: 12345}
    before = HttpsSocket._tls_policy_key(config, "localhost")
    config.h2_settings[1] = 54321
    assert HttpsSocket._tls_policy_key(config, "localhost") != before
    before = HttpsSocket._tls_policy_key(config, "localhost")
    config.h2_window_update = 65536
    assert HttpsSocket._tls_policy_key(config, "localhost") != before


def test_tls13_h2_reset_keeps_reused_connection(local_certificate):
    config = tls13_config()
    config.alpn_protocols = ["h2", "http/1.1"]
    streams = []

    def handler(conn):
        assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        conn.sendall(h2_frame(4, 0, 0))
        while len(streams) < 3:
            header = read_exact(conn, 9)
            read_exact(conn, int.from_bytes(header[:3], "big"))
            if header[3] != 1:
                continue
            stream = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
            streams.append(stream)
            if len(streams) == 1:
                conn.sendall(
                    h2_frame(1, 4, stream, b"\x88") + h2_frame(0, 1, stream, b"ok")
                )
            elif len(streams) == 2:
                conn.sendall(h2_frame(3, 0, stream, b"\x00\x00\x00\x02"))
            else:
                conn.sendall(
                    h2_frame(1, 4, stream, b"\x88") + h2_frame(0, 1, stream, b"ok")
                )
        while recv_with_ragged_eof(conn, 4096):
            pass

    with LocalServer(handler, tls13_context(*local_certificate, alpn="h2")) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = f"https://127.0.0.1:{server.port}/"
            assert session.get(url, timeout=3).content == b"ok"
            assert session.pool.get_stats()["total_connections"] == 1
            with pytest.raises(
                ConnectionError, match="HTTP/2 communication failed"
            ) as failure:
                session.get(url, timeout=3)
            assert "reset by peer" in str(failure.value.__cause__)
            assert session.pool.get_stats()["total_connections"] == 1
            assert session.get(url, timeout=3).content == b"ok"
    assert streams == [1, 3, 5]


def test_tls13_invalid_finished_aborts_before_http(local_certificate, monkeypatch):
    original = TLS13Handshake.verify_server_finished
    checks = []

    def corrupt_finished(handshake, data):
        checks.append(data)
        return original(handshake, data[:-1] + bytes([data[-1] ^ 1]))

    monkeypatch.setattr(TLS13Handshake, "verify_server_finished", corrupt_finished)
    server = LocalServer(
        lambda conn: pytest.fail("Client sent invalid Finished"),
        tls13_context(*local_certificate),
    )
    # The client must close before OpenSSL completes its side of the handshake.
    with pytest.raises(ssl.SSLError):
        with server:
            with Session(tls_config=tls13_config(), pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
    assert len(checks) == 1


def test_tls13_verify_true_is_not_silently_ignored(local_certificate):
    requests = []

    def handler(conn):
        requests.append(read_headers(conn))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

    config = tls13_config()
    config.server_name = "wrong.invalid"
    config.verify_cert = True
    server = LocalServer(handler, tls13_context(*local_certificate))
    with pytest.raises(ssl.SSLError):
        with server:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(
                        f"https://127.0.0.1:{server.port}/", timeout=2, verify=True
                    )
    assert requests == []


@pytest.mark.parametrize("version", [12, 13])
def test_browser_preset_negotiates_verified_tls(
    trusted_certificates, monkeypatch, fragmented_reads, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves["valid"]
    if version == 12:
        context = tls12_context(*certificate, cipher="ECDHE-RSA-AES128-GCM-SHA256")
    else:
        context = tls13_context(*certificate)

    def handler(conn):
        assert conn.version() == f"TLSv1.{version - 10}"
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    config = TlsConfig.from_browser("chrome", 120)
    config.verify_cert = True
    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert response.content == b"ok"


def test_browser_preset_rejects_bad_certificate_on_tls12_fallback(
    trusted_certificates, monkeypatch
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves["wrong-host"]
    context = tls12_context(*certificate, cipher="ECDHE-RSA-AES128-GCM-SHA256")
    config = TlsConfig.from_browser("chrome", 120)
    config.verify_cert = True
    verified = []
    original_verify = TLS._verify_server_certificate

    def record_verification(tls, certificate_data):
        verified.append(True)
        return original_verify(tls, certificate_data)

    monkeypatch.setattr(TLS, "_verify_server_certificate", record_verification)
    with pytest.raises(ssl.SSLError):
        with LocalServer(
            lambda conn: pytest.fail("Unverified request reached server"), context
        ) as server:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
    assert verified


@pytest.mark.parametrize(
    "version,certificate_variant,cipher",
    [
        (13, "valid", None),
        (13, "valid-ecdsa", None),
        (12, "valid", "ECDHE-RSA-AES128-GCM-SHA256"),
        (12, "valid-ecdsa", "ECDHE-ECDSA-AES128-GCM-SHA256"),
    ],
)
def test_secure_profile_verified_interop(
    trusted_certificates,
    monkeypatch,
    fragmented_reads,
    version,
    certificate_variant,
    cipher,
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves[certificate_variant]
    context = (
        tls13_context(*certificate)
        if version == 13
        else tls12_context(*certificate, cipher=cipher)
    )

    def handler(conn):
        assert conn.version() == f"TLSv1.{version - 10}"
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    config = TlsConfig.secure()
    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert response.content == b"ok"


@pytest.mark.parametrize("version", [12, 13])
def test_secure_profile_rejects_bad_certificate(
    trusted_certificates, monkeypatch, version
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves["wrong-host"]
    context = (
        tls13_context(*certificate)
        if version == 13
        else tls12_context(*certificate, cipher="ECDHE-RSA-AES128-GCM-SHA256")
    )
    verified = []
    original_verify = TLS._verify_server_certificate

    def record_verification(tls, certificate_data):
        verified.append(True)
        return original_verify(tls, certificate_data)

    monkeypatch.setattr(TLS, "_verify_server_certificate", record_verification)
    config = TlsConfig.secure()
    with pytest.raises(ssl.SSLError):
        with LocalServer(
            lambda conn: pytest.fail("Unverified request reached server"), context
        ) as server:
            with Session(tls_config=config, pool=ConnectionPool()) as session:
                with pytest.raises(ConnectionError, match="TLS handshake failed"):
                    session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
    assert verified


def test_secure_profile_p256_only_peer(
    trusted_certificates, monkeypatch, fragmented_reads
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves["valid"]
    context = tls13_context(*certificate, group="prime256v1")

    def handler(conn):
        assert conn.version() == "TLSv1.3"
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=TlsConfig.secure(), pool=ConnectionPool()) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert response.content == b"ok"


@pytest.mark.parametrize("cipher", [0x1301, 0x1302])
def test_tls13_hello_retry_request_with_p256_peer(
    trusted_certificates, monkeypatch, fragmented_reads, cipher
):
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    certificate = trusted_certificates.leaves["valid"]
    context = tls13_context(*certificate, group="prime256v1")
    config = TlsConfig.secure()
    config.cipher_suites = [cipher]
    config.key_share_groups = [29]
    selected_groups = []
    original_retry = TLS._send_retried_client_hello

    def record_retry(tls, message, suite, group, cookie):
        selected_groups.append(group)
        return original_retry(tls, message, suite, group, cookie)

    monkeypatch.setattr(TLS, "_send_retried_client_hello", record_retry)

    def handler(conn):
        assert conn.version() == "TLSv1.3"
        assert read_headers(conn).startswith(b"GET / HTTP/1.1\r\n")
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    with LocalServer(handler, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            response = session.get(f"https://127.0.0.1:{server.port}/", timeout=2)
            assert response.content == b"ok"
    assert selected_groups == [23]
