"""Independent TLS/wire evidence for HTTP/2 streaming and stream ownership."""

import struct
import threading

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection
from test import test_network_streaming as wire
from test.mock_servers.local import (
    LocalServer,
    h2_frame,
    read_exact,
    recv_with_ragged_eof,
    tls12_context,
    tls13_context,
)


def trusted_h2_peer(certificates, monkeypatch, version=13):
    monkeypatch.setenv("SSL_CERT_FILE", str(certificates.ca_path))
    config = TlsConfig.secure()
    config.alpn_protocols = ["h2"]
    certificate = certificates.leaves["valid"]
    if version == 12:
        config.cipher_suites = [0x1301, 0xC02F]
        context = tls12_context(
            *certificate, alpn="h2", cipher="ECDHE-RSA-AES128-GCM-SHA256"
        )
    else:
        config.cipher_suites = [0x1301]
        context = tls13_context(*certificate, alpn="h2")
    return config, context


@pytest.fixture
def h2_readers(monkeypatch):
    """Observe thread lifetime only; all protocol oracles use independent bytes."""
    readers = []
    original = H2MultiplexConnection.initiate

    def initiate(connection, *args, **kwargs):
        result = original(connection, *args, **kwargs)
        readers.append(connection._reader)
        return result

    monkeypatch.setattr(H2MultiplexConnection, "initiate", initiate)
    yield readers
    for reader in readers:
        reader.join(2)
        assert not reader.is_alive(), "HTTP/2 reader survived transport cleanup"


def start_h2(conn):
    assert conn.selected_alpn_protocol() == "h2"
    assert read_exact(conn, 24) == b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    conn.sendall(h2_frame(4, 0, 0))


def receive_frame(conn):
    header = read_exact(conn, 9)
    length = int.from_bytes(header[:3], "big")
    kind, flags, stream = struct.unpack("!BBI", header[3:])
    payload = read_exact(conn, length)
    if kind == 4 and not flags & 1:
        conn.sendall(h2_frame(4, 1, 0))
    return kind, flags, stream, payload


def receive_request(conn):
    while True:
        kind, flags, stream, _ = receive_frame(conn)
        if kind == 1:
            assert flags & 5 == 5  # A complete GET request header block.
            return stream


def await_transport_close(conn):
    while recv_with_ragged_eof(conn, 4096):
        pass


class H2GatedBody(wire.GatedBody):
    def __init__(self):
        super().__init__(b"", b"alpha", b"omega")
        self.streams = []

    def serve(self, conn):
        start_h2(conn)
        stream = receive_request(conn)
        self.streams.append(stream)
        # HPACK static-table index 8 independently encodes :status = 200.
        conn.sendall(h2_frame(1, 4, stream, b"\x88"))
        self.headers_sent.set()
        assert self.allow_first.wait(5), "Client waited for DATA before returning"
        conn.sendall(h2_frame(0, 0, stream, self.first))
        assert self.allow_tail.wait(5), "Client waited for END_STREAM before yielding"
        conn.sendall(h2_frame(0, 1, stream, self.tail))
        self.tail_sent.set()
        await_transport_close(conn)


@pytest.mark.parametrize("version", [12, 13], ids=["tls12", "tls13"])
@pytest.mark.parametrize("pooled", [False, True], ids=["unpooled", "pooled"])
def test_h2_headers_and_prefix_precede_end_stream(
    trusted_certificates, monkeypatch, h2_readers, version, pooled
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    gate = H2GatedBody()
    with LocalServer(gate.serve, context) as server:
        with Session(
            tls_config=config,
            pool=ConnectionPool() if pooled else None,
            use_pooling=pooled,
        ) as session:
            wire.assert_gated_delivery(
                session,
                "https://127.0.0.1:%d/stream" % server.port,
                gate,
                b"alphaomega",
            )
    assert gate.streams == [1]
    assert len(h2_readers) == 1


def test_h2_paused_stream_does_not_block_fast_stream_or_gain_unconsumed_credit(
    trusted_certificates, monkeypatch, h2_readers
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    config.h2_settings = {4: 8}
    streams, updates = [], []
    ping_ack = threading.Event()

    def serve(conn):
        start_h2(conn)
        advertised_window = None
        while not streams:
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 4 and not flags & 1:
                advertised_window = dict(struct.iter_unpack("!HI", payload)).get(4)
            elif kind == 1:
                streams.append(stream)
        assert advertised_window == 8
        conn.sendall(
            h2_frame(1, 4, streams[0], b"\x88")
            + h2_frame(0, 0, streams[0], b"paused00")
            + h2_frame(6, 0, 0, b"boundary")
        )
        # PING acknowledgement proves the reader processed the preceding DATA.
        while len(streams) < 2 or not ping_ack.is_set():
            kind, flags, stream, payload = receive_frame(conn)
            if kind == 1:
                streams.append(stream)
            elif kind == 8 and stream == streams[0]:
                updates.append(int.from_bytes(payload, "big"))
            elif kind == 6 and flags & 1:
                assert payload == b"boundary"
                ping_ack.set()
                assert not updates, "Paused stream gained credit before consumption"
        conn.sendall(
            h2_frame(1, 4, streams[1], b"\x88") + h2_frame(0, 1, streams[1], b"fast")
        )
        while not updates:
            kind, _, stream, payload = receive_frame(conn)
            if kind == 8 and stream == streams[0]:
                updates.append(int.from_bytes(payload, "big"))
        assert updates[0] >= 4
        conn.sendall(h2_frame(0, 1, streams[0], b"tail"))
        await_transport_close(conn)

    with LocalServer(serve, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = "https://127.0.0.1:%d" % server.port
            paused = session.get(url + "/paused", stream=True, timeout=3)
            try:
                fast = session.get(url + "/fast", timeout=3)
                try:
                    assert fast.content == b"fast"
                    assert ping_ack.is_set()
                    assert not updates
                finally:
                    fast.close()
                assert b"".join(paused.iter_content(chunk_size=4)) == b"paused00tail"
            finally:
                paused.close()
    assert streams == [1, 3]
    assert updates
    assert len(h2_readers) == 1


@pytest.mark.parametrize("cancel", ["close", "timeout"])
def test_h2_cancel_preserves_active_and_subsequent_streams(
    trusted_certificates, monkeypatch, h2_readers, cancel
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    streams, resets = [], []

    def serve(conn):
        start_h2(conn)
        while len(streams) < 3:
            kind, _, stream, payload = receive_frame(conn)
            if kind == 1:
                streams.append(stream)
                conn.sendall(h2_frame(1, 4, stream, b"\x88"))
                if len(streams) == 1:
                    conn.sendall(h2_frame(0, 0, stream, b"pre"))
                elif len(streams) == 3:
                    assert resets == [(streams[0], 8)]
                    conn.sendall(h2_frame(0, 1, stream, b"fresh"))
            elif kind == 3:
                resets.append((stream, int.from_bytes(payload, "big")))
                assert len(streams) == 2
                assert resets == [(streams[0], 8)]
                conn.sendall(h2_frame(0, 1, streams[1], b"fast"))
        await_transport_close(conn)

    with LocalServer(serve, context) as server:
        with Session(tls_config=config, pool=ConnectionPool()) as session:
            url = "https://127.0.0.1:%d" % server.port
            slow = session.get(
                url + "/slow",
                stream=True,
                timeout=(3, 0.2 if cancel == "timeout" else 3),
            )
            fast = None
            try:
                iterator = slow.iter_content(chunk_size=3)
                wire.assert_prefix(iterator, b"pre")
                fast = session.get(url + "/fast", stream=True, timeout=3)
                if cancel == "timeout":
                    with pytest.raises(TimeoutError, match="timed out"):
                        next(iterator)
                slow.close()
                assert fast.content == b"fast"
                fast.close()
                fresh = session.get(url + "/fresh", timeout=3)
                try:
                    assert fresh.content == b"fresh"
                finally:
                    fresh.close()
            finally:
                slow.close()
                if fast is not None:
                    fast.close()
    assert streams == [1, 3, 5]
    assert resets == [(1, 8)]
    assert len(h2_readers) == 1


def test_unpooled_h2_close_stops_reader_before_peer_closes(
    trusted_certificates, monkeypatch, h2_readers
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch)
    client_closed = threading.Event()
    allow_peer_close = threading.Event()
    resets = []

    def serve(conn):
        start_h2(conn)
        stream = receive_request(conn)
        conn.sendall(h2_frame(1, 4, stream, b"\x88") + h2_frame(0, 0, stream, b"pre"))
        try:
            while True:
                kind, _, received_stream, payload = receive_frame(conn)
                if kind == 3:
                    resets.append((received_stream, int.from_bytes(payload, "big")))
        except EOFError:
            client_closed.set()
            assert allow_peer_close.wait(5), "Reader did not stop after client close"

    with LocalServer(serve, context) as server:
        try:
            with Session(tls_config=config, use_pooling=False) as session:
                response = session.get(
                    "https://127.0.0.1:%d/stream" % server.port,
                    stream=True,
                    timeout=3,
                )
                try:
                    wire.assert_prefix(response.iter_content(chunk_size=3), b"pre")
                finally:
                    response.close()
                assert client_closed.wait(2)
                assert len(h2_readers) == 1
                h2_readers[0].join(2)
                assert not h2_readers[0].is_alive()
                assert not allow_peer_close.is_set()
        finally:
            allow_peer_close.set()
    assert resets == [(1, 8)]
