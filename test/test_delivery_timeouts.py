"""Bounded waits at connection sharing and TLS 1.2 resumption boundaries."""

import socket
import threading
from types import SimpleNamespace

import pytest

from ja3requests import TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.extensions import SessionTicketExtension
from ja3requests.protocol.tls.session_cache import TLSSessionCache
from ja3requests.sockets.https import HttpsSocket


@pytest.mark.parametrize("timeout", [0, 0.05])
def test_h2_waiting_request_honors_its_connect_timeout(monkeypatch, timeout):
    config = TlsConfig.secure()
    config.alpn_protocols = ["h2"]
    pool = ConnectionPool()
    policy = HttpsSocket._tls_policy_key(config, "example.com")
    _, owner = pool.get_h2_or_reserve("example.com", 443, policy)
    context = SimpleNamespace(
        destination_address="example.com",
        port=443,
        tls_config=config,
        connect_timeout=timeout,
    )
    client = HttpsSocket(context, pool=pool)
    connected = []

    def unexpected_connect(*_args):
        connected.append(True)
        raise OSError("test cleanup: no network connection expected")

    monkeypatch.setattr(client, "_new_conn", unexpected_connect)
    done = threading.Event()
    errors = []

    def request():
        try:
            client.new_conn()
        except Exception as error:
            errors.append(error)
        finally:
            done.set()

    worker = threading.Thread(target=request, daemon=True)
    worker.start()
    try:
        assert done.wait(1), "waiting request ignored its connect timeout"
        assert len(errors) == 1 and isinstance(errors[0], TimeoutError)
        assert not connected
        assert owner in pool._h2_connecting
        assert client._h2_reservation is None
    finally:
        pool.release_h2_reservation(owner)
        worker.join(1)
        pool.close_all()
    assert not worker.is_alive()


def test_h2_waiter_can_reserve_after_owner_releases(monkeypatch):
    pool = ConnectionPool()
    _, owner = pool.get_h2_or_reserve("example.com", 443, ("policy",))
    waiting = threading.Event()
    original_wait = pool._h2_condition.wait

    def observed_wait(timeout=None):
        waiting.set()
        return original_wait(timeout)

    monkeypatch.setattr(pool._h2_condition, "wait", observed_wait)
    results = []

    def acquire():
        results.append(pool.get_h2_or_reserve("example.com", 443, ("policy",)))

    worker = threading.Thread(target=acquire, daemon=True)
    worker.start()
    try:
        assert waiting.wait(1)
        pool.release_h2_reservation(owner)
        worker.join(1)
        assert not worker.is_alive()
        assert results == [(None, owner)]
    finally:
        pool.release_h2_reservation(owner)
        worker.join(1)
        pool.close_all()


@pytest.mark.parametrize("tls13_offer", [False, True])
@pytest.mark.parametrize("ticket", [False, True])
def test_tls12_resumption_times_out_before_server_finished(tls13_offer, ticket):
    cache = TLSSessionCache()
    policy = dict(
        tls_version=b"\x03\x03",
        extended_master_secret=True,
        verified=True,
        verified_hostname="example.com",
        sni="example.com",
    )
    if ticket:
        cache.put_tls12_ticket(
            "example.com", 443, b"ticket", b"m" * 48, 0xC02F, 300, **policy
        )
    else:
        cache.put("example.com", 443, b"id", b"m" * 48, 0xC02F, **policy)
    config = TlsConfig.secure()
    config.tls_version = 0x0304 if tls13_offer else 0x0303
    config.cipher_suites = [0x1301, 0xC02F] if tls13_offer else [0xC02F]
    if ticket:
        config.extensions.append(SessionTicketExtension())
    client, peer = socket.socketpair()
    tls = TLS(
        client,
        handshake_timeout=0.05,
        session_cache=cache,
        server_host="example.com",
        server_port=443,
    )
    tls.set_payload(config)
    done = threading.Event()
    results = []

    def handshake():
        try:
            results.append(tls.handshake())
        finally:
            done.set()

    worker = threading.Thread(target=handshake, daemon=True)
    worker.start()
    try:
        # An independent wire peer echoes the offered identity and EMS, then
        # deliberately withholds CCS/Finished without closing the connection.
        peer.settimeout(1)
        assert peer.recv(4096)
        identity = tls.body.session_id
        hello = (
            b"\x03\x03"
            + b"r" * 32
            + bytes([len(identity)])
            + identity
            + b"\xc0\x2f\x00\x00\x04\x00\x17\x00\x00"
        )
        message = b"\x02" + len(hello).to_bytes(3, "big") + hello
        peer.sendall(b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message)
        assert done.wait(1), "resumed handshake ignored its timeout"
        assert results == [False]
        assert tls._resumed_session is not None
        assert client.gettimeout() is None
        if ticket:
            assert cache.get_tls12_ticket("example.com", 443) is None
    finally:
        peer.close()
        worker.join(1)
        client.close()
    assert not worker.is_alive()
