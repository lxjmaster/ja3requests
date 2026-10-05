"""Path-checked TLS/HTTP measurements, explicitly run with ``pytest bench``."""

import gc
import ssl
import threading
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack

import pytest

from ja3requests import Session, TlsConfig
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.tls import TLS
from ja3requests.protocol.tls.extensions import SessionTicketExtension
from test.mock_servers.local import tls12_context, tls13_context

from bench.peers import TLSLoopbackPeer


def tls_config(version, protocol="http/1.1", ticket=False):
    config = TlsConfig.secure()
    config.tls_version = 0x0303 if version == "TLSv1.2" else 0x0304
    config.cipher_suites = [0xC02F] if version == "TLSv1.2" else [0x1302]
    config.alpn_protocols = [protocol]
    if ticket:
        config.extensions.append(SessionTicketExtension())
    return config


def server_context(certificates, version, protocol="http/1.1", session_id=False):
    certificate = certificates.leaves["valid"]
    if version == "TLSv1.2":
        context = tls12_context(
            *certificate, alpn=protocol, cipher="ECDHE-RSA-AES128-GCM-SHA256"
        )
        if session_id:
            context.options |= getattr(ssl, "OP_NO_TICKET")
    else:
        context = tls13_context(*certificate, alpn=protocol)
        context.num_tickets = 2
    return context


def consume(session, peer, timeout):
    started = time.perf_counter()
    response = session.get(
        peer.url,
        stream=True,
        timeout=timeout,
        allow_redirects=False,
        headers={"Accept-Encoding": "identity"},
    )
    returned = time.perf_counter()
    total = 0
    first = None
    try:
        assert response.status_code == 200
        for chunk in response.iter_content(chunk_size=16384):
            if not chunk:
                continue
            if first is None:
                first = time.perf_counter()
            assert chunk.count(b"x") == len(chunk)
            total += len(chunk)
        assert total == peer.body_bytes and first is not None
    finally:
        response.close()
    completed = time.perf_counter()
    return {
        "request_started_at": started,
        "request_returned_at": returned,
        "first_chunk_at": first,
        "response_complete_at": completed,
        "request_return_seconds": returned - started,
        "first_chunk_seconds": first - started,
        "complete_seconds": completed - started,
        "received_bytes": total,
        "payload_verified": True,
    }


def assert_peer(peer, version, protocol, connections):
    peer.wait_for_records()
    assert len(peer.connections) == connections
    expected_cipher = (
        "ECDHE-RSA-AES128-GCM-SHA256"
        if version == "TLSv1.2"
        else "TLS_AES_256_GCM_SHA384"
    )
    for connection in peer.connections:
        assert connection["tls_version"] == version
        assert connection["alpn"] == protocol
        assert connection["cipher"] == expected_cipher


HANDSHAKE_CASES = [
    ("TLSv1.2", "full"),
    ("TLSv1.2", "session_id"),
    ("TLSv1.2", "ticket"),
    ("TLSv1.2", "pooled"),
    ("TLSv1.3", "full"),
    ("TLSv1.3", "ticket"),
    ("TLSv1.3", "pooled"),
]


@pytest.mark.parametrize("version,mode", HANDSHAKE_CASES)
def test_handshake_paths(
    trusted_certificates, monkeypatch, perf_options, record_measurement, version, mode
):
    options = perf_options
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    handshakes = []
    original = TLS.handshake

    def timed_handshake(tls, *args, **kwargs):
        started = time.perf_counter()
        result = original(tls, *args, **kwargs)
        handshakes.append(
            {
                "client_handshake_seconds": time.perf_counter() - started,
                "client_hello_records": len(tls.sent_client_hellos),
            }
        )
        return result

    monkeypatch.setattr(TLS, "handshake", timed_handshake)
    for sample in range(options["repeat"]):
        count = options["requests"]
        warmup = int(mode != "full")
        context = server_context(
            trusted_certificates, version, session_id=mode == "session_id"
        )
        with TLSLoopbackPeer(
            context,
            "http/1.1",
            1024,
            count + warmup,
            options["timeout"],
            close_after_response=mode != "pooled",
        ) as peer, ExitStack() as stack:
            if mode != "full":
                session = stack.enter_context(
                    Session(
                        tls_config=tls_config(version, ticket=mode == "ticket"),
                        pool=ConnectionPool() if mode == "pooled" else None,
                        use_pooling=mode == "pooled",
                    )
                )
                consume(session, peer, options["timeout"])
            first_handshake = len(handshakes)
            started = time.perf_counter()
            samples = []
            for _ in range(count):
                if mode == "full":
                    with Session(
                        tls_config=tls_config(version), use_pooling=False
                    ) as fresh:
                        samples.append(consume(fresh, peer, options["timeout"]))
                else:
                    samples.append(consume(session, peer, options["timeout"]))
            elapsed = time.perf_counter() - started
            expected_connections = 1 if mode == "pooled" else count + warmup
            assert_peer(peer, version, "http/1.1", expected_connections)
            observed = sorted(peer.connections, key=lambda row: row["connection_id"])
            expected_reuse = (
                [False] + [True] * count
                if mode in ("ticket", "session_id")
                else [False] * expected_connections
            )
            assert [row["session_reused"] for row in observed] == expected_reuse
            measured = handshakes[first_handshake:]
            assert len(measured) == (0 if mode == "pooled" else count)
            record_measurement(
                {
                    "kind": "handshake_path",
                    "version": version,
                    "mode": mode,
                    "sample": sample + 1,
                    "warmup_requests_excluded": warmup,
                    "requests": count,
                    "elapsed_seconds": elapsed,
                    "requests_per_second": count / elapsed,
                    "client_handshakes": measured,
                    "request_samples": samples,
                    "server_connections": observed,
                    "server_responses": peer.records,
                    "path_verified": True,
                }
            )


TRANSPORT_CASES = [
    (library, version, protocol, concurrent)
    for library in ("ja3requests", "requests")
    for version in ("TLSv1.2", "TLSv1.3")
    for protocol in ("http/1.1", "h2")
    for concurrent in (False, True)
    if library == "ja3requests" or protocol == "http/1.1"
]


def client_session(stack, library, certificates, version, protocol):
    if library == "ja3requests":
        return stack.enter_context(
            Session(tls_config=tls_config(version, protocol), pool=ConnectionPool())
        )
    requests = pytest.importorskip(
        "requests", reason="optional shared HTTP/1.1 comparison"
    )
    session = stack.enter_context(requests.Session())
    session.trust_env = False
    session.verify = str(certificates.ca_path)
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=1, pool_maxsize=1, pool_block=True
    )
    session.mount("https://", adapter)
    return session


@pytest.mark.parametrize("library,version,protocol,concurrent", TRANSPORT_CASES)
def test_transport(
    trusted_certificates,
    monkeypatch,
    perf_options,
    record_measurement,
    library,
    version,
    protocol,
    concurrent,
):
    options = perf_options
    monkeypatch.setenv("SSL_CERT_FILE", str(trusted_certificates.ca_path))
    workers = options["concurrency"] if concurrent else 1
    sessions_count = workers if protocol == "http/1.1" else 1
    # Separate allocation measurement avoids charging tracemalloc to throughput.
    for sample in range(options["repeat"] + 1):
        memory = sample == options["repeat"]
        context = server_context(trusted_certificates, version, protocol)
        with TLSLoopbackPeer(
            context,
            protocol,
            options["body_bytes"],
            options["requests"] + sessions_count,
            options["timeout"],
            cohort=workers,
        ) as peer, ExitStack() as stack:
            sessions = [
                client_session(stack, library, trusted_certificates, version, protocol)
                for _ in range(sessions_count)
            ]
            for session in sessions:
                consume(session, peer, options["timeout"])
            barrier = threading.Barrier(workers)

            def run_worker(index):
                session = sessions[index] if protocol == "http/1.1" else sessions[0]
                barrier.wait(options["timeout"])
                return [
                    consume(session, peer, options["timeout"])
                    for _ in range(options["requests"] // workers)
                ]

            gc.collect()
            if memory:
                tracemalloc.start()
            started = time.perf_counter()
            try:
                if workers == 1:
                    rows = run_worker(0)
                else:
                    with ThreadPoolExecutor(max_workers=workers) as executor:
                        groups = list(executor.map(run_worker, range(workers)))
                    rows = [row for group in groups for row in group]
                elapsed = time.perf_counter() - started
                peak = tracemalloc.get_traced_memory()[1] if memory else None
            finally:
                if memory:
                    tracemalloc.stop()
            assert_peer(peer, version, protocol, sessions_count)
            if protocol == "h2" and concurrent:
                assert (
                    max(row["max_pending_h2_streams"] for row in peer.connections)
                    >= workers
                )
            assert all(not row["session_reused"] for row in peer.connections)
            record_measurement(
                {
                    "kind": "transport_memory" if memory else "transport_timing",
                    "library": library,
                    "version": version,
                    "protocol": protocol,
                    "workers": workers,
                    "sample": sample + 1,
                    "warmup_requests_excluded": sessions_count,
                    "body_bytes": options["body_bytes"],
                    "requests": options["requests"],
                    "elapsed_seconds": elapsed,
                    "requests_per_second": (
                        None if memory else options["requests"] / elapsed
                    ),
                    "python_peak_bytes": peak,
                    "request_samples": rows,
                    "server_connections": peer.connections,
                    "server_responses": peer.records,
                    "path_verified": True,
                    "payload_verified": all(row["payload_verified"] for row in rows),
                }
            )
