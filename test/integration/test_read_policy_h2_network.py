"""Mixed Session read policies through one real authenticated H2 transport."""

import threading
import time
from urllib.parse import urlsplit

import pytest

from ja3requests import Session
from ja3requests._sync_timeout import UNLIMITED_READ
from ja3requests.pool import ConnectionPool
from ja3requests.protocol.h2.frame import CONNECTION_PREFACE, H2Frame
from ja3requests.protocol.h2.multiplex import H2MultiplexConnection
from ja3requests.sockets._upload import _H2WriteGuard
from test.integration.test_h2_streaming_network import (
    await_transport_close,
    h2_readers,
    receive_frame,
    start_h2,
    trusted_h2_peer,
)
from test.integration.test_sync_upload_network import h2_write_guards
from test.mock_servers.local import LocalServer, h2_frame


@pytest.mark.parametrize('version', [12, 13])
@pytest.mark.parametrize('first_policy', ['legacy', 'phase'])
def test_mixed_policies_do_not_inherit_the_first_transport_owner(
    trusted_certificates,
    monkeypatch,
    h2_readers,
    h2_write_guards,
    version,
    first_policy,
):
    config, context = trusted_h2_peer(trusted_certificates, monkeypatch, version)
    active_write = threading.local()
    writes, header_budgets, body_budgets, snapshots = [], [], [], []
    original_send = H2MultiplexConnection._send_checked
    original_write = _H2WriteGuard.sendall
    original_headers = H2MultiplexConnection.receive_headers
    original_body = H2MultiplexConnection.read_stream

    def send(connection, data, timeout=None):
        if data == CONNECTION_PREFACE:
            kind, stream = -1, 0
        else:
            frames, remaining = H2Frame.parse_all(data)
            assert not remaining and len(frames) == 1
            kind, stream = frames[0].type, frames[0].stream_id
        previous = getattr(active_write, 'value', None)
        active_write.value = (id(connection), kind, stream, timeout)
        try:
            return original_send(connection, data, timeout)
        finally:
            active_write.value = previous

    def write(guard, data, deadline):
        connection, kind, stream, budget = active_write.value
        writes.append(
            (
                connection,
                kind,
                stream,
                budget,
                deadline,
                None if deadline is None else deadline - time.monotonic(),
            )
        )
        return original_write(guard, data, deadline)

    def receive_headers(connection, stream, timeout=None):
        header_budgets.append((id(connection), stream, timeout))
        return original_headers(connection, stream, timeout)

    def read_stream(connection, stream, size, timeout=None):
        body_budgets.append((id(connection), stream, timeout))
        return original_body(connection, stream, size, timeout)

    monkeypatch.setattr(H2MultiplexConnection, '_send_checked', send)
    monkeypatch.setattr(_H2WriteGuard, 'sendall', write)
    monkeypatch.setattr(H2MultiplexConnection, 'receive_headers', receive_headers)
    monkeypatch.setattr(H2MultiplexConnection, 'read_stream', read_stream)

    received, ping_acks = [], []

    def serve(conn):
        start_h2(conn)
        for _ in range(5):
            current, body, complete = None, bytearray(), False
            while not complete:
                kind, flags, stream, payload = receive_frame(conn)
                if kind == 1:
                    assert current is None
                    current, complete = stream, bool(flags & 1)
                elif kind == 0:
                    assert stream == current
                    body.extend(payload)
                    complete = bool(flags & 1)
            received.append((current, bytes(body)))
            ping = current.to_bytes(8, 'big')
            conn.sendall(h2_frame(1, 4, current, b'\x88') + h2_frame(6, 0, 0, ping))
            while True:
                kind, flags, _, payload = receive_frame(conn)
                if kind == 6 and flags & 1:
                    assert payload == ping
                    ping_acks.append(current)
                    break
            conn.sendall(h2_frame(0, 1, current, b'ok'))
        await_transport_close(conn)

    def capture(request):
        snapshots.append(
            (
                urlsplit(request.url).path,
                request.read_timeout_policy,
                request.timeout[1],
            )
        )

    other_policy = 'phase' if first_policy == 'legacy' else 'legacy'
    with LocalServer(serve, context) as peer, ConnectionPool() as pool, Session(
        tls_config=config,
        pool=pool,
        hooks={'before_request': [capture]},
    ) as owner, Session(
        tls_config=config,
        pool=pool,
        hooks={'before_request': [capture]},
    ) as other:
        owner.read_timeout_policy = first_policy
        other.read_timeout_policy = other_policy
        url = 'https://127.0.0.1:%d' % peer.port
        assert owner.get(url + '/first', timeout=(2, None)).content == b'ok'
        assert other.get(url + '/other', timeout=(2, None)).content == b'ok'
        assert (
            owner.post(
                url + '/buffered',
                data=b'buffered',
                timeout=(2, None),
            ).content
            == b'ok'
        )
        assert (
            other.put(
                url + '/upload',
                data=iter([b'upload']),
                timeout=(2, None),
            ).content
            == b'ok'
        )
        assert other.get(url + '/finite', timeout=(2, 0.4)).content == b'ok'
        assert not owner._uploads and not other._uploads
        assert len(h2_readers) == len(h2_write_guards) == 1
        with pytest.raises(ConnectionError, match='write timed out'):
            other.get(url + '/zero', timeout=(2, 0))

    assert received == [(1, b''), (3, b''), (5, b'buffered'), (7, b'upload'), (9, b'')]
    assert ping_acks == [1, 3, 5, 7, 9]
    assert snapshots == [
        ('/first', first_policy, None),
        ('/other', other_policy, None),
        ('/buffered', first_policy, None),
        ('/upload', other_policy, None),
        ('/finite', other_policy, 0.4),
        ('/zero', other_policy, 0),
    ]
    first = UNLIMITED_READ if first_policy == 'phase' else None
    later = UNLIMITED_READ if other_policy == 'phase' else None
    expected = {1: first, 3: later, 5: first, 7: later, 9: 0.4, 11: 0}
    application = [record for record in writes if record[1] in (0, 1)]
    controls = [record for record in writes if record[1] not in (0, 1)]
    assert {record[2] for record in application} == set(expected)
    assert {record[2] for record in application if record[1] == 0} == {5, 7}
    assert len({record[0] for record in writes}) == 1
    for _, _, stream, budget, deadline, remaining in application:
        assert budget == expected[stream]
        if expected[stream] is UNLIMITED_READ:
            assert deadline is None
        elif expected[stream] is None:
            assert 14 < remaining <= 15
        elif stream == 11:
            assert deadline is not None and remaining <= 0
        else:
            assert 0 < remaining <= 0.4
    assert controls
    assert any(record[1] == 6 for record in controls)
    assert all(record[3] is None and 14 < record[5] <= 15 for record in controls)
    assert {stream for _, stream, _ in header_budgets} == {1, 3, 5, 7, 9}
    assert {stream for _, stream, _ in body_budgets} == {1, 3, 5, 7, 9}
    assert all(budget == expected[stream] for _, stream, budget in header_budgets)
    assert all(budget == expected[stream] for _, stream, budget in body_budgets)
