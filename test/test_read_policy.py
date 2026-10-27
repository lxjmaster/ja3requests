"""Public policy validation, preparation, retries and redirect snapshots."""

from unittest.mock import patch

import pytest

from ja3requests import HTTPRetry, Session
from ja3requests.base import BaseSocket
from ja3requests.pool import ConnectionPool
from ja3requests.requests.http import HttpRequest
from ja3requests.requests.request import Request
from test.integration.test_sync_redirect_replay import BorrowedFile
from test.mock_servers.local import LocalServer, read_headers


@pytest.mark.parametrize('invalid', [None, True, 1, '', 'PHASE', [], {}, 'unknown'])
def test_policy_assignment_rejects_atomically(invalid):
    with Session(use_pooling=False) as session:
        assert session.read_timeout_policy == 'legacy'
        session.read_timeout_policy = 'phase'
        with pytest.raises(ValueError, match='read_timeout_policy'):
            session.read_timeout_policy = invalid
        assert session.read_timeout_policy == 'phase'
    prepared = Request('GET', 'http://example.test/').request()
    with pytest.raises(ValueError, match='read_timeout_policy'):
        prepared.read_timeout_policy = invalid
    assert prepared.read_timeout_policy == 'legacy'


@pytest.mark.parametrize('scheme', ['http', 'https'])
@pytest.mark.parametrize('entry', ['prepare', 'hook', 'session-send', 'transport-send'])
@pytest.mark.parametrize(
    'budget',
    [
        True,
        -1,
        float('nan'),
        float('inf'),
        -float('inf'),
        '1',
        [],
        (),
        (1,),
        (1, 2, 3),
        (1, True),
        (1, -1),
        (1, float('nan')),
    ],
)
def test_invalid_phase_budget_precedes_source_and_network(
    monkeypatch, scheme, entry, budget
):
    source = BorrowedFile(b'private')

    def connect(*args):
        raise AssertionError('Invalid budget reached connection work')

    monkeypatch.setattr(BaseSocket, '_new_conn', connect)
    with Session(use_pooling=False, retry=HTTPRetry(total=2)) as session:
        session.read_timeout_policy = 'phase'
        with pytest.raises(ValueError, match='timeout'):
            if entry == 'prepare':
                # Multipart preparation would read this borrowed file.
                session.post(
                    scheme + '://localhost:1/', files={'file': source}, timeout=budget
                )
            elif entry == 'hook':
                session.post(
                    scheme + '://localhost:1/',
                    data=source,
                    hooks={
                        'before_request': [
                            lambda request: setattr(request, 'timeout', budget)
                        ]
                    },
                )
            else:
                request = Request(
                    'POST',
                    scheme + '://localhost:1/',
                    data=source,
                    read_timeout_policy='phase',
                ).request()
                request.timeout = budget
                if entry == 'session-send':
                    session.send(request)
                else:
                    request.send()
    assert source.reads == 0 and source.tell() == 0 and not source.closed


def test_phase_validates_hook_replacement_before_preparing_its_source(monkeypatch):
    source = BorrowedFile(b'private')
    replacement = Request(
        'PUT', 'http://localhost:1/', data=source, read_timeout_policy='phase'
    ).request()
    replacement.timeout = (1, -1)
    with Session(use_pooling=False) as session:
        with pytest.raises(ValueError, match='read timeout'):
            session.get(
                'http://localhost:1/',
                hooks={'before_request': [lambda request: replacement]},
            )
    assert source.reads == 0 and not source.closed


@pytest.mark.parametrize('policy', ['legacy', 'phase'])
def test_session_preparation_captures_policy(policy):
    with Session(use_pooling=False) as session:
        session.read_timeout_policy = policy
        with patch.object(session, 'send', side_effect=lambda ready, **_: ready):
            prepared = session.get('http://example.test/', timeout=(2, None))
        session.read_timeout_policy = 'legacy' if policy == 'phase' else 'phase'
        assert prepared.read_timeout_policy == policy
        assert prepared.timeout == (2, None)


@pytest.mark.parametrize('policy', ['legacy', 'phase'])
@pytest.mark.parametrize('prepared_send', [False, True])
def test_retry_and_redirect_keep_policy_after_session_change(
    monkeypatch, policy, prepared_send
):
    sent = []
    statuses = iter([503, 302, 200])
    original = HttpRequest.send

    def send(request, **kwargs):
        sent.append(request.read_timeout_policy)
        return original(request, **kwargs)

    def serve(conn):
        for _ in range(3):
            read_headers(conn)
            status = next(statuses)
            location = b'Location: /final\r\n' if status == 302 else b''
            conn.sendall(
                ('HTTP/1.1 %d Result\r\n' % status).encode()
                + location
                + b'Content-Length: 2\r\n\r\nok'
            )

    monkeypatch.setattr(HttpRequest, 'send', send)
    pool = ConnectionPool()
    with LocalServer(serve) as peer, Session(
        pool=pool, retry=HTTPRetry(total=1, backoff_factor=0)
    ) as session:
        session.read_timeout_policy = policy
        session.hooks['before_request'].append(
            lambda request: setattr(
                session,
                'read_timeout_policy',
                'legacy' if policy == 'phase' else 'phase',
            )
        )
        url = 'http://127.0.0.1:%d/' % peer.port
        if prepared_send:
            prepared = Request(
                'GET', url, timeout=(2, None), read_timeout_policy=policy
            ).request()
            session.read_timeout_policy = 'legacy' if policy == 'phase' else 'phase'
            response = session.send(prepared)
        else:
            response = session.get(url, timeout=(2, None))
        assert response.content == b'ok'
        assert response.request.url.endswith('/final')
    pool.close_all()
    assert sent == [policy, policy, policy]


@pytest.mark.parametrize('budget', [None, 0, 1.5, (2, None), (2, 0), (None, 1.5)])
def test_valid_phase_preparation_and_legacy_low_level_default(budget):
    assert (
        Request(
            'GET', 'http://example.test/', timeout=budget, read_timeout_policy='phase'
        )
        .request()
        .timeout
        == budget
    )
    assert (
        Request('GET', 'http://example.test/').request().read_timeout_policy == 'legacy'
    )
