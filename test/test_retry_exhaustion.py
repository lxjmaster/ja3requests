"""Public Session retry outcomes against an independent, bounded HTTP peer."""

from contextlib import contextmanager

import pytest

from ja3requests import HTTPRetry, Session
from ja3requests.exceptions import MaxRetriedException
from test.mock_servers.local import LocalServer, read_headers


@contextmanager
def status_peer(statuses):
    """Return a fresh HTTP connection for each attempt, with an observable body."""
    observed = []

    def handle(conn):
        headers = read_headers(conn)
        status = statuses[len(observed)]
        observed.append(headers.split(b"\r\n", 1)[0])
        body = ("attempt-%d" % len(observed)).encode("ascii")
        response_headers = (
            "HTTP/1.1 %d Test\r\n"
            "Content-Length: %d\r\n"
            "Set-Cookie: attempt=%d; Path=/\r\n"
            "Connection: close\r\n" % (status, len(body), len(observed))
        )
        if status == 302:
            response_headers += "Location: /ok\r\n"
        conn.sendall((response_headers + "\r\n").encode("ascii") + body)

    with LocalServer(handle, connections=len(statuses)) as server:
        yield "http://127.0.0.1:%d/retry" % server.port, observed


@pytest.mark.parametrize("total", [0, 1, 2])
@pytest.mark.parametrize("raise_on_status", [True, False])
def test_status_exhaustion_obeys_policy_and_preserves_final_response(
    total, raise_on_status
):
    before = []
    after = []
    per_request = []
    retry = HTTPRetry(total=total, backoff_factor=0, raise_on_status=raise_on_status)
    with status_peer([503] * (total + 1)) as (url, observed):
        with Session(
            use_pooling=False,
            retry=retry,
            hooks={"before_request": [before.append], "after_request": [after.append]},
        ) as session:
            kwargs = {"timeout": 2, "hooks": {"after_request": [per_request.append]}}
            if raise_on_status:
                with pytest.raises(
                    MaxRetriedException,
                    match=r"Max retries \(%d\) exceeded, last status: 503" % total,
                ):
                    session.get(url, **kwargs)
                response = session.response
            else:
                response = session.get(url, **kwargs)

            try:
                assert len(observed) == total + 1
                assert len(before) == 1
                assert after == per_request == [response]
                assert session.response is response
                assert response.status_code == 503
                assert response.content == ("attempt-%d" % (total + 1)).encode("ascii")
                assert session.cookies.get("attempt") == str(total + 1)
            finally:
                response.close()


@pytest.mark.parametrize("statuses", [(503, 200), (503, 503, 200), (503, 500)])
def test_retry_returns_recovered_or_non_retryable_final_response(statuses):
    after = []
    with status_peer(statuses) as (url, observed):
        with Session(
            use_pooling=False,
            retry=HTTPRetry(total=2, backoff_factor=0),
            hooks={"after_request": [after.append]},
        ) as session:
            response = session.get(url, timeout=2)
            try:
                assert len(observed) == len(statuses)
                assert response.status_code == statuses[-1]
                assert response.content == ("attempt-%d" % len(statuses)).encode(
                    "ascii"
                )
                assert after == [response]
                assert session.response is response
            finally:
                response.close()


@pytest.mark.parametrize("raise_on_status", [True, False])
def test_non_retryable_method_returns_response_without_retrying(raise_on_status):
    with status_peer([503]) as (url, observed):
        with Session(
            use_pooling=False,
            retry=HTTPRetry(total=2, backoff_factor=0, raise_on_status=raise_on_status),
        ) as session:
            response = session.post(url, timeout=2)
            try:
                assert response.status_code == 503
                assert observed == [b"POST /retry HTTP/1.1"]
            finally:
                response.close()


def test_explicit_retryable_method_uses_exhaustion_policy():
    with status_peer([503, 503]) as (url, observed):
        with Session(
            use_pooling=False,
            retry=HTTPRetry(total=1, backoff_factor=0, allowed_methods={"POST"}),
        ) as session:
            with pytest.raises(MaxRetriedException):
                session.post(url, timeout=2)
            session.response.close()
            assert observed == [b"POST /retry HTTP/1.1"] * 2


def test_status_without_retry_configuration_returns_normally():
    with status_peer([503]) as (url, observed):
        with Session(use_pooling=False) as session:
            response = session.get(url, timeout=2)
            try:
                assert response.status_code == 503
                assert len(observed) == 1
            finally:
                response.close()


@pytest.mark.parametrize("total", [0, 1])
@pytest.mark.parametrize("raise_on_status", [True, False])
def test_successful_redirect_after_retryable_status_returns_success(
    total, raise_on_status
):
    with status_peer([302] * (total + 1) + [200]) as (url, observed):
        with Session(
            use_pooling=False,
            retry=HTTPRetry(
                total=total,
                backoff_factor=0,
                status_forcelist={302},
                raise_on_status=raise_on_status,
            ),
        ) as session:
            response = session.get(url, timeout=2)
            try:
                assert response.status_code == 200
                assert session.response is response
                assert observed == [b"GET /retry HTTP/1.1"] * (total + 1) + [
                    b"GET /ok HTTP/1.1"
                ]
            finally:
                response.close()


@pytest.mark.parametrize("raise_on_status", [True, False])
def test_retryable_redirect_with_redirects_disabled_obeys_status_policy(
    raise_on_status,
):
    with status_peer([302]) as (url, observed):
        with Session(
            use_pooling=False,
            retry=HTTPRetry(
                total=0, status_forcelist={302}, raise_on_status=raise_on_status
            ),
        ) as session:
            if raise_on_status:
                with pytest.raises(MaxRetriedException, match="last status: 302"):
                    session.get(url, timeout=2, allow_redirects=False)
                response = session.response
            else:
                response = session.get(url, timeout=2, allow_redirects=False)
            try:
                assert response.status_code == 302
                assert observed == [b"GET /retry HTTP/1.1"]
            finally:
                response.close()
