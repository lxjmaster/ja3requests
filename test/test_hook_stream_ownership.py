"""Response hooks must transfer or release each live streaming body once."""

import io

import pytest

from ja3requests import HTTPRetry, Session
from ja3requests.exceptions import MaxRetriedException, StreamConsumedError
from ja3requests.requests.http import HttpRequest
from ja3requests.response import HTTPResponse, Response


class MemorySocket:
    def __init__(self, wire):
        self.wire = wire

    def makefile(self, _mode):
        return io.BytesIO(self.wire)


@pytest.fixture
def raw_responses():
    """Observe ownership independently of sockets, with unconditional cleanup."""
    created = []
    released = []

    def make(status, name):
        body = name.encode('ascii')
        raw = HTTPResponse(
            MemorySocket(
                (
                    'HTTP/1.1 %d Test\r\nContent-Length: %d\r\n\r\n'
                    % (status, len(body))
                ).encode('ascii')
                + body
            ),
            release=lambda reusable: released.append((name, reusable)),
        )
        created.append(raw)
        raw.handle()
        return raw

    yield make, released
    for raw in created:
        raw._close_conn()


def request_for(raw, sent):
    request = HttpRequest()
    request.method = 'GET'

    def send(**_kwargs):
        sent.append(True)
        return raw

    request.send = send
    return request


@pytest.mark.parametrize(
    'status,raise_on_status', [(200, True), (503, False), (503, True)]
)
def test_independent_hook_replacements_release_superseded_streams(
    raw_responses, status, raise_on_status
):
    make, released = raw_responses
    original_raw = make(status, 'original')
    middle = Response(response=make(status, 'middle'), stream=True)
    final = Response(response=make(status, 'final'), stream=True)
    observed, sent = [], []

    def first(response):
        observed.append(response)
        return middle

    def second(response):
        observed.append(response)
        return final

    retry = HTTPRetry(
        total=1 if status == 200 else 0,
        backoff_factor=0,
        raise_on_status=raise_on_status,
    )
    with Session(
        use_pooling=False, retry=retry, hooks={'after_request': [first]}
    ) as session:
        request = request_for(original_raw, sent)
        options = {'stream': True, 'hooks': {'after_request': [second]}}
        if status == 503 and raise_on_status:
            with pytest.raises(MaxRetriedException, match='last status: 503'):
                session.send(request, **options)
            result = session.response
            expected = [('original', False), ('middle', False), ('final', False)]
        else:
            result = session.send(request, **options)
            assert released == [('original', False), ('middle', False)]
            assert b''.join(result.iter_content(2)) == b'final'
            expected = [('original', False), ('middle', False), ('final', True)]
        assert result is final
        assert observed[1] is middle
        assert released == expected
        for response in observed + [result]:
            response.close()
        assert released == expected
        assert len(sent) == 1


@pytest.mark.parametrize('status', [200, 503])
@pytest.mark.parametrize('error_type', [RuntimeError, OSError])
def test_failure_after_hook_replacement_closes_both_bodies_without_retry(
    raw_responses, status, error_type
):
    make, released = raw_responses
    original_raw = make(status, 'original')
    replacement = Response(response=make(status, 'replacement'), stream=True)
    observed, sent = [], []

    def replace(response):
        observed.append(response)
        return replacement

    def fail(response):
        assert response is replacement
        raise error_type('later hook failed')

    retry = HTTPRetry(total=2 if status == 200 else 0, backoff_factor=0)
    with Session(
        use_pooling=False, retry=retry, hooks={'after_request': [replace]}
    ) as session:
        with pytest.raises(error_type, match='later hook failed'):
            session.send(
                request_for(original_raw, sent),
                stream=True,
                hooks={'after_request': [fail]},
            )
    assert released == [('original', False), ('replacement', False)]
    assert len(sent) == 1
    for response in observed + [replacement]:
        response.close()
    assert released == [('original', False), ('replacement', False)]


@pytest.mark.parametrize('status', [200, 503])
def test_invalid_hook_replacement_closes_current_and_superseded_bodies(
    raw_responses, status
):
    make, released = raw_responses
    raw = make(status, 'original')
    replacement = Response(response=make(status, 'replacement'), stream=True)
    sent, subsequent = [], []

    retry = HTTPRetry(total=2 if status == 200 else 0, backoff_factor=0)
    with Session(
        use_pooling=False,
        retry=retry,
        hooks={'after_request': [lambda _response: replacement]},
    ) as session:
        with pytest.raises(TypeError):
            session.send(
                request_for(raw, sent),
                stream=True,
                hooks={
                    'after_request': [
                        lambda _response: 'not a response',
                        subsequent.append,
                    ]
                },
            )
    assert released == [('original', False), ('replacement', False)]
    assert len(sent) == 1
    assert subsequent == []
    replacement.close()
    assert released == [('original', False), ('replacement', False)]


@pytest.mark.parametrize('status', [200, 503])
def test_same_body_wrapper_transfer_survives_old_wrapper_close(raw_responses, status):
    make, released = raw_responses
    raw = make(status, 'shared-body')
    originals, sent = [], []

    def rewrap(response):
        originals.append(response)
        return Response(
            request=response.request, response=response.response, stream=True
        )

    retry = HTTPRetry(total=0, backoff_factor=0, raise_on_status=False)
    with Session(
        use_pooling=False, retry=retry, hooks={'after_request': [rewrap]}
    ) as session:
        result = session.send(request_for(raw, sent), stream=True)
        original = originals[0]
        assert result is not original
        assert released == []
        original.close()
        original.close()
        assert released == []
        with pytest.raises(StreamConsumedError):
            _ = original.content
        assert b''.join(result.iter_content(2)) == b'shared-body'
        assert released == [('shared-body', True)]
        result.close()
        original.close()
        assert released == [('shared-body', True)]
        assert len(sent) == 1
