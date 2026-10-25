"""Direct lifecycle boundaries for the strictly typed async helpers."""

import asyncio
import contextvars
from types import SimpleNamespace

import pytest

from ja3requests import RequestException, Timeout
from ja3requests._async_utils import owner_task, phase_wait


def test_owner_task_has_detached_context_and_preserves_result():
    marker = contextvars.ContextVar('async-helper-test', default='detached')

    async def scenario():
        token = marker.set('caller')

        async def operation():
            assert marker.get() == 'detached'
            marker.set('owned')
            return 42

        try:
            assert await owner_task(operation()) == 42
            assert marker.get() == 'caller'
        finally:
            marker.reset(token)

    asyncio.run(scenario())


@pytest.mark.parametrize('budget', [None, 1])
def test_phase_wait_preserves_result(budget):
    async def scenario():
        value = object()

        async def operation():
            return value

        assert await phase_wait(operation(), budget, 'read') is value

    asyncio.run(scenario())


def test_phase_expiry_records_phase_cause_and_finishes_cancellation():
    async def scenario():
        started = asyncio.Event()
        stopped = asyncio.Event()

        async def operation():
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        task = asyncio.create_task(operation())
        await started.wait()
        with pytest.raises(Timeout) as caught:
            await phase_wait(task, 0, 'HTTP/2 write')
        assert caught.value.phase == 'HTTP/2 write'
        assert isinstance(caught.value.__cause__, asyncio.TimeoutError)
        assert task.cancelled() and stopped.is_set()

    asyncio.run(scenario())


@pytest.mark.parametrize('budget', [None, 1])
def test_phase_wait_preserves_external_cancellation(budget):
    async def scenario():
        started = asyncio.Event()
        stopped = asyncio.Event()

        async def operation():
            started.set()
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        task = asyncio.create_task(phase_wait(operation(), budget, 'read'))
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert task.cancelled() and stopped.is_set()

    asyncio.run(scenario())


def test_exception_metadata_keeps_existing_dynamic_objects():
    request = object()
    response = SimpleNamespace(request=request)
    failure = RequestException('failed', response=response)
    assert failure.args == ('failed',)
    assert failure.response is response and failure.request is request
    explicit = object()
    failure = RequestException('failed', response=response, request=explicit)
    assert failure.request is explicit
    assert not hasattr(Timeout('manual'), 'phase')
