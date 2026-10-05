"""Small loop-local lifecycle and phase-budget helpers."""

from __future__ import annotations

import asyncio
import contextvars
import math
from typing import Any, Awaitable, Optional, Tuple, TypeVar

from ja3requests.exceptions import Timeout
from ja3requests._typing import Timeout as TimeoutInput

_T = TypeVar('_T')


def timeout_pair(value: TimeoutInput) -> Tuple[Optional[float], Optional[float]]:
    """Validate budgets before any connection or pool admission."""
    values = value if isinstance(value, tuple) else (value, value)
    if len(values) != 2:
        raise ValueError('timeout must be a number, None, or a (connect, read) pair')
    for budget in values:
        if budget is not None and (
            isinstance(budget, bool)
            or not isinstance(budget, (int, float))
            or not math.isfinite(budget)
            or budget < 0
        ):
            raise ValueError(
                'timeout values must be finite non-negative numbers or None'
            )
    return values


async def phase_wait(
    operation: Awaitable[_T], timeout: Optional[float], phase: str
) -> _T:
    """Only an owned phase timeout is translated; cancellation propagates."""
    try:
        if timeout is None:
            return await operation
        return await asyncio.wait_for(operation, timeout)
    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError as error:
        failure = Timeout('Async request timed out during ' + phase)
        failure.phase = phase
        raise failure from error


def owner_task(coroutine: Any) -> asyncio.Task:
    """Connection/cleanup tasks must not inherit request ContextVar state."""
    loop = asyncio.get_running_loop()
    return contextvars.Context().run(loop.create_task, coroutine)
