"""Request-owned synchronous read budgets, separate from connect limits."""

from __future__ import annotations

import math
import time
from typing import TYPE_CHECKING, Optional, Union, cast

from ja3requests._typing import Timeout

if TYPE_CHECKING:
    from ja3requests._typing import ReadTimeoutPolicy


class _UnlimitedRead:
    """Distinguish an unlimited application budget from legacy None."""


UNLIMITED_READ = _UnlimitedRead()
SyncReadTimeout = Optional[Union[float, _UnlimitedRead]]


def normalize_read_policy(value: object) -> ReadTimeoutPolicy:
    """Validate before replacing a Session or prepared-request setting."""
    if not isinstance(value, str) or value not in ('legacy', 'phase'):
        raise ValueError("read_timeout_policy must be 'legacy' or 'phase'")
    return cast('ReadTimeoutPolicy', value)


def validate_read_timeout(timeout: Timeout, policy: ReadTimeoutPolicy) -> None:
    """Phase validates the read component before source or network work."""
    normalize_read_policy(policy)
    if policy == 'legacy':
        return
    if isinstance(timeout, tuple):
        if len(timeout) != 2:
            raise ValueError(
                'timeout must be a number, None, or a (connect, read) pair'
            )
        budget = timeout[1]
    else:
        budget = timeout
    if budget is None:
        return
    if isinstance(budget, bool) or not isinstance(budget, (int, float)):
        raise ValueError('read timeout must be a finite non-negative number or None')
    try:
        valid = math.isfinite(budget) and budget >= 0
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError('read timeout must be a finite non-negative number or None')


def application_read_timeout(
    timeout: Optional[float], policy: ReadTimeoutPolicy
) -> SyncReadTimeout:
    """Resolve only the opt-in unlimited value; leave legacy None intact."""
    return UNLIMITED_READ if timeout is None and policy == 'phase' else timeout


def read_deadline(timeout: SyncReadTimeout) -> Optional[float]:
    """Control/default None retains the historical fifteen-second limit."""
    if isinstance(timeout, _UnlimitedRead):
        return None
    return time.monotonic() + (15.0 if timeout is None else timeout)


def read_remaining(deadline: Optional[float]) -> SyncReadTimeout:
    """Carry an absent deadline through incremental collector operations."""
    return UNLIMITED_READ if deadline is None else max(0, deadline - time.monotonic())


def source_timeout(timeout: SyncReadTimeout) -> Optional[float]:
    """Source None has always been unlimited, including under legacy."""
    return None if isinstance(timeout, _UnlimitedRead) else timeout
