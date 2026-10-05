"""
Ja3Requests.retry
~~~~~~~~~~~~~~~~~

HTTP-level retry with configurable backoff strategy.
"""

from __future__ import annotations

import time
import random
from typing import TYPE_CHECKING, Collection, Optional

if TYPE_CHECKING:
    from ja3requests.response import Response


DEFAULT_STATUS_FORCELIST = frozenset({502, 503, 504})
DEFAULT_ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
DEFAULT_BACKOFF_FACTOR = 0.5
DEFAULT_MAX_RETRIES = 3


class HTTPRetry:
    """
    HTTP-level retry configuration with backoff.

    Retries requests on:
    - Configurable HTTP status codes (default: 502, 503, 504)
    - Connection errors (ConnectionError, ConnectionResetError)

    Supports exponential backoff with optional jitter.

    Usage:
        retry = HTTPRetry(total=3, backoff_factor=0.5)
        session = Session(retry=retry)
    """

    def __init__(
        self,
        total: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        status_forcelist: Optional[Collection[int]] = None,
        allowed_methods: Optional[Collection[str]] = None,
        raise_on_status: bool = True,
        respect_retry_after: bool = True,
    ) -> None:
        """
        :param total: Maximum number of retries after the initial attempt.
        :param backoff_factor: Factor for exponential backoff.
            Sleep time = backoff_factor * (2 ** (retry_number - 1))
            e.g., 0.5 → 0.5s, 1s, 2s, 4s...
        :param status_forcelist: Set of HTTP status codes to retry on.
        :param allowed_methods: Set of HTTP methods that are safe to retry.
        :param raise_on_status: Raise MaxRetriedException when the final response
            has a retryable status and method, including when total is zero.
            If False, return that response instead. The final response remains
            available as session.response after response hooks run.
        :param respect_retry_after: If True, honor Retry-After response header.
        """
        self.total = total
        self.backoff_factor = backoff_factor
        self.status_forcelist = status_forcelist or set(DEFAULT_STATUS_FORCELIST)
        self.allowed_methods = allowed_methods or set(DEFAULT_ALLOWED_METHODS)
        self.raise_on_status = raise_on_status
        self.respect_retry_after = respect_retry_after

    def is_retryable_method(self, method: str) -> bool:
        """Check if the HTTP method is safe to retry."""
        return method.upper() in self.allowed_methods

    def is_retryable_status(self, status_code: int) -> bool:
        """Check if the status code should trigger a retry."""
        return status_code in self.status_forcelist

    def get_backoff_time(self, retry_number: int) -> float:
        """Calculate backoff time with jitter for a given retry attempt."""
        if retry_number <= 0:
            return 0
        base: float = self.backoff_factor * (2 ** (retry_number - 1))
        # Add jitter: random between 0 and base
        return base + random.uniform(0, base * 0.1)

    def get_retry_after(self, response: Response) -> Optional[float]:
        """Parse Retry-After header value in seconds."""
        if not self.respect_retry_after:
            return None
        retry_after = response.headers.get("Retry-After") or response.headers.get(
            "retry-after"
        )
        if retry_after is None:
            return None
        try:
            return float(retry_after)
        except (ValueError, TypeError):
            return None

    def sleep_for_retry(self, response: Optional[Response], retry_number: int) -> None:
        """Sleep before retrying, respecting Retry-After if present."""
        retry_after = self.get_retry_after(response) if response else None
        if retry_after is not None:
            time.sleep(retry_after)
        else:
            backoff = self.get_backoff_time(retry_number)
            if backoff > 0:
                time.sleep(backoff)
