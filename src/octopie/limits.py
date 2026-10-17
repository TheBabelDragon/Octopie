"""Configurable resource budgets, connection caps, concurrency, and rate limits."""

from __future__ import annotations

import time
from collections import deque
from typing import Deque, Optional


class RateLimiter:
    """Token-bucket style expansion rate limiter."""

    def __init__(self, max_per_second: float, max_concurrent: int):
        self._max_per_second = max_per_second
        self._max_concurrent = max_concurrent
        self._timestamps: Deque[float] = deque()
        self._in_flight = 0

    def allow_admission(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        self._prune(now)
        if self._in_flight >= self._max_concurrent:
            return False
        if len(self._timestamps) >= self._max_per_second:
            # simple sliding window of 1 second
            return False
        return True

    def record_admission(self, now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        self._timestamps.append(now)
        # Admission is instantaneous for simulation; in-flight is used only
        # while a request is being processed. Release immediately after record
        # so concurrent slots free up for the next request in the same tick.
        # Real deployments would hold the slot until the handshake completes.
        self._in_flight += 1
        self.release()

    def release(self) -> None:
        if self._in_flight > 0:
            self._in_flight -= 1

    def _prune(self, now: float) -> None:
        cutoff = now - 1.0
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
