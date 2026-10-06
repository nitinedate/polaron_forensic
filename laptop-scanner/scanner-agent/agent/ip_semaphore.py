"""Resizable non-blocking semaphore for one-IP OpenVAS tasks."""
from __future__ import annotations

import threading


class AdaptiveIPSemaphore:
    """Admission semaphore whose live limit can change without killing holders.

    ``try_acquire(limit)`` refuses new work whenever active holders are already
    at/above the latest adaptive limit.  Shrinking 10 -> 5 therefore lets the
    existing 10 finish and starts nothing new until active drops below five.
    """

    def __init__(self, max_permits: int = 10) -> None:
        self.max_permits = max(1, int(max_permits))
        self._active = 0
        self._lock = threading.Lock()

    @property
    def active(self) -> int:
        with self._lock:
            return self._active

    def try_acquire(self, limit: int) -> bool:
        live_limit = max(0, min(self.max_permits, int(limit)))
        with self._lock:
            if self._active >= live_limit:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            if self._active > 0:
                self._active -= 1

    def restore(self, count: int) -> None:
        """Account for already-running tasks discovered during resume."""
        with self._lock:
            self._active += max(0, int(count))
