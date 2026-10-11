"""Small resilience helpers: retry with backoff, and loop detection."""

from __future__ import annotations

import logging
import time

log = logging.getLogger("ctf.resilience")


def retry(fn, *, attempts=4, base_delay=1.0, max_delay=20.0, exc=(Exception,)):
    """Call fn() with exponential backoff on transient errors. Re-raises last."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except exc as e:
            last = e
            if i == attempts - 1:
                break
            delay = min(max_delay, base_delay * (2 ** i))
            log.warning("attempt %d/%d failed (%s); retrying in %.1fs",
                        i + 1, attempts, e, delay)
            time.sleep(delay)
    raise last


class LoopGuard:
    """Detect the model repeating the same failing tool call over and over."""

    def __init__(self, limit: int = 3):
        self.limit = limit
        self._counts: dict[str, int] = {}

    def record(self, name: str, arguments: dict, ok: bool) -> bool:
        """Return True if this (name,args) has failed `limit` times — i.e. stuck."""
        key = f"{name}:{sorted((arguments or {}).items())}"
        if ok:
            self._counts.pop(key, None)
            return False
        self._counts[key] = self._counts.get(key, 0) + 1
        return self._counts[key] >= self.limit
