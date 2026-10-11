"""
Subsystem lifecycle — the contract offense and defense both implement.

A Subsystem is a self-contained loop with setup / tick / teardown. The
orchestrator runs each one on its own thread, calling tick() every `interval`
seconds. Subsystems never call each other directly; they coordinate only through
the shared EventBus, which is why either can run alone.

A tick should be short and non-blocking-ish — do a unit of work and return. Long
work (a model-driven solve) should be chunked across ticks or run in the
runner's thread pool, so one subsystem can't starve another.
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod

log = logging.getLogger("ctf.subsystem")


class Subsystem(ABC):
    name: str = "subsystem"

    def __init__(self, ctx, interval: float = 5.0):
        self.ctx = ctx                 # shared AgentContext (core services)
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ticks = 0
        self._errors = 0

    # --- override these -----------------------------------------------------

    def setup(self) -> None:
        """One-time init before the loop starts."""

    @abstractmethod
    def tick(self) -> None:
        """One unit of work. Called repeatedly."""

    def teardown(self) -> None:
        """Cleanup after the loop stops."""

    # --- lifecycle (don't override) ----------------------------------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.setup()
        self._thread = threading.Thread(target=self._loop, name=self.name, daemon=True)
        self._thread.start()
        log.info("%s started (interval %ss)", self.name, self.interval)

    def _loop(self) -> None:
        while not self._stop.is_set():
            start = time.time()
            try:
                self.tick()
                self._ticks += 1
            except Exception:
                self._errors += 1
                log.exception("%s tick failed (%d errors total)", self.name, self._errors)
            # sleep the remainder of the interval, but stay responsive to stop
            elapsed = time.time() - start
            self._stop.wait(max(0.0, self.interval - elapsed))

    def stop(self, join_timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=join_timeout)
        self.teardown()
        log.info("%s stopped (%d ticks, %d errors)", self.name, self._ticks, self._errors)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def status(self) -> dict:
        return {"name": self.name, "running": self.running,
                "ticks": self._ticks, "errors": self._errors}
