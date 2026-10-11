"""
Orchestrator — runs the subsystems you ask for, independently and concurrently.

    orch = Orchestrator(ctx)
    orch.add(DefenseSubsystem(ctx))
    orch.add(OffenseSubsystem(ctx))
    orch.start(["defense"])          # defense only
    orch.start(["offense"])          # offense only
    orch.start()                     # both, together

Each subsystem runs on its own thread with its own tick cadence. They share only
the EventBus, so any combination is valid: run one, run the other, run both.
Stopping is clean and idempotent.
"""

from __future__ import annotations

import logging
import signal

from core.subsystem import Subsystem

log = logging.getLogger("ctf.orchestrator")


class Orchestrator:
    def __init__(self, ctx):
        self.ctx = ctx
        self._subs: dict[str, Subsystem] = {}

    def add(self, sub: Subsystem) -> None:
        self._subs[sub.name] = sub

    def start(self, names: list[str] | None = None) -> None:
        targets = names or list(self._subs.keys())
        for n in targets:
            sub = self._subs.get(n)
            if sub is None:
                log.warning("no subsystem named %r; have %s", n, list(self._subs))
                continue
            sub.start()

    def stop(self, names: list[str] | None = None) -> None:
        targets = names or list(self._subs.keys())
        for n in targets:
            sub = self._subs.get(n)
            if sub:
                sub.stop()

    def status(self) -> list[dict]:
        return [s.status() for s in self._subs.values()]

    def run_forever(self, names: list[str] | None = None) -> None:
        """Start selected subsystems and block until SIGINT/SIGTERM."""
        import threading
        self.start(names)
        done = threading.Event()

        def _handle(signum, _frame):
            log.info("signal %s -> shutting down", signum)
            done.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handle)
            except ValueError:
                pass  # not in main thread (e.g. tests)
        try:
            done.wait()
        finally:
            self.stop()
