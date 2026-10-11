"""
OffenseSubsystem — discover, replay, harvest, submit.

Each tick:
  1. Drain the exploit queue and fire each exploit across all in-scope instances
     of its service (the mass-exploitation loop), submitting flags via the sink.
  2. Autonomous discovery (throttled): for each service with a matching solver,
     try solve() against one target to find a NEW exploit. Anything found is
     enqueued, so it then fans out to every team on the next drain.

Independence:
  - Standalone: the operator enqueues exploits, or the solvers discover them.
    No defense half required.
  - Together: it subscribes to EXPLOIT_OBSERVED, so every attack defense catches
    becomes an exploit here and is replayed back across the field — the
    capture->weaponize bridge. If defense isn't running, the queue is simply fed
    by solvers and the operator instead. Neither half imports the other.
"""

from __future__ import annotations

import logging
import threading

from core.subsystem import Subsystem
from core.bus import EXPLOIT_OBSERVED, FLAG_CAPTURED
from offense.solver import Exploit, SolverRegistry
from offense.replay import ReplayEngine
from offense.targets import TargetProvider

log = logging.getLogger("ctf.offense")


class OffenseSubsystem(Subsystem):
    name = "offense"

    def __init__(self, ctx, flag_sink, interval: float = 10.0,
                 solvers: SolverRegistry | None = None, flag_format: str | None = None,
                 discover: bool = True, discover_every: int = 3):
        super().__init__(ctx, interval)
        self.solvers = solvers or SolverRegistry()
        self.targets = TargetProvider(ctx)
        self.engine = ReplayEngine(ctx, flag_sink, self.solvers, self.targets, flag_format)
        self.discover = discover
        self.discover_every = discover_every
        self._queue: list[Exploit] = []
        self._lock = threading.Lock()
        self._seq = 0
        self._submitted = 0

    def setup(self) -> None:
        # subscribe to defense's captured exploits (harmless if defense never runs)
        self.ctx.bus.subscribe(EXPLOIT_OBSERVED, self._on_exploit_observed)

    # --- queue --------------------------------------------------------------

    def enqueue(self, exploit: Exploit) -> None:
        with self._lock:
            self._queue.append(exploit)

    def _next_id(self) -> str:
        self._seq += 1
        return f"x{self._seq}"

    def _on_exploit_observed(self, event) -> None:
        p = event.payload
        req = p.get("request", b"")
        if isinstance(req, str):
            req = req.encode("latin-1", "replace")
        self.enqueue(Exploit(
            id=self._next_id(),
            category=p.get("category", _category_for_rule(p.get("rule", ""))),
            service=p.get("service", ""),
            request=req,
            spec={"matched": p.get("matched"), "rule": p.get("rule")},
            origin="captured",
            meta={"from": "defense", "severity": p.get("severity"), "confirmed": p.get("confirmed")},
        ))
        log.info("queued captured exploit from defense (%s on %s)", p.get("rule"), p.get("service"))

    # --- loop ---------------------------------------------------------------

    def tick(self) -> None:
        self._drain_and_fire()
        if self.discover and self._ticks % self.discover_every == 0:
            self._discover_once()

    def _drain_and_fire(self) -> None:
        with self._lock:
            batch, self._queue = self._queue, []
        for exploit in batch:
            result = self.engine.fire(exploit)
            if result.get("flags"):
                self._submitted += result["flags"]
                self.ctx.bus.publish(FLAG_CAPTURED, {
                    "service": exploit.service, "count": result["flags"],
                    "exploit": exploit.id,
                }, source="offense")

    def _discover_once(self) -> None:
        for svc in self.ctx.service_list():
            solvers = self.solvers.for_service(svc)
            if not solvers:
                continue
            tlist = self.targets.targets_for(svc.name)
            if not tlist:
                continue
            target = tlist[0]           # probe one instance to find a vuln
            for solver in solvers:
                res = solver.solve(self.ctx, svc, target)
                if res.ok and res.exploit:
                    log.info("solver %s discovered an exploit for %s", type(solver).__name__, svc.name)
                    res.exploit.id = self._next_id()
                    self.enqueue(res.exploit)       # fan out to all teams next drain
                    break

    def status(self) -> dict:
        s = super().status()
        s.update({"queued": len(self._queue), "flags_submitted": self._submitted})
        return s


def _category_for_rule(rule: str) -> str:
    rule = (rule or "").lower()
    if any(k in rule for k in ("sqli", "ssti", "traversal", "deserialize", "flag_path", "flag_out")):
        return "web"
    if any(k in rule for k in ("nop_sled", "format_string", "oversize")):
        return "pwn"
    return "misc"
