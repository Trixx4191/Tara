"""
ReplayEngine — the attack-defense scoring core.

One working exploit should score against every team running that service. The
engine takes an exploit, enumerates the service's in-scope target instances, and
fires the exploit at each one through the matching solver, harvesting flags and
handing them to the FlagSink (which validates, dedupes, and submits).

It also handles raw captured-flow replay directly: if an exploit carries raw
request bytes and no solver claims it, the engine replays those bytes with the
scoped tcp/http tools and scans the response for flags. That's the generic
capture->weaponize path for the attacks defense hands over.

Every send goes through the gated runner, so replay can only ever hit in-scope
targets — the engine does not open its own sockets.
"""

from __future__ import annotations

import logging
import re

from offense.solver import Exploit, SolveResult
from offense.targets import Target

log = logging.getLogger("ctf.replay")


class ReplayEngine:
    def __init__(self, ctx, submit, solver_registry, target_provider, flag_format: str | None = None):
        """`submit(flag, source, meta) -> status_str` decides what happens to a
        captured flag: queue it for operator review (default) or submit it. The
        engine never talks to the sink directly, so the human-in-the-loop choice
        lives in one place."""
        self.ctx = ctx
        self.submit = submit
        self.solvers = solver_registry
        self.targets = target_provider
        self.flag_re = re.compile(flag_format) if flag_format else None

    # --- public -------------------------------------------------------------

    def fire(self, exploit: Exploit, targets: list[Target] | None = None) -> dict:
        """Fire one exploit across all in-scope instances of its service."""
        tlist = targets if targets is not None else self.targets.targets_for(exploit.service)
        if not tlist:
            return {"ok": False, "detail": "no in-scope targets", "flags": 0}

        svc = self.ctx.services.get(exploit.service)
        solver = None
        if svc:
            cands = self.solvers.for_category(exploit.category) or self.solvers.for_service(svc)
            solver = cands[0] if cands else None

        queued = 0        # flags handed to submit() (queued for review or submitted)
        hit_targets = 0
        for t in tlist:
            res = (solver.replay(self.ctx, exploit, t) if solver
                   else self._raw_replay(exploit, t))
            if res.flags:
                hit_targets += 1
            for flag in res.flags:
                status = self.submit(flag, f"{exploit.service}@{t.host}",
                                     {"exploit": exploit.id, "team": t.team})
                if status in ("accepted", "pending"):
                    queued += 1
        log.info("exploit %s fired at %d targets, %d flags from %d",
                 exploit.id, len(tlist), queued, hit_targets)
        return {"ok": queued > 0, "targets": len(tlist),
                "hit": hit_targets, "flags": queued}

    def harvest(self, exploit: Exploit, response_text: str) -> list[str]:
        """Pull flag-formatted tokens from a response (used by solvers too)."""
        if not self.flag_re:
            return []
        return self.flag_re.findall(response_text)

    # --- generic raw replay (no solver) ------------------------------------

    def _raw_replay(self, exploit: Exploit, target: Target) -> SolveResult:
        if not exploit.request:
            return SolveResult(ok=False, detail="no raw request to replay")
        # send the captured bytes verbatim and read the response, via the gate
        res = self.ctx.runner.run("tcp_probe", {
            "host": target.host, "port": target.port or 0,
            "send": exploit.request.decode("latin-1", "replace"),
            "read_bytes": 65536, "timeout": 6,
        })
        if not res.ok:
            return SolveResult(ok=False, detail=res.output)
        flags = self.harvest(exploit, res.output)
        return SolveResult(ok=bool(flags), flags=flags, detail="raw replay")
