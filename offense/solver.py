"""
Solver plugin interface — the seam that keeps categories independent.

Web, pwn, crypto, rev, forensics are genuinely different problems that share
almost no logic, so the robust design is a thin common engine plus pluggable
per-category solvers behind ONE interface. Adding a category is a new plugin,
never a change to the engine. No solver imports another; the engine imports none
of them by name (they register themselves).

A Solver does two things:
  solve(ctx, service, target)  -> discover an exploit / flag against one target
                                  (the "find a new vuln" path)
  replay(ctx, exploit, target) -> fire a KNOWN exploit at one target
                                  (the "mass-exploit across teams" path, and the
                                   way a captured attack from defense is reused)

Both return a SolveResult with any flags found. The engine handles enumerating
targets, validating/deduping/submitting flags, and scope — solvers just attack
one target and report.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

log = logging.getLogger("ctf.solver")


@dataclass
class Exploit:
    id: str
    category: str                 # web | pwn | crypto | rev | misc
    service: str = ""
    # how to attack: a captured raw request, or a structured spec a solver understands
    request: bytes = b""
    spec: dict = field(default_factory=dict)
    origin: str = "crafted"       # captured | crafted | solver
    meta: dict = field(default_factory=dict)


@dataclass
class SolveResult:
    ok: bool
    flags: list[str] = field(default_factory=list)
    exploit: Exploit | None = None    # a reusable exploit, if one was found
    detail: str = ""


class Solver(ABC):
    category: str = "misc"

    @abstractmethod
    def can_handle(self, service) -> bool:
        ...

    def solve(self, ctx, service, target) -> SolveResult:
        """Discover an exploit/flag against one target. Default: nothing found."""
        return SolveResult(ok=False, detail="solve() not implemented")

    def replay(self, ctx, exploit, target) -> SolveResult:
        """Fire a known exploit at one target. Default: nothing."""
        return SolveResult(ok=False, detail="replay() not implemented")


class SolverRegistry:
    def __init__(self):
        self._solvers: list[Solver] = []

    def register(self, solver: Solver) -> None:
        self._solvers.append(solver)
        log.info("registered solver: %s (%s)", type(solver).__name__, solver.category)

    def for_service(self, service) -> list[Solver]:
        return [s for s in self._solvers if s.can_handle(service)]

    def for_category(self, category: str) -> list[Solver]:
        return [s for s in self._solvers if s.category == category]

    def all(self) -> list[Solver]:
        return list(self._solvers)
