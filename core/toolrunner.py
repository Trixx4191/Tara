"""
ToolRunner — the single chokepoint through which every tool call passes.

Responsibilities, in order:
  1. Look up the tool.
  2. Ask it what it will touch, and run those targets through the ScopePolicy
     (resolving names when enabled). Out of scope -> refused here, never runs.
  3. In dry-run mode, log the intended call and return without side effects.
  4. Execute under a hard wall-clock timeout so one stuck tool can't freeze the
     agent during a scored tick. Capture + cap output, record in state.

One chokepoint means scope and timeouts can never be forgotten at a call site —
there is only one call site. The socket-level NetworkGuard sits under this as a
second, non-bypassable layer.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

from core.scope import ScopePolicy, ScopeViolation
from core.state import StateStore
from tools.base import ToolRegistry, ToolResult

log = logging.getLogger("ctf.runner")

MAX_OUTPUT = 100_000   # hard cap on captured tool output (chars)


class ToolRunner:
    def __init__(
        self,
        registry: ToolRegistry,
        scope: ScopePolicy,
        state: StateStore,
        default_timeout: float = 120.0,
    ):
        self.registry = registry
        self.scope = scope
        self.state = state
        self.default_timeout = default_timeout
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="tool")

    def run(self, name: str, arguments: dict, timeout: float | None = None) -> ToolResult:
        tool = self.registry.get(name)
        if tool is None:
            return ToolResult(ok=False, output=f"no such tool: {name}")

        if not isinstance(arguments, dict):
            return ToolResult(ok=False, output=f"arguments must be an object, got {type(arguments).__name__}")

        # 1 + 2: scope gate, always, before anything runs.
        try:
            targets = tool.targets(**arguments)
            if targets:
                self.scope.check_targets(targets)
        except ScopeViolation as v:
            log.warning("REFUSED %s: %s", name, v)
            return ToolResult(ok=False, output=f"scope refused: {v}")
        except TypeError as e:
            return ToolResult(ok=False, output=f"bad arguments for {name}: {e}")
        except Exception as e:
            return ToolResult(ok=False, output=f"scope check error for {name}: {e}")

        # 3: dry run
        if self.scope.dry_run and targets:
            msg = f"[dry-run] would run {name} against {targets} with {arguments}"
            log.info(msg)
            return ToolResult(ok=True, output=msg, meta={"dry_run": True})

        # 4: execute under timeout
        tmo = timeout if timeout is not None else getattr(tool, "timeout", None) or self.default_timeout
        start = time.time()
        future = self._pool.submit(self._safe_run, tool, arguments)
        try:
            result = future.result(timeout=tmo)
        except FutTimeout:
            log.warning("tool %s timed out after %ss", name, tmo)
            result = ToolResult(ok=False, output=f"tool timed out after {tmo}s", meta={"timeout": True})
        dur = time.time() - start

        if result.output and len(result.output) > MAX_OUTPUT:
            result.output = result.output[:MAX_OUTPUT] + f"\n...[truncated {len(result.output) - MAX_OUTPUT} chars]"

        try:
            self.state.set(
                "tool_log",
                f"{time.time():.3f}_{name}",
                {"args": self._safe_args(arguments), "ok": result.ok,
                 "secs": round(dur, 2), "out_head": (result.output or "")[:500]},
            )
            self.state.rotate("tool_log", keep=500)
        except Exception:
            log.debug("tool_log write failed", exc_info=True)
        return result

    @staticmethod
    def _safe_run(tool, arguments) -> ToolResult:
        try:
            return tool.run(**arguments)
        except Exception as e:
            log.exception("tool %s raised", tool.name)
            return ToolResult(ok=False, output=f"tool error: {e}")

    @staticmethod
    def _safe_args(arguments: dict) -> dict:
        # avoid logging huge blobs
        out = {}
        for k, v in arguments.items():
            s = v if isinstance(v, (int, float, bool)) else str(v)
            out[k] = s[:200] if isinstance(s, str) and len(s) > 200 else s
        return out

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False)
