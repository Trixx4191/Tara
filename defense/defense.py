"""
DefenseSubsystem — monitor -> detect -> mitigate/alert -> (feed offense).

Each tick:
  1. Health sweep. A DOWN service fires SERVICE_DOWN immediately (SLA is the
     most expensive thing to lose).
  2. Drain capture/IDS sources through the flow-aware Detector. Findings are
     stored and logged. The Detector's checker allowlist means the organiser's
     SLA checker never triggers a finding or a block.
  3. Response policy per finding:
       - replayable -> publish EXPLOIT_OBSERVED carrying the FULL flow, so a
         running offense half can replay it faithfully (not just a regex slice).
       - high/critical + auto_mitigate -> install an edge block rule (SLA-safe,
         reversible) instead of risking a code patch mid-tick.
       - flag_out -> escalate: your flag is actively leaking.

Runs standalone: with no offense subscriber and no enforcers configured, it
still monitors, detects, and can patch. Mitigation and patching are policy-gated,
not fired blindly every tick.
"""

from __future__ import annotations

import logging

from core.subsystem import Subsystem
from core.bus import EXPLOIT_OBSERVED, SERVICE_DOWN
from defense.capture import CaptureSource, Detector
from defense.patch import PatchManager
from defense.mitigation import MitigationManager
from defense.assurance import (
    AlertDeduper, ConfidenceScorer, Confirmer, FalsePositiveGuard,
)

log = logging.getLogger("ctf.defense")


class DefenseSubsystem(Subsystem):
    name = "defense"

    def __init__(self, ctx, interval: float = 5.0, sources: list[CaptureSource] | None = None,
                 flag_format: str | None = None, checker_allowlist: list[str] | None = None,
                 mitigation: MitigationManager | None = None, auto_mitigate: bool = False,
                 scorer: ConfidenceScorer | None = None, confirmer: Confirmer | None = None,
                 fp_guard: FalsePositiveGuard | None = None, dedup_window: float = 30.0):
        super().__init__(ctx, interval)
        self.sources = sources or []
        self.detector = Detector(flag_format=flag_format, checker_allowlist=checker_allowlist)
        self.patcher = PatchManager(ctx)
        self.mitigation = mitigation or MitigationManager()
        self.auto_mitigate = auto_mitigate
        # assurance layer
        self.deduper = AlertDeduper(window=dedup_window)
        self.scorer = scorer or ConfidenceScorer()
        self.confirmer = confirmer
        self.fp_guard = fp_guard or FalsePositiveGuard(checker_patterns=checker_allowlist or [])
        self._down: set[str] = set()
        self._findings: list = []
        self._suppressed = 0      # findings dropped by dedup/low-confidence
        self._blocks_vetoed = 0   # block rules rejected by the FP guard

    def add_source(self, src: CaptureSource) -> None:
        self.sources.append(src)

    # --- the loop -----------------------------------------------------------

    def tick(self) -> None:
        self._health_sweep()
        self._detect_sweep()

    def _health_sweep(self) -> None:
        services = self.ctx.service_list()
        if not services:
            return
        # Check services concurrently and isolate failures: one slow or throwing
        # check must not delay or abort detection of the others (SLA is the most
        # expensive thing to lose, so the sweep has to stay responsive).
        from concurrent.futures import ThreadPoolExecutor, as_completed
        results: dict[str, bool] = {}
        with ThreadPoolExecutor(max_workers=min(16, len(services)), thread_name_prefix="health") as pool:
            futs = {pool.submit(self._check_one, svc): svc for svc in services}
            for fut in as_completed(futs):
                svc = futs[fut]
                try:
                    up, detail = fut.result()
                except Exception as e:
                    up, detail = False, f"health check raised: {e}"
                results[svc.name] = up
                if not up and svc.name not in self._down:
                    self._down.add(svc.name)
                    log.warning("service %s went DOWN: %s", svc.name, detail)
                    self.ctx.bus.publish(SERVICE_DOWN, {"service": svc.name, "detail": detail}, source="defense")
                elif up and svc.name in self._down:
                    self._down.discard(svc.name)
                    log.info("service %s recovered", svc.name)

    def _check_one(self, svc) -> tuple[bool, str]:
        res = self.ctx.runner.run("service_health", {
            "host": svc.host, "port": svc.port,
            "proto": svc.proto, "path": svc.health_path,
        })
        return bool(res.meta and res.meta.get("up")), res.output

    def _detect_sweep(self) -> None:
        for src in self.sources:
            for item in src.poll():
                findings = self.detector.scan(item)
                # dedup: drop repeats within the window so one pattern can't storm
                findings = [f for f in findings if self.deduper.fresh(f)]
                if findings:
                    self._handle_group(findings)

    def _handle_group(self, findings: list) -> None:
        """Score a flow's signals together, confirm if possible, then decide once."""
        score = self.scorer.score(findings)
        confirmation = self.confirmer.confirm(findings[0]) if self.confirmer else None
        confirmed = confirmation.confirmed if confirmation else None

        for f in findings:
            self._findings.append(f)
            self.ctx.state.set("findings", f"{len(self._findings):06d}",
                               {"rule": f.rule, "severity": f.severity, "reason": f.reason,
                                "matched": f.matched, "where": f.where,
                                "score": score, "confirmed": confirmed})
            if f.rule == "flag_out":
                log.error("FLAG_OUT on service %s — flag actively leaking!", f.flow.service or f.flow.dst)
            else:
                log.info("detected %s [%s] in %s (score %.2f, confirmed=%s): %s",
                         f.rule, f.severity, f.where, score, confirmed, f.reason)

        act = self.scorer.should_act(score, confirmed)
        share = self.scorer.should_share(score, confirmed)

        # Low-confidence and unconfirmed -> observe only, take no action.
        if not share:
            self._suppressed += 1
            log.debug("group below share threshold (score %.2f) — observing only", score)
            return

        lead = max(findings, key=lambda x: {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(x.severity, 0))

        # SLA-safe edge mitigation — only when confident AND the block is proven
        # not to hit benign/checker traffic.
        if act and self.auto_mitigate and self.mitigation.enforcers and lead.severity in ("high", "critical"):
            rule = self.mitigation.rule_from_finding(lead)
            safe, why = self.fp_guard.is_safe(rule)
            if safe:
                for e in self.mitigation.enforcers:
                    try:
                        e.apply(rule)
                    except Exception:
                        log.exception("enforcer failed")
                self.ctx.state.set("mitigations", rule.rule_id,
                                   {"kind": rule.kind, "pattern": rule.pattern, "reason": rule.reason})
                log.info("edge block installed: %s", rule.pattern)
            else:
                self._blocks_vetoed += 1
                log.warning("block rule VETOED by FP guard (%s): %s", why, rule.pattern)

        # feed offense the FULL flow for faithful replay (confident/confirmed only)
        if lead.replayable:
            self.ctx.bus.publish(EXPLOIT_OBSERVED, {
                "rule": lead.rule, "severity": lead.severity, "score": score,
                "confirmed": confirmed,
                "request": lead.flow.request, "response": lead.flow.response,
                "service": lead.flow.service, "host": lead.flow.dst, "port": lead.flow.port,
                "matched": lead.matched,
            }, source="defense")

    # --- operator / policy entry points ------------------------------------

    def recent_findings(self, limit: int = 20):
        return self._findings[-limit:]

    def auto_patch(self, service_name: str, patch: dict) -> dict:
        svc = self.ctx.services.get(service_name)
        if not svc:
            return {"ok": False, "error": f"no service {service_name!r}"}
        return self.patcher.apply(svc, patch)

    def block(self, finding) -> dict:
        """Manually install an edge block from a finding — still FP-guarded."""
        if not self.mitigation.enforcers:
            return {"ok": False, "error": "no enforcers configured"}
        rule = self.mitigation.rule_from_finding(finding)
        safe, why = self.fp_guard.is_safe(rule)
        if not safe:
            self._blocks_vetoed += 1
            return {"ok": False, "vetoed": True, "reason": why}
        for e in self.mitigation.enforcers:
            e.apply(rule)
        return {"ok": True, "rule_id": rule.rule_id, "kind": rule.kind, "pattern": rule.pattern}

    def status(self) -> dict:
        s = super().status()
        s.update({"findings": len(self._findings),
                  "suppressed": self._suppressed,
                  "blocks_vetoed": self._blocks_vetoed})
        return s

    def analyze(self, finding) -> str:
        from core.agent import Agent
        prompt = (
            "You are the defensive analyst for a CTF service. An incoming flow tripped "
            "a detector. Explain the likely vulnerability and propose the MINIMAL code "
            "change to close it without breaking the service's intended behaviour. If a "
            "code patch is risky for SLA, propose an edge filter (payload regex) instead."
            f"\n\nRule: {finding.rule} ({finding.severity})\nReason: {finding.reason}\n"
            f"Matched: {finding.matched}\nRequest: {finding.flow.request_text()[:1000]}"
        )
        agent = Agent(self.ctx.provider, self.ctx.runner,
                      system_prompt="Concise defensive security analyst.", max_iters=4)
        return agent.run(prompt)
