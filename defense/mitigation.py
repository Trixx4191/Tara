"""
Mitigation — SLA-safe responses that stop an exploit without editing code.

Research lesson: patching code risks breaking the organiser's SLA check, which
costs points continuously. A safer first response is often to block the exploit
at the edge (mod_security-style) while the service keeps serving legitimate
traffic. This module turns a Finding into a block rule and applies it through a
pluggable enforcer.

Enforcers (pick per deployment; all optional, none competition-specific):
  - BlocklistEnforcer : an in-process set of payload regexes a reverse-proxy /
    WAF shim consults per request. Zero privilege, instant, reversible.
  - NftEmitter        : emits nftables/iptables commands to drop a source or a
    payload match. Emit-only by default — it returns the commands for the
    operator / OS-enforcement phase rather than running them, so nothing touches
    the host firewall without an explicit decision.

Every rule is reversible and recorded, and the checker allowlist (in Detector)
means a mitigation is never generated from the SLA checker's own traffic.
"""

from __future__ import annotations

import logging
import re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import time

log = logging.getLogger("ctf.mitigation")


@dataclass
class BlockRule:
    rule_id: str
    kind: str                 # "payload" | "src"
    pattern: str              # regex (payload) or IP/CIDR (src)
    reason: str
    service: str = ""
    created: float = field(default_factory=time.time)
    active: bool = True


class Enforcer(ABC):
    @abstractmethod
    def apply(self, rule: BlockRule): ...
    @abstractmethod
    def remove(self, rule_id: str): ...


class BlocklistEnforcer(Enforcer):
    """In-process WAF the operator wires a reverse proxy / service shim into.

    A proxy calls allows(request_bytes, src) on each request; if it returns
    False, the proxy drops/429s it. Reversible by removing the rule.
    """
    def __init__(self):
        self._rules: dict[str, BlockRule] = {}
        self._payload_res: dict[str, re.Pattern] = {}
        self._lock = threading.RLock()

    def apply(self, rule: BlockRule):
        with self._lock:
            self._rules[rule.rule_id] = rule
            if rule.kind == "payload":
                try:
                    self._payload_res[rule.rule_id] = re.compile(rule.pattern)
                except re.error:
                    # fall back to a literal match if the pattern is not valid regex
                    self._payload_res[rule.rule_id] = re.compile(re.escape(rule.pattern))
        log.info("blocklist +%s (%s): %s", rule.rule_id, rule.kind, rule.reason)

    def remove(self, rule_id: str):
        with self._lock:
            self._rules.pop(rule_id, None)
            self._payload_res.pop(rule_id, None)

    def allows(self, request: bytes | str, src: str = "") -> bool:
        """True if the request is permitted; False if any active rule blocks it."""
        blob = request if isinstance(request, str) else request.decode("latin-1", "replace")
        with self._lock:
            for rid, rule in self._rules.items():
                if not rule.active:
                    continue
                if rule.kind == "src" and src and (src == rule.pattern or src.startswith(rule.pattern)):
                    return False
                if rule.kind == "payload" and self._payload_res.get(rid) and self._payload_res[rid].search(blob):
                    return False
        return True

    def active_rules(self) -> list[BlockRule]:
        with self._lock:
            return [r for r in self._rules.values() if r.active]


class NftEmitter(Enforcer):
    """Emit firewall commands rather than run them (OS-enforcement phase)."""
    def __init__(self, run: bool = False):
        self.run = run
        self.emitted: list[str] = []

    def _cmd(self, rule: BlockRule) -> str:
        if rule.kind == "src":
            return f"nft add rule inet filter input ip saddr {rule.pattern} drop  # {rule.reason}"
        # payload match via string matching extension (best-effort, operator reviews)
        return (f"iptables -A INPUT -m string --algo bm --string {rule.pattern!r} "
                f"-j DROP  # {rule.reason}")

    def apply(self, rule: BlockRule):
        cmd = self._cmd(rule)
        self.emitted.append(cmd)
        if self.run:
            import subprocess
            subprocess.run(cmd, shell=True)
        else:
            log.info("nft (emit-only): %s", cmd)
        return cmd

    def remove(self, rule_id: str):
        log.info("nft remove requested for %s (manual/flush in OS phase)", rule_id)


class MitigationManager:
    """Turn findings into block rules and apply them through chosen enforcers."""
    def __init__(self, enforcers: list[Enforcer] | None = None):
        self.enforcers = enforcers or []
        self._seq = 0

    def add_enforcer(self, e: Enforcer):
        self.enforcers.append(e)

    def rule_from_finding(self, finding) -> BlockRule:
        self._seq += 1
        # prefer a payload rule from the matched slice; fall back to source block
        matched = getattr(finding, "matched", "")
        flow = getattr(finding, "flow", None)
        if matched and len(matched) >= 4:
            return BlockRule(
                rule_id=f"r{self._seq}", kind="payload",
                pattern=re.escape(matched), reason=f"{finding.rule}: {finding.reason}",
                service=getattr(flow, "service", "") if flow else "",
            )
        src = getattr(flow, "src", "") if flow else ""
        return BlockRule(
            rule_id=f"r{self._seq}", kind="src", pattern=src or "0.0.0.0/32",
            reason=f"{finding.rule}: {finding.reason}",
            service=getattr(flow, "service", "") if flow else "",
        )

    def mitigate(self, finding) -> BlockRule:
        rule = self.rule_from_finding(finding)
        for e in self.enforcers:
            try:
                e.apply(rule)
            except Exception:
                log.exception("enforcer %s failed", type(e).__name__)
        return rule
