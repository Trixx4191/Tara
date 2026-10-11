"""
Assurance — defense against false positives, false alarms, and hallucinations.

Detection that acts on a single regex hit is dangerous in A/D: a false block can
drop legitimate traffic or the SLA checker and cost you the game, and a
hallucinated flag or patch wastes a tick. This module adds the judgement layer
between "something matched" and "take an action":

  AlertDeduper    — collapse identical/repeated findings so one attack pattern
                    doesn't storm the bus.
  ConfidenceScorer— turn a group of signals on one flow into a 0..1 score
                    (severity + corroboration + IDS agreement + direct evidence).
                    Two thresholds: share-with-offense (low) and act/block (high).
  Confirmer       — the "confirm" in detect->confirm->act: replay the suspect
                    request against a local replica and check it actually does
                    something (leaks a flag, errors, diverges from baseline).
                    A confirmed finding is trusted regardless of score; an
                    unconfirmable one falls back to the score.
  FalsePositiveGuard — before ANY block rule goes live, test it against a
                    benign-traffic corpus and the checker patterns. If the rule
                    would also match good traffic, it is REJECTED. This is what
                    stops an auto-block from taking down your own service.
  validate_flag   — a token is only a flag if it matches the competition flag
                    format. Rejects hallucinated/garbage "flags" before they are
                    recorded or submitted.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field

log = logging.getLogger("ctf.assurance")


# --- dedup ------------------------------------------------------------------

class AlertDeduper:
    def __init__(self, window: float = 30.0):
        self.window = window
        self._seen: dict[str, float] = {}

    def _key(self, finding) -> str:
        flow = getattr(finding, "flow", None)
        src = getattr(flow, "src", "") if flow else ""
        return f"{finding.rule}|{src}|{finding.matched[:40]}"

    def fresh(self, finding) -> bool:
        now = time.time()
        k = self._key(finding)
        last = self._seen.get(k)
        self._seen[k] = now
        # prune occasionally
        if len(self._seen) > 5000:
            self._seen = {kk: tt for kk, tt in self._seen.items() if now - tt < self.window}
        return last is None or (now - last) > self.window


# --- confidence -------------------------------------------------------------

_SEV_BASE = {"critical": 0.60, "high": 0.45, "medium": 0.25, "low": 0.10}


class ConfidenceScorer:
    def __init__(self, share_threshold: float = 0.40, act_threshold: float = 0.70):
        self.share_threshold = share_threshold
        self.act_threshold = act_threshold

    def score(self, findings: list) -> float:
        if not findings:
            return 0.0
        base = max(_SEV_BASE.get(f.severity, 0.1) for f in findings)
        distinct_rules = len({f.rule for f in findings})
        if distinct_rules >= 2:
            base += 0.20                       # corroboration across rules
        if any(str(f.rule).startswith("suricata:") for f in findings):
            base += 0.25                       # an independent IDS agrees
        if any(f.rule == "flag_out" for f in findings):
            base += 0.30                       # direct evidence of a real leak
        return min(1.0, round(base, 3))

    def should_share(self, score: float, confirmed) -> bool:
        return confirmed is True or score >= self.share_threshold

    def should_act(self, score: float, confirmed) -> bool:
        return confirmed is True or score >= self.act_threshold


# --- confirmation (replay against a replica) --------------------------------

@dataclass
class Confirmation:
    confirmed: bool
    evidence: str = ""


class Confirmer:
    """Replay a suspect request against a local replica to see if it DOES anything.

    replay_fn(request_bytes) -> response_bytes   (operator/offense supplies this;
    it should target a LOCAL replica of the service, never a live opponent).
    baseline_fn() -> response_bytes              (optional: a known-good response
    to diff against, so "diverges from normal" counts as confirmation).
    """
    def __init__(self, replay_fn=None, baseline_fn=None, flag_format: str | None = None):
        self.replay_fn = replay_fn
        self.baseline_fn = baseline_fn
        self.flag_re = re.compile(flag_format) if flag_format else None

    def confirm(self, finding):
        """Return Confirmation, or None if we cannot confirm either way."""
        if self.replay_fn is None:
            return None
        flow = getattr(finding, "flow", None)
        req = getattr(flow, "request", b"") if flow else b""
        if not req:
            return None
        try:
            resp = self.replay_fn(req)
        except Exception as e:
            log.debug("replay failed: %s", e)
            return None
        text = resp.decode("latin-1", "replace") if isinstance(resp, bytes) else str(resp)
        if self.flag_re and self.flag_re.search(text):
            return Confirmation(True, "replay leaked a flag-formatted token")
        if self.baseline_fn is not None:
            try:
                base = self.baseline_fn()
                base_t = base.decode("latin-1", "replace") if isinstance(base, bytes) else str(base)
                if text and text != base_t and abs(len(text) - len(base_t)) > 16:
                    return Confirmation(True, "replay response diverged from baseline")
            except Exception:
                pass
        return Confirmation(False, "replay produced nothing anomalous")


# --- false-positive guard for block rules -----------------------------------

class FalsePositiveGuard:
    """Veto a block rule that would also hit benign traffic or the SLA checker."""
    def __init__(self, benign_corpus: list[str] | None = None,
                 checker_patterns: list[str] | None = None, min_pattern_len: int = 4):
        self.benign = list(benign_corpus or [])
        self.checker = list(checker_patterns or [])
        self.min_len = min_pattern_len

    def is_safe(self, rule) -> tuple[bool, str]:
        if rule.kind == "payload":
            raw = rule.pattern
            # a too-short/too-generic pattern is inherently risky
            literal = raw
            try:
                # unescape for length judgement
                literal = re.sub(r"\\(.)", r"\1", raw)
            except re.error:
                pass
            if len(literal) < self.min_len:
                return False, f"pattern too short/generic ({literal!r})"
            try:
                rx = re.compile(raw)
            except re.error as e:
                return False, f"invalid regex: {e}"
            for sample in self.benign:
                if rx.search(sample):
                    return False, f"would block benign traffic: {sample[:40]!r}"
            for cp in self.checker:
                if rx.search(cp) or (cp in literal):
                    return False, "would block the SLA checker"
            return True, "ok"
        if rule.kind == "src":
            # never block loopback or an empty/placeholder source
            if rule.pattern in ("", "0.0.0.0/32", "127.0.0.1", "::1"):
                return False, f"refusing to block source {rule.pattern!r}"
            return True, "ok"
        return False, f"unknown rule kind {rule.kind!r}"


# --- flag validation (anti-hallucination) -----------------------------------

def validate_flag(token: str, flag_format: str | None) -> bool:
    """A token is only a flag if it matches the competition's flag format."""
    if not token:
        return False
    if not flag_format:
        # no format known: accept but caller should treat as low-trust
        return True
    return re.fullmatch(flag_format, token.strip()) is not None
