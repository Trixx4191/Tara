"""
Assurance tests: false positives, confidence, confirmation, dedup, hallucinated
flags. No network, no model.
Run: python test_assurance.py
"""

import tempfile

from core.state import StateStore, Flag
from core.scope import ScopePolicy
from core.toolrunner import ToolRunner
from core.bus import EventBus, EXPLOIT_OBSERVED
from core.context import AgentContext
from tools.base import ToolRegistry
from defense.health import ServiceHealthTool
from defense.capture import QueueSource, Flow, Finding
from defense.defense import DefenseSubsystem
from defense.mitigation import BlocklistEnforcer, MitigationManager, BlockRule
from defense.assurance import (
    AlertDeduper, ConfidenceScorer, Confirmer, FalsePositiveGuard, validate_flag,
)


class FakeProvider:
    name = "fake"
    def complete(self, messages, tools=None, **k):
        from providers.base import Completion
        return Completion(text="x")


def _ctx():
    scope = ScopePolicy.from_config({"scope": {"allowed_cidrs": ["127.0.0.0/8"], "resolve_check": False}})
    state = StateStore(tempfile.mkdtemp())
    reg = ToolRegistry(); reg.register(ServiceHealthTool())
    runner = ToolRunner(reg, scope, state, default_timeout=5)
    return AgentContext(FakeProvider(), runner, state, EventBus(), scope, config={"state_dir": state.root})


# --- confidence scoring -----------------------------------------------------

def test_single_signal_is_low_confidence():
    s = ConfidenceScorer()
    f = Finding("sqli", "high", "sqli", matched="UNION SELECT")
    sc = s.score([f])
    assert sc == 0.45
    assert s.should_act(sc, None) is False          # one high signal: don't block
    assert s.should_share(sc, None) is True          # but worth sharing

def test_corroboration_raises_confidence():
    s = ConfidenceScorer()
    fs = [Finding("cmd_injection", "critical", "ci", matched=";id"),
          Finding("flag_path", "medium", "flag", matched="/flag")]
    sc = s.score(fs)
    assert sc >= 0.70 and s.should_act(sc, None) is True

def test_ids_agreement_raises_confidence():
    s = ConfidenceScorer()
    fs = [Finding("suricata:2001", "high", "ET rule", matched="x")]
    assert s.score(fs) >= 0.70

def test_confirmed_overrides_low_score():
    s = ConfidenceScorer()
    assert s.should_act(0.1, True) is True           # confirmation beats score


# --- confirmation via replay ------------------------------------------------

def test_confirmer_confirms_on_flag_leak():
    c = Confirmer(replay_fn=lambda req: b"HTTP 200\nCTF{x}", flag_format=r"CTF\{[^}]+\}")
    f = Finding("sqli", "high", "x", flow=Flow(request=b"id=1' UNION SELECT flag--"))
    conf = c.confirm(f)
    assert conf and conf.confirmed is True

def test_confirmer_negative_when_nothing_happens():
    c = Confirmer(replay_fn=lambda req: b"HTTP 200\nnormal", flag_format=r"CTF\{[^}]+\}")
    f = Finding("sqli", "high", "x", flow=Flow(request=b"id=1' UNION SELECT flag--"))
    conf = c.confirm(f)
    assert conf and conf.confirmed is False

def test_confirmer_none_without_replay():
    c = Confirmer()   # no replay_fn
    assert c.confirm(Finding("sqli", "high", "x", flow=Flow(request=b"x"))) is None


# --- false-positive guard on block rules ------------------------------------

def test_fp_guard_vetoes_block_hitting_benign():
    g = FalsePositiveGuard(benign_corpus=["GET /api/items?select=name"])
    # a block on 'select' would also hit legit traffic
    rule = BlockRule("r1", "payload", pattern="select", reason="x")
    ok, why = g.is_safe(rule)
    assert ok is False

def test_fp_guard_vetoes_block_hitting_checker():
    g = FalsePositiveGuard(checker_patterns=["SLA-CHECK-TOKEN"])
    rule = BlockRule("r1", "payload", pattern="SLA-CHECK-TOKEN", reason="x")
    assert g.is_safe(rule)[0] is False

def test_fp_guard_vetoes_too_short_pattern():
    g = FalsePositiveGuard()
    assert g.is_safe(BlockRule("r1", "payload", pattern="a", reason="x"))[0] is False

def test_fp_guard_refuses_to_block_loopback():
    g = FalsePositiveGuard()
    assert g.is_safe(BlockRule("r1", "src", pattern="127.0.0.1", reason="x"))[0] is False

def test_fp_guard_allows_specific_safe_payload():
    g = FalsePositiveGuard(benign_corpus=["GET /index"])
    ok, why = g.is_safe(BlockRule("r1", "payload", pattern=r"\.\./\.\./etc/passwd", reason="x"))
    assert ok is True


# --- dedup ------------------------------------------------------------------

def test_deduper_collapses_repeats():
    d = AlertDeduper(window=60)
    f = Finding("sqli", "high", "x", matched="UNION", flow=Flow(src="10.0.0.9"))
    assert d.fresh(f) is True
    assert d.fresh(f) is False        # same finding again within window -> stale


# --- end-to-end: FP guard actually prevents a bad auto-block ----------------

def test_auto_mitigate_vetoed_when_pattern_hits_checker():
    ctx = _ctx()
    bl = BlocklistEnforcer()
    # checker uses the literal 'HealthPing' in its requests
    d = DefenseSubsystem(
        ctx, sources=[],
        mitigation=MitigationManager([bl]), auto_mitigate=True,
        fp_guard=FalsePositiveGuard(checker_patterns=["HealthPing"]),
    )
    # high-confidence group (two signals) whose lead slice IS the checker token
    bad = Finding("cmd_injection", "critical", "ci", matched="HealthPing",
                  flow=Flow(src="10.0.0.9", service="web"), where="request")
    corrob = Finding("oversize", "medium", "big", matched="A" * 10,
                     flow=Flow(src="10.0.0.9", service="web"), where="request")
    d._handle_group([bad, corrob])    # score -> acts, then FP guard vetoes
    assert not bl.active_rules(), "FP guard must stop a block that hits the checker"
    assert d._blocks_vetoed == 1

def test_auto_mitigate_installs_safe_block():
    ctx = _ctx()
    bl = BlocklistEnforcer()
    d = DefenseSubsystem(ctx, sources=[], mitigation=MitigationManager([bl]), auto_mitigate=True)
    # two corroborating signals -> high confidence -> acts; pattern is safe
    good = Finding("cmd_injection", "critical", "ci", matched=";cat /flag",
                   flow=Flow(src="10.0.0.9", service="web"), where="request", replayable=True)
    corrob = Finding("flag_path", "medium", "flag", matched="/flag",
                     flow=Flow(src="10.0.0.9", service="web"), where="request")
    d._handle_group([good, corrob])
    assert bl.active_rules(), "a safe high-confidence block should install"


# --- low confidence -> no action -------------------------------------------

def test_low_confidence_observes_only():
    ctx = _ctx()
    bl = BlocklistEnforcer()
    shared = []
    ctx.bus.subscribe(EXPLOIT_OBSERVED, lambda ev: shared.append(ev))
    d = DefenseSubsystem(ctx, sources=[], mitigation=MitigationManager([bl]), auto_mitigate=True,
                         scorer=ConfidenceScorer(share_threshold=0.5, act_threshold=0.9))
    weak = Finding("flag_path", "medium", "flag path", matched="/flag",
                   flow=Flow(src="10.0.0.9"), replayable=True)
    d._handle_group([weak])          # score 0.25 -> below share 0.5
    assert not bl.active_rules() and not shared, "weak single signal must not act or share"
    assert d._findings, "but it is still recorded for review"


# --- hallucinated flag rejection --------------------------------------------

def test_validate_flag():
    fmt = r"CTF\{[0-9a-f]{8}\}"
    assert validate_flag("CTF{deadbeef}", fmt) is True
    assert validate_flag("not a flag", fmt) is False
    assert validate_flag("CTF{xyz}", fmt) is False

def test_record_flag_rejects_hallucination():
    st = StateStore(tempfile.mkdtemp())
    fmt = r"CTF\{[0-9a-f]{8}\}"
    assert st.record_flag(Flag(value="I think the flag is here", source="llm"), flag_format=fmt) is False
    assert st.record_flag(Flag(value="CTF{deadbeef}", source="llm"), flag_format=fmt) is True


if __name__ == "__main__":
    import traceback
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"PASS {name}"); passed += 1
            except Exception:
                print(f"FAIL {name}"); traceback.print_exc(); failed += 1
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(1 if failed else 0)
