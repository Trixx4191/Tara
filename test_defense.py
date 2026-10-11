"""
Defense subsystem tests. No live network, no model.
Run: python test_defense.py
"""

import os
import shutil
import tempfile
import time

from core.scope import ScopePolicy
from core.state import StateStore
from core.toolrunner import ToolRunner
from core.bus import EventBus, EXPLOIT_OBSERVED, SERVICE_DOWN, SERVICE_PATCHED
from core.context import AgentContext, Service
from core.orchestrator import Orchestrator
from tools.base import ToolRegistry
from defense.health import ServiceHealthTool
from defense.capture import QueueSource, Detector
from defense.defense import DefenseSubsystem


class FakeProvider:
    name = "fake"
    def complete(self, messages, tools=None, **k):
        from providers.base import Completion
        return Completion(text="(fake analysis)")


def _ctx():
    scope = ScopePolicy.from_config({"scope": {
        "allowed_cidrs": ["127.0.0.0/8"],
        "allowed_paths": [tempfile.gettempdir()],
        "resolve_check": False,
    }})
    state = StateStore(tempfile.mkdtemp())
    bus = EventBus()
    reg = ToolRegistry()
    reg.register(ServiceHealthTool())
    runner = ToolRunner(reg, scope, state, default_timeout=10)
    return AgentContext(provider=FakeProvider(), runner=runner, state=state,
                        bus=bus, scope=scope, config={"state_dir": state.root})


# --- detector ---------------------------------------------------------------

def test_detector_catches_traversal():
    d = Detector()
    fs = d.scan({"data": "GET /../../etc/passwd"})
    assert any(f.rule == "path_traversal" for f in fs)

def test_detector_catches_sqli():
    d = Detector()
    fs = d.scan({"data": "id=1' OR '1'='1"})
    assert any(f.rule == "sqli" for f in fs)

def test_detector_catches_cmd_injection():
    d = Detector()
    fs = d.scan({"data": "name=foo;cat /flag"})
    assert any(f.rule in ("cmd_injection", "flag_path") for f in fs)

def test_detector_flag_out_in_response():
    from defense.capture import Flow
    d = Detector(flag_format=r"CTF\{[^}]+\}")
    # flag leaving in a RESPONSE is the FLAG_OUT signal
    fl = Flow(request=b"GET /note?id=1", response=b"HTTP/1.1 200\n\nCTF{leaked_secret}")
    fs = d.scan(fl)
    assert any(f.rule == "flag_out" and f.severity == "critical" and f.where == "response" for f in fs)

def test_detector_flag_in_request_is_not_flag_out():
    from defense.capture import Flow
    d = Detector(flag_format=r"CTF\{[^}]+\}")
    # a flag token in a REQUEST (e.g. a submit) must not be mistaken for a leak
    fl = Flow(request=b"POST /submit flag=CTF{ours}", response=b"ok")
    assert not any(f.rule == "flag_out" for f in d.scan(fl))

def test_detector_oversize():
    d = Detector()
    fs = d.scan({"data": "A" * 5000})
    assert any(f.rule == "oversize" for f in fs)

def test_detector_clean_traffic():
    d = Detector()
    assert d.scan({"data": "GET /index.html HTTP/1.1"}) == []


# --- capture source ---------------------------------------------------------

def test_queue_source():
    q = QueueSource()
    q.push({"data": "x"}); q.push({"data": "y"})
    assert len(q.poll()) == 2
    assert q.poll() == []   # drained


# --- defense subsystem: detection -> bus ------------------------------------

def test_defense_publishes_exploit_observed():
    ctx = _ctx()
    got = []
    ctx.bus.subscribe(EXPLOIT_OBSERVED, lambda ev: got.append(ev))
    q = QueueSource()
    d = DefenseSubsystem(ctx, sources=[q])
    q.push({"data": "id=1' UNION SELECT password--", "host": "127.0.0.1", "port": 80})
    d.tick()
    assert got, "expected an EXPLOIT_OBSERVED event"
    assert got[0].payload["rule"] == "sqli"


def test_defense_runs_standalone_without_offense():
    # no subscriber for EXPLOIT_OBSERVED -> must not raise
    ctx = _ctx()
    q = QueueSource()
    d = DefenseSubsystem(ctx, sources=[q])
    q.push({"data": "../../flag"})
    d.tick()   # should be a no-op-safe publish
    assert d.recent_findings(), "finding still recorded even with no offense"


# --- health sweep -> SERVICE_DOWN -------------------------------------------

def test_health_down_publishes():
    ctx = _ctx()
    downs = []
    ctx.bus.subscribe(SERVICE_DOWN, lambda ev: downs.append(ev))
    # port 1 on loopback: nothing listening -> DOWN
    ctx.add_service(Service(name="svc1", host="127.0.0.1", port=1, proto="tcp"))
    d = DefenseSubsystem(ctx)
    d.tick()
    assert downs and downs[0].payload["service"] == "svc1"


# --- patch manager: verify + rollback ---------------------------------------

def _make_service_src(vuln_text):
    src = tempfile.mkdtemp(dir=tempfile.gettempdir())
    with open(os.path.join(src, "app.py"), "w") as f:
        f.write(vuln_text)
    return src

def _live_listener():
    """A real TCP listener so the post-patch liveness probe sees the service up."""
    import socket, threading
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(8)
    port = srv.getsockname()[1]
    def _serve():
        while True:
            try:
                c, _ = srv.accept(); c.close()
            except OSError:
                break
    threading.Thread(target=_serve, daemon=True).start()
    return srv, port

def test_patch_applied_and_verified():
    ctx = _ctx()
    src = _make_service_src("def handle(x): return eval(x)  # VULN\n")
    # checker passes only if the word 'eval' is gone
    checker = "! grep -q eval app.py"
    srv, port = _live_listener()
    svc = Service(name="p1", host="127.0.0.1", port=port, source_dir=src, checker=checker)
    ctx.add_service(svc)
    patched = []
    ctx.bus.subscribe(SERVICE_PATCHED, lambda ev: patched.append(ev))
    d = DefenseSubsystem(ctx)
    res = d.auto_patch("p1", {"kind": "replace", "file": "app.py",
                              "find": "eval(x)", "replace": "int(x)"})
    assert res["ok"] and res["verified"], res
    assert patched, "expected SERVICE_PATCHED event"
    with open(os.path.join(src, "app.py")) as f:
        assert "eval" not in f.read()
    shutil.rmtree(src, ignore_errors=True)

def test_patch_rolls_back_when_checker_fails():
    ctx = _ctx()
    src = _make_service_src("def handle(x): return eval(x)\n")
    checker = "grep -q NONEXISTENT_TOKEN app.py"   # always fails
    svc = Service(name="p2", host="127.0.0.1", port=9, source_dir=src, checker=checker)
    ctx.add_service(svc)
    d = DefenseSubsystem(ctx)
    res = d.auto_patch("p2", {"kind": "replace", "file": "app.py",
                              "find": "eval(x)", "replace": "int(x)"})
    assert not res["ok"] and res.get("rolled_back"), res
    with open(os.path.join(src, "app.py")) as f:
        assert "eval(x)" in f.read(), "should have rolled back to vulnerable original"
    shutil.rmtree(src, ignore_errors=True)


# --- orchestrator: defense alone, start/stop clean --------------------------

def test_orchestrator_defense_only():
    ctx = _ctx()
    q = QueueSource()
    orch = Orchestrator(ctx)
    orch.add(DefenseSubsystem(ctx, interval=0.2, sources=[q]))
    orch.start(["defense"])
    q.push({"data": "../../flag"})
    time.sleep(0.5)
    orch.stop()
    statuses = {s["name"]: s for s in orch.status()}
    assert statuses["defense"]["ticks"] >= 1
    assert not statuses["defense"]["running"]


# --- checker allowlist: protect our own SLA checker -------------------------

def test_checker_allowlist_suppresses():
    from defense.capture import Flow
    # the SLA checker sends traffic that looks like traversal; we must NOT alarm
    d = Detector(checker_allowlist=[r"X-Checker-Token: SLA123"])
    fl = Flow(request=b"GET /../etc/passwd\nX-Checker-Token: SLA123")
    assert d.scan(fl) == [], "checker traffic must be suppressed"

def test_checker_allowlist_still_catches_real_attack():
    from defense.capture import Flow
    d = Detector(checker_allowlist=[r"X-Checker-Token: SLA123"])
    fl = Flow(request=b"GET /../etc/passwd")   # no checker token
    assert any(f.rule == "path_traversal" for f in d.scan(fl))


# --- suricata source --------------------------------------------------------

def test_suricata_source_parses_alert():
    import json as _j, tempfile as _t, os as _o
    from defense.capture import SuricataSource
    p = _o.path.join(_t.mkdtemp(), "eve.json")
    with open(p, "w") as f:
        f.write(_j.dumps({"event_type": "alert", "src_ip": "10.0.0.9", "dest_ip": "10.0.0.1",
                          "dest_port": 80, "alert": {"signature_id": 2001, "severity": 1,
                          "signature": "ET EXPLOIT something", "category": "attack"}}) + "\n")
        f.write(_j.dumps({"event_type": "flow"}) + "\n")  # ignored
    findings = SuricataSource(p).poll()
    assert len(findings) == 1 and findings[0].rule == "suricata:2001" and findings[0].severity == "critical"


# --- mitigation: edge blocklist + firewall emitter --------------------------

def test_blocklist_blocks_matching_payload():
    from defense.mitigation import BlocklistEnforcer, MitigationManager
    from defense.capture import Flow, Finding
    bl = BlocklistEnforcer()
    mm = MitigationManager([bl])
    f = Finding("sqli", "high", "sqli pattern", matched="UNION SELECT",
                flow=Flow(src="10.0.0.9", service="web"))
    mm.mitigate(f)
    assert bl.allows(b"GET /normal") is True
    assert bl.allows(b"id=1 UNION SELECT pw") is False   # blocked

def test_blocklist_reversible():
    from defense.mitigation import BlocklistEnforcer, BlockRule
    bl = BlocklistEnforcer()
    bl.apply(BlockRule(rule_id="r1", kind="payload", pattern="BADPAT", reason="x"))
    assert bl.allows(b"has BADPAT") is False
    bl.remove("r1")
    assert bl.allows(b"has BADPAT") is True

def test_nft_emitter_emits_without_running():
    from defense.mitigation import NftEmitter, MitigationManager
    from defense.capture import Flow, Finding
    nft = NftEmitter(run=False)
    mm = MitigationManager([nft])
    f = Finding("cmd_injection", "critical", "ci", matched=";cat /flag",
                flow=Flow(src="10.0.0.5"))
    mm.mitigate(f)
    assert nft.emitted and "DROP" in nft.emitted[0]


# --- full flow reaches offense ----------------------------------------------

def test_exploit_observed_carries_full_flow():
    from defense.capture import QueueSource, Flow
    ctx = _ctx()
    got = []
    ctx.bus.subscribe(EXPLOIT_OBSERVED, lambda ev: got.append(ev))
    q = QueueSource()
    d = DefenseSubsystem(ctx, sources=[q])
    q.push(Flow(request=b"id=1' UNION SELECT secret--", response=b"", service="web", dst="10.0.0.1", port=80))
    d.tick()
    assert got and got[0].payload["request"] == b"id=1' UNION SELECT secret--"
    assert got[0].payload["service"] == "web"


# --- auto-mitigate policy ---------------------------------------------------

def test_auto_mitigate_installs_block():
    from defense.capture import QueueSource, Flow
    from defense.mitigation import BlocklistEnforcer, MitigationManager
    ctx = _ctx()
    bl = BlocklistEnforcer()
    q = QueueSource()
    d = DefenseSubsystem(ctx, sources=[q], mitigation=MitigationManager([bl]), auto_mitigate=True)
    q.push(Flow(request=b"name=x;cat /flag", service="web", dst="10.0.0.1", port=80))
    d.tick()
    assert bl.active_rules(), "auto-mitigate should have installed a block rule"


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
