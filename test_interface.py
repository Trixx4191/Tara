"""
Operator GUI tests: console snapshot/controls + a live loopback server round-trip.
No external network, no model.
Run: python test_interface.py
"""

import json
import tempfile
import urllib.request

from core.scope import ScopePolicy
from core.state import StateStore
from core.toolrunner import ToolRunner
from core.bus import EventBus
from core.context import AgentContext, Service
from core.orchestrator import Orchestrator
from tools.base import ToolRegistry
from defense.health import ServiceHealthTool
from defense.defense import DefenseSubsystem
from defense.mitigation import MitigationManager, BlocklistEnforcer, BlockRule
from interface.console import Console
from interface.server import ConsoleServer


class FakeProvider:
    name = "fake"
    def complete(self, *a, **k):
        from providers.base import Completion
        return Completion(text="x")


def _ctx():
    scope = ScopePolicy.from_config({"scope": {"allowed_cidrs": ["127.0.0.0/8"], "resolve_check": False}})
    state = StateStore(tempfile.mkdtemp())
    reg = ToolRegistry(); reg.register(ServiceHealthTool())
    runner = ToolRunner(reg, scope, state, default_timeout=5)
    return AgentContext(FakeProvider(), runner, state, EventBus(), scope, config={"state_dir": state.root})


def _orch_with_defense(ctx, mitig=None):
    orch = Orchestrator(ctx)
    orch.add(DefenseSubsystem(ctx, mitigation=mitig or MitigationManager([BlocklistEnforcer()])))
    return orch


# --- console snapshot -------------------------------------------------------

def test_snapshot_shape():
    ctx = _ctx()
    ctx.add_service(Service(name="web", host="10.0.0.1", port=80, proto="http"))
    c = Console(ctx, _orch_with_defense(ctx))
    snap = c.snapshot()
    for key in ("ts", "agent", "subsystems", "services", "findings", "mitigations", "flags"):
        assert key in snap, f"missing {key}"
    assert snap["agent"]["name"] == "Tara"
    assert snap["services"][0]["name"] == "web"
    assert snap["flags"]["total"] == 0

def test_snapshot_reads_findings_and_flags():
    ctx = _ctx()
    ctx.state.set("findings", "000001", {"rule": "sqli", "severity": "high",
                                         "reason": "x", "score": 0.72, "confirmed": True})
    from core.state import Flag
    ctx.state.record_flag(Flag(value="FLAG{abc}", source="t"))
    ctx.state.mark_submitted("FLAG{abc}", accepted=True)
    c = Console(ctx, _orch_with_defense(ctx))
    snap = c.snapshot()
    assert snap["findings"][0]["rule"] == "sqli" and snap["findings"][0]["confirmed"] is True
    assert snap["flags"]["total"] == 1 and snap["flags"]["accepted"] == 1


# --- console controls -------------------------------------------------------

def test_control_start_stop_defense():
    ctx = _ctx()
    orch = _orch_with_defense(ctx)
    c = Console(ctx, orch)
    assert c.control("start_defense")["ok"] is True
    assert orch._subs["defense"].running is True
    assert c.control("stop_defense")["ok"] is True
    assert orch._subs["defense"].running is False

def test_control_unknown_action():
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    assert c.control("launch_nukes")["ok"] is False

def test_control_start_missing_subsystem():
    ctx = _ctx()
    c = Console(ctx, Orchestrator(ctx))   # no offense configured
    assert c.control("start_offense")["ok"] is False

def test_add_and_remove_service():
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    r = c.control("add_service", {"name": "web", "host": "10.60.1.2", "port": 9000, "proto": "http"})
    assert r["ok"] and "web" in ctx.services
    assert c.control("add_service", {"name": "web", "host": "x", "port": 1})["ok"] is False  # dup
    assert c.control("remove_service", {"name": "web"})["ok"] and "web" not in ctx.services

def test_add_target_in_and_out_of_scope():
    ctx = _ctx()  # scope allows 127.0.0.0/8 only
    c = Console(ctx, _orch_with_defense(ctx))
    inr = c.control("add_target", {"service": "web", "host": "127.0.0.9", "port": 9000})
    assert inr["ok"] and inr["in_scope"] is True
    outr = c.control("add_target", {"service": "web", "host": "8.8.8.8", "port": 9000})
    assert outr["ok"] and outr["in_scope"] is False and "OUT of scope" in outr["note"]
    # both stored, but snapshot/enumeration will skip the out-of-scope one
    assert len(ctx.config["targets"]["web"]) == 2

def test_remove_target():
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    c.control("add_target", {"service": "web", "host": "127.0.0.9", "port": 9000})
    assert c.control("remove_target", {"service": "web", "host": "127.0.0.9"})["ok"]
    assert ctx.config["targets"]["web"] == []

def test_scope_add_cidr_and_onion():
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    assert c.control("scope_add", {"kind": "cidr", "value": "10.60.0.0/16"})["ok"]
    assert any(str(n) == "10.60.0.0/16" for n in ctx.scope.allowed_cidrs)
    assert c.control("scope_add", {"kind": "cidr", "value": "not-a-cidr"})["ok"] is False
    v3 = "a" * 56 + ".onion"
    assert c.control("scope_add", {"kind": "onion", "value": v3})["ok"]
    assert v3 in ctx.scope.allowed_onions
    assert c.control("scope_add", {"kind": "onion", "value": "bad.onion"})["ok"] is False

def test_scope_add_makes_target_in_scope():
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    out = c.control("add_target", {"service": "web", "host": "10.60.1.5", "port": 9000})
    assert out["in_scope"] is False
    c.control("scope_add", {"kind": "cidr", "value": "10.60.0.0/16"})
    # now the same host checks in-scope
    assert c._target_in_scope("10.60.1.5", 9000) is True

def test_set_options():
    ctx = _ctx()
    orch = _orch_with_defense(ctx)
    c = Console(ctx, orch)
    assert c.control("set_option", {"dry_run": True})["ok"] and ctx.scope.dry_run is True
    assert c.control("set_option", {"auto_mitigate": True})["ok"]
    assert orch._subs["defense"].auto_mitigate is True
    assert c.control("set_option", {"flag_format": r"X\{\w+\}"})["ok"]
    assert ctx.config["flag_format"] == r"X\{\w+\}"

def test_run_task_no_model_returns_note():
    import time as _t
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    r = c.control("run_task", {"task": "probe something"})
    assert r["ok"] and r["task_id"]
    for _ in range(50):
        tl = c.task_list()
        if tl and tl[0]["status"] in ("done", "error"):
            break
        _t.sleep(0.02)
    assert c.task_list()[0]["status"] == "done"

def test_snapshot_has_all_sections():
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    snap = c.snapshot()
    for k in ("targets", "scope", "options", "tasks", "chat"):
        assert k in snap, f"snapshot missing {k}"
    assert "cidrs" in snap["scope"] and "flag_format" in snap["options"]
    assert "messages" in snap["chat"] and "busy" in snap["chat"]


# --- chat: live conversation with the agent ---------------------------------

def test_chat_send_and_reply():
    import time as _t
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    assert c.control("chat_send", {"message": "what do you see?"})["ok"]
    for _ in range(100):
        if not c.chat()["busy"]:
            break
        _t.sleep(0.02)
    msgs = c.chat()["messages"]
    assert msgs[0]["role"] == "user" and msgs[0]["content"] == "what do you see?"
    assert msgs[-1]["role"] == "assistant" and msgs[-1]["content"]

def test_chat_empty_rejected():
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    assert c.control("chat_send", {"message": "  "})["ok"] is False

def test_chat_context_persists_across_turns():
    import time as _t
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    for m in ("first", "second"):
        c.control("chat_send", {"message": m})
        for _ in range(100):
            if not c.chat()["busy"]:
                break
            _t.sleep(0.02)
    # same persistent agent instance reused (context carried across turns)
    assert c._chat_agent is not None
    roles = [m["role"] for m in c.chat()["messages"]]
    assert roles == ["user", "assistant", "user", "assistant"]

def test_chat_busy_rejects_concurrent():
    import threading, time as _t
    ctx = _ctx()
    gate = threading.Event()
    class SlowProvider:
        name = "slow"
        def complete(self, *a, **k):
            gate.wait(2)
            from providers.base import Completion
            return Completion(text="done")
    ctx.provider = SlowProvider()
    c = Console(ctx, _orch_with_defense(ctx))
    assert c.control("chat_send", {"message": "one"})["ok"]           # starts, busy
    _t.sleep(0.05)
    r2 = c.control("chat_send", {"message": "two"})                    # should bounce
    assert r2["ok"] is False and "wait" in r2["error"]
    gate.set()
    for _ in range(100):
        if not c.chat()["busy"]:
            break
        _t.sleep(0.02)
    assert not c.chat()["busy"]

def test_chat_clear():
    import time as _t
    ctx = _ctx()
    c = Console(ctx, _orch_with_defense(ctx))
    c.control("chat_send", {"message": "hi"})
    for _ in range(100):
        if not c.chat()["busy"]:
            break
        _t.sleep(0.02)
    assert c.chat()["messages"]
    assert c.control("chat_clear")["ok"]
    assert c.chat()["messages"] == [] and c._chat_agent is None

def test_control_drop_rule():
    ctx = _ctx()
    bl = BlocklistEnforcer()
    bl.apply(BlockRule(rule_id="r1", kind="payload", pattern="BADPAT", reason="x"))
    ctx.state.set("mitigations", "r1", {"kind": "payload", "pattern": "BADPAT", "reason": "x"})
    orch = _orch_with_defense(ctx, mitig=MitigationManager([bl]))
    c = Console(ctx, orch)
    assert bl.allows(b"has BADPAT") is False
    res = c.control("drop_rule", {"rule_id": "r1"})
    assert res["ok"] and bl.allows(b"has BADPAT") is True
    assert "r1" not in ctx.state.load("mitigations")


# --- server: refuses non-loopback bind --------------------------------------

def test_server_refuses_public_bind():
    ctx = _ctx()
    try:
        ConsoleServer(Console(ctx, _orch_with_defense(ctx)), host="0.0.0.0")
        assert False, "should refuse to bind to 0.0.0.0"
    except ValueError:
        pass


# --- live loopback round-trip -----------------------------------------------

def test_live_server_snapshot_and_control():
    ctx = _ctx()
    ctx.add_service(Service(name="web", host="10.0.0.1", port=80, proto="http"))
    orch = _orch_with_defense(ctx)
    srv = ConsoleServer(Console(ctx, orch), host="127.0.0.1", port=0, token="secret")
    srv.start()
    try:
        base = f"http://127.0.0.1:{srv.port}"
        # auth enforced
        req = urllib.request.Request(base + "/api/snapshot")
        try:
            urllib.request.urlopen(req, timeout=3)
            assert False, "expected 403 without token"
        except urllib.error.HTTPError as e:
            assert e.code == 403
        # with token
        req = urllib.request.Request(base + "/api/snapshot", headers={"X-Tara-Token": "secret"})
        snap = json.loads(urllib.request.urlopen(req, timeout=3).read())
        assert snap["agent"]["name"] == "Tara" and snap["services"][0]["name"] == "web"
        # control: start defense
        body = json.dumps({"action": "start_defense"}).encode()
        req = urllib.request.Request(base + "/api/control", data=body, method="POST",
                                     headers={"X-Tara-Token": "secret", "Content-Type": "application/json"})
        res = json.loads(urllib.request.urlopen(req, timeout=3).read())
        assert res["ok"] and orch._subs["defense"].running is True
        # index page serves
        html = urllib.request.urlopen(base + "/", timeout=3).read().decode().lower()
        assert "tara" in html and "services" in html
        # bundled font serves from the static subdir with the right content-type
        fr = urllib.request.urlopen(base + "/static/fonts/plex-mono-400.woff2", timeout=3)
        assert fr.status == 200 and fr.headers.get("Content-Type") == "font/woff2"
        assert len(fr.read()) > 1000
        # path traversal on static is refused
        try:
            urllib.request.urlopen(base + "/static/../server.py", timeout=3)
            assert False, "traversal should be blocked"
        except urllib.error.HTTPError as e:
            assert e.code == 404
    finally:
        orch.stop()
        srv.stop()


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
