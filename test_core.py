"""
Smoke + hardening tests for the shared core. No API key needed.
Run: python test_core.py   (or: python -m pytest test_core.py)
"""

import ipaddress
import socket

from core.scope import ScopePolicy, ScopeViolation, normalize_ip
from core.state import StateStore, Flag
from core.toolrunner import ToolRunner
from core.netguard import NetworkGuard
from core.resilience import retry, LoopGuard
from tools.base import ToolRegistry, Tool, ToolResult


class FakeAttackTool(Tool):
    name = "fake_attack"
    description = "pretends to hit a host; used to test the gate"
    parameters = {"type": "object", "properties": {"host": {"type": "string"}}}

    def targets(self, host, **_):
        return [(host, 1337)]

    def run(self, host, **_):
        return ToolResult(ok=True, output=f"hit {host}")


class HangTool(Tool):
    name = "hang"
    description = "hangs forever; tests the runner timeout"
    parameters = {"type": "object", "properties": {}}

    def run(self, **_):
        import time
        time.sleep(30)
        return ToolResult(ok=True, output="done")


def _policy(resolve_check=False):
    cfg = {"scope": {
        "allowed_cidrs": ["10.60.0.0/16"],
        "allowed_hosts": ["checker.ctf"],
        "resolve_check": resolve_check,
    }}
    return ScopePolicy.from_config(cfg)


def _runner(resolve_check=False, timeout=120):
    state = StateStore("/tmp/ctf_test_state")
    reg = ToolRegistry()
    reg.register(FakeAttackTool())
    reg.register(HangTool())
    return ToolRunner(reg, _policy(resolve_check), state, default_timeout=timeout)


# --- scope basics -----------------------------------------------------------

def test_in_scope_allowed():
    assert _runner().run("fake_attack", {"host": "10.60.4.9"}).ok

def test_out_of_scope_refused():
    r = _runner().run("fake_attack", {"host": "8.8.8.8"})
    assert not r.ok and "scope refused" in r.output

def test_hostname_not_listed_refused():
    assert not _runner().run("fake_attack", {"host": "google.com"}).ok

def test_allowed_host_ok():
    assert _runner().run("fake_attack", {"host": "checker.ctf"}).ok


# --- hardening: IPv4-mapped IPv6 bypass -------------------------------------

def test_ipv4_mapped_normalized():
    # ::ffff:8.8.8.8 must NOT pass an IPv4 allowlist, and ::ffff:10.60.1.1 must.
    p = _policy()
    try:
        p.check_target("::ffff:8.8.8.8", 80)
        assert False, "mapped out-of-scope v6 should be refused"
    except ScopeViolation:
        pass
    p.check_target("::ffff:10.60.1.1", 80)  # in-scope mapped -> allowed

def test_normalize_ip():
    assert str(normalize_ip(ipaddress.ip_address("::ffff:1.2.3.4"))) == "1.2.3.4"


# --- hardening: special ranges ---------------------------------------------

def test_metadata_blocked_even_if_cidr_would_match():
    # a careless broad scope that includes metadata must still block it
    p = ScopePolicy.from_config({"scope": {"allowed_cidrs": ["169.254.0.0/16"]}})
    try:
        p.check_target("169.254.169.254", 80)
        assert False, "cloud metadata must be blocked"
    except ScopeViolation:
        pass

def test_special_explicit_override():
    # if the exact host is explicitly allowed, it's permitted
    p = ScopePolicy.from_config({"scope": {"allowed_hosts": ["169.254.169.254"]}})
    p.check_target("169.254.169.254", 80)  # no raise


# --- hardening: port gate ---------------------------------------------------

def test_port_gate():
    p = ScopePolicy.from_config({"scope": {"allowed_cidrs": ["10.0.0.0/8"], "allowed_ports": [9000]}})
    p.check_target("10.0.0.1", 9000)
    try:
        p.check_target("10.0.0.1", 22)
        assert False
    except ScopeViolation:
        pass


# --- hardening: runner timeout ---------------------------------------------

def test_tool_timeout():
    r = _runner(timeout=1).run("hang", {})
    assert not r.ok and "timed out" in r.output


# --- hardening: netguard IP decision ---------------------------------------

def test_netguard_blocks_out_of_scope():
    g = NetworkGuard(_policy(), control_hosts=[])
    try:
        g.authorize_ip("8.8.8.8", 443)
        assert False, "should block"
    except ScopeViolation:
        pass

def test_netguard_allows_in_scope():
    g = NetworkGuard(_policy(), control_hosts=[])
    g.authorize_ip("10.60.1.2", 9000)  # no raise

def test_netguard_allows_control_plane():
    g = NetworkGuard(_policy(), control_hosts=["203.0.113.5"])
    g.authorize_ip("203.0.113.5", 443)  # control-plane -> allowed

def test_netguard_blocks_metadata():
    g = NetworkGuard(ScopePolicy.from_config({"scope": {"allowed_cidrs": ["0.0.0.0/0"]}}))
    try:
        g.authorize_ip("169.254.169.254", 80)
        assert False
    except ScopeViolation:
        pass


# --- resilience -------------------------------------------------------------

def test_retry_succeeds_eventually():
    calls = {"n": 0}
    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("blip")
        return "ok"
    assert retry(flaky, attempts=5, base_delay=0.01) == "ok"
    assert calls["n"] == 3

def test_loop_guard_trips():
    g = LoopGuard(limit=3)
    assert g.record("t", {"a": 1}, ok=False) is False
    assert g.record("t", {"a": 1}, ok=False) is False
    assert g.record("t", {"a": 1}, ok=False) is True   # 3rd failure -> stuck

def test_loop_guard_resets_on_success():
    g = LoopGuard(limit=2)
    g.record("t", {}, ok=False)
    g.record("t", {}, ok=True)       # reset
    assert g.record("t", {}, ok=False) is False


# --- state ------------------------------------------------------------------

def test_flag_dedupe():
    import tempfile
    st = StateStore(tempfile.mkdtemp())
    assert st.record_flag(Flag(value="FLAG{abc}", source="t1")) is True
    assert st.record_flag(Flag(value="FLAG{abc}", source="t1")) is False

def test_state_rotate():
    import tempfile
    st = StateStore(tempfile.mkdtemp())
    for i in range(20):
        st.set("tool_log", f"{i:04d}_x", {"i": i})
    st.rotate("tool_log", keep=5)
    assert len(st.load("tool_log")) == 5


if __name__ == "__main__":
    import traceback
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
                passed += 1
            except Exception:
                print(f"FAIL {name}")
                traceback.print_exc()
                failed += 1
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(1 if failed else 0)
