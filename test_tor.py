"""
Tor / onion scope + transport tests. No Tor daemon, no network (fake transport).
Run: python test_tor.py
"""

import tempfile

from core.scope import ScopePolicy, ScopeViolation, is_onion, valid_onion
from core.state import StateStore
from core.toolrunner import ToolRunner
from tools.base import ToolRegistry
from tools.tor_tool import TorTcp, TorHttpRequest

V3 = "a" * 56 + ".onion"            # well-formed v3 onion (base32 a-z2-7)
V3_OTHER = "b" * 56 + ".onion"
FLAG = "FLAG{onion_reached}"


# --- onion address helpers --------------------------------------------------

def test_is_onion():
    assert is_onion(V3) and is_onion("x.onion:80")
    assert not is_onion("example.com") and not is_onion("10.0.0.1")

def test_valid_onion():
    assert valid_onion(V3) is True
    assert valid_onion("a" * 16 + ".onion") is True           # v2
    assert valid_onion("short.onion") is False
    assert valid_onion(("A" * 56 + ".onion")) is True         # case-insensitive (normalized)
    assert valid_onion("notonion") is False


# --- scope onion gate (deny-by-default) -------------------------------------

def test_onion_denied_by_default():
    s = ScopePolicy.from_config({"scope": {"allowed_cidrs": ["10.0.0.0/8"]}})
    try:
        s.check_onion(V3, 80)
        assert False, "onion must be denied when not allowlisted"
    except ScopeViolation:
        pass

def test_onion_allowed_when_listed():
    s = ScopePolicy.from_config({"scope": {"allowed_onions": [V3]}})
    s.check_onion(V3, 80)        # no raise

def test_onion_malformed_rejected():
    s = ScopePolicy.from_config({"scope": {"allowed_onions": [V3]}})
    try:
        s.check_onion("bad.onion", 80)
        assert False
    except ScopeViolation:
        pass

def test_malformed_onion_in_config_ignored():
    s = ScopePolicy.from_config({"scope": {"allowed_onions": ["bad.onion", V3]}})
    assert V3 in s.allowed_onions and "bad.onion" not in s.allowed_onions

def test_check_targets_routes_onion():
    s = ScopePolicy.from_config({"scope": {"allowed_onions": [V3]}})
    s.check_targets([(V3, 80)])                  # allowed
    try:
        s.check_targets([(V3_OTHER, 80)])        # not listed
        assert False
    except ScopeViolation:
        pass


# --- fake transport so tools run without a Tor daemon -----------------------

class FakeSocket:
    def __init__(self, response: bytes):
        self._resp = response
        self.sent = b""
    def sendall(self, data): self.sent += data
    def recv(self, n):
        out, self._resp = self._resp[:n], self._resp[n:]
        return out
    def settimeout(self, t): pass
    def close(self): pass

class FakeTransport:
    def __init__(self, response: bytes):
        self.response = response
        self.opened = []
    @staticmethod
    def available(): return True
    def open(self, host, port, timeout=15):
        self.opened.append((host, port))
        return FakeSocket(self.response)


def _runner(allowed_onions):
    scope = ScopePolicy.from_config({"scope": {"allowed_onions": allowed_onions}})
    state = StateStore(tempfile.mkdtemp())
    reg = ToolRegistry()
    return reg, ToolRunner(reg, scope, state, default_timeout=10)


# --- tor tools through the gated runner -------------------------------------

def test_tor_tcp_in_scope_connects():
    reg, runner = _runner([V3])
    ft = FakeTransport(response=f"banner {FLAG}".encode())
    reg.register(TorTcp(ft))
    res = runner.run("tor_tcp", {"host": V3, "port": 1337, "send": "hi"})
    assert res.ok and FLAG in res.output
    assert ft.opened == [(V3, 1337)]        # it actually tried to connect via tor

def test_tor_tcp_out_of_scope_refused_before_connect():
    reg, runner = _runner([V3])             # only V3 allowed
    ft = FakeTransport(response=b"should not happen")
    reg.register(TorTcp(ft))
    res = runner.run("tor_tcp", {"host": V3_OTHER, "port": 1337})
    assert not res.ok and "scope refused" in res.output
    assert ft.opened == []                   # gate stopped it before any connection

def test_tor_http_parses_response():
    reg, runner = _runner([V3])
    http_resp = (f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>{FLAG}</html>").encode()
    ft = FakeTransport(response=http_resp)
    reg.register(TorHttpRequest(ft))
    res = runner.run("tor_http_request", {"host": V3, "port": 80, "path": "/flag"})
    assert res.ok and res.meta["status"] == 200 and FLAG in res.meta["body"]

def test_tor_refused_clearnet_host():
    # a clearnet host handed to a tor tool is not an onion -> treated as normal
    # target and denied (no onion allowlist entry, no cidr) — proving tor tools
    # can't be used to reach non-onion targets out of scope.
    reg, runner = _runner([V3])
    ft = FakeTransport(response=b"x")
    reg.register(TorTcp(ft))
    res = runner.run("tor_tcp", {"host": "8.8.8.8", "port": 80})
    assert not res.ok and ft.opened == []


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
