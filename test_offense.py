"""
Offense tests against a real loopback HTTP server serving a flag.
No external network, no model.
Run: python test_offense.py
"""

import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from core.scope import ScopePolicy
from core.state import StateStore
from core.toolrunner import ToolRunner
from core.bus import EventBus, EXPLOIT_OBSERVED, FLAG_CAPTURED
from core.context import AgentContext, Service
from tools.base import ToolRegistry
from tools.http_tool import HttpRequest
from tools.net_probe import TcpProbe
from offense.solver import SolverRegistry, Exploit
from offense.replay import ReplayEngine
from offense.targets import TargetProvider, Target
from offense.flagsink import FlagSink, StdoutSink, FileSink, SubmitResult
from offense.offense import OffenseSubsystem
from offense.solvers.web import WebSolver

FLAG = "CTF{deadbeef}"
FLAG_FMT = r"CTF\{[0-9a-f]+\}"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/flag" or "UNION" in self.path or "../" in self.path:
            self.send_response(200); self.end_headers()
            self.wfile.write(f"here you go: {FLAG}".encode())
        else:
            self.send_response(200); self.end_headers()
            self.wfile.write(b"nothing here")


def _server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _ctx(port):
    scope = ScopePolicy.from_config({"scope": {"allowed_cidrs": ["127.0.0.0/8"], "resolve_check": False}})
    state = StateStore(tempfile.mkdtemp())
    reg = ToolRegistry()
    reg.register(HttpRequest()); reg.register(TcpProbe())
    runner = ToolRunner(reg, scope, state, default_timeout=10)
    ctx = AgentContext(_FakeProvider(), runner, state, EventBus(), scope,
                       config={"state_dir": state.root,
                               "targets": {"web": [{"host": "127.0.0.1", "port": port}]}})
    # defended service lives on a different host so loopback targets aren't filtered as "self"
    ctx.add_service(Service(name="web", host="10.9.9.9", port=port, proto="http"))
    return ctx


class _FakeProvider:
    name = "fake"
    def complete(self, *a, **k):
        from providers.base import Completion
        return Completion(text="x")


# --- flag sink --------------------------------------------------------------

def test_sink_rejects_bad_format():
    s = StdoutSink(flag_format=FLAG_FMT)
    assert s.offer("not a flag").status == "invalid"

def test_sink_dedupes():
    st = StateStore(tempfile.mkdtemp())
    s = StdoutSink(state=st, flag_format=FLAG_FMT)
    assert s.offer(FLAG).status == "accepted"
    assert s.offer(FLAG).status == "duplicate"

def test_filesink_writes():
    st = StateStore(tempfile.mkdtemp())
    path = tempfile.mktemp()
    s = FileSink(path, state=st, flag_format=FLAG_FMT)
    assert s.offer(FLAG).status == "accepted"
    with open(path) as f:
        assert FLAG in f.read()


# --- targets ----------------------------------------------------------------

def test_target_provider_scope_filtered():
    port = 9000
    ctx = _ctx(port)
    ctx.config["targets"]["web"] = [
        {"host": "127.0.0.1", "port": port},
        {"host": "8.8.8.8", "port": port},      # out of scope -> dropped
    ]
    tp = TargetProvider(ctx)
    hosts = [t.host for t in tp.targets_for("web")]
    assert "127.0.0.1" in hosts and "8.8.8.8" not in hosts


# --- web solver: discovery --------------------------------------------------

def test_web_solver_discovers_flag():
    srv, port = _server()
    try:
        ctx = _ctx(port)
        solver = WebSolver(flag_format=FLAG_FMT)
        res = solver.solve(ctx, ctx.services["web"], Target("127.0.0.1", port))
        assert res.ok and FLAG in res.flags and res.exploit is not None
    finally:
        srv.shutdown()


# --- replay engine: fire across targets, submit -----------------------------

def test_replay_engine_fires_and_submits():
    srv, port = _server()
    try:
        ctx = _ctx(port)
        reg = SolverRegistry(); reg.register(WebSolver(flag_format=FLAG_FMT))
        sink = StdoutSink(state=ctx.state, flag_format=FLAG_FMT)
        submit = lambda f, s, m: sink.offer(f, source=s, meta=m).status
        engine = ReplayEngine(ctx, submit, reg, TargetProvider(ctx), flag_format=FLAG_FMT)
        exploit = Exploit(id="x1", category="web", service="web",
                          spec={"method": "GET", "path": "/flag"})
        result = engine.fire(exploit)
        assert result["ok"] and result["flags"] == 1
    finally:
        srv.shutdown()


def test_raw_replay_via_tcp():
    srv, port = _server()
    try:
        ctx = _ctx(port)
        reg = SolverRegistry()      # no solver -> engine uses raw tcp replay
        sink = StdoutSink(state=ctx.state, flag_format=FLAG_FMT)
        submit = lambda f, s, m: sink.offer(f, source=s, meta=m).status
        engine = ReplayEngine(ctx, submit, reg, TargetProvider(ctx), flag_format=FLAG_FMT)
        raw = b"GET /flag HTTP/1.0\r\nHost: x\r\n\r\n"
        exploit = Exploit(id="x2", category="misc", service="web", request=raw)
        result = engine.fire(exploit)
        assert result["flags"] == 1
    finally:
        srv.shutdown()


# --- offense subsystem: bus bridge (defense -> offense) ---------------------

def test_offense_consumes_exploit_observed():
    srv, port = _server()
    try:
        ctx = _ctx(port)
        reg = SolverRegistry(); reg.register(WebSolver(flag_format=FLAG_FMT))
        sink = StdoutSink(state=ctx.state, flag_format=FLAG_FMT)
        off = OffenseSubsystem(ctx, sink, solvers=reg, flag_format=FLAG_FMT, discover=False)
        off.setup()   # subscribe
        caught = []
        ctx.bus.subscribe(FLAG_CAPTURED, lambda ev: caught.append(ev))
        # defense publishes a captured web attack (raw request)
        ctx.bus.publish(EXPLOIT_OBSERVED, {
            "rule": "sqli", "service": "web", "category": "web",
            "request": b"GET /flag HTTP/1.0\r\nHost: x\r\n\r\n",
            "severity": "high",
        }, source="defense")
        off.tick()     # drains queue, fires -> flag goes to REVIEW (default)
        # default is human-in-the-loop: nothing submitted, one flag pending
        assert off.review.pending(), "captured flag should be queued for review, not auto-submitted"
        assert off.review.pending()[0]["flag"] == FLAG
        assert caught and caught[0].payload["review"] is True
    finally:
        srv.shutdown()


def test_offense_auto_submit_opt_in():
    srv, port = _server()
    try:
        ctx = _ctx(port)
        reg = SolverRegistry(); reg.register(WebSolver(flag_format=FLAG_FMT))
        sink = StdoutSink(state=ctx.state, flag_format=FLAG_FMT)
        off = OffenseSubsystem(ctx, sink, solvers=reg, flag_format=FLAG_FMT,
                               discover=False, auto_submit=True)
        off.setup()
        ctx.bus.publish(EXPLOIT_OBSERVED, {"rule": "sqli", "service": "web", "category": "web",
            "request": b"GET /flag HTTP/1.0\r\nHost: x\r\n\r\n", "severity": "high"}, source="defense")
        off.tick()
        # with auto_submit on, it submits directly and nothing waits for review
        assert off.review.pending() == []
        assert off.review.counts().get("submitted", 0) == 0  # submitted via sink, not queue
    finally:
        srv.shutdown()


# --- review queue: approve / reject -----------------------------------------

def test_review_approve_submits():
    ctx = _ctx(9000)
    from offense.review import ReviewQueue
    sink = StdoutSink(state=ctx.state, flag_format=FLAG_FMT)
    q = ReviewQueue(sink, ctx.state, FLAG_FMT)
    assert q.enqueue(FLAG, source="web@10.0.0.1") == "pending"
    assert len(q.pending()) == 1
    fid = q.pending()[0]["id"]
    res = q.approve(fid)
    assert res["ok"] and res["status"] == "submitted"
    assert q.pending() == []                        # no longer pending
    assert q.counts()["submitted"] == 1

def test_review_reject_does_not_submit():
    ctx = _ctx(9000)
    sink = StdoutSink(state=ctx.state, flag_format=FLAG_FMT)
    from offense.review import ReviewQueue
    q = ReviewQueue(sink, ctx.state, FLAG_FMT)
    q.enqueue(FLAG, source="x")
    fid = q.pending()[0]["id"]
    assert q.reject(fid)["ok"]
    assert q.pending() == [] and q.counts()["rejected"] == 1
    # the flag was never recorded as submitted
    assert ctx.state.load("flags").get("items", {}) == {}

def test_review_rejects_invalid_and_duplicate():
    ctx = _ctx(9000)
    sink = StdoutSink(state=ctx.state, flag_format=FLAG_FMT)
    from offense.review import ReviewQueue
    q = ReviewQueue(sink, ctx.state, FLAG_FMT)
    assert q.enqueue("not a flag", source="x") == "invalid"
    assert q.enqueue(FLAG, source="x") == "pending"
    assert q.enqueue(FLAG, source="x") == "duplicate"

def test_review_approve_all():
    ctx = _ctx(9000)
    sink = StdoutSink(state=ctx.state, flag_format=FLAG_FMT)
    from offense.review import ReviewQueue
    q = ReviewQueue(sink, ctx.state, FLAG_FMT)
    for v in ["CTF{aaaa1111}", "CTF{bbbb2222}", "CTF{cccc3333}"]:
        q.enqueue(v, source="x")
    r = q.approve_all()
    assert r["approved"] == 3 and q.pending() == []


# --- offense subsystem: standalone discovery --------------------------------

def test_offense_standalone_discovery():
    srv, port = _server()
    try:
        ctx = _ctx(port)
        reg = SolverRegistry(); reg.register(WebSolver(flag_format=FLAG_FMT))
        sink = StdoutSink(state=ctx.state, flag_format=FLAG_FMT)
        off = OffenseSubsystem(ctx, sink, solvers=reg, flag_format=FLAG_FMT,
                               discover=True, discover_every=1)
        off.setup()
        off.tick()     # tick 1: discover -> enqueue exploit
        off.tick()     # tick 2: drain -> fire -> flag to review
        assert off.review.pending(), "standalone discovery should queue a flag for review"
    finally:
        srv.shutdown()


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
