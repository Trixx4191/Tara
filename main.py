"""
Entrypoint — wires the whole agent together.

Two modes:

  # run the live loop: defense, offense, or both (the competition mode)
  python main.py --config config/default.yaml --mode both
  python main.py --mode defense
  python main.py --mode offense

  # run a single ad-hoc agent task against the tools (debugging / one-offs)
  python main.py --task "probe 10.60.4.9:9000 and report what service it is"

The orchestrator runs each subsystem on its own thread; they coordinate only
through the EventBus, so any mode is valid. Everything network-touching runs
through the scoped runner and the socket-level egress guard.
"""

from __future__ import annotations

import argparse
import logging
from urllib.parse import urlparse

import yaml

from core.scope import ScopePolicy
from core.state import StateStore
from core.toolrunner import ToolRunner
from core.agent import Agent
from core.netguard import NetworkGuard
from core.bus import EventBus
from core.context import AgentContext, Service
from core.orchestrator import Orchestrator
from providers.registry import build_provider
from tools.base import ToolRegistry
from tools.net_probe import TcpProbe
from tools.http_tool import HttpRequest
from tools.tor_tool import TorTcp, TorHttpRequest, TorTransport
from defense.health import ServiceHealthTool
from defense.defense import DefenseSubsystem
from defense.mitigation import MitigationManager, BlocklistEnforcer
from offense.offense import OffenseSubsystem
from offense.solver import SolverRegistry
from offense.solvers.web import WebSolver
from offense.flagsink import StdoutSink, FileSink

_PROVIDER_HOSTS = {"anthropic": "api.anthropic.com", "openai": "api.openai.com"}

SYSTEM_PROMPT = """You are a CTF competition agent operating ONLY inside a \
sandboxed, authorized attack-defense competition environment. Every target you \
touch must be in the configured scope; the runner enforces this and refuses \
out-of-scope actions. Work methodically: probe, hypothesise, test, iterate. \
Report findings and any flags clearly."""


def _install_guard(cfg, scope):
    if not cfg.get("scope", {}).get("enforce_egress", True):
        return
    guard = NetworkGuard(scope, control_hosts=cfg.get("scope", {}).get("control_hosts", []))
    llm = cfg.get("llm", {})
    base_url = llm.get("base_url")
    host = urlparse(base_url).hostname if base_url else _PROVIDER_HOSTS.get(
        llm.get("provider", "anthropic").lower())
    if host:
        guard.add_control_host(host)
    # the Tor SOCKS proxy is control-plane: the agent connects to it, and Tor
    # (not our socket) reaches the onion. Onion scope is enforced separately.
    tor = cfg.get("tor", {})
    if tor.get("enabled"):
        guard.add_control_host(tor.get("socks_host", "127.0.0.1"))
    guard.install()


def _build_tools(cfg):
    reg = ToolRegistry()
    reg.register(TcpProbe())
    reg.register(HttpRequest())
    reg.register(ServiceHealthTool())
    tor = cfg.get("tor", {})
    if tor.get("enabled"):
        transport = TorTransport(tor.get("socks_host", "127.0.0.1"), tor.get("socks_port", 9050))
        reg.register(TorTcp(transport))
        reg.register(TorHttpRequest(transport))
    return reg


def build_context(cfg: dict) -> AgentContext:
    scope = ScopePolicy.from_config(cfg)
    state = StateStore(cfg.get("state_dir", "./state"))
    _install_guard(cfg, scope)
    provider = build_provider(cfg)
    registry = _build_tools(cfg)
    runner = ToolRunner(registry, scope, state)
    ctx = AgentContext(provider=provider, runner=runner, state=state,
                       bus=EventBus(), scope=scope, config=cfg)
    for s in cfg.get("services", []):
        ctx.add_service(Service(**s))
    return ctx


def build_defense(ctx, cfg):
    dcfg = cfg.get("defense", {})
    mitig = MitigationManager([BlocklistEnforcer()])
    return DefenseSubsystem(
        ctx, interval=dcfg.get("interval", 5.0),
        flag_format=cfg.get("flag_format"),
        checker_allowlist=dcfg.get("checker_allowlist", []),
        mitigation=mitig, auto_mitigate=dcfg.get("auto_mitigate", False),
    )


def build_offense(ctx, cfg):
    ocfg = cfg.get("offense", {})
    solvers = SolverRegistry()
    solvers.register(WebSolver(flag_format=cfg.get("flag_format")))
    # more category solvers register here as they're built (pwn/crypto/rev)
    sink_path = ocfg.get("flag_file")
    sink = (FileSink(sink_path, state=ctx.state, flag_format=cfg.get("flag_format"))
            if sink_path else StdoutSink(state=ctx.state, flag_format=cfg.get("flag_format")))
    return OffenseSubsystem(
        ctx, sink, interval=ocfg.get("interval", 10.0), solvers=solvers,
        flag_format=cfg.get("flag_format"), discover=ocfg.get("discover", True),
        auto_submit=ocfg.get("auto_submit", False),   # default: operator reviews flags first
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/default.yaml")
    ap.add_argument("--mode", choices=["defense", "offense", "both"], default=None)
    ap.add_argument("--task", default=None, help="run a single agent task instead of the loop")
    ap.add_argument("--ui", action="store_true", help="serve the operator GUI (loopback only)")
    ap.add_argument("--ui-port", type=int, default=8787)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    ctx = build_context(cfg)

    if args.task:
        agent = Agent(ctx.provider, ctx.runner, SYSTEM_PROMPT,
                      autonomy=cfg.get("agent", {}).get("autonomy", "auto"),
                      max_iters=cfg.get("agent", {}).get("max_iters", 25))
        print(agent.run(args.task))
        return

    from tara import banner
    logging.getLogger("ctf").info(banner())

    mode = args.mode or "both"
    orch = Orchestrator(ctx)
    if mode in ("defense", "both"):
        orch.add(build_defense(ctx, cfg))
    if mode in ("offense", "both"):
        orch.add(build_offense(ctx, cfg))
    names = None if mode == "both" else [mode]
    logging.getLogger("ctf").info("starting mode=%s", mode)

    ui_server = None
    if args.ui or cfg.get("ui", {}).get("enabled"):
        from interface.console import Console
        from interface.server import ConsoleServer
        ui = cfg.get("ui", {})
        console = Console(ctx, orch)
        ui_server = ConsoleServer(console, host=ui.get("host", "127.0.0.1"),
                                  port=args.ui_port or ui.get("port", 8787),
                                  token=ui.get("token"))
        ui_server.start()

    try:
        orch.run_forever(names)
    finally:
        if ui_server:
            ui_server.stop()


if __name__ == "__main__":
    main()
