"""
AgentContext — the shared spine handed to every subsystem.

Bundles the core services (provider, tool runner, state, event bus, scope, and
the service inventory) so a subsystem takes a single ctx rather than a fistful
of arguments. Subsystems reach the LLM, run tools, read/write state, and
publish/subscribe to events all through here — and through nothing that belongs
to the other subsystem.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.scope import ScopePolicy
from core.state import StateStore
from core.toolrunner import ToolRunner
from core.bus import EventBus
from providers.base import LLMProvider


@dataclass
class Service:
    """A competition service — defended by us, and (same shape) attacked on others."""
    name: str
    host: str
    port: int
    proto: str = "tcp"                 # tcp | http
    health_path: str = "/"             # for http
    checker: str | None = None         # command that verifies the service works
    source_dir: str | None = None      # local path to the service's code, if we have it
    meta: dict = field(default_factory=dict)


@dataclass
class AgentContext:
    provider: LLMProvider
    runner: ToolRunner
    state: StateStore
    bus: EventBus
    scope: ScopePolicy
    services: dict[str, Service] = field(default_factory=dict)
    config: dict = field(default_factory=dict)

    def add_service(self, svc: Service) -> None:
        self.services[svc.name] = svc

    def service_list(self) -> list[Service]:
        return list(self.services.values())
