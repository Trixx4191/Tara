"""
TargetProvider — enumerate the instances of a service to attack, scope-filtered.

In attack-defense every team runs the same services, so "exploit service X" means
firing at X on every team's host. This turns a service into its list of target
instances, drawn from config, and — critically — filters them through the scope
policy, so the engine can only ever enumerate in-scope targets. An out-of-scope
host simply isn't returned.

Config shapes supported (per service, under config['targets'][service_name]):
  - explicit list:   [{"host": "10.60.1.2", "port": 9000}, ...]
  - a range + port:  {"cidr": "10.60.0.0/24", "port": 9000, "skip": ["10.60.0.1"]}
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass

from core.scope import ScopeViolation

log = logging.getLogger("ctf.targets")


@dataclass
class Target:
    host: str
    port: int
    team: str = ""


class TargetProvider:
    def __init__(self, ctx):
        self.ctx = ctx

    def _raw(self, service_name: str) -> list[Target]:
        spec = self.ctx.config.get("targets", {}).get(service_name)
        svc = self.ctx.services.get(service_name)
        default_port = svc.port if svc else 0
        out: list[Target] = []
        if spec is None:
            return out
        if isinstance(spec, list):
            for item in spec:
                out.append(Target(item["host"], int(item.get("port", default_port)),
                                  item.get("team", "")))
        elif isinstance(spec, dict) and "cidr" in spec:
            port = int(spec.get("port", default_port))
            skip = set(spec.get("skip", []))
            for ip in ipaddress.ip_network(spec["cidr"], strict=False).hosts():
                if str(ip) in skip:
                    continue
                out.append(Target(str(ip), port, team=str(ip)))
        return out

    def targets_for(self, service_name: str, include_self: bool = False) -> list[Target]:
        """In-scope targets for a service. Out-of-scope hosts are dropped silently."""
        result = []
        for t in self._raw(service_name):
            try:
                # string-level check is enough here; the guard re-checks at connect
                self.ctx.scope.check_target(t.host, t.port)
            except ScopeViolation:
                log.debug("target %s:%s out of scope, skipping", t.host, t.port)
                continue
            result.append(t)
        if not include_self:
            own = {s.host for s in self.ctx.service_list()}
            result = [t for t in result if t.host not in own]
        return result
