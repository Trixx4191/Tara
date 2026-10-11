"""
Scope enforcement — the hard gate.

Every network-touching action in the agent must pass through a ScopePolicy
check before it runs. The policy is deny-by-default: a target is only reachable
if it is explicitly inside the configured competition scope.

This exists for two reasons that point the same way:
  1. Correctness — an attack-defense agent must only touch competition targets.
  2. Containment — a misfire that leaves the sandbox is how teams get
     disqualified, investigated, or fined. The gate makes that physically hard.

Hardening in this version:
  - IPv4-mapped IPv6 (::ffff:8.8.8.8) is normalised before the CIDR test, so it
    cannot be used to slip past an IPv4 allowlist.
  - resolve_and_check() resolves a hostname and checks EVERY resolved address,
    closing the "in-scope name, out-of-scope IP" (DNS rebinding) gap.
  - Special ranges (cloud metadata 169.254.169.254, link-local, CGNAT,
    multicast, reserved) are denied unless the exact address/host is explicitly
    allowlisted — even if a broad CIDR would otherwise include them.
  - from_config warns loudly on dangerously broad scope (e.g. a /0).

No "off" switch by design. Dry-run checks scope and logs instead of executing;
the check itself always runs.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field

log = logging.getLogger("ctf.scope")

IPAddr = "ipaddress.IPv4Address | ipaddress.IPv6Address"
IPNet = "ipaddress.IPv4Network | ipaddress.IPv6Network"

# Ranges that are almost never a legitimate CTF target and are dangerous to hit
# by accident. Denied unless the exact host/IP is explicitly in allowed_hosts.
_SPECIAL_DENY = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local incl. cloud metadata
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
    ipaddress.ip_network("100.64.0.0/10"),     # CGNAT
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("240.0.0.0/4"),       # reserved
    ipaddress.ip_network("ff00::/8"),          # IPv6 multicast
]


class ScopeViolation(Exception):
    """Raised when an action targets something outside the allowed scope."""


def normalize_ip(ip: "IPAddr") -> "IPAddr":
    """Collapse IPv4-mapped IPv6 to its IPv4 form so CIDR tests see the truth."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def is_onion(host: str) -> bool:
    return isinstance(host, str) and host.lower().split(":")[0].endswith(".onion")


def valid_onion(addr: str) -> bool:
    """A well-formed v2 (16-char) or v3 (56-char) base32 onion address."""
    name = addr.lower().split(":")[0]
    if not name.endswith(".onion"):
        return False
    label = name[: -len(".onion")]
    return bool(re.fullmatch(r"[a-z2-7]{16}|[a-z2-7]{56}", label))


@dataclass
class ScopePolicy:
    allowed_hosts: set[str] = field(default_factory=set)
    allowed_cidrs: list = field(default_factory=list)
    allowed_ports: set[int] = field(default_factory=set)
    allowed_paths: list[str] = field(default_factory=list)
    allowed_onions: set[str] = field(default_factory=set)   # explicit .onion allowlist
    dry_run: bool = False
    block_special: bool = True          # deny metadata/link-local/etc.
    resolve_check: bool = True          # resolve names and check resolved IPs

    @classmethod
    def from_config(cls, cfg: dict) -> "ScopePolicy":
        scope = cfg.get("scope", {})
        cidrs = []
        for c in scope.get("allowed_cidrs", []):
            try:
                cidrs.append(ipaddress.ip_network(c, strict=False))
            except ValueError as e:
                raise ValueError(f"bad CIDR in scope.allowed_cidrs: {c!r} ({e})")
        onions = set()
        for o in scope.get("allowed_onions", []):
            name = str(o).lower().split(":")[0]
            if not valid_onion(name):
                log.warning("ignoring malformed onion in scope.allowed_onions: %r", o)
                continue
            onions.add(name)
        policy = cls(
            allowed_hosts=set(scope.get("allowed_hosts", [])),
            allowed_cidrs=cidrs,
            allowed_ports=set(int(p) for p in scope.get("allowed_ports", [])),
            allowed_paths=list(scope.get("allowed_paths", [])),
            allowed_onions=onions,
            dry_run=bool(cfg.get("dry_run", False)),
            block_special=bool(scope.get("block_special", True)),
            resolve_check=bool(scope.get("resolve_check", True)),
        )
        policy._audit()
        return policy

    def _audit(self) -> None:
        if not self.allowed_hosts and not self.allowed_cidrs:
            log.warning(
                "Scope has no allowed hosts or CIDRs. Every network action will "
                "be denied until you populate scope.allowed_*. Safe default, not a bug."
            )
        for net in self.allowed_cidrs:
            # a /0, or anything bigger than a /8 for v4 / /32 for v6, is suspicious
            too_broad = (net.version == 4 and net.prefixlen < 8) or (
                net.version == 6 and net.prefixlen < 32
            )
            if net.prefixlen == 0 or too_broad:
                log.warning(
                    "DANGEROUSLY BROAD scope CIDR %s — this likely includes "
                    "targets outside the competition. Narrow it.", net
                )

    # --- predicates ---------------------------------------------------------

    def _is_special(self, ip: "IPAddr") -> bool:
        return any(ip in net for net in _SPECIAL_DENY)

    def _ip_in_cidrs(self, ip: "IPAddr") -> bool:
        ip = normalize_ip(ip)
        return any(ip in net for net in self.allowed_cidrs)

    def _host_allowed(self, host: str) -> bool:
        # An explicit allowlist entry always wins (even for special ranges).
        if host in self.allowed_hosts:
            return True
        try:
            ip = normalize_ip(ipaddress.ip_address(host))
        except ValueError:
            return False  # a bare hostname not explicitly listed is not allowed
        if self.block_special and self._is_special(ip):
            return False
        return self._ip_in_cidrs(ip)

    # --- the gate -----------------------------------------------------------

    def check_target(self, host: str, port: int | None = None) -> None:
        """String-level check (fast path). See resolve_and_check for the full one."""
        if not self._host_allowed(host):
            raise ScopeViolation(
                f"host {host!r} is outside competition scope — refusing. Add it to "
                f"scope.allowed_hosts/allowed_cidrs if it is a legitimate target."
            )
        self._check_port(host, port)
        log.debug("scope OK (string): %s:%s", host, port)

    def resolve_and_check(self, host: str, port: int | None = None) -> list[str]:
        """
        Resolve host and verify EVERY resolved address is in scope. Returns the
        list of approved IP strings (pin these for the actual connection to avoid
        a re-resolve race). Closes the DNS-rebinding gap.
        """
        # explicit host allowlist still has to resolve to something, but we trust
        # the name; for IP literals this is a no-op.
        self._check_port(host, port)
        try:
            ipaddress.ip_address(host)
            is_literal = True
        except ValueError:
            is_literal = False

        if is_literal:
            self.check_target(host, port)
            return [host]

        if host not in self.allowed_hosts and not self.resolve_check:
            # name not explicitly allowed and we're not resolving → refuse
            raise ScopeViolation(f"hostname {host!r} not in allowed_hosts")

        try:
            infos = socket.getaddrinfo(host, port)
        except socket.gaierror as e:
            raise ScopeViolation(f"cannot resolve {host!r}: {e}")

        resolved = sorted({info[4][0] for info in infos})
        if not resolved:
            raise ScopeViolation(f"{host!r} resolved to nothing")

        approved = []
        for addr in resolved:
            ip = normalize_ip(ipaddress.ip_address(addr))
            explicit = host in self.allowed_hosts
            if self.block_special and self._is_special(ip) and not explicit:
                raise ScopeViolation(
                    f"{host!r} resolves to special/metadata address {addr} — refusing"
                )
            if explicit or self._ip_in_cidrs(ip):
                approved.append(addr)
            else:
                raise ScopeViolation(
                    f"{host!r} resolves to {addr}, which is OUTSIDE scope "
                    f"(possible DNS rebinding) — refusing"
                )
        log.debug("scope OK (resolved): %s -> %s", host, approved)
        return approved

    def _check_port(self, host, port) -> None:
        if port is not None and self.allowed_ports and int(port) not in self.allowed_ports:
            raise ScopeViolation(
                f"port {port} on {host!r} is outside allowed ports "
                f"{sorted(self.allowed_ports)}"
            )

    def check_onion(self, host: str, port: int | None = None) -> None:
        """Gate a .onion target at the application layer.

        Tor resolves the onion name remotely inside the circuit, so the socket
        guard only ever sees the loopback Tor proxy — it cannot see this target.
        This is therefore the ONLY place onion scope is enforced, and it is
        deny-by-default: an onion must be explicitly in scope.allowed_onions.
        """
        name = host.lower().split(":")[0]
        if not valid_onion(name):
            raise ScopeViolation(f"{host!r} is not a well-formed onion address")
        if name not in self.allowed_onions:
            raise ScopeViolation(
                f"onion {name!r} is outside competition scope — refusing. Tor egress "
                f"is restricted to scope.allowed_onions, which keeps the agent on the "
                f"organiser's onion challenges and nothing else."
            )
        self._check_port(host, port)
        log.debug("scope OK (onion): %s:%s", name, port)

    def check_targets(self, targets: list[tuple[str, int | None]]) -> None:
        for host, port in targets:
            if is_onion(host):
                self.check_onion(host, port)
            elif self.resolve_check:
                self.resolve_and_check(host, port)
            else:
                self.check_target(host, port)

    def check_path(self, path: str) -> None:
        import os
        rp = os.path.realpath(path)
        for root in self.allowed_paths:
            rr = os.path.realpath(root)
            if rp == rr or rp.startswith(rr + os.sep):
                return
        raise ScopeViolation(f"path {path!r} is outside allowed roots {self.allowed_paths}")
