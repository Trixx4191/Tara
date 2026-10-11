"""
NetworkGuard — socket-level egress enforcement (defense in depth).

The ScopePolicy gate in the ToolRunner is advisory: it only sees targets a tool
declares. This guard sits UNDER that, at the socket layer, so that every single
outbound TCP connection the process makes is checked against scope — whether a
tool declared it, forgot to, or a third-party library opened it. A tool that
lies about or omits its targets still cannot leave the sandbox.

Two planes, kept separate on purpose:
  - control plane: hosts the agent itself must reach to function (the LLM API,
    the outbound proxy, loopback). Allowed regardless of competition scope.
  - target plane: competition targets, governed entirely by the ScopePolicy.

Everything not in one of those two is denied at connect() time.

Install once at startup: NetworkGuard(policy, control_hosts).install().
It is process-wide and idempotent.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

from .scope import ScopePolicy, ScopeViolation, normalize_ip

log = logging.getLogger("ctf.netguard")

_ORIG_CONNECT = socket.socket.connect
_ORIG_GETADDRINFO = socket.getaddrinfo
_INSTALLED = {"on": False}


class NetworkGuard:
    def __init__(self, policy: ScopePolicy, control_hosts: list[str] | None = None):
        self.policy = policy
        # control-plane IPs/hosts the agent needs for itself
        self.control_hosts: set[str] = set(control_hosts or [])
        self.control_ips: set[str] = set()
        self._seed_defaults()

    def _seed_defaults(self) -> None:
        # loopback always allowed (local challenge services, local model server)
        for h in ("127.0.0.1", "::1", "localhost"):
            self.control_hosts.add(h)
        # outbound proxy, if the environment uses one
        for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            val = os.environ.get(var)
            if val:
                host = urlparse(val if "://" in val else "http://" + val).hostname
                if host:
                    self.control_hosts.add(host)
        # pre-resolve control hosts to IPs so connect-time checks are cheap/safe
        for h in list(self.control_hosts):
            try:
                ipaddress.ip_address(h)
                self.control_ips.add(h)
            except ValueError:
                try:
                    for info in _ORIG_GETADDRINFO(h, None):
                        self.control_ips.add(info[4][0])
                except socket.gaierror:
                    pass

    def add_control_host(self, host: str) -> None:
        """Permit a control-plane host (e.g. the configured LLM endpoint)."""
        self.control_hosts.add(host)
        try:
            ipaddress.ip_address(host)
            self.control_ips.add(host)
        except ValueError:
            try:
                for info in _ORIG_GETADDRINFO(host, None):
                    self.control_ips.add(info[4][0])
            except socket.gaierror:
                pass

    # --- the decision -------------------------------------------------------

    def _ip_is_control(self, addr: str) -> bool:
        if addr in self.control_ips:
            return True
        try:
            ip = normalize_ip(ipaddress.ip_address(addr))
        except ValueError:
            return False
        return str(ip) in self.control_ips

    def authorize_ip(self, addr: str, port: int | None) -> None:
        """Allow if control-plane or in competition scope; else raise."""
        if self._ip_is_control(addr):
            return
        # delegate to the policy's IP-level logic
        try:
            ip = normalize_ip(ipaddress.ip_address(addr))
        except ValueError:
            raise ScopeViolation(f"egress to non-IP {addr!r} blocked")
        if self.policy.block_special and self.policy._is_special(ip):
            raise ScopeViolation(f"egress to special address {addr} blocked")
        if self.policy._ip_in_cidrs(ip) or str(ip) in self.policy.allowed_hosts:
            self.policy._check_port(addr, port)
            return
        raise ScopeViolation(
            f"egress to {addr}:{port} blocked — not control-plane and not in scope"
        )

    # --- installation -------------------------------------------------------

    def install(self) -> None:
        if _INSTALLED["on"]:
            log.debug("netguard already installed")
            return
        guard = self

        def guarded_connect(self_sock, address):
            try:
                host = address[0]
                port = address[1] if len(address) > 1 else None
                guard.authorize_ip(host, port)
            except ScopeViolation as v:
                log.warning("EGRESS BLOCKED %s: %s", address, v)
                raise OSError(f"egress blocked by scope guard: {v}")
            except Exception:
                # never let the guard itself crash a connection silently-open;
                # if we can't reason about it, block it.
                log.warning("EGRESS BLOCKED (unparseable) %s", address)
                raise OSError("egress blocked by scope guard: unparseable address")
            return _ORIG_CONNECT(self_sock, address)

        def guarded_getaddrinfo(host, *a, **k):
            infos = _ORIG_GETADDRINFO(host, *a, **k)
            # filter to control-plane + in-scope; if nothing survives, block
            kept = []
            for info in infos:
                addr = info[4][0]
                try:
                    guard.authorize_ip(addr, info[4][1] if len(info[4]) > 1 else None)
                    kept.append(info)
                except ScopeViolation:
                    continue
            if not kept:
                raise socket.gaierror(f"all addresses for {host!r} blocked by scope guard")
            return kept

        socket.socket.connect = guarded_connect
        socket.getaddrinfo = guarded_getaddrinfo
        _INSTALLED["on"] = True
        log.info(
            "netguard installed: %d control IPs, %d scope CIDRs",
            len(self.control_ips), len(self.policy.allowed_cidrs),
        )

    @staticmethod
    def uninstall() -> None:
        socket.socket.connect = _ORIG_CONNECT
        socket.getaddrinfo = _ORIG_GETADDRINFO
        _INSTALLED["on"] = False
