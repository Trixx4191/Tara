"""
Service health — the single most point-relevant thing in defense.

In attack-defense, a service that is DOWN loses you SLA points every tick no
matter how well you've patched it. So the first job of defense is simply knowing,
continuously, whether each of your services is answering correctly.

ServiceHealthTool does one check against one in-scope service (TCP connect, or an
HTTP request) and reports up/down + latency. It's a normal Tool, so it runs
through the gated runner and the LLM can also invoke it directly.
"""

from __future__ import annotations

import http.client
import socket
import time

from tools.base import Tool, ToolResult


class ServiceHealthTool(Tool):
    name = "service_health"
    description = (
        "Check whether an in-scope service is up. proto 'tcp' does a connect (and "
        "optional banner read); proto 'http' does a GET and checks the status code."
    )
    timeout = 15
    parameters = {
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer"},
            "proto": {"type": "string", "enum": ["tcp", "http"], "default": "tcp"},
            "path": {"type": "string", "default": "/"},
            "expect_status": {"type": "integer", "default": 200},
            "timeout": {"type": "number", "default": 5},
        },
        "required": ["host", "port"],
    }

    def targets(self, host, port, **_):
        return [(host, int(port))]

    def run(self, host, port, proto="tcp", path="/", expect_status=200, timeout=5, **_):
        port = int(port)
        start = time.time()
        try:
            if proto == "http":
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
                conn.request("GET", path)
                resp = conn.getresponse()
                body = resp.read(4096)
                conn.close()
                up = resp.status == expect_status
                latency = round((time.time() - start) * 1000, 1)
                return ToolResult(
                    ok=up,
                    output=f"HTTP {resp.status} in {latency}ms ({len(body)}B)",
                    meta={"up": up, "status": resp.status, "latency_ms": latency},
                )
            else:
                with socket.create_connection((host, port), timeout=timeout) as s:
                    s.settimeout(timeout)
                    try:
                        banner = s.recv(256)
                    except socket.timeout:
                        banner = b""
                latency = round((time.time() - start) * 1000, 1)
                return ToolResult(
                    ok=True,
                    output=f"TCP up in {latency}ms, banner={banner[:64]!r}",
                    meta={"up": True, "latency_ms": latency, "banner": banner.decode(errors="replace")},
                )
        except OSError as e:
            latency = round((time.time() - start) * 1000, 1)
            return ToolResult(
                ok=False,
                output=f"DOWN: {e} (after {latency}ms)",
                meta={"up": False, "error": str(e), "latency_ms": latency},
            )
