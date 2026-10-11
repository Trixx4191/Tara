"""
A scoped TCP probe — the reference example of a network tool done right.

It does one honest thing: open a TCP connection to (host, port), optionally send
a payload, read a short banner/response, and return it. The whole reason it is
here is to demonstrate the contract: `targets()` reports exactly what `run()`
will touch, so the ScopePolicy can approve or refuse it before a packet leaves.

Every richer offense/defense tool added later (service health checks, exploit
launchers, traffic replay) follows this same shape.
"""

from __future__ import annotations

import socket

from .base import Tool, ToolResult


class TcpProbe(Tool):
    name = "tcp_probe"
    description = (
        "Open a TCP connection to an in-scope host:port, optionally send bytes, "
        "and read the response. Used for service discovery and health checks."
    )
    parameters = {
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "target host or IP"},
            "port": {"type": "integer", "description": "target port"},
            "send": {"type": "string", "description": "optional data to send first"},
            "timeout": {"type": "number", "default": 5},
            "read_bytes": {"type": "integer", "default": 2048},
        },
        "required": ["host", "port"],
    }

    def targets(self, host, port, **_):
        return [(host, int(port))]

    def run(self, host, port, send="", timeout=5, read_bytes=2048, **_):
        try:
            with socket.create_connection((host, int(port)), timeout=timeout) as s:
                s.settimeout(timeout)
                if send:
                    s.sendall(send.encode() if isinstance(send, str) else send)
                data = b""
                try:
                    data = s.recv(read_bytes)
                except socket.timeout:
                    pass
            return ToolResult(
                ok=True,
                output=data.decode(errors="replace"),
                meta={"bytes": len(data), "host": host, "port": port},
            )
        except OSError as e:
            return ToolResult(ok=False, output=f"connect failed: {e}")
