"""
HttpRequest — a scoped HTTP tool for web exploitation and replay.

Declares its target so the gate/guard see it, like every network tool. Returns
status, headers, and body so a solver can look for a flag in the response.
"""

from __future__ import annotations

import http.client
import urllib.parse

from tools.base import Tool, ToolResult


class HttpRequest(Tool):
    name = "http_request"
    description = (
        "Send an HTTP request to an in-scope service and return status/headers/body. "
        "Used for web exploitation and for replaying captured web attacks."
    )
    timeout = 20
    parameters = {
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "port": {"type": "integer", "default": 80},
            "method": {"type": "string", "default": "GET"},
            "path": {"type": "string", "default": "/"},
            "headers": {"type": "object", "default": {}},
            "body": {"type": "string", "default": ""},
            "timeout": {"type": "number", "default": 8},
        },
        "required": ["host"],
    }

    def targets(self, host, port=80, **_):
        return [(host, int(port))]

    def run(self, host, port=80, method="GET", path="/", headers=None, body="", timeout=8, **_):
        headers = headers or {}
        try:
            conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
            conn.request(method.upper(), path, body=body or None, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(65536)
            hdrs = dict(resp.getheaders())
            conn.close()
            text = raw.decode("latin-1", "replace")
            return ToolResult(
                ok=True,
                output=f"HTTP {resp.status}\n{text}",
                meta={"status": resp.status, "headers": hdrs, "body": text, "host": host, "port": int(port)},
            )
        except OSError as e:
            return ToolResult(ok=False, output=f"request failed: {e}")

    @staticmethod
    def encode_params(params: dict) -> str:
        return urllib.parse.urlencode(params)
