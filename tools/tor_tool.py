"""
Tor transport tools — reach onion-hosted challenges, nothing else.

Some organisers host challenges as Tor onion services, so the agent needs to
connect over Tor. These tools do exactly that and no more:

  - They route through Tor's SOCKS proxy with REMOTE name resolution
    (rdns=True / SOCKS5h), because an onion address has no DNS — Tor resolves it
    inside the circuit.
  - Every call declares its onion target, so the runner's onion scope check runs
    FIRST. Tor egress is deny-by-default and limited to scope.allowed_onions.
    This is the only layer that can gate an onion target (the socket guard sees
    only the loopback Tor proxy), so it matters that these tools route through
    the gated runner and never open a bare socket themselves.

This is onion *reachability*, deliberately not traffic anonymisation: it cannot
send attacks at clearnet targets through Tor, only reach allowlisted onions.
"""

from __future__ import annotations

import logging

from tools.base import Tool, ToolResult

log = logging.getLogger("ctf.tor")

DEFAULT_SOCKS_HOST = "127.0.0.1"
DEFAULT_SOCKS_PORT = 9050        # Tor daemon default (Tor Browser bundle uses 9150)


class TorTransport:
    """Opens TCP connections to onion services through the Tor SOCKS proxy."""
    def __init__(self, socks_host: str = DEFAULT_SOCKS_HOST, socks_port: int = DEFAULT_SOCKS_PORT):
        self.socks_host = socks_host
        self.socks_port = int(socks_port)

    @staticmethod
    def available() -> bool:
        try:
            import socks  # PySocks  # noqa
            return True
        except Exception:
            return False

    def open(self, host: str, port: int, timeout: float = 15):
        import socks  # PySocks
        s = socks.socksocket()
        # rdns=True -> the onion name is resolved by Tor, not locally (SOCKS5h)
        s.set_proxy(socks.SOCKS5, self.socks_host, self.socks_port, rdns=True)
        s.settimeout(timeout)
        s.connect((host, int(port)))
        return s


class _TorTool(Tool):
    """Base for tor tools; holds an injectable transport (for testing)."""
    def __init__(self, transport: TorTransport | None = None):
        self.transport = transport or TorTransport()


class TorTcp(_TorTool):
    name = "tor_tcp"
    description = ("Open a raw TCP connection to an in-scope .onion service through Tor, "
                  "optionally send data, and read the response.")
    timeout = 40
    parameters = {
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "a .onion address"},
            "port": {"type": "integer"},
            "send": {"type": "string", "default": ""},
            "read_bytes": {"type": "integer", "default": 4096},
            "timeout": {"type": "number", "default": 15},
        },
        "required": ["host", "port"],
    }

    def targets(self, host, port, **_):
        return [(host, int(port))]

    def run(self, host, port, send="", read_bytes=4096, timeout=15, **_):
        if not self.transport.available():
            return ToolResult(ok=False, output="Tor support needs PySocks (pip install pysocks) and a running Tor daemon")
        try:
            s = self.transport.open(host, int(port), timeout)
            try:
                if send:
                    s.sendall(send.encode() if isinstance(send, str) else send)
                data = b""
                try:
                    data = s.recv(read_bytes)
                except Exception:
                    pass
            finally:
                s.close()
            return ToolResult(ok=True, output=data.decode("latin-1", "replace"),
                              meta={"bytes": len(data), "onion": host})
        except Exception as e:
            return ToolResult(ok=False, output=f"tor connect failed: {e}")


class TorHttpRequest(_TorTool):
    name = "tor_http_request"
    description = ("Send an HTTP request to an in-scope .onion service through Tor and return "
                  "status/body. Used to reach onion-hosted web challenges.")
    timeout = 60
    parameters = {
        "type": "object",
        "properties": {
            "host": {"type": "string", "description": "a .onion address"},
            "port": {"type": "integer", "default": 80},
            "method": {"type": "string", "default": "GET"},
            "path": {"type": "string", "default": "/"},
            "headers": {"type": "object", "default": {}},
            "body": {"type": "string", "default": ""},
            "timeout": {"type": "number", "default": 20},
        },
        "required": ["host"],
    }

    def targets(self, host, port=80, **_):
        return [(host, int(port))]

    def run(self, host, port=80, method="GET", path="/", headers=None, body="", timeout=20, **_):
        if not self.transport.available():
            return ToolResult(ok=False, output="Tor support needs PySocks (pip install pysocks) and a running Tor daemon")
        headers = dict(headers or {})
        headers.setdefault("Host", host)
        headers.setdefault("Connection", "close")
        req = f"{method.upper()} {path} HTTP/1.1\r\n"
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
        if body:
            req += f"Content-Length: {len(body)}\r\n"
        req += "\r\n" + (body or "")
        try:
            s = self.transport.open(host, int(port), timeout)
            try:
                s.sendall(req.encode("latin-1", "replace"))
                chunks = []
                while True:
                    try:
                        b = s.recv(8192)
                    except Exception:
                        break
                    if not b:
                        break
                    chunks.append(b)
                    if sum(len(c) for c in chunks) > 262144:
                        break
            finally:
                s.close()
            raw = b"".join(chunks).decode("latin-1", "replace")
            status = 0
            if raw.startswith("HTTP/"):
                try:
                    status = int(raw.split(" ", 2)[1])
                except (IndexError, ValueError):
                    pass
            body_text = raw.split("\r\n\r\n", 1)[1] if "\r\n\r\n" in raw else raw
            return ToolResult(ok=True, output=raw,
                              meta={"status": status, "body": body_text, "onion": host})
        except Exception as e:
            return ToolResult(ok=False, output=f"tor http failed: {e}")
