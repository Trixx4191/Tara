"""
GUI server — a loopback-only HTTP server that serves the console frontend and a
small JSON API over a Console facade.

Binds to 127.0.0.1 by design: it is an operator surface, not a network service,
and must never be reachable from the game network. (It's loopback, which the
NetworkGuard already treats as control-plane.) No external dependencies — pure
stdlib — so it runs wherever Tara runs with no build step.

API:
  GET  /                -> the dashboard page
  GET  /api/snapshot    -> full live snapshot (JSON)
  POST /api/control     -> {"action": "...", "params": {...}} operator actions
"""

from __future__ import annotations

import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("ctf.ui")

_STATIC = os.path.join(os.path.dirname(__file__), "static")


def make_handler(console, token: str | None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet; we have our own logging
            pass

        def _auth_ok(self) -> bool:
            if not token:
                return True
            return self.headers.get("X-Tara-Token") == token

        def _send(self, code, body, ctype="application/json"):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                return self._serve_static("index.html", "text/html; charset=utf-8")
            if self.path.startswith("/static/"):
                rel = self.path[len("/static/"):].split("?", 1)[0].lstrip("/")
                return self._serve_static(rel, self._ctype(self.path))
            if self.path == "/api/snapshot":
                if not self._auth_ok():
                    return self._send(403, json.dumps({"error": "forbidden"}))
                return self._send(200, json.dumps(console.snapshot(), default=str))
            return self._send(404, json.dumps({"error": "not found"}))

        def do_POST(self):
            if self.path != "/api/control":
                return self._send(404, json.dumps({"error": "not found"}))
            if not self._auth_ok():
                return self._send(403, json.dumps({"error": "forbidden"}))
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._send(400, json.dumps({"error": "bad json"}))
            result = console.control(payload.get("action", ""), payload.get("params"))
            return self._send(200 if result.get("ok") else 400, json.dumps(result, default=str))

        def _serve_static(self, name, ctype):
            path = os.path.realpath(os.path.join(_STATIC, name))
            # traversal guard: resolved path must stay under the static root
            if os.path.commonpath([_STATIC, path]) != _STATIC or not os.path.isfile(path):
                return self._send(404, json.dumps({"error": "not found"}))
            with open(path, "rb") as f:
                self._send(200, f.read(), ctype)

        @staticmethod
        def _ctype(path):
            if path.endswith(".css"):
                return "text/css"
            if path.endswith(".js"):
                return "application/javascript"
            if path.endswith(".woff2"):
                return "font/woff2"
            if path.endswith(".woff"):
                return "font/woff"
            return "application/octet-stream"

    return Handler


class ConsoleServer:
    def __init__(self, console, host: str = "127.0.0.1", port: int = 8787, token: str | None = None):
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError(
                f"ConsoleServer refuses to bind to {host!r}: the operator GUI is "
                f"loopback-only by design and must not be exposed to the network."
            )
        self.console = console
        self.host = host
        self.port = port
        self.token = token
        self._httpd = None
        self._thread = None

    def start(self) -> None:
        handler = make_handler(self.console, self.token)
        self._httpd = ThreadingHTTPServer((self.host, self.port), handler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True, name="tara-ui")
        self._thread.start()
        authnote = "token required" if self.token else "no token (loopback trust)"
        log.info("Tara console on http://%s:%d  (%s)", self.host, self.port, authnote)

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
