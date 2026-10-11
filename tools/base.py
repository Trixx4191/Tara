"""
Tool interface + registry.

A Tool is something the agent can call: run a binary, send a request, read a
file. Every tool declares a JSON-schema for its arguments (so providers can
expose it as a function) and, crucially, a `targets()` method that reports which
(host, port) pairs the call will touch. The runner uses that to enforce scope
BEFORE the tool does anything.

Tools that touch nothing on the network return [] from targets() and skip the
gate. Tools that do must report honestly — a tool that lies about its targets is
a scope bypass, so keep that method dead simple and auditable.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ToolResult:
    ok: bool
    output: str
    meta: dict | None = None


class Tool(ABC):
    name: str = ""
    description: str = ""
    parameters: dict = {"type": "object", "properties": {}}

    def targets(self, **kwargs) -> list[tuple[str, int | None]]:
        """(host, port) pairs this invocation will touch. Default: none."""
        return []

    @abstractmethod
    def run(self, **kwargs) -> ToolResult:
        ...

    def spec(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }


class ToolRegistry:
    def __init__(self):
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        if not tool.name:
            raise ValueError("tool needs a name")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def specs(self) -> list[dict]:
        return [t.spec() for t in self._tools.values()]

    def __iter__(self):
        return iter(self._tools.values())
