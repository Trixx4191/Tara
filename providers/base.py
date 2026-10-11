"""
Provider-agnostic LLM interface.

The reasoning loop talks to whatever model drives it through this one small
surface. Concrete providers (Anthropic, OpenAI, a local Ollama/vLLM server)
implement `complete`. Swapping them is a config change, not a code change —
which matters when the competition network is air-gapped and you fall back to a
local model.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class Message:
    role: str                       # "system" | "user" | "assistant" | "tool"
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None  # for role="tool" results


@dataclass
class Completion:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: object = None               # provider-native response, for debugging


class LLMProvider(ABC):
    """One method to implement. Keep provider quirks behind it."""

    name: str = "base"

    @abstractmethod
    def complete(
        self,
        messages: list[Message],
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> Completion:
        """Run one turn. Return assistant text and any tool calls it wants."""
        raise NotImplementedError
