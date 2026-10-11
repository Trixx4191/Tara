"""Anthropic provider — Claude via the Messages API with tool use."""

from __future__ import annotations

import logging

from .base import LLMProvider, Message, Completion, ToolCall

log = logging.getLogger("ctf.provider.anthropic")


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self, model: str, api_key: str | None = None, base_url: str | None = None):
        try:
            import anthropic
        except ImportError as e:
            raise RuntimeError("pip install anthropic") from e
        kwargs = {}
        if api_key:
            kwargs["api_key"] = api_key
        if base_url:
            kwargs["base_url"] = base_url
        self._client = anthropic.Anthropic(**kwargs)
        self.model = model

    def _split(self, messages: list[Message]):
        """Anthropic takes system separately and interleaves tool results."""
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        out = []
        for m in messages:
            if m.role == "system":
                continue
            if m.role == "tool":
                out.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": m.tool_call_id,
                        "content": m.content,
                    }],
                })
            elif m.role == "assistant" and m.tool_calls:
                blocks = []
                if m.content:
                    blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    blocks.append({
                        "type": "tool_use", "id": tc.id,
                        "name": tc.name, "input": tc.arguments,
                    })
                out.append({"role": "assistant", "content": blocks})
            else:
                out.append({"role": m.role, "content": m.content})
        return system, out

    def complete(self, messages, tools=None, max_tokens=4096, temperature=0.2):
        system, msgs = self._split(messages)
        req = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": msgs,
        }
        if system:
            req["system"] = system
        if tools:
            req["tools"] = [self._tool_schema(t) for t in tools]
        resp = self._client.messages.create(**req)

        text, calls = "", []
        for block in resp.content:
            if block.type == "text":
                text += block.text
            elif block.type == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, arguments=block.input))
        return Completion(text=text, tool_calls=calls, raw=resp)

    @staticmethod
    def _tool_schema(t: dict) -> dict:
        # Our internal tool spec -> Anthropic schema.
        return {
            "name": t["name"],
            "description": t.get("description", ""),
            "input_schema": t.get("parameters", {"type": "object", "properties": {}}),
        }
