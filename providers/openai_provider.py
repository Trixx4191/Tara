"""
OpenAI-compatible provider.

Works for OpenAI itself and for any server that speaks the OpenAI chat API —
which includes vLLM, Ollama (via its OpenAI-compat endpoint), LM Studio, etc.
So this single class doubles as the local-model fallback: point base_url at
http://localhost:11434/v1 (Ollama) or your vLLM server and set the model name.
"""

from __future__ import annotations

import json
import logging

from .base import LLMProvider, Message, Completion, ToolCall

log = logging.getLogger("ctf.provider.openai")


class OpenAIProvider(LLMProvider):
    name = "openai"

    def __init__(self, model: str, api_key: str | None = None, base_url: str | None = None):
        try:
            import openai
        except ImportError as e:
            raise RuntimeError("pip install openai") from e
        self._client = openai.OpenAI(
            api_key=api_key or "not-needed-for-local",
            base_url=base_url,
        )
        self.model = model

    def _convert(self, messages: list[Message]):
        out = []
        for m in messages:
            if m.role == "tool":
                out.append({
                    "role": "tool",
                    "tool_call_id": m.tool_call_id,
                    "content": m.content,
                })
            elif m.role == "assistant" and m.tool_calls:
                out.append({
                    "role": "assistant",
                    "content": m.content or None,
                    "tool_calls": [{
                        "id": tc.id, "type": "function",
                        "function": {"name": tc.name, "arguments": json.dumps(tc.arguments)},
                    } for tc in m.tool_calls],
                })
            else:
                out.append({"role": m.role, "content": m.content})
        return out

    def complete(self, messages, tools=None, max_tokens=4096, temperature=0.2):
        req = {
            "model": self.model,
            "messages": self._convert(messages),
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools:
            req["tools"] = [{
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("parameters", {"type": "object", "properties": {}}),
                },
            } for t in tools]
        resp = self._client.chat.completions.create(**req)
        msg = resp.choices[0].message
        calls = []
        for tc in (msg.tool_calls or []):
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))
        return Completion(text=msg.content or "", tool_calls=calls, raw=resp)
