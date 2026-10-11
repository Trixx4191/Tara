"""Build the configured provider from config. One place that knows the names.

If the configured provider can't be built (missing SDK, missing key, or kind
"none"), fall back to NoneProvider so the agent and GUI still boot — monitoring
and replay don't need a model, and the operator gets a clear note instead of a
crashed process.
"""

from __future__ import annotations

import logging
import os

from .base import LLMProvider

log = logging.getLogger("ctf.provider")


def build_provider(cfg: dict) -> LLMProvider:
    p = cfg.get("llm", {})
    kind = p.get("provider", "anthropic").lower()
    model = p.get("model")
    api_key = p.get("api_key") or os.environ.get(p.get("api_key_env", ""), None)
    base_url = p.get("base_url")

    if kind in ("none", "off", ""):
        from .none_provider import NoneProvider
        return NoneProvider()

    try:
        if kind == "anthropic":
            from .anthropic_provider import AnthropicProvider
            if not api_key and not base_url:
                raise RuntimeError("no API key configured")
            return AnthropicProvider(model=model or "claude-sonnet-4-5", api_key=api_key, base_url=base_url)
        if kind in ("openai", "local", "vllm", "ollama"):
            from .openai_provider import OpenAIProvider
            if kind == "ollama" and not base_url:
                base_url = "http://localhost:11434/v1"
            return OpenAIProvider(model=model or "gpt-4o", api_key=api_key, base_url=base_url)
        raise ValueError(f"unknown llm.provider {kind!r}")
    except Exception as e:
        from .none_provider import NoneProvider
        log.warning("LLM provider %r unavailable (%s); falling back to no-model mode", kind, e)
        return NoneProvider()
