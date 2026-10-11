"""
NoneProvider — a no-model fallback so the agent (and the GUI) still boots when no
LLM is configured or its SDK/key is missing.

Defense monitoring, detection, patching, offense replay and flag submission do
not need a model — only the ad-hoc reasoning loop does. Rather than crash at
startup without a key, we fall back to this: it answers every turn with a plain
note and never requests a tool, so the loop ends immediately and the operator
sees why instead of a dead process.
"""

from __future__ import annotations

from .base import LLMProvider, Completion

_MSG = ("[no LLM configured] This Tara instance is running without a model, so "
        "the reasoning loop is disabled. Monitoring, detection, patching and "
        "replay still work. Set llm.provider + a key (or a local model) to enable "
        "ad-hoc agent tasks.")


class NoneProvider(LLMProvider):
    name = "none"

    def complete(self, messages, tools=None, max_tokens=4096, temperature=0.2):
        return Completion(text=_MSG, tool_calls=[])
