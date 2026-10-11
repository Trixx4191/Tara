"""
The reasoning loop.

think -> (maybe) call a tool -> observe -> think again, until the model stops
asking for tools or the iteration cap is hit.

Resilience added:
  - provider.complete is wrapped in retry+backoff so a transient API/network
    blip doesn't kill a run.
  - message history is trimmed (keeping the system prompt + a recent window) so
    a long competition doesn't overflow the model's context.
  - a LoopGuard halts the model if it hammers the same failing tool call,
    instead of burning the whole tick on a dead end.

Autonomy is a dial, not a capability switch: it only governs how far the loop
runs before pausing for a human. It changes nothing about what tools can do.
"""

from __future__ import annotations

import logging

from core.toolrunner import ToolRunner
from core.resilience import retry, LoopGuard
from providers.base import LLMProvider, Message

log = logging.getLogger("ctf.agent")


class Agent:
    def __init__(
        self,
        provider: LLMProvider,
        runner: ToolRunner,
        system_prompt: str,
        autonomy: str = "auto",
        max_iters: int = 25,
        on_step=None,
        history_window: int = 60,   # max non-system messages kept in context
    ):
        self.provider = provider
        self.runner = runner
        self.autonomy = autonomy
        self.max_iters = max_iters
        self.on_step = on_step
        self.history_window = history_window
        self.system = Message(role="system", content=system_prompt)
        self.messages: list[Message] = [self.system]
        self.loop_guard = LoopGuard(limit=3)

    def _trim(self) -> None:
        """Keep system prompt + the most recent history_window messages.

        Trims at a safe boundary so a tool result is never separated from the
        assistant turn that requested it (which would break providers).
        """
        body = self.messages[1:]
        if len(body) <= self.history_window:
            return
        cut = len(body) - self.history_window
        # advance cut until the first kept message is not an orphan tool result
        while cut < len(body) and body[cut].role == "tool":
            cut += 1
        self.messages = [self.system] + body[cut:]
        log.debug("trimmed history, dropped %d messages", cut)

    def _complete(self, tool_specs):
        return retry(
            lambda: self.provider.complete(self.messages, tools=tool_specs),
            attempts=4, base_delay=1.5,
        )

    def run(self, task: str) -> str:
        self.messages.append(Message(role="user", content=task))
        tool_specs = self.runner.registry.specs()

        for i in range(self.max_iters):
            self._trim()
            try:
                comp = self._complete(tool_specs)
            except Exception as e:
                log.error("provider failed after retries: %s", e)
                return f"[provider error: {e}]"

            self.messages.append(
                Message(role="assistant", content=comp.text, tool_calls=comp.tool_calls)
            )

            if not comp.tool_calls:
                log.info("agent finished after %d iters", i + 1)
                return comp.text

            for call in comp.tool_calls:
                if self.autonomy == "step" and self.on_step:
                    if not self.on_step(call.name, call.arguments):
                        return (comp.text or "") + "\n[halted by operator]"

                log.info("-> %s %s", call.name, call.arguments)
                result = self.runner.run(call.name, call.arguments)

                content = result.output[:8000] if result.output else "(no output)"
                if self.loop_guard.record(call.name, call.arguments, result.ok):
                    content += (
                        "\n\n[loop guard] This exact call has failed repeatedly. "
                        "Stop retrying it; try a different approach or report the blocker."
                    )
                self.messages.append(
                    Message(role="tool", tool_call_id=call.id, content=content)
                )

        return "[reached max iterations]"
