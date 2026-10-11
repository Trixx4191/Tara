"""
FlagSink — where captured flags go, abstracted from how they're submitted.

A competition scores flags through some mechanism: an HTTP scoreboard API, a TCP
submission port, a file the organiser reads, stdout for a dry run. The offense
engine shouldn't care which — it just hands flags to a FlagSink. Swap the sink
per competition; nothing else changes. (This is the deliberate anti-lock-in
point: no scoreboard API is wired into the engine itself.)

Every sink runs validation + dedupe first: a token is only submitted if it
matches the known flag format and hasn't been submitted before. That keeps
hallucinated or duplicate "flags" out of the submission stream.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass

from defense.assurance import validate_flag

log = logging.getLogger("ctf.flagsink")


@dataclass
class SubmitResult:
    status: str          # accepted | rejected | duplicate | invalid | error
    detail: str = ""


class FlagSink(ABC):
    def __init__(self, state=None, flag_format: str | None = None):
        self.state = state
        self.flag_format = flag_format

    def offer(self, flag: str, source: str = "", meta: dict | None = None) -> SubmitResult:
        """Validate + dedupe, then submit. The single entry point to use."""
        flag = (flag or "").strip()
        if not validate_flag(flag, self.flag_format):
            return SubmitResult("invalid", "does not match flag format")
        if self.state is not None:
            from core.state import Flag as FlagRec
            is_new = self.state.record_flag(FlagRec(value=flag, source=source), flag_format=self.flag_format)
            if not is_new:
                return SubmitResult("duplicate", "already seen")
        try:
            res = self.submit(flag, meta or {})
        except Exception as e:
            log.exception("sink submit failed")
            return SubmitResult("error", str(e))
        if self.state is not None:
            self.state.mark_submitted(flag, accepted=(res.status == "accepted"))
        return res

    @abstractmethod
    def submit(self, flag: str, meta: dict) -> SubmitResult:
        ...


class StdoutSink(FlagSink):
    def submit(self, flag, meta):
        print(f"[FLAG] {flag}  {meta}")
        return SubmitResult("accepted", "printed")


class FileSink(FlagSink):
    def __init__(self, path, state=None, flag_format=None):
        super().__init__(state, flag_format)
        self.path = path

    def submit(self, flag, meta):
        with open(self.path, "a") as f:
            f.write(flag + "\n")
        return SubmitResult("accepted", f"appended to {self.path}")


class CallbackSink(FlagSink):
    """Wrap any submit function — this is where a real scoreboard client plugs in.

    fn(flag, meta) -> str status ("accepted"/"rejected"/...). The network call it
    makes still goes through the scope guard if it uses the runner's tools.
    """
    def __init__(self, fn, state=None, flag_format=None):
        super().__init__(state, flag_format)
        self.fn = fn

    def submit(self, flag, meta):
        status = self.fn(flag, meta)
        return SubmitResult(status if isinstance(status, str) else "accepted")
