"""
State store — durable, per-service / per-target scratchpads.

Both halves of the agent (offense working a target, defense working a service)
need somewhere to keep notes, confirmed vulns, working exploits, and captured
flags without stepping on each other. This is a small JSON-backed store keyed by
namespace, flushed to disk so a crash mid-competition doesn't lose progress.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field, asdict

log = logging.getLogger("ctf.state")


@dataclass
class Flag:
    value: str
    source: str          # where it came from (target host / challenge name)
    submitted: bool = False
    accepted: bool | None = None
    first_seen: float = field(default_factory=time.time)


class StateStore:
    def __init__(self, root: str):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self._lock = threading.RLock()
        self._cache: dict[str, dict] = {}

    def _path(self, namespace: str) -> str:
        safe = namespace.replace("/", "_").replace("..", "_")
        return os.path.join(self.root, f"{safe}.json")

    def load(self, namespace: str) -> dict:
        with self._lock:
            if namespace in self._cache:
                return self._cache[namespace]
            p = self._path(namespace)
            data = {}
            if os.path.exists(p):
                try:
                    with open(p) as f:
                        data = json.load(f)
                except (json.JSONDecodeError, ValueError, OSError) as e:
                    # A crash or disk-full mid-write can leave corrupt JSON.
                    # Don't let it poison every future load for the rest of the
                    # game: quarantine the bad file and start that namespace
                    # fresh. Flags/findings written before the corruption may be
                    # lost, but the agent keeps running.
                    log.error("state namespace %r is corrupt (%s); quarantining and resetting", namespace, e)
                    try:
                        os.replace(p, p + ".corrupt")
                    except OSError:
                        pass
                    data = {}
            self._cache[namespace] = data
            return data

    def save(self, namespace: str) -> None:
        with self._lock:
            p = self._path(namespace)
            tmp = p + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._cache.get(namespace, {}), f, indent=2, default=str)
            os.replace(tmp, p)  # atomic

    def set(self, namespace: str, key: str, value) -> None:
        with self._lock:
            self.load(namespace)[key] = value
            self.save(namespace)

    def get(self, namespace: str, key: str, default=None):
        return self.load(namespace).get(key, default)

    def rotate(self, namespace: str, keep: int = 500) -> None:
        """Keep only the most recent `keep` keys (by sorted key order).

        Used for append-heavy namespaces like tool_log whose keys are
        timestamp-prefixed, so lexical sort == chronological. Prevents the
        store from growing without bound over a long competition.
        """
        with self._lock:
            data = self.load(namespace)
            if len(data) <= keep:
                return
            for k in sorted(data.keys())[:-keep]:
                del data[k]
            self.save(namespace)

    # --- flags are important enough to get their own helpers ----------------

    def record_flag(self, flag: Flag, flag_format: str | None = None) -> bool:
        """Store a flag. Returns True if it was new (dedupe by value).

        If flag_format is given, a token that does not match it is rejected —
        this stops a hallucinated/garbage 'flag' from entering the store.
        """
        if flag_format is not None:
            import re
            if not re.fullmatch(flag_format, (flag.value or "").strip()):
                log.warning("rejected non-conforming flag from %s: %r", flag.source, flag.value[:40])
                return False
        with self._lock:
            ns = self.load("flags")
            flags = ns.setdefault("items", {})
            if flag.value in flags:
                return False
            flags[flag.value] = asdict(flag)
            self.save("flags")
            log.info("new flag recorded from %s", flag.source)
            return True

    def pending_flags(self) -> list[dict]:
        flags = self.load("flags").get("items", {})
        return [f for f in flags.values() if not f["submitted"]]

    def mark_submitted(self, value: str, accepted: bool) -> None:
        with self._lock:
            flags = self.load("flags").get("items", {})
            if value in flags:
                flags[value]["submitted"] = True
                flags[value]["accepted"] = accepted
                self.save("flags")
