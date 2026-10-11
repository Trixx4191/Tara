"""
EventBus — the only thing offense and defense share when run together.

It is pub/sub, thread-safe, and completely optional: a subsystem publishes
events it discovers and subscribes to events it can use, but if nobody is
listening (the other half isn't running), publishing is a no-op and nothing
breaks. This is what lets each half run standalone yet cooperate when both are up.

Event types are plain strings so subsystems never need to import each other's
classes. Payloads are dicts. Keep it dumb; that's the point.
"""

from __future__ import annotations

import logging
import threading
from collections import defaultdict
from dataclasses import dataclass, field
import time

log = logging.getLogger("ctf.bus")

# well-known topics (strings so there's no cross-subsystem import)
EXPLOIT_OBSERVED = "exploit.observed"     # defense saw an attack it could reuse
EXPLOIT_CONFIRMED = "exploit.confirmed"   # an exploit was confirmed working
SERVICE_DOWN = "service.down"             # a defended service failed its health check
SERVICE_PATCHED = "service.patched"       # defense patched a service
FLAG_CAPTURED = "flag.captured"           # offense grabbed a flag


@dataclass
class Event:
    topic: str
    payload: dict
    source: str = ""
    ts: float = field(default_factory=time.time)


class EventBus:
    def __init__(self):
        self._subs: dict[str, list] = defaultdict(list)
        self._lock = threading.RLock()
        self._history: list[Event] = []
        self._history_cap = 1000

    def subscribe(self, topic: str, callback) -> None:
        with self._lock:
            self._subs[topic].append(callback)
        log.debug("subscribed to %s", topic)

    def publish(self, topic: str, payload: dict, source: str = "") -> None:
        ev = Event(topic=topic, payload=payload, source=source)
        with self._lock:
            self._history.append(ev)
            if len(self._history) > self._history_cap:
                self._history = self._history[-self._history_cap:]
            subs = list(self._subs.get(topic, []))
        for cb in subs:
            try:
                cb(ev)
            except Exception:
                log.exception("subscriber for %s raised", topic)

    def recent(self, topic: str | None = None, limit: int = 50) -> list[Event]:
        with self._lock:
            items = self._history if topic is None else [e for e in self._history if e.topic == topic]
            return items[-limit:]
