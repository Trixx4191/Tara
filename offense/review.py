"""
ReviewQueue — human-in-the-loop flag submission.

Auto-submitting flags is risky: the agent could push an inaccurate or
low-confidence token and waste a submission (or worse, trip an anti-spam
penalty). So by default every captured flag — whether offense discovered it or
defense caught it in traffic and handed it over — lands here as PENDING and is
presented to the operator, who approves or rejects it. Only on approval is it
actually submitted through the FlagSink.

Each item keeps where it came from (source, exploit, team) so the operator can
judge accuracy before approving. Validation + dedupe happen on enqueue, so
malformed or duplicate tokens never reach the queue.
"""

from __future__ import annotations

import logging
import threading
import time

from defense.assurance import validate_flag

log = logging.getLogger("ctf.review")


class ReviewQueue:
    def __init__(self, sink, state, flag_format: str | None = None):
        self.sink = sink
        self.state = state
        self.flag_format = flag_format
        self._items: dict[str, dict] = {}
        self._seq = 0
        self._lock = threading.Lock()
        self._load()

    def _load(self):
        if self.state is None:
            return
        saved = self.state.load("pending_flags")
        if saved:
            self._items = dict(saved)
            self._seq = max((v.get("n", 0) for v in self._items.values()), default=0)

    def _save(self):
        if self.state is None:
            return
        data = self.state.load("pending_flags")
        data.clear()
        data.update(self._items)
        self.state.save("pending_flags")

    # --- enqueue (from offense/defense) ------------------------------------

    def enqueue(self, flag: str, source: str = "", meta: dict | None = None) -> str:
        """Validate + dedupe, then queue as PENDING. Returns a status string."""
        flag = (flag or "").strip()
        if not validate_flag(flag, self.flag_format):
            return "invalid"
        with self._lock:
            # dedupe by flag value across the whole queue
            for it in self._items.values():
                if it["flag"] == flag:
                    return "duplicate"
            self._seq += 1
            fid = f"f{self._seq}"
            self._items[fid] = {
                "id": fid, "n": self._seq, "flag": flag, "source": source,
                "meta": meta or {}, "status": "pending", "ts": time.time(),
            }
            self._save()
        log.info("flag queued for review from %s", source)
        return "pending"

    # --- reads --------------------------------------------------------------

    def pending(self) -> list[dict]:
        with self._lock:
            return [dict(v) for v in self._items.values() if v["status"] == "pending"]

    def all(self) -> list[dict]:
        with self._lock:
            return sorted((dict(v) for v in self._items.values()),
                          key=lambda x: x["n"], reverse=True)

    def counts(self) -> dict:
        with self._lock:
            c = {"pending": 0, "submitted": 0, "rejected": 0, "failed": 0}
            for v in self._items.values():
                c[v["status"]] = c.get(v["status"], 0) + 1
            return c

    # --- operator decisions -------------------------------------------------

    def approve(self, fid: str) -> dict:
        with self._lock:
            it = self._items.get(fid)
            if not it:
                return {"ok": False, "error": "no such pending flag"}
            if it["status"] != "pending":
                return {"ok": False, "error": f"already {it['status']}"}
        # submit through the sink (validates + dedupes + records) outside the lock
        res = self.sink.offer(it["flag"], source=it["source"], meta=it["meta"])
        with self._lock:
            it["status"] = "submitted" if res.status == "accepted" else (
                "failed" if res.status in ("rejected", "error") else res.status)
            it["submit_detail"] = res.detail
            self._save()
        return {"ok": res.status == "accepted", "status": it["status"], "detail": res.detail}

    def reject(self, fid: str) -> dict:
        with self._lock:
            it = self._items.get(fid)
            if not it:
                return {"ok": False, "error": "no such pending flag"}
            it["status"] = "rejected"
            self._save()
        return {"ok": True, "status": "rejected"}

    def approve_all(self) -> dict:
        ids = [it["id"] for it in self.pending()]
        results = [self.approve(i) for i in ids]
        ok = sum(1 for r in results if r.get("ok"))
        return {"ok": True, "approved": ok, "of": len(ids)}
