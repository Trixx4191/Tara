"""
Capture + detection (flow-aware).

Upgraded from line-oriented logging to the model real A/D teams use: reassembled
request/response FLOWS, multiple capture backends, an optional IDS alert feed,
and detection that protects your own SLA checker from false positives.

Sources (all yield Flow objects via poll(), non-blocking):
  - QueueSource     : flows pushed in programmatically (tap / sidecar / tests)
  - FileLogSource   : one flow per log line (request only) — the simple backend
  - SuricataSource  : tails Suricata eve.json, turning IDS alerts into findings
  - PcapSource      : reassembles flows from a pcap dir (lazy scapy import)
  - PcapOverIpSource: reads a PCAP-over-IP stream (as tulip/tcpdump expose)

Detector.scan(flow) -> list[Finding]
  - runs signature + heuristic rules over BOTH request and response bytes
  - response scanning is what catches FLAG_OUT: your flag leaving in a reply
  - a checker allowlist suppresses findings on the organiser's SLA checker, so
    detection/edge-blocking never trips on benign checker traffic (losing SLA
    points to your own defense is the classic own-goal)
"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import socket
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

log = logging.getLogger("ctf.capture")


# --- the flow model ---------------------------------------------------------

@dataclass
class Flow:
    """One reassembled exchange with a service."""
    src: str = ""
    dst: str = ""
    service: str = ""
    port: int | None = None
    request: bytes = b""
    response: bytes = b""
    ts: float = 0.0
    meta: dict = field(default_factory=dict)

    @classmethod
    def from_event(cls, ev: dict) -> "Flow":
        """Accept the old {'data': ...} event shape too, for compatibility."""
        data = ev.get("data", b"")
        if isinstance(data, str):
            data = data.encode("latin-1", "replace")
        return cls(
            src=ev.get("src", ""), dst=ev.get("dst", ev.get("host", "")),
            service=ev.get("service", ""), port=ev.get("port"),
            request=ev.get("request", data) if not isinstance(ev.get("request"), str)
                    else ev["request"].encode("latin-1", "replace"),
            response=ev.get("response", b"") if not isinstance(ev.get("response"), str)
                    else ev["response"].encode("latin-1", "replace"),
            ts=ev.get("ts", 0.0), meta={k: v for k, v in ev.items()
                 if k not in ("data", "request", "response")},
        )

    def text(self) -> str:
        r = self.request.decode("latin-1", "replace")
        s = self.response.decode("latin-1", "replace")
        return r + ("\n<<<RESPONSE>>>\n" + s if s else "")

    def request_text(self) -> str:
        return self.request.decode("latin-1", "replace")

    def response_text(self) -> str:
        return self.response.decode("latin-1", "replace")


# --- sources ----------------------------------------------------------------

class CaptureSource(ABC):
    @abstractmethod
    def poll(self) -> list:
        """Return Flow objects (or Findings, for IDS sources) seen since last poll."""
        ...


class QueueSource(CaptureSource):
    def __init__(self):
        self._q: list = []
        self._lock = threading.Lock()

    def push(self, item) -> None:
        with self._lock:
            self._q.append(item if isinstance(item, Flow) else Flow.from_event(item))

    def poll(self) -> list:
        with self._lock:
            out, self._q = self._q, []
        return out


class FileLogSource(CaptureSource):
    def __init__(self, path: str, parse=None):
        self.path = path
        self.parse = parse or (lambda line: Flow(request=line.encode("latin-1", "replace")))
        self._pos = 0

    def poll(self) -> list:
        flows = []
        try:
            with open(self.path, "r", errors="replace") as f:
                f.seek(self._pos)
                for line in f:
                    line = line.rstrip("\n")
                    if line:
                        flows.append(self.parse(line))
                self._pos = f.tell()
        except FileNotFoundError:
            pass
        return flows


class SuricataSource(CaptureSource):
    """Tail Suricata's eve.json and surface IDS alerts as Findings directly.

    Riding a battle-tested rule set (ET Open, custom .rules) beats only our own
    regexes. Rule metadata becomes the finding's tags, mirroring tulip's model.
    """
    def __init__(self, eve_path: str):
        self.path = eve_path
        self._pos = 0

    def poll(self) -> list:
        findings = []
        try:
            with open(self.path, "r", errors="replace") as f:
                f.seek(self._pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if ev.get("event_type") != "alert":
                        continue
                    a = ev.get("alert", {})
                    sev_map = {1: "critical", 2: "high", 3: "medium"}
                    findings.append(Finding(
                        rule=f"suricata:{a.get('signature_id')}",
                        severity=sev_map.get(a.get("severity", 3), "medium"),
                        reason=a.get("signature", "suricata alert"),
                        matched=str(a.get("category", "")),
                        replayable=True,
                        flow=Flow(src=ev.get("src_ip", ""), dst=ev.get("dest_ip", ""),
                                  port=ev.get("dest_port"), ts=0.0,
                                  meta={"suricata": a}),
                    ))
                self._pos = f.tell()
        except FileNotFoundError:
            pass
        return findings


class PcapSource(CaptureSource):
    """Reassemble flows from pcap files dropped in a directory (lazy scapy).

    Best-effort and framework-agnostic: works with any rotating tcpdump feeding
    a directory (the tulip/vulnbox pattern). Falls back gracefully if scapy is
    not installed — call available() to check.
    """
    def __init__(self, pcap_dir: str, bpf_ports: list[int] | None = None):
        self.dir = pcap_dir
        self.bpf_ports = set(bpf_ports or [])
        self._seen: set[str] = set()

    @staticmethod
    def available() -> bool:
        try:
            import scapy.all  # noqa
            return True
        except Exception:
            return False

    def poll(self) -> list:
        if not self.available():
            return []
        from scapy.all import rdpcap, TCP, IP  # type: ignore
        flows = []
        for path in sorted(glob.glob(os.path.join(self.dir, "*.pcap*"))):
            if path in self._seen:
                continue
            self._seen.add(path)
            try:
                packets = rdpcap(path)
            except Exception:
                continue
            # crude per-(dst,port) reassembly: concat payloads in capture order
            streams: dict[tuple, Flow] = {}
            for pkt in packets:
                if TCP not in pkt or IP not in pkt:
                    continue
                dport = int(pkt[TCP].dport)
                sport = int(pkt[TCP].sport)
                if self.bpf_ports and dport not in self.bpf_ports and sport not in self.bpf_ports:
                    continue
                payload = bytes(pkt[TCP].payload)
                if not payload:
                    continue
                inbound = (not self.bpf_ports) or dport in self.bpf_ports
                key = (pkt[IP].src, pkt[IP].dst, dport if inbound else sport)
                fl = streams.setdefault(key, Flow(
                    src=pkt[IP].src, dst=pkt[IP].dst,
                    port=dport if inbound else sport, ts=float(pkt.time)))
                if inbound:
                    fl.request += payload
                else:
                    fl.response += payload
            flows.extend(streams.values())
        return flows


class PcapOverIpSource(CaptureSource):
    """Connect to a PCAP-over-IP endpoint (host:port) and buffer flows.

    The endpoint (e.g. `tcpdump -w - | nc -lk <port>`) is a control-plane feed;
    add it to the NetworkGuard control hosts if egress enforcement is on.
    """
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._buf: list = []
        self._lock = threading.Lock()
        self._thread = None

    def start(self):
        import threading as _t
        self._thread = _t.Thread(target=self._reader, daemon=True)
        self._thread.start()

    def _reader(self):
        try:
            from scapy.all import PcapReader  # type: ignore
        except Exception:
            log.warning("scapy not available; PcapOverIpSource inert")
            return
        try:
            s = socket.create_connection((self.host, self.port), timeout=10)
            reader = PcapReader(s.makefile("rb"))
            for pkt in reader:
                fl = Flow(request=bytes(getattr(pkt, "load", b"")), ts=float(getattr(pkt, "time", 0)))
                with self._lock:
                    self._buf.append(fl)
        except Exception:
            log.debug("pcap-over-ip reader stopped", exc_info=True)

    def poll(self) -> list:
        with self._lock:
            out, self._buf = self._buf, []
        return out


# --- detection --------------------------------------------------------------

@dataclass
class Finding:
    rule: str
    severity: str                 # low | medium | high | critical
    reason: str
    matched: str = ""
    replayable: bool = False
    flow: Flow = field(default_factory=Flow)
    where: str = "request"        # request | response


_RULES = [
    ("path_traversal", "high", re.compile(r"\.\.[\\/]"), "directory traversal sequence", True),
    ("cmd_injection", "critical", re.compile(r"[;&|`]\s*\w+|\$\([^)]+\)"), "shell command-injection metacharacters", True),
    ("sqli", "high", re.compile(r"('|%27)\s*(or|union|;)|union\s+select|--\s", re.I), "SQL-injection pattern", True),
    ("format_string", "high", re.compile(r"(%[0-9$]*[nxs]){3,}"), "format-string specifiers", True),
    ("nop_sled", "critical", re.compile(r"(\\x90){8,}|\x90{8,}"), "NOP sled / shellcode", True),
    ("flag_path", "medium", re.compile(r"/flag|/home/[^/]+/flag|flag\.txt", re.I), "direct access to a flag path", True),
    ("ssti", "high", re.compile(r"\{\{.*?\}\}|\$\{.*?\}"), "template-injection braces", True),
    ("deserialize", "high", re.compile(r"\bO:\d+:|\brO0|\xac\xed\x00\x05", re.I), "serialized-object payload", True),
]

_OVERSIZE = 2048


class Detector:
    def __init__(self, flag_format: str | None = None, checker_allowlist: list[str] | None = None):
        self.flag_re = re.compile(flag_format) if flag_format else None
        # patterns that identify the organiser's SLA checker's own traffic;
        # findings whose flow matches any of these are suppressed, so we never
        # block or alarm on the thing that scores our uptime.
        self.checker_allow = [re.compile(p) for p in (checker_allowlist or [])]

    def _is_checker(self, flow: Flow) -> bool:
        if not self.checker_allow:
            return False
        blob = flow.text()
        return any(rx.search(blob) for rx in self.checker_allow)

    def scan(self, item) -> list:
        # a Finding straight from an IDS source passes through (still allowlisted)
        if isinstance(item, Finding):
            if self._is_checker(item.flow):
                return []
            return [item]

        flow = item if isinstance(item, Flow) else Flow.from_event(item)
        if self._is_checker(flow):
            return []

        findings: list[Finding] = []
        req = flow.request_text()
        resp = flow.response_text()

        for name, sev, rx, reason, replayable in _RULES:
            m = rx.search(req)
            if m:
                findings.append(Finding(name, sev, reason, m.group(0)[:120], replayable, flow, "request"))

        # FLAG_OUT: your flag leaving in a response is the highest-value signal
        if self.flag_re and resp:
            fm = self.flag_re.search(resp)
            if fm:
                findings.append(Finding(
                    "flag_out", "critical",
                    "your flag is leaving in a service response — active theft",
                    fm.group(0)[:120], replayable=True, flow=flow, where="response"))

        if len(req) >= _OVERSIZE:
            findings.append(Finding(
                "oversize", "medium", f"request is {len(req)} bytes (possible overflow)",
                req[:60] + "...", True, flow, "request"))

        return findings
