"""
Console — a read + control facade over a running Tara, with full CLI parity.

The GUI talks only to this. It snapshots live state and exposes every operator
action the CLI offers: start/stop subsystems, define services and attack targets,
view and extend the competition scope, run an ad-hoc agent task, apply a patch,
and flip runtime toggles (dry-run, auto-mitigate, flag format).

It holds no attack logic of its own — it reflects and steers what the
orchestrator, subsystems, scope policy and tool runner already do. Scope edits
mutate the SAME ScopePolicy object the gate and the socket guard enforce, so a
target added here is still subject to deny-by-default containment.
"""

from __future__ import annotations

import ipaddress
import threading
import time

from core.context import Service
from core.scope import valid_onion, is_onion


class Console:
    def __init__(self, ctx, orchestrator):
        self.ctx = ctx
        self.orch = orchestrator
        self._tasks: dict[str, dict] = {}
        self._task_seq = 0
        self._lock = threading.Lock()
        # a persistent conversation with the agent (context kept across turns)
        self._chat_msgs: list[dict] = []
        self._chat_busy = False
        self._chat_agent = None

    # ========================= reads =========================

    def snapshot(self) -> dict:
        return {
            "ts": time.time(),
            "agent": self._agent(),
            "subsystems": self.orch.status(),
            "services": self.services(),
            "targets": self.targets(),
            "scope": self.scope(),
            "options": self.options(),
            "findings": self.findings(limit=50),
            "mitigations": self.mitigations(),
            "flags": self.flags(),
            "review": self.review(),
            "tasks": self.task_list(),
            "chat": self.chat(),
        }

    def review(self) -> dict:
        """Flags captured by offense/defense awaiting the operator's decision."""
        off = self.orch._subs.get("offense")
        if off is not None:
            pending = off.pending_flags()
            auto = getattr(off, "auto_submit", False)
        else:
            # offense not configured this session: read any persisted pending items
            data = self.ctx.state.load("pending_flags")
            pending = [v for v in data.values() if v.get("status") == "pending"]
            auto = False
        return {"pending": pending, "auto_submit": auto}

    def chat(self) -> dict:
        with self._lock:
            return {"messages": self._chat_msgs[-60:], "busy": self._chat_busy}

    def _agent(self) -> dict:
        try:
            from tara import NAME, NAME_FA, VERSION
            name, name_fa, version = NAME, NAME_FA, VERSION
        except Exception:
            name, name_fa, version = "Tara", "", "?"
        return {"name": name, "name_fa": name_fa, "version": version}

    def services(self) -> list[dict]:
        down = self._defense_down_set()
        out = []
        for svc in self.ctx.service_list():
            out.append({
                "name": svc.name, "host": svc.host, "port": svc.port, "proto": svc.proto,
                "health_path": svc.health_path, "has_checker": bool(svc.checker),
                "has_source": bool(svc.source_dir),
                "up": (svc.name not in down) if down is not None else None,
            })
        return out

    def targets(self) -> dict:
        out = {}
        for name, spec in (self.ctx.config.get("targets", {}) or {}).items():
            if isinstance(spec, list):
                out[name] = [{"host": t.get("host"), "port": t.get("port")} for t in spec]
            elif isinstance(spec, dict):
                out[name] = [{"cidr": spec.get("cidr"), "port": spec.get("port")}]
        return out

    def scope(self) -> dict:
        s = self.ctx.scope
        return {
            "cidrs": [str(c) for c in s.allowed_cidrs],
            "hosts": sorted(s.allowed_hosts),
            "onions": sorted(getattr(s, "allowed_onions", set())),
            "ports": sorted(s.allowed_ports),
            "dry_run": s.dry_run,
        }

    def options(self) -> dict:
        defense = self.orch._subs.get("defense")
        offense = self.orch._subs.get("offense")
        return {
            "flag_format": self.ctx.config.get("flag_format"),
            "auto_mitigate": bool(getattr(defense, "auto_mitigate", False)) if defense else False,
            "auto_submit": bool(getattr(offense, "auto_submit", False)) if offense else False,
            "dry_run": self.ctx.scope.dry_run,
        }

    def findings(self, limit: int = 50) -> list[dict]:
        data = self.ctx.state.load("findings")
        items = [dict(v, _k=k) for k, v in data.items()]
        items.sort(key=lambda x: x.get("_k", ""), reverse=True)
        return items[:limit]

    def mitigations(self) -> list[dict]:
        data = self.ctx.state.load("mitigations")
        return [dict(v, rule_id=k) for k, v in data.items()]

    def flags(self) -> dict:
        items = self.ctx.state.load("flags").get("items", {})
        vals = list(items.values())
        return {
            "total": len(vals),
            "submitted": sum(1 for f in vals if f.get("submitted")),
            "accepted": sum(1 for f in vals if f.get("accepted") is True),
            "recent": sorted(vals, key=lambda f: f.get("first_seen", 0), reverse=True)[:25],
        }

    def task_list(self) -> list[dict]:
        with self._lock:
            return sorted(self._tasks.values(), key=lambda t: t["id"], reverse=True)[:8]

    def _defense_down_set(self):
        sub = self.orch._subs.get("defense")
        return getattr(sub, "_down", None) if sub else None

    # ========================= controls =========================

    def control(self, action: str, params: dict | None = None) -> dict:
        p = params or {}
        try:
            if action in ("start_defense", "stop_defense", "start_offense", "stop_offense"):
                return self._subsystem(action)
            if action == "drop_rule":        return self._drop_rule(p.get("rule_id"))
            if action == "add_service":       return self._add_service(p)
            if action == "remove_service":    return self._remove_service(p.get("name"))
            if action == "add_target":        return self._add_target(p)
            if action == "remove_target":     return self._remove_target(p)
            if action == "scope_add":         return self._scope_add(p)
            if action == "set_option":        return self._set_option(p)
            if action == "patch":             return self._patch(p)
            if action == "run_task":          return self._run_task(p.get("task", ""))
            if action == "chat_send":         return self._chat_send(p.get("message", ""))
            if action == "chat_clear":        return self._chat_clear()
            if action == "approve_flag":      return self._review_action("approve_flag", p.get("id"))
            if action == "reject_flag":       return self._review_action("reject_flag", p.get("id"))
            if action == "approve_all_flags": return self._review_action("approve_all_flags", None)
            return {"ok": False, "error": f"unknown action {action!r}"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # --- subsystems ---------------------------------------------------------

    def _subsystem(self, action):
        verb, _, name = action.partition("_")
        if name not in self.orch._subs:
            return {"ok": False, "error": f"no {name} subsystem configured"}
        (self.orch.start if verb == "start" else self.orch.stop)([name])
        return {"ok": True, "action": action}

    # --- services -----------------------------------------------------------

    def _add_service(self, p) -> dict:
        name = (p.get("name") or "").strip()
        host = (p.get("host") or "").strip()
        if not name or not host:
            return {"ok": False, "error": "name and host are required"}
        if name in self.ctx.services:
            return {"ok": False, "error": f"service {name!r} already exists"}
        try:
            port = int(p.get("port") or 0)
        except (TypeError, ValueError):
            return {"ok": False, "error": "port must be a number"}
        self.ctx.add_service(Service(
            name=name, host=host, port=port, proto=p.get("proto", "tcp"),
            health_path=p.get("health_path", "/"), checker=p.get("checker") or None,
            source_dir=p.get("source_dir") or None,
        ))
        return {"ok": True, "added": name}

    def _remove_service(self, name) -> dict:
        if name in self.ctx.services:
            del self.ctx.services[name]
            return {"ok": True, "removed": name}
        return {"ok": False, "error": f"no service {name!r}"}

    # --- targets (the "give a target" path) ---------------------------------

    def _add_target(self, p) -> dict:
        service = (p.get("service") or "").strip()
        host = (p.get("host") or "").strip()
        if not service or not host:
            return {"ok": False, "error": "service and host are required"}
        try:
            port = int(p.get("port") or 0)
        except (TypeError, ValueError):
            return {"ok": False, "error": "port must be a number"}
        # validate the host is sane before storing (an onion or an ip/hostname)
        if not is_onion(host):
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass  # allow hostnames; scope check happens at enumeration
        targets = self.ctx.config.setdefault("targets", {})
        lst = targets.setdefault(service, [])
        if not isinstance(lst, list):
            return {"ok": False, "error": f"targets for {service!r} use a cidr spec; edit config"}
        if any(t.get("host") == host and int(t.get("port", 0)) == port for t in lst):
            return {"ok": False, "error": "target already present"}
        lst.append({"host": host, "port": port})
        in_scope = self._target_in_scope(host, port)
        return {"ok": True, "added": f"{host}:{port}", "in_scope": in_scope,
                "note": None if in_scope else "added, but OUT of scope — it will be skipped until you add it to scope"}

    def _remove_target(self, p) -> dict:
        service, host = p.get("service"), p.get("host")
        lst = (self.ctx.config.get("targets", {}) or {}).get(service)
        if not isinstance(lst, list):
            return {"ok": False, "error": "no such target list"}
        before = len(lst)
        self.ctx.config["targets"][service] = [t for t in lst if t.get("host") != host]
        return {"ok": before != len(self.ctx.config["targets"][service]), "removed": host}

    def _target_in_scope(self, host, port) -> bool:
        from core.scope import ScopeViolation
        try:
            if is_onion(host):
                self.ctx.scope.check_onion(host, port)
            else:
                self.ctx.scope.check_target(host, port)
            return True
        except ScopeViolation:
            return False

    # --- scope --------------------------------------------------------------

    def _scope_add(self, p) -> dict:
        kind = p.get("kind")
        value = (p.get("value") or "").strip()
        s = self.ctx.scope
        if kind == "cidr":
            try:
                net = ipaddress.ip_network(value, strict=False)
            except ValueError as e:
                return {"ok": False, "error": f"bad CIDR: {e}"}
            s.allowed_cidrs.append(net)      # same object the guard enforces
            return {"ok": True, "added": f"cidr {net}"}
        if kind == "host":
            if not value:
                return {"ok": False, "error": "host required"}
            s.allowed_hosts.add(value)
            return {"ok": True, "added": f"host {value}"}
        if kind == "onion":
            name = value.lower().split(":")[0]
            if not valid_onion(name):
                return {"ok": False, "error": "not a well-formed .onion address"}
            s.allowed_onions.add(name)
            return {"ok": True, "added": f"onion {name}"}
        if kind == "port":
            try:
                s.allowed_ports.add(int(value))
            except (TypeError, ValueError):
                return {"ok": False, "error": "port must be a number"}
            return {"ok": True, "added": f"port {value}"}
        return {"ok": False, "error": f"unknown scope kind {kind!r}"}

    # --- options ------------------------------------------------------------

    def _set_option(self, p) -> dict:
        changed = {}
        if "dry_run" in p:
            self.ctx.scope.dry_run = bool(p["dry_run"]); changed["dry_run"] = self.ctx.scope.dry_run
        if "auto_mitigate" in p:
            d = self.orch._subs.get("defense")
            if d:
                d.auto_mitigate = bool(p["auto_mitigate"]); changed["auto_mitigate"] = d.auto_mitigate
        if "auto_submit" in p:
            o = self.orch._subs.get("offense")
            if o:
                o.auto_submit = bool(p["auto_submit"]); changed["auto_submit"] = o.auto_submit
        if "flag_format" in p:
            fmt = p["flag_format"]
            self.ctx.config["flag_format"] = fmt
            import re
            d = self.orch._subs.get("defense")
            if d and getattr(d, "detector", None):
                d.detector.flag_re = re.compile(fmt) if fmt else None
            changed["flag_format"] = fmt
        return {"ok": bool(changed), "changed": changed}

    # --- patch --------------------------------------------------------------

    def _patch(self, p) -> dict:
        d = self.orch._subs.get("defense")
        if not d:
            return {"ok": False, "error": "defense not running"}
        patch = {"kind": p.get("kind", "replace"), "file": p.get("file"),
                 "find": p.get("find"), "replace": p.get("replace"), "cmd": p.get("cmd")}
        return d.auto_patch(p.get("service"), {k: v for k, v in patch.items() if v is not None})

    # --- ad-hoc agent task (the --task path) --------------------------------

    def _run_task(self, task: str) -> dict:
        task = (task or "").strip()
        if not task:
            return {"ok": False, "error": "task text required"}
        with self._lock:
            self._task_seq += 1
            tid = f"t{self._task_seq}"
            self._tasks[tid] = {"id": self._task_seq, "tid": tid, "task": task,
                                "status": "running", "output": "", "started": time.time()}
        threading.Thread(target=self._task_worker, args=(tid, task), daemon=True).start()
        return {"ok": True, "task_id": tid}

    def _task_worker(self, tid, task):
        from core.agent import Agent
        try:
            agent = Agent(self.ctx.provider, self.ctx.runner,
                          system_prompt=("You are a CTF agent operating ONLY inside the "
                                         "authorized, scoped competition environment. The runner "
                                         "refuses out-of-scope actions. Probe, hypothesise, test, report."),
                          max_iters=self.ctx.config.get("agent", {}).get("max_iters", 20))
            out = agent.run(task)
            status = "done"
        except Exception as e:
            out, status = f"error: {e}", "error"
        with self._lock:
            self._tasks[tid].update(status=status, output=out[:4000], finished=time.time())

    # --- flag review (human-in-the-loop submission) -------------------------

    def _review_action(self, method: str, fid) -> dict:
        off = self.orch._subs.get("offense")
        if off is None:
            return {"ok": False, "error": "offense not configured this session"}
        if method == "approve_all_flags":
            return off.approve_all_flags()
        if not fid:
            return {"ok": False, "error": "flag id required"}
        return getattr(off, method)(fid)

    # --- chat: a live conversation with the agent ---------------------------

    def _chat_send(self, message: str) -> dict:
        message = (message or "").strip()
        if not message:
            return {"ok": False, "error": "message required"}
        with self._lock:
            if self._chat_busy:
                return {"ok": False, "error": "agent is still answering — wait a moment"}
            self._chat_msgs.append({"role": "user", "content": message, "ts": time.time()})
            self._chat_busy = True
        threading.Thread(target=self._chat_worker, args=(message,), daemon=True).start()
        return {"ok": True}

    def _chat_worker(self, message: str):
        from core.agent import Agent
        try:
            if self._chat_agent is None:
                # one persistent agent so context carries across turns; it runs
                # through the SAME gated runner, so it is scope-bound like everything.
                self._chat_agent = Agent(
                    self.ctx.provider, self.ctx.runner,
                    system_prompt=(
                        "You are Tara, a CTF attack-defense agent, talking live with your "
                        "operator during a competition. You operate ONLY inside the authorized, "
                        "scoped environment; the runner refuses out-of-scope actions. The operator "
                        "may direct you, ask what you're seeing, or have you probe/patch/analyse a "
                        "scoped target. Be concise and concrete; report findings and flags clearly."),
                    max_iters=self.ctx.config.get("agent", {}).get("max_iters", 20),
                )
            out = self._chat_agent.run(message)
        except Exception as e:
            out = f"[error: {e}]"
        with self._lock:
            self._chat_msgs.append({"role": "assistant", "content": out, "ts": time.time()})
            self._chat_busy = False

    def _chat_clear(self) -> dict:
        with self._lock:
            self._chat_msgs = []
            self._chat_agent = None
            self._chat_busy = False
        return {"ok": True}

    def _drop_rule(self, rule_id) -> dict:
        if not rule_id:
            return {"ok": False, "error": "rule_id required"}
        sub = self.orch._subs.get("defense")
        mitig = getattr(sub, "mitigation", None) if sub else None
        if mitig:
            for e in mitig.enforcers:
                try:
                    e.remove(rule_id)
                except Exception:
                    pass
        data = self.ctx.state.load("mitigations")
        if rule_id in data:
            del data[rule_id]
            self.ctx.state.save("mitigations")
        return {"ok": True, "dropped": rule_id}
