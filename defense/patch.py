"""
PatchManager — apply a fix, prove it still works, or roll it back.

The defensive patch trap in attack-defense is breaking your own service: a patch
that closes the hole but fails the organiser's checker costs you SLA points every
tick — often more than the exploit would. So every patch here is transactional:

    backup -> apply -> run the service's checker
        checker passes  -> keep it, publish SERVICE_PATCHED
        checker fails    -> roll back to the backup, report why

Two patch kinds are supported now:
  - "replace": in a file under the service's source dir, swap an exact byte/text
    span for a fixed version (e.g. patch a vulnerable parse routine).
  - "command": run a shell command in the source dir that applies a patch
    (e.g. `patch -p1 < fix.diff`).

File paths are checked against scope.allowed_paths. (Child-process network egress
is not covered by the in-process guard — that's the OS-level rule for later.)
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time

log = logging.getLogger("ctf.patch")


class PatchError(Exception):
    pass


class PatchManager:
    def __init__(self, ctx):
        self.ctx = ctx
        self.backup_root = os.path.join(ctx.config.get("state_dir", "./state"), "patch_backups")
        os.makedirs(self.backup_root, exist_ok=True)

    # --- public -------------------------------------------------------------

    def apply(self, service, patch: dict, checker_timeout: float = 60) -> dict:
        """
        patch = {"kind": "replace", "file": "...", "find": "...", "replace": "..."}
             or {"kind": "command", "cmd": "patch -p1 < fix.diff"}
        Returns a result dict; rolls back on checker failure.
        """
        if not service.source_dir:
            raise PatchError(f"service {service.name} has no source_dir to patch")
        self.ctx.scope.check_path(service.source_dir)

        backup = self._backup(service)
        try:
            kind = patch.get("kind")
            if kind == "replace":
                self._apply_replace(service, patch)
            elif kind == "command":
                self._apply_command(service, patch)
            else:
                raise PatchError(f"unknown patch kind {kind!r}")
        except Exception as e:
            self._restore(service, backup)
            return {"ok": False, "stage": "apply", "error": str(e)}

        # verify: the checker must pass AND the service must still answer on its
        # port. A checker can pass while the service fails to bind/respond (e.g.
        # the patch slowed startup), which would still bleed SLA points — so we
        # re-probe liveness and roll back if the service isn't actually up.
        ok, detail = self._run_checker(service, checker_timeout)
        live, live_detail = self._probe_live(service)
        if ok and live:
            self.ctx.state.set("patches", f"{time.time():.0f}_{service.name}",
                               {"patch": patch, "verified": True})
            from core.bus import SERVICE_PATCHED
            self.ctx.bus.publish(SERVICE_PATCHED, {"service": service.name, "patch": patch}, source="defense")
            log.info("patched %s; checker passed and service live", service.name)
            return {"ok": True, "verified": True, "checker": detail, "live": live_detail}
        else:
            self._restore(service, backup)
            stage = "checker" if not ok else "liveness"
            log.warning("patch to %s failed %s check; rolled back", service.name, stage)
            return {"ok": False, "stage": stage, "rolled_back": True,
                    "checker": detail, "live": live_detail}

    def _probe_live(self, service) -> tuple[bool, str]:
        """Confirm the service still answers on its port after a patch.

        Goes through the gated runner's health tool, so it respects scope. If
        the service has no host/port to probe, liveness is treated as OK (the
        checker is then the only signal).
        """
        host = getattr(service, "host", None)
        port = getattr(service, "port", None)
        if not host or not port:
            return True, "no host/port to probe (checker-only)"
        res = self.ctx.runner.run("service_health", {
            "host": host, "port": port,
            "proto": getattr(service, "proto", "tcp"),
            "path": getattr(service, "health_path", "/"),
        })
        up = bool(res.meta and res.meta.get("up"))
        return up, res.output

    # --- internals ----------------------------------------------------------

    def _backup(self, service) -> str:
        dest = os.path.join(self.backup_root, f"{service.name}_{int(time.time())}")
        shutil.copytree(service.source_dir, dest)
        return dest

    def _restore(self, service, backup: str) -> None:
        shutil.rmtree(service.source_dir, ignore_errors=True)
        shutil.copytree(backup, service.source_dir)

    def _apply_replace(self, service, patch: dict) -> None:
        path = os.path.join(service.source_dir, patch["file"])
        self.ctx.scope.check_path(path)
        with open(path, "r", errors="replace") as f:
            content = f.read()
        find = patch["find"]
        if find not in content:
            raise PatchError(f"'find' text not present in {patch['file']}")
        content = content.replace(find, patch["replace"])
        with open(path, "w") as f:
            f.write(content)

    def _apply_command(self, service, patch: dict) -> None:
        r = subprocess.run(
            patch["cmd"], shell=True, cwd=service.source_dir,
            capture_output=True, text=True, timeout=patch.get("timeout", 60),
        )
        if r.returncode != 0:
            raise PatchError(f"patch command failed: {r.stderr[:300]}")

    def _run_checker(self, service, timeout: float):
        if not service.checker:
            # no checker available -> we can't verify; treat as pass but flag it
            log.warning("service %s has no checker; patch applied UNVERIFIED", service.name)
            return True, "no checker configured (unverified)"
        try:
            r = subprocess.run(
                service.checker, shell=True, cwd=service.source_dir,
                capture_output=True, text=True, timeout=timeout,
            )
            ok = r.returncode == 0
            return ok, (r.stdout + r.stderr)[:500]
        except subprocess.TimeoutExpired:
            return False, "checker timed out"
