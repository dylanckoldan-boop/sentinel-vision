"""The protected service's logic, independent of Windows so every rule can be tested on any platform.

On Windows it runs inside the "Sentinel Vision Protection" service (LocalSystem). Its data folder is readable and
writable only by the operating system and administrators, so malware running as the user can't delete the
rollback vault or quarantine, and can't quietly weaken protection:

* every user gets a private rollback vault and quarantine, keyed by the account's security identifier (SID);
  one user never sees another's files;
* the service only stores and returns bytes. It never reads or writes the user's own files (that happens in the
  user's own process), so it can't be abused to reach places the user can't;
* settings that *weaken* protection (turning a protection off, adding an exclusion, ...) are only accepted from an
  elevated caller, i.e. after the user approved Windows' administrator prompt. Strengthening is always allowed;
* refused attempts are recorded so the app can warn the user.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import shutil
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sentinel_vision import __version__
from sentinel_vision.quarantine import Quarantine, QuarantineError
from sentinel_vision.vault import RollbackVault, VaultError

log = logging.getLogger("sentinel_vision.service")

PROTOCOL = 1
MAX_UPLOAD = 2 * 1024 * 1024 * 1024  # largest file accepted into quarantine
MAX_FRAME = 64 * 1024 * 1024  # largest single payload (vault versions are at most a few dozen MB)
READ_CHUNK = 8 * 1024 * 1024
SID_RE = re.compile(r"^S-1(-\d{1,10}){1,15}$")

# ---------------------------------------------------------------------------------------------- policy
# Which settings protect the user, and which direction counts as "weaker".
BOOL_ON = (
    "realtime_enabled", "behavior_enabled", "behavior_kill_malicious", "behavior_block_ransomware",
    "ransomware_enabled", "ransomware_auto_suspend", "network_enabled", "webshield_enabled", "auto_quarantine",
    "hash_enabled", "yara_enabled", "clamav_enabled", "heuristics_enabled", "usb_autoscan", "privacy_monitor",
    "netsec_enabled", "scan_archives", "check_app_updates", "schedule_quick_daily", "schedule_full_weekly",
    "schedule_memory_scan", "keep_running",
)  # fmt: skip
LIST_KEEP = ("ransomware_folders", "watch_paths", "enabled_feeds")  # removing an entry weakens
LIST_GROW = ("exclusions", "approved_plugins")  # adding an entry weakens
NUM_LOWER_IS_STRONGER = ("heuristic_threshold",)
NUM_HIGHER_IS_STRONGER = ("max_file_size_mb", "vault_max_mb", "vault_keep_versions")
GLOBAL_BOOL_ON = ("webshield_block_hosts", "firewall_block")  # machine-wide
LABELS = {
    "realtime_enabled": "real-time file protection",
    "behavior_enabled": "behavior monitoring",
    "behavior_kill_malicious": "ending programs confirmed as malware",
    "behavior_block_ransomware": "stopping ransomware from deleting backups",
    "ransomware_enabled": "the ransomware shield and rollback vault",
    "ransomware_auto_suspend": "freezing likely ransomware",
    "network_enabled": "live network monitoring",
    "webshield_enabled": "Web Shield",
    "auto_quarantine": "automatic quarantine",
    "keep_running": "starting at sign-in and restarting if closed",
    "exclusions": "exclusions",
    "approved_plugins": "allowed plugins",
    "ransomware_folders": "ransomware-protected folders",
    "watch_paths": "real-time protected folders",
    "enabled_feeds": "threat-definition sources",
    "webshield_block_hosts": "system-wide website blocking",
    "firewall_block": "firewall blocking of malicious networks",
    "auto_update_hours": "automatic definition updates",
}
POLICY_FIELDS = (
    BOOL_ON + LIST_KEEP + LIST_GROW + NUM_LOWER_IS_STRONGER + NUM_HIGHER_IS_STRONGER + ("auto_update_hours",)
)


def label(name: str) -> str:
    return LABELS.get(name, name.replace("_", " "))


def _norm_list(v) -> list[str]:
    return sorted({os.path.normcase(str(x)) for x in (v or [])})


def weakened(old: dict, new: dict) -> list[str]:
    """Names of the fields whose change in ``new`` makes protection weaker than ``old``."""
    out = []
    for k in BOOL_ON + GLOBAL_BOOL_ON:
        if k in new and bool(old.get(k, True)) and not bool(new[k]):
            out.append(k)
    for k in LIST_KEEP:
        if k in new and set(_norm_list(old.get(k))) - set(_norm_list(new[k])):
            out.append(k)
    for k in LIST_GROW:
        if k in new and set(_norm_list(new[k])) - set(_norm_list(old.get(k))):
            out.append(k)
    for k in NUM_LOWER_IS_STRONGER:
        if k in new and k in old and float(new[k]) > float(old[k]):
            out.append(k)
    for k in NUM_HIGHER_IS_STRONGER:
        if k in new and k in old and float(new[k]) < float(old[k]):
            out.append(k)
    if "auto_update_hours" in new and "auto_update_hours" in old:
        o, n = int(old["auto_update_hours"]), int(new["auto_update_hours"])
        if (o > 0 and n == 0) or (o > 0 and n > o):
            out.append("auto_update_hours")
    return out


def policy_from_settings(settings) -> dict:
    d = {k: getattr(settings, k) for k in POLICY_FIELDS if hasattr(settings, k)}
    d["enabled_feeds"] = sorted(f.name for f in getattr(settings, "feeds", []) if f.enabled)
    return json.loads(json.dumps(d))  # plain JSON types


def apply_policy(settings, policy: dict) -> None:
    """Overlay the protected values onto locally loaded settings (the protected copy always wins)."""
    for k, v in policy.items():
        if k == "enabled_feeds":
            enabled = set(v)
            for f in settings.feeds:
                f.enabled = f.name in enabled
        elif hasattr(settings, k):
            setattr(settings, k, v)


# ---------------------------------------------------------------------------------------------- core
@dataclass
class Caller:
    sid: str
    elevated: bool = False
    pid: int = 0
    session: int = -1


@dataclass
class Event:
    ts: float
    sid: str
    kind: str  # refused | changed | watchdog | system
    detail: str


@dataclass
class _Transfer:
    sid: str
    path: Path
    size: int = 0
    meta: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


class ServiceError(Exception):
    def __init__(self, code: str, message: str, **extra) -> None:
        super().__init__(message)
        self.code, self.extra = code, extra


class SystemApplier:
    """Machine-wide actions (hosts file, firewall). The Windows service provides the real implementation."""

    def apply_hosts(self) -> str:
        return "not available"

    def remove_hosts(self) -> str:
        return "not available"

    def apply_firewall(self) -> str:
        return "not available"

    def remove_firewall(self) -> str:
        return "not available"

    def status(self) -> dict:
        return {}


class ServiceCore:
    def __init__(self, root: Path, applier: SystemApplier | None = None) -> None:
        self.root = Path(root)
        for d in ("users", "transfers"):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        for leftover in (self.root / "transfers").iterdir():  # from a previous run
            leftover.unlink(missing_ok=True)
        self.applier = applier or SystemApplier()
        self._lock = threading.RLock()
        self._vaults: dict[str, RollbackVault] = {}
        self._quarantines: dict[str, Quarantine] = {}
        self._plugin_logs: dict = {}
        self._transfers: dict[str, _Transfer] = {}
        self.events: list[Event] = []
        self.heartbeats: dict[tuple[str, int], tuple[float, int]] = {}  # (sid, session) -> (time, pid)
        self.paused: set[tuple[str, int]] = set()  # (sid, session): the user chose to stop protection
        self.started = time.time()

    # ------------------------------------------------------------------ storage per user
    def _user_dir(self, sid: str) -> Path:
        if not SID_RE.match(sid):
            raise ServiceError("bad_sid", "invalid account identifier")
        d = self.root / "users" / sid
        d.mkdir(parents=True, exist_ok=True)
        return d

    def policy(self, sid: str) -> dict:
        p = self._user_dir(sid) / "policy.json"
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_policy(self, sid: str, policy: dict) -> None:
        p = self._user_dir(sid) / "policy.json"
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(policy, indent=2), encoding="utf-8")
        os.replace(tmp, p)

    def global_policy(self) -> dict:
        try:
            return json.loads((self.root / "global.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_global(self, g: dict) -> None:
        p = self.root / "global.json"
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(g, indent=2), encoding="utf-8")
        os.replace(tmp, p)

    def vault(self, sid: str) -> RollbackVault:
        with self._lock:
            v = self._vaults.get(sid)
            if v is None:
                pol = self.policy(sid)
                v = RollbackVault(
                    self._user_dir(sid) / "vault",
                    max_total_mb=int(pol.get("vault_max_mb", 5120)),
                    keep_versions=int(pol.get("vault_keep_versions", 10)),
                )
                self._vaults[sid] = v
            return v

    def quarantine(self, sid: str) -> Quarantine:
        with self._lock:
            q = self._quarantines.get(sid)
            if q is None:
                q = self._quarantines[sid] = Quarantine(self._user_dir(sid) / "quarantine")
            return q

    def close(self) -> None:
        with self._lock:
            for v in self._vaults.values():
                v.close()
            self._vaults.clear()

    def _event(self, sid: str, kind: str, detail: str) -> None:
        with self._lock:
            self.events.append(Event(time.time(), sid, kind, detail))
            del self.events[:-500]
        try:
            with open(self.root / "events.log", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(self.events[-1])) + "\n")
        except OSError:
            pass

    # ------------------------------------------------------------------ dispatch
    def handle(self, caller: Caller, op: str, args: dict, payload: bytes = b"") -> tuple[dict, bytes]:
        fn = getattr(self, "op_" + op.replace(".", "_"), None)
        if fn is None:
            raise ServiceError("unknown_op", f"unknown request {op!r}")
        out = fn(caller, args or {}, payload)
        if isinstance(out, tuple):
            return out
        return out, b""

    # ------------------------------------------------------------------ general
    def op_ping(self, c: Caller, a: dict, p: bytes) -> dict:
        return {"version": __version__, "protocol": PROTOCOL, "sid": c.sid, "elevated": c.elevated}

    def op_status(self, c: Caller, a: dict, p: bytes) -> dict:
        return {
            "version": __version__,
            "uptime": time.time() - self.started,
            "global": self.global_policy(),
            "system": self.applier.status(),
            "paused": (c.sid, c.session) in self.paused,
        }

    def op_events(self, c: Caller, a: dict, p: bytes) -> dict:
        since = float(a.get("since", 0))
        with self._lock:
            mine = [asdict(e) for e in self.events if e.ts > since and (e.sid == c.sid or e.sid == "*")]
        return {"events": mine}

    def op_heartbeat(self, c: Caller, a: dict, p: bytes) -> dict:
        with self._lock:
            self.heartbeats[(c.sid, c.session)] = (time.time(), c.pid)
        return {"ok": True, "paused": (c.sid, c.session) in self.paused}

    def op_pause(self, c: Caller, a: dict, p: bytes) -> dict:
        """Stop protection until the next sign-in (the app quits and is not restarted)."""
        sid, session = str(a.get("sid", c.sid)), int(a.get("session", c.session))
        if not c.elevated:
            self._event(sid, "refused", "A program tried to stop Sentinel Vision without administrator approval")
            raise ServiceError("elevation_required", "administrator approval is needed to stop protection")
        with self._lock:
            self.paused.add((sid, session))
        self._event(sid, "changed", "Protection stopped by the user until the next sign-in")
        return {"ok": True}

    def op_resume(self, c: Caller, a: dict, p: bytes) -> dict:
        with self._lock:
            self.paused.discard((c.sid, c.session))
        return {"ok": True}

    # ------------------------------------------------------------------ protected settings
    def op_policy_get(self, c: Caller, a: dict, p: bytes) -> dict:
        sid = str(a.get("sid", c.sid))
        if sid != c.sid and not c.elevated:
            raise ServiceError("denied", "another account's settings")
        return {"policy": self.policy(sid), "global": self.global_policy()}

    def op_policy_set(self, c: Caller, a: dict, p: bytes) -> dict:
        sid = str(a.get("sid", c.sid))
        if sid != c.sid and not c.elevated:
            raise ServiceError("denied", "another account's settings")
        new = {k: v for k, v in (a.get("policy") or {}).items() if k in POLICY_FIELDS}
        new_global = {k: bool(v) for k, v in (a.get("global") or {}).items() if k in GLOBAL_BOOL_ON}
        old = self.policy(sid)
        old_global = self.global_policy()
        first_time = not old
        weaker = [] if first_time else weakened(old, new)
        weaker += weakened({k: old_global.get(k, False) for k in new_global}, new_global)
        if weaker and not c.elevated:
            names = ", ".join(label(w) for w in weaker)
            self._event(
                sid, "refused", f"A change that weakens protection was refused (no administrator approval): {names}"
            )
            raise ServiceError(
                "elevation_required", f"administrator approval is needed to change: {names}", fields=weaker
            )
        merged = {**old, **new}
        self._save_policy(sid, merged)
        if new_global:
            g = {**old_global, **new_global}
            self._save_global(g)
            self._apply_global_changes(old_global, g)
        if weaker:
            self._event(
                sid, "changed", "Protection changed with administrator approval: " + ", ".join(label(w) for w in weaker)
            )
        with self._lock:
            v = self._vaults.get(sid)
            if v is not None:
                v.max_total = int(merged.get("vault_max_mb", 5120)) * 1024 * 1024
                v.keep_versions = max(1, int(merged.get("vault_keep_versions", 10)))
        return {"policy": merged, "global": self.global_policy()}

    def _apply_global_changes(self, old: dict, new: dict) -> None:
        for key, on, off in (
            ("webshield_block_hosts", self.applier.apply_hosts, self.applier.remove_hosts),
            ("firewall_block", self.applier.apply_firewall, self.applier.remove_firewall),
        ):
            if bool(new.get(key)) != bool(old.get(key)):
                try:
                    msg = on() if new.get(key) else off()
                    log.info("%s %s: %s", label(key), "on" if new.get(key) else "off", msg)
                    self._event("*", "system", f"{label(key)}: {msg}")
                except Exception as exc:  # reported, never fatal
                    log.warning("%s failed: %s", label(key), exc)
                    self._event("*", "system", f"{label(key)} failed: {exc}")

    def op_system_refresh(self, c: Caller, a: dict, p: bytes) -> dict:
        """Re-apply machine-wide blocking from the service's own up-to-date lists (any user may ask)."""
        g = self.global_policy()
        out = {}
        if g.get("webshield_block_hosts"):
            out["hosts"] = self.applier.apply_hosts()
        if g.get("firewall_block"):
            out["firewall"] = self.applier.apply_firewall()
        return out

    # ------------------------------------------------------------------ plugin logs (append-only)
    def _plugin_log(self, sid: str, name: str):
        from sentinel_vision.pluginlog import AppendOnlyLog, PluginLogError, check_name

        try:
            check_name(name)
        except PluginLogError as exc:
            raise ServiceError("bad_request", str(exc)) from exc
        key = (sid, name)
        with self._lock:
            log_ = self._plugin_logs.get(key)
            if log_ is None:
                log_ = self._plugin_logs[key] = AppendOnlyLog(self._user_dir(sid) / "plugins" / name / "log.jsonl")
            return log_

    def op_plugin_append(self, c: Caller, a: dict, p: bytes) -> dict:
        """Add a record to the caller's own log for a plugin. Records can be added, never changed or removed."""
        from sentinel_vision.pluginlog import PluginLogError

        try:
            return self._plugin_log(c.sid, str(a.get("name", ""))).append(
                a.get("record"), pid=c.pid, elevated=c.elevated
            )
        except PluginLogError as exc:
            raise ServiceError("bad_request", str(exc)) from exc

    def op_plugin_read(self, c: Caller, a: dict, p: bytes) -> dict:
        from sentinel_vision.pluginlog import PluginLogError

        sid = str(a.get("sid", c.sid))
        if sid != c.sid and not c.elevated:
            raise ServiceError("denied", "another account's records")
        try:
            log_ = self._plugin_log(sid, str(a.get("name", "")))
            entries = log_.read(int(a.get("since", 0)), int(a.get("limit", 1000)))
            ok, count = log_.verify() if a.get("verify") else (None, None)
        except PluginLogError as exc:
            raise ServiceError("bad_request", str(exc)) from exc
        return {"entries": entries, "intact": ok, "count": count}

    # ------------------------------------------------------------------ rollback vault
    @staticmethod
    def _version(v) -> dict | None:
        return asdict(v) if v is not None else None

    def op_vault_store(self, c: Caller, a: dict, p: bytes) -> dict:
        v = self.vault(c.sid).store(str(a["key"]), p, float(a.get("mtime", 0)), bool(a.get("force")))
        return {"version": self._version(v)}

    def op_vault_read(self, c: Caller, a: dict, p: bytes) -> tuple[dict, bytes]:
        try:
            v, data = self.vault(c.sid).read(int(a["id"]))
        except VaultError as exc:
            raise ServiceError("vault", str(exc)) from exc
        return {"version": asdict(v)}, data

    def op_vault_get(self, c: Caller, a: dict, p: bytes) -> dict:
        try:
            return {"version": asdict(self.vault(c.sid).get(int(a["id"])))}
        except VaultError as exc:
            raise ServiceError("vault", str(exc)) from exc

    def op_vault_versions(self, c: Caller, a: dict, p: bytes) -> dict:
        return {"versions": [asdict(v) for v in self.vault(c.sid).versions(str(a["key"]))]}

    def op_vault_files(self, c: Caller, a: dict, p: bytes) -> dict:
        return {"files": [list(r) for r in self.vault(c.sid).files(int(a.get("limit", 5000)))]}

    def op_vault_stats(self, c: Caller, a: dict, p: bytes) -> dict:
        v = self.vault(c.sid)
        return {"stats": list(v.stats()), "max_total": v.max_total, "max_file": v.max_file}

    def op_vault_plan(self, c: Caller, a: dict, p: bytes) -> dict:
        return {"plan": [list(x) for x in self.vault(c.sid).rollback_plan(float(a["since"]), str(a.get("folder", "")))]}

    # ------------------------------------------------------------------ quarantine
    def _new_transfer(self, c: Caller, meta: dict) -> str:
        token = secrets.token_hex(16)
        path = self.root / "transfers" / token
        path.touch()
        with self._lock:
            self._transfers[token] = _Transfer(c.sid, path, meta=meta)
        return token

    def _transfer(self, c: Caller, token: str) -> _Transfer:
        with self._lock:
            t = self._transfers.get(str(token))
        if t is None or t.sid != c.sid:
            raise ServiceError("bad_transfer", "unknown transfer")
        return t

    def _end_transfer(self, token: str) -> None:
        with self._lock:
            t = self._transfers.pop(str(token), None)
        if t:
            t.path.unlink(missing_ok=True)

    def op_quarantine_begin(self, c: Caller, a: dict, p: bytes) -> dict:
        meta = {k: str(a.get(k, "")) for k in ("original_path", "threat", "engine")}
        return {"token": self._new_transfer(c, meta)}

    def op_quarantine_chunk(self, c: Caller, a: dict, p: bytes) -> dict:
        t = self._transfer(c, a["token"])
        if t.size + len(p) > MAX_UPLOAD:
            self._end_transfer(a["token"])
            raise ServiceError("too_large", "file is too large to quarantine")
        with open(t.path, "ab") as fh:
            fh.write(p)
        t.size += len(p)
        return {"size": t.size}

    def op_quarantine_commit(self, c: Caller, a: dict, p: bytes) -> dict:
        t = self._transfer(c, a["token"])
        try:
            with open(t.path, "rb") as fh:
                item = self.quarantine(c.sid).add_stream(
                    fh, t.meta["original_path"], t.meta["threat"], t.meta["engine"]
                )
        finally:
            self._end_transfer(a["token"])
        if a.get("sha256") and a["sha256"] != item.sha256:
            self.quarantine(c.sid).delete(item.id)
            raise ServiceError("corrupt", "the file changed while it was being quarantined")
        return {"item": asdict(item)}

    def op_quarantine_abort(self, c: Caller, a: dict, p: bytes) -> dict:
        self._transfer(c, a["token"])
        self._end_transfer(a["token"])
        return {"ok": True}

    def op_quarantine_list(self, c: Caller, a: dict, p: bytes) -> dict:
        return {"items": [asdict(i) for i in self.quarantine(c.sid).list()]}

    def op_quarantine_get(self, c: Caller, a: dict, p: bytes) -> dict:
        try:
            return {"item": asdict(self.quarantine(c.sid).get(str(a["id"])))}
        except QuarantineError as exc:
            raise ServiceError("quarantine", str(exc)) from exc

    def op_quarantine_open(self, c: Caller, a: dict, p: bytes) -> dict:
        """Decrypt and verify an item into a private transfer file; the client then reads it in chunks."""
        q = self.quarantine(c.sid)
        try:
            item = q.get(str(a["id"]))
        except QuarantineError as exc:
            raise ServiceError("quarantine", str(exc)) from exc
        token = self._new_transfer(c, {"id": item.id})
        t = self._transfer(c, token)
        try:
            with open(t.path, "wb") as out:
                for chunk in q.iter_plain(item.id):
                    out.write(chunk)
        except QuarantineError as exc:
            self._end_transfer(token)
            raise ServiceError("quarantine", str(exc)) from exc
        t.size = t.path.stat().st_size
        return {"token": token, "size": t.size, "item": asdict(item)}

    def op_quarantine_read(self, c: Caller, a: dict, p: bytes) -> tuple[dict, bytes]:
        t = self._transfer(c, a["token"])
        offset = int(a.get("offset", 0))
        with open(t.path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(min(int(a.get("length", READ_CHUNK)), READ_CHUNK))
        return {"offset": offset, "eof": offset + len(data) >= t.size}, data

    def op_quarantine_close(self, c: Caller, a: dict, p: bytes) -> dict:
        self._transfer(c, a["token"])
        self._end_transfer(a["token"])
        return {"ok": True}

    def op_quarantine_delete(self, c: Caller, a: dict, p: bytes) -> dict:
        try:
            self.quarantine(c.sid).delete(str(a["id"]))
        except QuarantineError as exc:
            raise ServiceError("quarantine", str(exc)) from exc
        return {"ok": True}

    # ------------------------------------------------------------------ uninstall
    def wipe_all(self) -> None:
        """Remove every user's protected data (only on uninstall, after the user said yes)."""
        self.close()
        shutil.rmtree(self.root / "users", ignore_errors=True)
