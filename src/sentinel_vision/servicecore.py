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
import math
import os
import re
import secrets
import shutil
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from sentinel_vision import __version__
from sentinel_vision.quarantine import Quarantine, QuarantineError
from sentinel_vision.schema import (
    BOOL_ON,
    GLOBAL_BOOL_ON,
    LIST_GROW,
    LIST_KEEP,
    NUM_HIGHER_IS_STRONGER,
    NUM_LOWER_IS_STRONGER,
    SchemaError,
)
from sentinel_vision.schema import check as check_field
from sentinel_vision.vault import RollbackVault, VaultError, VaultRefused

log = logging.getLogger("sentinel_vision.service")

PROTOCOL = 1
MAX_UPLOAD = 2 * 1024 * 1024 * 1024  # largest file accepted into quarantine
MAX_FRAME = 64 * 1024 * 1024  # largest single payload (vault versions are at most a few dozen MB)
READ_CHUNK = 8 * 1024 * 1024
# Resource limits per account (audit finding SV-F03)
MAX_TRANSFERS = 4
MAX_IN_TRANSIT = 4 * 1024**3
TRANSFER_IDLE = 15 * 60
RATE_PER_SECOND = 50  # changing requests, with bursts up to RATE_BURST
RATE_BURST = 100
REFRESH_EVERY = 10 * 60
MUTATING = frozenset(
    {"pause", "resume", "policy.set", "system.refresh", "plugin.append", "vault.store", "vault.preserve",
     "quarantine.begin", "quarantine.chunk", "quarantine.commit", "quarantine.abort", "quarantine.delete",
     "quarantine.release", "update.install"}
)  # fmt: skip
RELEASE_SECONDS = 120  # how long an administrator's approval to restore one quarantined item lasts
SID_RE = re.compile(r"^S-1(-\d{1,10}){1,15}$")

# ---------------------------------------------------------------------------------------------- policy
# Which settings protect the user (and their allowed values) are defined in schema.py; "weaker" is decided here.

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


def _no_constants(name: str):
    raise ValueError(f"{name} is not allowed")


def _valid_field(name: str, value) -> bool:
    try:
        check_field(name, value)
        return True
    except SchemaError:
        return False


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


def strengthen(policy: dict, floor: dict) -> dict:
    """``policy`` with every field at least as strong as in ``floor`` (stronger choices in ``policy`` are kept)."""
    out = dict(policy)
    for k, fv in floor.items():
        pv = policy.get(k, fv)
        if k in BOOL_ON or k in GLOBAL_BOOL_ON:
            out[k] = bool(pv) or bool(fv)
        elif k in LIST_KEEP:
            out[k] = list(dict.fromkeys([*fv, *pv]))
        elif k in LIST_GROW:
            keep = set(_norm_list(fv))
            out[k] = [x for x in pv if _norm_list([x])[0] in keep]
        elif k in NUM_LOWER_IS_STRONGER:
            out[k] = min(pv, fv)
        elif k in NUM_HIGHER_IS_STRONGER:
            out[k] = max(pv, fv)
        elif k == "auto_update_hours":
            out[k] = fv if (pv == 0 and fv > 0) or (fv > 0 and pv > fv) else pv
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


# ---------------------------------------------------------------------------------------------- request schema
# Every request is checked against its schema before it runs (audit finding SV-F01): only the listed arguments,
# each of the right type and size. Anything else is refused with "bad_request" and changes nothing.
MAX_PATH_CHARS = 32_767
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _int(lo: int, hi: int):
    def v(x):
        return type(x) is int and lo <= x <= hi

    return v


def _num(lo: float, hi: float):
    def v(x):
        return type(x) in (int, float) and math.isfinite(x) and lo <= x <= hi

    return v


def _text(max_chars: int, allow_empty: bool = True):
    def v(x):
        return type(x) is str and (allow_empty or x) and len(x) <= max_chars and "\0" not in x

    return v


def _match(rx):
    return lambda x: type(x) is str and bool(rx.match(x))


def _is_bool(x):
    return type(x) is bool


def _is_dict(x):
    return type(x) is dict


_SID = _match(SID_RE)
_TOKEN = _match(HEX32_RE)
_ID = _int(1, 2**62)
_PATH = _text(MAX_PATH_CHARS, allow_empty=False)
_TIME = _num(0, 1e11)
SCHEMAS: dict[str, dict] = {
    "ping": {}, "status": {}, "heartbeat": {}, "resume": {}, "system.refresh": {},
    "events": {"after": _int(0, 2**62), "since": _TIME},
    "pause": {"sid": _SID, "session": _int(0, 65_535)},
    "policy.get": {"sid": _SID},
    "policy.set": {"sid": _SID, "policy": _is_dict, "global": _is_dict},
    "plugin.append": {"name": _text(40), "record": _is_dict},
    "plugin.read": {"name": _text(40), "sid": _SID, "since": _int(0, 2**62), "limit": _int(1, 1000),
                    "verify": _is_bool},
    "vault.store": {"key": _PATH, "mtime": _TIME},
    "vault.preserve": {"key": _PATH, "mtime": _TIME},
    "vault.read": {"id": _ID}, "vault.get": {"id": _ID},
    "vault.versions": {"key": _PATH}, "vault.files": {"limit": _int(1, 5000)}, "vault.stats": {},
    "vault.plan": {"since": _TIME, "folder": _text(MAX_PATH_CHARS)},
    "quarantine.begin": {"original_path": _PATH, "threat": _text(200), "engine": _text(200)},
    "quarantine.chunk": {"token": _TOKEN}, "quarantine.commit": {"token": _TOKEN, "sha256": _match(HEX64_RE)},
    "quarantine.abort": {"token": _TOKEN}, "quarantine.list": {},
    "quarantine.get": {"id": _TOKEN, "sid": _SID},
    "quarantine.open": {"id": _TOKEN}, "quarantine.delete": {"id": _TOKEN},
    "quarantine.release": {"sid": _SID, "id": _TOKEN},
    "quarantine.read": {"token": _TOKEN, "offset": _int(0, 2**42), "length": _int(1, READ_CHUNK)},
    "quarantine.close": {"token": _TOKEN},
    "update.install": {"version": _text(32)},
}  # fmt: skip
REQUIRED = {
    "pause": ("sid", "session"), "plugin.append": ("name", "record"), "plugin.read": ("name",),
    "vault.store": ("key",), "vault.preserve": ("key",), "vault.read": ("id",), "vault.get": ("id",),
    "vault.versions": ("key",), "vault.plan": ("since",), "quarantine.chunk": ("token",),
    "quarantine.commit": ("token",), "quarantine.abort": ("token",), "quarantine.get": ("id",),
    "quarantine.open": ("id",), "quarantine.delete": ("id",), "quarantine.read": ("token",),
    "quarantine.release": ("sid", "id"),
    "quarantine.close": ("token",),
}  # fmt: skip


def check_request(op: str, args) -> None:
    schema = SCHEMAS.get(op)
    if schema is None:
        raise ServiceError("unknown_op", f"unknown request {op!r}")
    if type(args) is not dict:
        raise ServiceError("bad_request", "arguments must be an object")
    for k, v in args.items():
        if k not in schema:
            raise ServiceError("bad_request", f"{op}: unknown argument {k!r}")
        if not schema[k](v):
            raise ServiceError("bad_request", f"{op}: invalid value for {k!r}")
    missing = [k for k in REQUIRED.get(op, ()) if k not in args]
    if missing:
        raise ServiceError("bad_request", f"{op}: missing {', '.join(missing)}")


def check_policy(policy: dict, global_: dict) -> None:
    for k, v in policy.items():
        if k not in POLICY_FIELDS:
            raise ServiceError("bad_request", f"unknown setting {k!r}")
        try:
            check_field(k, v)
        except SchemaError as exc:
            raise ServiceError("bad_request", str(exc)) from exc
    for k, v in global_.items():
        if k not in GLOBAL_BOOL_ON or type(v) is not bool:
            raise ServiceError("bad_request", f"invalid machine-wide setting {k!r}")


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
    kind: str  # refused | changed | watchdog | system | warning
    detail: str
    seq: int = 0  # increases by one per event; clients ask for events after the last seq they saw


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

    def install_update(self) -> str:
        raise ServiceError("unsupported", "updates are installed by the Windows protection service")


def _program_name(pid: int) -> str:
    """'C:\\path\\to\\program.exe (process 1234)' while the process runs, else 'process 1234'."""
    try:
        import psutil

        exe = psutil.Process(pid).exe()
    except Exception:
        exe = ""
    return f"{exe} (process {pid})" if exe else f"process {pid}"


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
        self._log_writers: dict[tuple[str, str], Counter] = {}  # (sid, plugin) -> records added per process id
        self._log_warned: dict[tuple[str, str, bool], float] = {}  # (sid, plugin, full) -> when last reported
        self._last_refusal: dict = {}
        self._released: dict[tuple[str, str], float] = {}
        self._buckets: dict[str, list[float]] = {}  # sid -> [tokens, last time]
        self._last_refresh: dict[str, float] = {}
        self._transfers: dict[str, _Transfer] = {}
        self.events: list[Event] = []
        self._event_seq = 0
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
            raw = json.loads(p.read_text(encoding="utf-8"), parse_constant=_no_constants)
        except (OSError, ValueError):
            return {}
        if type(raw) is not dict:
            return {}
        # only valid values count (a damaged or older file never breaks the vault or weakens anything)
        return {k: v for k, v in raw.items() if k in POLICY_FIELDS and _valid_field(k, v)}

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
            self._event_seq += 1
            ev = Event(time.time(), sid, kind, detail, self._event_seq)
            self.events.append(ev)
            del self.events[:-500]
        try:
            with open(self.root / "events.log", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(ev)) + "\n")
        except OSError:
            pass

    # ------------------------------------------------------------------ dispatch
    def handle(self, caller: Caller, op: str, args: dict, payload: bytes = b"") -> tuple[dict, bytes]:
        args = {} if args is None else args
        check_request(str(op), args)
        if op in MUTATING:
            self._rate(caller.sid)
        fn = getattr(self, "op_" + str(op).replace(".", "_"), None)
        if fn is None:
            raise ServiceError("unknown_op", f"unknown request {op!r}")
        out = fn(caller, args, payload)
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
        """Events for the caller. ``after``: those after a sequence number (exact; the reply's ``last`` is the next
        cursor). ``since``: those after a time (older clients; can miss events in the same clock tick)."""
        with self._lock:
            if "after" in a:
                after = int(a["after"])
                mine = [asdict(e) for e in self.events if e.seq > after and (e.sid == c.sid or e.sid == "*")]
            else:
                since = float(a.get("since", 0))
                mine = [asdict(e) for e in self.events if e.ts > since and (e.sid == c.sid or e.sid == "*")]
            return {"events": mine, "last": self._event_seq}

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
        check_policy(a.get("policy") or {}, a.get("global") or {})  # before anything is compared (SV-A03)
        new = dict(a.get("policy") or {})
        new_global = dict(a.get("global") or {})
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
        """Re-apply machine-wide blocking from the service's own up-to-date lists (any user may ask, at most once
        every ten minutes)."""
        now = time.time()
        with self._lock:
            if now - self._last_refresh.get(c.sid, 0) < REFRESH_EVERY:
                raise ServiceError("too_many", "blocking was refreshed less than ten minutes ago")
            self._last_refresh[c.sid] = now
        g = self.global_policy()
        out = {}
        if g.get("webshield_block_hosts"):
            out["hosts"] = self.applier.apply_hosts()
        if g.get("firewall_block"):
            out["firewall"] = self.applier.apply_firewall()
        return out

    # ------------------------------------------------------------------ updates
    def op_update_install(self, c: Caller, a: dict, p: bytes) -> dict:
        """Install the newest signed release (any signed-in user may ask; only newer, signed releases are ever
        installed, and the service downloads and checks them itself)."""
        now = time.time()
        with self._lock:
            if now - self._last_refresh.get((c.sid, "update"), 0) < REFRESH_EVERY:
                raise ServiceError("too_many", "an update was started less than ten minutes ago")
            self._last_refresh[(c.sid, "update")] = now
        try:
            version = self.applier.install_update()
        except ServiceError:
            raise
        except Exception as exc:
            raise ServiceError("update_failed", str(exc)) from exc
        self._event("*", "changed", f"Updating Sentinel Vision to {version}")
        return {"version": version}

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
        """Add a record to the caller's own log for a plugin. Records can be added, never changed or removed.

        Any program running as the user may add to any of the user's plugin logs, so one could fill a log to keep a
        plugin's later records out. A log that passes WARN_SHARE of its limit, or refuses a record because it is
        full, is reported to the user with the programs that added most of its records (INT-N01)."""
        from sentinel_vision.pluginlog import MAX_LOG, WARN_SHARE, PluginLogError

        name = str(a.get("name", ""))
        log_ = self._plugin_log(c.sid, name)
        try:
            r = log_.append(a.get("record"), pid=c.pid, elevated=c.elevated)
        except PluginLogError as exc:
            if str(exc).startswith("log is full"):
                self._report_log_filling(c.sid, name, log_.size(), full=True)
            raise ServiceError("bad_request", str(exc)) from exc
        with self._lock:
            writers = self._log_writers.setdefault((c.sid, name), Counter())
            writers[c.pid] += 1
            if len(writers) > 1000:  # many short-lived processes: keep the ones that wrote most
                self._log_writers[(c.sid, name)] = Counter(dict(writers.most_common(500)))
        if r["bytes"] >= WARN_SHARE * MAX_LOG:
            self._report_log_filling(c.sid, name, r["bytes"], full=False)
        return r

    def _report_log_filling(self, sid: str, name: str, used: int, *, full: bool) -> None:
        """Tell the user a plugin log is nearly full (at most once a day) or full (at most once an hour)."""
        from sentinel_vision.pluginlog import MAX_LOG

        now = time.time()
        with self._lock:
            if now - self._log_warned.get((sid, name, full), 0) < (3600 if full else 86400):
                return
            self._log_warned[(sid, name, full)] = now
            top = self._log_writers.get((sid, name), Counter()).most_common(3)
        writers = "; ".join(f"{_program_name(pid)}: {n} record(s)" for pid, n in top)
        source = (
            f"Since Sentinel Vision started, most of its records came from {writers}."
            if writers
            else "Its records were added before Sentinel Vision last started."
        )
        if full:
            what = f"The protected record log '{name}' is full, so new records can't be added to it."
        else:
            what = f"The protected record log '{name}' is {min(99, round(100 * used / MAX_LOG))}% full."
        self._event(
            sid,
            "warning",
            f"{what} {source} Any program running as you can add records, so it may be filling up on purpose. "
            "docs/PLUGINS.md says how an administrator makes room.",
        )

    def op_plugin_read(self, c: Caller, a: dict, p: bytes) -> dict:
        from sentinel_vision.pluginlog import MAX_LOG, PluginLogError

        sid = str(a.get("sid", c.sid))
        if sid != c.sid and not c.elevated:
            raise ServiceError("denied", "another account's records")
        try:
            log_ = self._plugin_log(sid, str(a.get("name", "")))
            entries = log_.read(int(a.get("since", 0)), int(a.get("limit", 1000)))
            ok, count = log_.verify() if a.get("verify") else (None, None)
        except PluginLogError as exc:
            raise ServiceError("bad_request", str(exc)) from exc
        return {"entries": entries, "intact": ok, "count": count, "bytes": log_.size(), "limit": MAX_LOG}

    # ------------------------------------------------------------------ rollback vault
    @staticmethod
    def _version(v) -> dict | None:
        return asdict(v) if v is not None else None

    def _vault_key(self, sid: str, key: str) -> str:
        """Only normalised absolute paths inside the account's protected folders (audit finding SV-F02): the vault
        must not hold versions of places a program running as the user picks, such as a Startup folder."""
        norm = os.path.normcase(os.path.abspath(key))
        bad = (
            norm != key
            or ".." in key.replace("\\", "/").split("/")
            or key.startswith(("\\\\", "//"))
            or key[:4] in ("\\\\?\\", "\\\\.\\")
        )
        folders = [os.path.normcase(os.path.abspath(f)) for f in self.policy(sid).get("ransomware_folders", [])]
        inside = any(norm.startswith(f.rstrip(os.sep) + os.sep) for f in folders if f)
        if bad or not inside:
            raise ServiceError("bad_request", "the vault only keeps files inside your protected folders")
        return norm

    def _vault_put(self, c: Caller, a: dict, p: bytes, preserve: bool) -> dict:
        key = self._vault_key(c.sid, a["key"])
        try:
            v = self.vault(c.sid).store(key, p, float(a.get("mtime", 0)), force=preserve, preserve=preserve)
        except VaultRefused as exc:
            self._refusal(c.sid, f"The rollback vault refused a new version: {exc}")
            raise ServiceError("refused", str(exc)) from exc
        return {"version": self._version(v)}

    def op_vault_store(self, c: Caller, a: dict, p: bytes) -> dict:
        """A new version of a protected document. Content that looks encrypted is never stored this way."""
        return self._vault_put(c, a, p, preserve=False)

    def op_vault_preserve(self, c: Caller, a: dict, p: bytes) -> dict:
        """The copy kept just before a restore overwrites a file (stored even if it looks encrypted, so a restore
        can be undone). It never removes anything to make room."""
        return self._vault_put(c, a, p, preserve=True)

    def _refusal(self, sid: str, detail: str) -> None:
        """A refused-event, at most one per ten minutes per account and kind of message."""
        key = (sid, detail.split(":")[0])
        now = time.time()
        with self._lock:
            if now - self._last_refusal.get(key, 0) < 600:
                return
            self._last_refusal[key] = now
        self._event(sid, "refused", detail)

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
        return {
            "stats": list(v.stats()),
            "max_total": v.max_total,
            "max_file": v.max_file,
            "full_since": v.full_since(),
        }

    def op_vault_plan(self, c: Caller, a: dict, p: bytes) -> dict:
        return {"plan": [list(x) for x in self.vault(c.sid).rollback_plan(float(a["since"]), str(a.get("folder", "")))]}

    # ------------------------------------------------------------------ quarantine
    def _rate(self, sid: str) -> None:
        """Token bucket per account: RATE_PER_SECOND changing requests, bursts up to RATE_BURST."""
        now = time.time()
        with self._lock:
            tokens, last = self._buckets.get(sid, [float(RATE_BURST), now])
            tokens = min(float(RATE_BURST), tokens + (now - last) * RATE_PER_SECOND)
            if tokens < 1:
                self._buckets[sid] = [tokens, now]
                raise ServiceError("too_many", "too many requests; try again shortly", retry_after=0.1)
            self._buckets[sid] = [tokens - 1, now]

    def _expire_transfers(self) -> None:
        cutoff = time.time() - TRANSFER_IDLE
        with self._lock:
            stale = [tok for tok, t in self._transfers.items() if t.ts < cutoff]
        for tok in stale:
            self._end_transfer(tok)

    def _new_transfer(self, c: Caller, meta: dict) -> str:
        self._expire_transfers()
        with self._lock:
            mine = [t for t in self._transfers.values() if t.sid == c.sid]
            if len(mine) >= MAX_TRANSFERS:
                raise ServiceError("too_many", f"at most {MAX_TRANSFERS} transfers at a time")
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
        t.ts = time.time()
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
        with self._lock:
            in_transit = sum(x.size for x in self._transfers.values() if x.sid == c.sid)
        if in_transit + len(p) > MAX_IN_TRANSIT:
            raise ServiceError("too_large", "too much data in transit; finish other transfers first")
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
        sid = str(a.get("sid", c.sid))
        if sid != c.sid and not c.elevated:
            raise ServiceError("denied", "another account's quarantine")
        try:
            return {"item": asdict(self.quarantine(sid).get(str(a["id"])))}
        except QuarantineError as exc:
            raise ServiceError("quarantine", str(exc)) from exc

    def op_quarantine_release(self, c: Caller, a: dict, p: bytes) -> dict:
        """Administrator approval to restore one item: the account may open it once within two minutes. The
        approval comes from the elevated helper, which never writes files itself (the app restores as the user)."""
        if not c.elevated:
            raise ServiceError("elevation_required", "administrator approval is needed to restore from quarantine")
        sid, item_id = str(a["sid"]), str(a["id"])
        try:
            item = self.quarantine(sid).get(item_id)
        except QuarantineError as exc:
            raise ServiceError("quarantine", str(exc)) from exc
        with self._lock:
            self._released[(sid, item_id)] = time.time() + RELEASE_SECONDS
        self._event(sid, "changed", f"Restoring {item.original_path} ({item.threat}) from quarantine was approved")
        return {"ok": True}

    def op_quarantine_open(self, c: Caller, a: dict, p: bytes) -> dict:
        """Decrypt and verify an item into a private transfer file; the client then reads it in chunks. Only with
        administrator approval: decrypting quarantined malware weakens protection (audit finding SV-A04)."""
        q = self.quarantine(c.sid)
        try:
            item = q.get(str(a["id"]))
        except QuarantineError as exc:
            raise ServiceError("quarantine", str(exc)) from exc
        if not c.elevated:
            with self._lock:
                until = self._released.pop((c.sid, item.id), 0)
            if until < time.time():
                self._refusal(c.sid, f"A program tried to restore {item.original_path} from quarantine without "
                                     "administrator approval")  # fmt: skip
                raise ServiceError(
                    "elevation_required", "administrator approval is needed to restore from quarantine", id=item.id
                )
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
