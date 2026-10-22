"""Wires every subsystem together; shared by the GUI, the CLI and the tests."""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from logging.handlers import RotatingFileHandler

from sentinel_vision import service_client
from sentinel_vision.advisor import NetGuard
from sentinel_vision.behavior import BehaviorMonitor
from sentinel_vision.config import Settings, sub_dir
from sentinel_vision.db import Database
from sentinel_vision.devices import DriveWatcher, PrivacyMonitor, due_scans
from sentinel_vision.network.monitor import NetworkMonitor
from sentinel_vision.network.threatintel import IntelStore
from sentinel_vision.quarantine import Quarantine
from sentinel_vision.ransomware import RansomwareShield
from sentinel_vision.realtime import RealtimeProtection
from sentinel_vision.reputation import ReputationService
from sentinel_vision.scanner import Scanner, ScanSummary
from sentinel_vision.servicecore import ServiceError, apply_policy, policy_from_settings
from sentinel_vision.updater import Updater
from sentinel_vision.vault import RollbackVault
from sentinel_vision.webshield import DomainIntel


def setup_logging(verbose: bool = False) -> None:
    root = logging.getLogger()
    if any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        return
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    fh = RotatingFileHandler(
        sub_dir("logs") / "sentinel.log", maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(fh)


Alert = Callable[[str, str, str], None]  # (title, text, level: info | warning | danger)


class ProtectionChangeNeedsAdmin(Exception):
    """The change weakens protection; the protection service only accepts it with administrator approval."""

    def __init__(self, fields: list[str], message: str) -> None:
        super().__init__(message)
        self.fields = fields


class Sentinel:
    def __init__(self, settings: Settings | None = None, use_service: bool = True, service=None) -> None:
        self.settings = settings or Settings.load()
        s = self.settings
        self.db = Database()
        # Windows: the protection service keeps the vault, quarantine and protection settings out of reach of
        # other programs. Elsewhere (or if it isn't installed) they live in the user's own data folder.
        self.service = service if service is not None else (service_client.connect() if use_service else None)
        self.migrated: tuple[int, int] = (0, 0)
        if self.service is not None:
            self._attach_service()
            self.quarantine = service_client.RemoteQuarantine(self.service)
        else:
            self.quarantine = Quarantine()
        self.scanner = Scanner(s, self.db, self.quarantine)
        self.reputation = ReputationService(s, self.db)
        self.scanner.reputation = self.reputation
        self.intel = IntelStore()
        self.domains = DomainIntel()
        self.network = NetworkMonitor(s, self.intel, self.db)
        self.realtime = RealtimeProtection(self.scanner)
        self.updater = Updater(s, self.db, self.intel, self.domains)
        self.behavior = BehaviorMonitor(self.scanner, s)
        if self.service is not None:
            self.vault = service_client.RemoteVault(self.service)
        else:
            self.vault = RollbackVault(max_total_mb=s.vault_max_mb, keep_versions=s.vault_keep_versions)
        self.ransomware = RansomwareShield(s, self.db, self.vault)
        self.drives = DriveWatcher(self._on_drive)
        self.privacy = PrivacyMonitor(self._on_device_use)
        self.netguard = NetGuard(self.db, self.intel, lambda text, level: self.alert("Network warning", text, level))
        self.alert_listeners: list[Alert] = []
        self._scheduled_lock = threading.Lock()
        self.scheduled_running = ""
        self._engine_key = self._current_engine_key()
        self._watch_key: tuple | None = None
        self._rw_key: tuple | None = None
        self._events_since = time.time()

    # ------------------------------------------------------------------ protection service
    def _global_from_settings(self) -> dict:
        return {
            "webshield_block_hosts": self.settings.webshield_block_hosts,
            "firewall_block": self.settings.firewall_block,
        }

    def _attach_service(self) -> None:
        log = logging.getLogger(__name__)
        t = self.service
        try:
            self.migrated = service_client.migrate_local_data(t, sub_dir("vault"), sub_dir("quarantine"))
            if any(self.migrated):
                self.db.log_event(
                    "service",
                    f"Moved {self.migrated[0]} document version(s) and {self.migrated[1]} quarantined file(s) "
                    "into the protected storage",
                )
        except Exception:
            log.exception("moving local data into the protection service failed (kept locally)")
        r = t.call("policy.get")[0]
        if not r.get("policy"):
            t.call(
                "policy.set", {"policy": policy_from_settings(self.settings), "global": self._global_from_settings()}
            )
            self.db.log_event("service", "Protection settings are now guarded by the protection service")
        else:
            apply_policy(self.settings, r["policy"])  # the protected copy wins over the settings file
            g = r.get("global") or {}
            self.settings.webshield_block_hosts = bool(
                g.get("webshield_block_hosts", self.settings.webshield_block_hosts)
            )
            self.settings.firewall_block = bool(g.get("firewall_block", self.settings.firewall_block))

    def save_settings(self) -> None:
        """Save settings. With the protection service, a change that weakens protection raises
        :class:`ProtectionChangeNeedsAdmin` and nothing is saved."""
        if self.service is not None:
            try:
                self.service.call(
                    "policy.set",
                    {"policy": policy_from_settings(self.settings), "global": self._global_from_settings()},
                )
            except ServiceError as exc:
                if exc.code == "elevation_required":
                    raise ProtectionChangeNeedsAdmin(list(exc.extra.get("fields", [])), str(exc)) from exc
                raise
        self.settings.save()

    def reload_protected_settings(self) -> None:
        """Undo unsaved changes to protected settings (after the user declined the administrator prompt)."""
        if self.service is not None:
            r = self.service.call("policy.get")[0]
            apply_policy(self.settings, r.get("policy") or {})
            g = r.get("global") or {}
            self.settings.webshield_block_hosts = bool(g.get("webshield_block_hosts", False))
            self.settings.firewall_block = bool(g.get("firewall_block", True))

    def service_tick(self) -> list[dict]:
        """Heartbeat to the protection service; returns new events for this user (refused changes, restarts)."""
        if self.service is None:
            return []
        self.service.call("heartbeat")
        events = self.service.call("events", {"since": self._events_since})[0]["events"]
        if events:
            self._events_since = max(e["ts"] for e in events)
        return events

    # ------------------------------------------------------------------ alerts
    def alert(self, title: str, text: str, level: str = "info") -> None:
        if self.settings.quiet_mode and level == "info":
            return
        for fn in list(self.alert_listeners):
            try:
                fn(title, text, level)
            except Exception:
                logging.getLogger(__name__).exception("alert listener failed")

    def _current_engine_key(self) -> tuple:
        s = self.settings
        return (s.hash_enabled, s.yara_enabled, s.clamav_enabled, s.heuristics_enabled, s.heuristic_threshold,
                s.clamd_address)  # fmt: skip

    # ------------------------------------------------------------------ lifecycle
    def start_protection(self) -> None:
        """Start every background protection the settings ask for (idempotent)."""
        s = self.settings
        watch_key = (s.realtime_enabled, tuple(s.watch_paths), tuple(s.exclusions))
        if s.realtime_enabled:
            if watch_key != self._watch_key or not self.realtime.running:
                self.realtime.start(s.watch_paths)
        else:
            self.realtime.stop()
        self._watch_key = watch_key
        for enabled, sub in (
            (s.network_enabled, self.network),
            (s.behavior_enabled, self.behavior),
            (s.usb_autoscan, self.drives),
            (s.privacy_monitor, self.privacy),
            (s.netsec_enabled, self.netguard),
        ):
            if enabled:
                sub.start()
            else:
                sub.stop()
        rw_key = (s.ransomware_enabled, tuple(s.ransomware_folders))
        if s.ransomware_enabled:
            if rw_key != self._rw_key or not self.ransomware.running:
                self.ransomware.start(s.ransomware_folders)
        else:
            was_on = self._rw_key is not None and self._rw_key[0]
            self.ransomware.stop()
            if was_on:  # switched off by the user: don't leave hidden decoys behind
                RansomwareShield.cleanup_decoys(list(self._rw_key[1]))
        self._rw_key = rw_key

    def apply_settings(self) -> None:
        """Persist settings and re-apply them to running subsystems after the user changes them.
        Raises :class:`ProtectionChangeNeedsAdmin` (nothing applied) when the change needs administrator approval."""
        self.save_settings()
        key = self._current_engine_key()
        if key != self._engine_key:  # rebuilding compiles every YARA rule, so only do it when needed
            self.scanner.build_engines()
            self._engine_key = key
        self.vault.max_total = self.settings.vault_max_mb * 1024 * 1024
        self.start_protection()

    def after_update(self) -> None:
        self.scanner.reload_signatures()

    def shutdown(self) -> None:
        for sub in (
            self.ransomware,
            self.netguard,
            self.privacy,
            self.drives,
            self.behavior,
            self.realtime,
            self.network,
        ):
            try:
                sub.stop()
            except Exception:
                logging.getLogger(__name__).exception("stopping %s failed", type(sub).__name__)
        self.vault.close()
        self.domains.close()
        self.db.close()
        if self.service is not None:
            self.service.close()

    # ------------------------------------------------------------------ devices & schedules
    def scan_drive(self, mountpoint: str) -> ScanSummary:
        self.db.log_event("usb", f"Scanning new drive {mountpoint}")
        summary = self.scanner.scan_paths([mountpoint], origin="usb", max_files=50000)
        self.alert("Drive scanned", f"{mountpoint}: {summary.scanned:,} files, {_outcome(summary)}", _level(summary))
        return summary

    def _on_drive(self, mountpoint: str) -> None:
        threading.Thread(target=self.scan_drive, args=(mountpoint,), name="usb-scan", daemon=True).start()

    def _on_device_use(self, use) -> None:
        kind = "camera" if use.kind == "camera" else "microphone"
        self.db.log_event("privacy", f"{use.app} started using the {kind}")
        self.alert(f"{kind.capitalize()} in use", f"{use.app} is using your {kind}.", "warning")

    def run_due_scans(self) -> list[str]:
        """Run scheduled scans that are due (in the background). Returns the kinds started."""
        last_q = float(self.db.get_meta("last_sched_quick", "0") or 0)
        last_f = float(self.db.get_meta("last_sched_full", "0") or 0)
        due = due_scans(self.settings, last_q, last_f)
        if not due or not self._scheduled_lock.acquire(blocking=False):
            return []
        kind = due[0]

        def work() -> None:
            try:
                self.scheduled_running = kind
                now = str(time.time())
                self.db.set_meta("last_sched_full" if kind == "full" else "last_sched_quick", now)
                if kind == "full":
                    self.db.set_meta("last_sched_quick", now)
                roots = self.scanner.full_scan_roots() if kind == "full" else self.scanner.quick_scan_roots()
                summary = self.scanner.scan_paths(roots, origin="scheduled")
                if kind == "quick":
                    proc = self.scanner.scan_processes()
                    summary.infected += proc.infected
                    summary.review += proc.review
                    summary.results += proc.results
                mem_note = ""
                if kind == "full" and self.settings.schedule_memory_scan:
                    from sentinel_vision import memscan

                    mem = memscan.scan_processes(self.scanner)
                    if mem.hits:
                        names = ", ".join(f"{h.name} ({h.pid})" for h in mem.hits[:5])
                        mem_note = f"; memory scan: {len(mem.hits)} suspicious program(s): {names}"
                        self.db.log_event("memscan", f"Scheduled memory scan: {names}", "warning")
                    else:
                        mem_note = f"; memory of {mem.scanned} programs checked, nothing found"
                self.alert(
                    f"Scheduled {kind} scan finished",
                    f"{summary.scanned:,} files checked, {_outcome(summary)}{mem_note}",
                    "warning" if mem_note.startswith("; memory scan:") and not summary.threats else _level(summary),
                )
            finally:
                self.scheduled_running = ""
                self._scheduled_lock.release()

        threading.Thread(target=work, name=f"scheduled-{kind}", daemon=True).start()
        return [kind]


def _outcome(summary: ScanSummary) -> str:
    """Plain wording for a finished scan: what was found and what was actually done about it."""
    if not summary.infected:
        return "no threats found"
    quarantined = sum(1 for r in summary.results if r.action == "quarantined")
    parts = []
    if summary.threats:
        parts.append(f"{summary.threats} threat(s) found")
    if summary.review:
        parts.append(f"{summary.review} item(s) to review")
    if quarantined:
        parts.append(f"{quarantined} moved to quarantine")
    return ", ".join(parts)


def _level(summary: ScanSummary) -> str:
    return "danger" if summary.threats else ("warning" if summary.review else "info")
