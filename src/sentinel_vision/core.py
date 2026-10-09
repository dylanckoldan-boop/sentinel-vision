"""Wires every subsystem together; shared by the GUI, the CLI and the tests."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from sentinel_vision.behavior import BehaviorMonitor
from sentinel_vision.config import Settings, sub_dir
from sentinel_vision.db import Database
from sentinel_vision.network.monitor import NetworkMonitor
from sentinel_vision.network.threatintel import IntelStore
from sentinel_vision.quarantine import Quarantine
from sentinel_vision.realtime import RealtimeProtection
from sentinel_vision.scanner import Scanner
from sentinel_vision.updater import Updater


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


class Sentinel:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.load()
        self.db = Database()
        self.quarantine = Quarantine()
        self.scanner = Scanner(self.settings, self.db, self.quarantine)
        self.intel = IntelStore()
        self.network = NetworkMonitor(self.settings, self.intel, self.db)
        self.realtime = RealtimeProtection(self.scanner)
        self.updater = Updater(self.settings, self.db, self.intel)
        self.behavior = BehaviorMonitor(self.scanner, self.settings)
        self._engine_key = self._current_engine_key()
        self._watch_key: tuple | None = None

    def _current_engine_key(self) -> tuple:
        s = self.settings
        return (s.hash_enabled, s.yara_enabled, s.clamav_enabled, s.heuristics_enabled, s.heuristic_threshold,
                s.clamd_address)  # fmt: skip

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
        if s.network_enabled:
            self.network.start()
        else:
            self.network.stop()
        if s.behavior_enabled:
            self.behavior.start()
        else:
            self.behavior.stop()

    def apply_settings(self) -> None:
        """Persist settings and re-apply them to running subsystems after the user changes them."""
        self.settings.save()
        key = self._current_engine_key()
        if key != self._engine_key:  # rebuilding compiles every YARA rule, so only do it when needed
            self.scanner.build_engines()
            self._engine_key = key
        self.start_protection()

    def after_update(self) -> None:
        self.scanner.reload_signatures()

    def shutdown(self) -> None:
        self.behavior.stop()
        self.realtime.stop()
        self.network.stop()
        self.db.close()
