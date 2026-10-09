"""Wires every subsystem together; shared by the GUI, the CLI and the tests."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

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

    def apply_settings(self) -> None:
        """Re-read settings into running subsystems after the user changes them."""
        self.settings.save()
        self.scanner.build_engines()
        if self.settings.realtime_enabled:
            self.realtime.start(self.settings.watch_paths)
        else:
            self.realtime.stop()
        if self.settings.network_enabled:
            self.network.start()
        else:
            self.network.stop()

    def after_update(self) -> None:
        self.scanner.reload_signatures()

    def shutdown(self) -> None:
        self.realtime.stop()
        self.network.stop()
        self.db.close()
