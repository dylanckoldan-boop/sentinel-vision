"""Audit finding SV-A01: when the installed protection service can't be reached, Sentinel Vision fails closed
(degraded mode) instead of falling back to unprotected local storage and settings."""

import sys

import pytest

from sentinel_vision.config import Settings


@pytest.fixture
def unreachable(monkeypatch):
    from sentinel_vision import service_client

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(service_client, "service_installed", lambda: True)
    monkeypatch.setattr(service_client, "connect", lambda *a, **k: None)
    return service_client


def _settings(**over):
    s = Settings()
    s.feeds, s.clamav_enabled, s.realtime_enabled, s.network_enabled = [], False, False, False
    for k, v in over.items():
        setattr(s, k, v)
    return s


def test_weakened_local_settings_are_raised_to_full_strength(unreachable, tmp_path):
    from sentinel_vision.core import Sentinel

    # another program edited settings.json: protection off, exclusions added; the user had chosen a stronger limit
    s = _settings(ransomware_enabled=False, exclusions=["C:\\\\"], max_file_size_mb=1024, heuristic_threshold=80,
                  approved_plugins=["evil@1#x"])  # fmt: skip
    sv = Sentinel(s)
    try:
        assert sv.degraded
        assert sv.settings.ransomware_enabled is True and sv.settings.exclusions == []
        assert sv.settings.approved_plugins == []  # no plugins without the service
        assert sv.settings.max_file_size_mb == 1024  # a stronger choice is kept
        assert sv.settings.heuristic_threshold == Settings().heuristic_threshold  # a weaker one is not
        from sentinel_vision.quarantine import QuarantineError

        f = tmp_path / "x.bin"
        f.write_bytes(b"x")
        with pytest.raises(QuarantineError):
            sv.quarantine.add(f, "T", "hash")
        assert f.exists() and sv.vault.snapshot(f) is None
        assert any("Protection service unreachable" in e[3] for e in sv.db.recent_events(20))
    finally:
        sv.shutdown()


def test_stronger_changes_still_save_in_degraded_mode(unreachable, tmp_path):
    from sentinel_vision.core import Sentinel

    sv = Sentinel(_settings())
    try:
        sv.settings.ransomware_folders = [*sv.settings.ransomware_folders, str(tmp_path)]
        sv.save_settings()  # adding protection is fine
        assert str(tmp_path) in Settings.load().ransomware_folders
    finally:
        sv.shutdown()


def test_reconnecting_switches_to_protected_storage(unreachable, monkeypatch, tmp_path):
    from sentinel_vision import service_client
    from sentinel_vision.core import Sentinel
    from sentinel_vision.servicecore import Caller, ServiceCore

    sv = Sentinel(_settings())
    core = ServiceCore(tmp_path / "svc")
    try:
        assert sv.degraded and not sv.try_reconnect()
        transport = service_client.LocalTransport(core, Caller("S-1-5-21-1-2-3-1001", pid=1, session=1))
        monkeypatch.setattr(service_client, "connect", lambda *a, **k: transport)
        assert sv.try_reconnect() and not sv.degraded
        assert isinstance(sv.quarantine, service_client.RemoteQuarantine)
        assert sv.scanner.quarantine is sv.quarantine and sv.ransomware.vault is sv.vault
    finally:
        sv.shutdown()
        core.close()


def test_running_from_source_without_a_service_is_unchanged(monkeypatch):
    """Developers and macOS/Linux: no service installed means the ordinary local mode, as before."""
    from sentinel_vision import service_client
    from sentinel_vision.core import Sentinel
    from sentinel_vision.quarantine import Quarantine

    monkeypatch.setattr(service_client, "connect", lambda *a, **k: None)
    sv = Sentinel(_settings())
    try:
        assert not sv.degraded and isinstance(sv.quarantine, Quarantine)
    finally:
        sv.shutdown()


def test_the_window_shows_the_degraded_banner(unreachable):
    from PySide6.QtWidgets import QApplication

    from sentinel_vision.core import Sentinel
    from sentinel_vision.gui.app import MainWindow

    app = QApplication.instance() or QApplication([])
    sv = Sentinel(_settings())
    win = MainWindow(sv)
    try:
        app.processEvents()
        assert win.degraded_banner.isVisibleTo(win)
        assert "tamper protection is off" in win.degraded_text.text()
        assert win.reconnect_timer.isActive()
    finally:
        win._quitting = True
        win.stop_timers()
        win.tray.hide()
        win.deleteLater()
        app.processEvents()
        sv.shutdown()
