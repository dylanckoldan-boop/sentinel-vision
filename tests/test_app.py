import json
import time

from sentinel_vision.config import Settings


def test_settings_roundtrip_and_corruption(isolated_home):
    s = Settings()
    s.heuristic_threshold = 42
    s.exclusions = ["/x"]
    s.save()
    loaded = Settings.load()
    assert loaded.heuristic_threshold == 42 and loaded.exclusions == ["/x"]
    assert len(loaded.feeds) == len(s.feeds)
    Settings.path().write_text("{ not json")
    assert Settings.load().heuristic_threshold == Settings().heuristic_threshold
    Settings.path().write_text(json.dumps({"heuristic_threshold": "evil", "unknown": 1}))
    assert Settings.load().heuristic_threshold == Settings().heuristic_threshold


def test_feed_url_needs_key():
    s = Settings()
    mb = next(f for f in s.feeds if f.requires_key)
    assert s.feed_url(mb) is None
    s.abusech_auth_key = "KEY123"
    assert "KEY123" in s.feed_url(mb)


def test_realtime_catches_dropped_file(sentinel, workdir, eicar):
    sentinel.realtime.start([str(workdir)])
    try:
        time.sleep(0.5)
        target = workdir / "download.exe"
        target.write_bytes(eicar)
        deadline = time.time() + 15
        while time.time() < deadline and (target.exists() or sentinel.realtime.threats_blocked < 1):
            time.sleep(0.2)
        assert not target.exists(), "real-time protection should quarantine the file"
        assert sentinel.realtime.threats_blocked == 1
    finally:
        sentinel.realtime.stop()


def test_scan_paths_summary(sentinel, workdir, eicar):
    (workdir / "a.txt").write_text("fine")
    (workdir / "sub").mkdir()
    (workdir / "sub" / "bad.com").write_bytes(eicar)
    found = []
    summary = sentinel.scanner.scan_paths([workdir], on_result=found.append)
    assert summary.scanned == 2 and summary.infected == 1
    assert found[0].path.endswith("bad.com")
    assert sentinel.db.detection_count() == 1
    assert any("finished" in e[3] for e in sentinel.db.recent_events())


def test_cli_scan_exit_codes(workdir, eicar, capsys):
    from sentinel_vision.cli import main

    (workdir / "ok.txt").write_text("ok")
    assert main(["scan", str(workdir), "--json"]) == 0
    (workdir / "bad.com").write_bytes(eicar)
    assert main(["scan", str(workdir), "--json", "--no-quarantine"]) == 1
    out = capsys.readouterr().out
    payload = json.loads(out[out.rindex('{\n  "scanned"') :])
    assert payload["infected"] == 1
    assert (workdir / "bad.com").exists()


def test_gui_builds_every_page(sentinel):
    from PySide6.QtWidgets import QApplication

    from sentinel_vision.gui import theme
    from sentinel_vision.gui.app import NAV, MainWindow

    app = QApplication.instance() or QApplication([])
    app.setStyleSheet(theme.STYLESHEET)
    win = MainWindow(sentinel)
    sentinel.network.poll()
    for key, _label, _cls in NAV:
        win.navigate(key)
        app.processEvents()
    from PySide6.QtCore import QThreadPool

    QThreadPool.globalInstance().waitForDone(180000)  # background work (e.g. the checkup) finishes first
    app.processEvents()
    win._quitting = True
    win.stop_timers()
    win.tray.hide()
    win.deleteLater()
    app.processEvents()
