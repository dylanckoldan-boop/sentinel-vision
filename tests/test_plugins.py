"""Plugin host: plugins appear only after approval, come only from places other programs can't change, and can
never crash Sentinel Vision."""

import re
from pathlib import Path

import pytest

PLUGIN_SRC = """
from PySide6.QtWidgets import QLabel

from sentinel_vision.plugin_api import PluginPage

MODE = {mode!r}


class Demo(QLabel):
    def refresh(self):
        if MODE == "refresh-fails":
            raise RuntimeError("refresh broke")


def _factory(ctx):
    if MODE == "factory-fails":
        raise RuntimeError("factory broke")
    ctx.notify("Demo", "mounted", "info")
    return Demo("demo plugin page")


def register():
    if MODE == "register-fails":
        raise RuntimeError("register broke")
    if MODE == "bad-descriptor":
        return [object()]
    if MODE == "steals-key":
        return [PluginPage("overview", "Fake overview", _factory)]
    return [PluginPage("{key}", "Demo plugin", _factory)]
"""


def make_plugin(folder: Path, name: str = "sv_demo_plugin", mode: str = "ok", key: str = "demo") -> Path:
    """A minimal installed distribution (as pip would leave it) declaring a sentinel_vision.plugins entry point."""
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.py").write_text(PLUGIN_SRC.format(mode=mode, key=key))
    di = folder / f"{name}-1.0.dist-info"
    di.mkdir()
    (di / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n")
    (di / "entry_points.txt").write_text(f"[sentinel_vision.plugins]\n{name} = {name}:register\n")
    (di / "RECORD").write_text(f"{name}.py,,\n")
    return folder


@pytest.fixture
def app():
    from PySide6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def _window(sentinel, app):
    from sentinel_vision.gui.app import MainWindow

    win = MainWindow(sentinel)
    app.processEvents()
    return win


def _close(win, app):
    win._quitting = True
    win.stop_timers()
    win.tray.hide()
    win.deleteLater()
    app.processEvents()


def test_python_plugins_are_found_and_only_shown_after_approval(tmp_path, monkeypatch, sentinel, app):
    from sentinel_vision import plugins

    monkeypatch.syspath_prepend(str(make_plugin(tmp_path / "site")))
    found = [f for f in plugins.discover() if f.name == "sv_demo_plugin"]
    assert len(found) == 1 and found[0].loadable and found[0].fingerprint.startswith("sv_demo_plugin@1.0#")
    asked = []
    monkeypatch.setattr("sentinel_vision.gui.app.MainWindow._ask_about_plugins", lambda self, new: asked.extend(new))
    win = _window(sentinel, app)
    assert "demo" not in win.pages  # not allowed yet
    _close(win, app)

    sentinel.settings.approved_plugins = [found[0].fingerprint]
    notes = []
    monkeypatch.setattr("sentinel_vision.gui.app.MainWindow.notify", lambda self, *a: notes.append(a))
    win = _window(sentinel, app)
    assert ("Demo", "mounted", "info") in notes  # the plugin used the host's notifications
    assert "demo" in win.pages and "demo" in win.buttons
    win.navigate("demo")
    app.processEvents()
    assert win.stack.currentWidget() is win.pages["demo"]
    _close(win, app)


@pytest.mark.parametrize("mode", ["register-fails", "factory-fails", "bad-descriptor", "steals-key", "refresh-fails"])
def test_a_broken_plugin_cannot_crash_the_app(mode, tmp_path, monkeypatch, sentinel, app):
    from sentinel_vision import plugins

    name = "sv_broken_" + mode.replace("-", "_")
    monkeypatch.syspath_prepend(str(make_plugin(tmp_path / "site", name=name, mode=mode)))
    fp = next(f.fingerprint for f in plugins.discover() if f.name == name)
    sentinel.settings.approved_plugins = [fp]
    win = _window(sentinel, app)  # must not raise
    if mode == "refresh-fails":
        win.navigate("demo")
        win.navigate("demo")  # the error is contained (and logged once)
    else:
        assert "demo" not in win.pages
    assert win.pages["overview"].__class__.__name__ != "PluginHost"  # built-in pages can't be replaced
    for key in ("overview", "scan"):
        win.navigate(key)
    _close(win, app)


def test_installed_app_loads_only_from_the_protected_folder(tmp_path, monkeypatch):
    from sentinel_vision import plugins

    root = tmp_path / "Program Files" / "Sentinel Vision" / "plugins"
    make_plugin(root / "demo", name="sv_folder_plugin")
    monkeypatch.setattr(plugins, "plugins_root", lambda: root)
    monkeypatch.setattr(plugins, "admin_only_problem", lambda p: "")
    (f,) = plugins.discover()
    assert f.source == "folder" and f.loadable and f.name == "sv_folder_plugin"
    assert [p.key for p in plugins.load_pages(f)] == ["demo"]
    before = f.fingerprint
    (root / "demo" / "sv_folder_plugin.py").write_text(
        "# changed\n" + (root / "demo" / "sv_folder_plugin.py").read_text()
    )
    assert plugins.discover()[0].fingerprint != before  # a changed plugin needs approval again
    # a folder that a normal user could change is refused, with the reason
    monkeypatch.setattr(plugins, "admin_only_problem", lambda p: f"{p} can be changed by S-1-5-32-545")
    (f,) = plugins.discover()
    assert not f.loadable and "can be changed" in f.problem
    with pytest.raises(RuntimeError):
        plugins.load_pages(f)


def test_frozen_portable_or_unusual_locations_have_no_plugins(monkeypatch, tmp_path):
    import sys

    from sentinel_vision import plugins

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "Downloads" / "SentinelVision" / "SentinelVision.exe"))
    monkeypatch.setenv("ProgramFiles", str(tmp_path / "Program Files"))
    assert plugins.plugins_root() is None
    monkeypatch.setattr(sys, "executable", str(tmp_path / "Program Files" / "Sentinel Vision" / "SentinelVision.exe"))
    assert plugins.plugins_root() == tmp_path / "Program Files" / "Sentinel Vision" / "plugins"


def test_allowing_a_plugin_needs_administrator_approval_with_the_service():
    from sentinel_vision.servicecore import weakened

    assert weakened({"approved_plugins": []}, {"approved_plugins": ["foldward@1.0#abc"]}) == ["approved_plugins"]
    assert weakened({"approved_plugins": ["foldward@1.0#abc"]}, {"approved_plugins": []}) == []


def test_sentinel_vision_never_imports_a_plugin_by_name():
    src = Path(__file__).resolve().parents[1] / "src"
    # companions (Foldward, formerly Agent Guard) are found by iterating the entry-point group, never by name
    pattern = re.compile(r"^\s*(import|from)\s+(foldward|agent_guard)\b|entry_points\(\)\[|import_module\(", re.M)
    offenders = [str(p) for p in src.rglob("*.py") if pattern.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


def test_plugin_api_surface():
    from sentinel_vision import plugin_api

    assert plugin_api.API_VERSION == 1 and plugin_api.ENTRY_POINT_GROUP == "sentinel_vision.plugins"
    from sentinel_vision.gui.pages.base import AppContext, Page

    assert plugin_api.AppContext is AppContext and plugin_api.Page is Page


def test_foldward_is_found_in_its_own_folder_by_iterating_the_group(tmp_path, monkeypatch):
    """Foldward (formerly Agent Guard) installs into plugins\\foldward and declares the entry point `foldward`.
    Nothing in Sentinel Vision names it: any folder, any entry-point name in the group is found the same way."""
    from sentinel_vision import plugins

    root = tmp_path / "Program Files" / "Sentinel Vision" / "plugins"
    make_plugin(root / "foldward", name="foldward", key="ag_dashboard")
    monkeypatch.setattr(plugins, "plugins_root", lambda: root)
    monkeypatch.setattr(plugins, "admin_only_problem", lambda p: "")
    (f,) = plugins.discover()
    assert f.loadable and f.name == "foldward" and f.location.endswith("foldward")
    assert [ep.name for ep in f.entry_points] == ["foldward"]
    assert [p.key for p in plugins.load_pages(f)] == ["ag_dashboard"]
    assert f.fingerprint.startswith("foldward@1.0#")  # a new name: the user allows it once more
