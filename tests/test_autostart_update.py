import hashlib
import json
import sys

import pytest

from sentinel_vision import app_update, autostart


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setattr(autostart.Path, "home", classmethod(lambda cls: home))
    return home


@pytest.fixture
def clean_windows_run_key():
    yield
    if sys.platform == "win32":
        try:
            autostart.disable()
        except autostart.AutostartError:
            pass


def test_launch_command_points_at_gui_minimized():
    cmd = autostart.launch_command()
    assert cmd[-1] == "--minimized"
    if not getattr(sys, "frozen", False):
        assert cmd[1:3] == ["-m", "sentinel_vision"]


def test_enable_disable_roundtrip(fake_home, clean_windows_run_key):
    autostart.disable()
    assert not autostart.is_enabled()
    autostart.enable(["/opt/Sentinel Vision/SentinelVision", "--minimized"])
    st = autostart.status()
    assert st.enabled and st.scope == "user"
    assert "--minimized" in st.command
    if sys.platform.startswith("linux"):
        text = (fake_home / ".config/autostart/sentinel-vision.desktop").read_text()
        assert 'Exec="/opt/Sentinel Vision/SentinelVision" --minimized' in text
    autostart.disable()
    assert not autostart.is_enabled()
    autostart.disable()  # idempotent


def test_repair_repoints_missing_target(fake_home, clean_windows_run_key, tmp_path):
    autostart.enable([str(tmp_path / "gone" / "SentinelVision"), "--minimized"])
    assert autostart.repair() is True
    assert str(tmp_path / "gone") not in autostart.status().command
    assert autostart.repair() is False  # target now exists
    autostart.disable()


def test_desktop_quoting():
    assert autostart._desktop_quote("plain") == "plain"
    assert autostart._desktop_quote("/a b/c") == '"/a b/c"'
    assert autostart._desktop_quote('x"$`\\') == '"x\\"\\$\\`\\\\"'


# ----------------------------------------------------------------------------- app self-update

RELEASE = {
    "tag_name": "v9.8.7",
    "html_url": "https://github.com/dylanckoldan-boop/sentinel-vision/releases/tag/v9.8.7",
    "body": "notes",
    "draft": False,
    "prerelease": False,
    "assets": [
        {"name": "SentinelVision-9.8.7-Setup.exe", "browser_download_url": "https://example.test/setup.exe"},
        {"name": "SHA256SUMS.txt", "browser_download_url": "https://example.test/sums"},
        {"name": "SentinelVision-9.8.7-linux.tar.gz", "browser_download_url": "https://example.test/linux"},
    ],
}


def test_version_compare():
    assert app_update.is_newer("0.2.0", "0.1.9")
    assert app_update.is_newer("v1.0.0", "0.9.9")
    assert not app_update.is_newer("0.2.0", "0.2.0")
    assert not app_update.is_newer("garbage", "0.1.0")
    assert app_update.parse_version("1.2.3-rc1") == (1, 2, 3)


def test_parse_release_and_check(monkeypatch):
    info = app_update.parse_release(RELEASE)
    assert info.version == "9.8.7"
    assert info.installer_name == "SentinelVision-9.8.7-Setup.exe"
    assert info.sums_url == "https://example.test/sums"
    monkeypatch.setattr(app_update, "download", lambda *a, **k: json.dumps(RELEASE).encode())
    assert app_update.check_latest().version == "9.8.7"
    old = dict(RELEASE, tag_name="v0.0.1")
    monkeypatch.setattr(app_update, "download", lambda *a, **k: json.dumps(old).encode())
    assert app_update.check_latest() is None
    pre = dict(RELEASE, prerelease=True)
    monkeypatch.setattr(app_update, "download", lambda *a, **k: json.dumps(pre).encode())
    assert app_update.check_latest() is None


def test_installer_hash_is_enforced(monkeypatch):
    info = app_update.parse_release(RELEASE)
    payload = b"MZ fake installer"
    good = hashlib.sha256(payload).hexdigest()
    monkeypatch.setattr(app_update, "can_self_install", lambda _i: True)

    def fake_download(url, headers=None, limit=0):
        if url.endswith("sums"):
            return f"{good}  SentinelVision-9.8.7-Setup.exe\n{'0' * 64}  other.zip\n".encode()
        return payload

    monkeypatch.setattr(app_update, "download", fake_download)
    path = app_update.download_installer(info)
    assert path.read_bytes() == payload and path.name == "SentinelVision-9.8.7-Setup.exe"

    def tampered(url, headers=None, limit=0):
        return fake_download(url) if url.endswith("sums") else payload + b"evil"

    monkeypatch.setattr(app_update, "download", tampered)
    with pytest.raises(app_update.AppUpdateError):
        app_update.download_installer(info)


def test_expected_hash_parsing():
    h = "a" * 64
    assert app_update.expected_hash(f"{h} *SentinelVision-1.0.0-Setup.exe\n", "SentinelVision-1.0.0-Setup.exe") == h
    with pytest.raises(app_update.AppUpdateError):
        app_update.expected_hash(f"{h}  other\n", "SentinelVision-1.0.0-Setup.exe")


def test_self_install_only_for_windows_installer_build():
    info = app_update.parse_release(RELEASE)
    assert app_update.can_self_install(info) is False  # tests never run from an installed build
