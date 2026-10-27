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


SIGNED_RELEASE = dict(
    RELEASE,
    assets=[*RELEASE["assets"], {"name": "SHA256SUMS.txt.sig", "browser_download_url": "https://example.test/sig"}],
)


def _fake_release(monkeypatch, payload: bytes, sums: bytes, sig: bytes | None):
    def fake_download(url, headers=None, limit=0):
        if url.endswith("sums"):
            return sums
        if url.endswith("sig"):
            if sig is None:
                raise AssertionError("signature should not be requested")
            return sig
        return payload

    monkeypatch.setattr(app_update, "download", fake_download)
    monkeypatch.setattr(app_update, "can_self_install", lambda _i: True)


def test_installer_requires_valid_pq_signature_and_hash(monkeypatch, tmp_path):
    from sentinel_vision import pqsign

    key = pqsign.PrivateKey.generate()
    monkeypatch.setattr(app_update, "release_keys", lambda: [key.public_key()])
    info = app_update.parse_release(SIGNED_RELEASE)
    assert info.signed
    payload = b"MZ fake installer"
    sums = f"{hashlib.sha256(payload).hexdigest()}  SentinelVision-9.8.7-Setup.exe\n".encode()
    good_sig = pqsign.sign(key, sums, pqsign.CONTEXT_RELEASE)

    _fake_release(monkeypatch, payload, sums, good_sig)
    path = app_update.fetch_verified_installer(info, tmp_path)
    assert path.read_bytes() == payload and path.name == "SentinelVision-9.8.7-Setup.exe"

    # tampered installer (hash mismatch)
    _fake_release(monkeypatch, payload + b"evil", sums, good_sig)
    with pytest.raises(app_update.AppUpdateError, match="SHA-256"):
        app_update.fetch_verified_installer(info, tmp_path)

    # attacker swaps the checksum list too: signature no longer matches
    evil = b"MZ evil"
    evil_sums = f"{hashlib.sha256(evil).hexdigest()}  SentinelVision-9.8.7-Setup.exe\n".encode()
    _fake_release(monkeypatch, evil, evil_sums, good_sig)
    with pytest.raises(app_update.AppUpdateError, match="signature"):
        app_update.fetch_verified_installer(info, tmp_path)

    # signed by a different (unpinned) key
    rogue = pqsign.sign(pqsign.PrivateKey.generate(), evil_sums, pqsign.CONTEXT_RELEASE)
    _fake_release(monkeypatch, evil, evil_sums, rogue)
    with pytest.raises(app_update.AppUpdateError, match="signature"):
        app_update.fetch_verified_installer(info, tmp_path)


def test_unsigned_release_is_not_auto_installed_once_keys_are_pinned(monkeypatch):
    from sentinel_vision import pqsign

    monkeypatch.setattr(app_update, "release_keys", lambda: [pqsign.PrivateKey.generate().public_key()])
    monkeypatch.setattr(app_update, "is_installed_build", lambda: True)
    monkeypatch.setattr(app_update.sys, "platform", "win32")
    assert app_update.can_self_install(app_update.parse_release(RELEASE)) is False
    assert app_update.can_self_install(app_update.parse_release(SIGNED_RELEASE)) is True
    with pytest.raises(app_update.AppUpdateError, match="not signed"):
        app_update.verify_checksums(b"x", None)


def test_downgrade_is_refused(monkeypatch, tmp_path):
    old = dict(SIGNED_RELEASE, tag_name="v0.0.1")
    old["assets"] = [
        {"name": "SentinelVision-0.0.1-Setup.exe", "browser_download_url": "https://example.test/setup.exe"},
        *SIGNED_RELEASE["assets"][1:],
    ]
    info = app_update.parse_release(old)
    _fake_release(monkeypatch, b"MZ", b"", b"")
    with pytest.raises(app_update.AppUpdateError, match="downgrade"):
        app_update.fetch_verified_installer(info, tmp_path)


def test_expected_hash_parsing():
    h = "a" * 64
    assert app_update.expected_hash(f"{h} *SentinelVision-1.0.0-Setup.exe\n", "SentinelVision-1.0.0-Setup.exe") == h
    with pytest.raises(app_update.AppUpdateError):
        app_update.expected_hash(f"{h}  other\n", "SentinelVision-1.0.0-Setup.exe")


def test_self_install_only_for_windows_installer_build():
    info = app_update.parse_release(RELEASE)
    assert app_update.can_self_install(info) is False  # tests never run from an installed build


def test_service_update_runs_only_a_verified_newer_installer_once(monkeypatch, tmp_path):
    """Audit finding SV-A07: the service fetches, verifies and launches the installer from its own folder."""
    from sentinel_vision import pqsign

    key = pqsign.PrivateKey.generate()
    monkeypatch.setattr(app_update, "release_keys", lambda: [key.public_key()])
    info = app_update.parse_release(SIGNED_RELEASE)
    payload = b"MZ fake installer"
    sums = f"{hashlib.sha256(payload).hexdigest()}  SentinelVision-9.8.7-Setup.exe\n".encode()
    launched = []

    def launch(path, args):
        launched.append((path, args))

    folder = tmp_path / "updates"
    _fake_release(monkeypatch, payload + b"tampered", sums, pqsign.sign(key, sums, pqsign.CONTEXT_RELEASE))
    with pytest.raises(app_update.AppUpdateError):
        app_update.service_update(folder, launch, latest=lambda: info)
    assert launched == []

    old = dict(SIGNED_RELEASE, tag_name="v0.0.1")
    old["assets"] = [{"name": "SentinelVision-0.0.1-Setup.exe", "browser_download_url": "https://example.test/x"},
                     *SIGNED_RELEASE["assets"][1:]]  # fmt: skip
    with pytest.raises(app_update.AppUpdateError):
        app_update.service_update(folder, launch, latest=lambda: app_update.parse_release(old))
    assert launched == []

    _fake_release(monkeypatch, payload, sums, pqsign.sign(key, sums, pqsign.CONTEXT_RELEASE))
    assert app_update.service_update(folder, launch, latest=lambda: info) == "9.8.7"
    assert len(launched) == 1
    path, args = launched[0]
    assert path.parent == folder and path.read_bytes() == payload
    assert "/SERVICEUPDATE=1" in args and "/VERYSILENT" in args


def test_update_op_needs_the_windows_service_and_is_rate_limited(tmp_path):
    from sentinel_vision.servicecore import Caller, ServiceCore, ServiceError, SystemApplier

    class Applier(SystemApplier):
        runs = 0

        def install_update(self):
            Applier.runs += 1
            return "9.8.7"

    alice = Caller("S-1-5-21-1-2-3-1001", pid=1, session=1)
    core = ServiceCore(tmp_path / "svc", Applier())
    try:
        assert core.handle(alice, "update.install", {"version": "9.8.7"})[0] == {"version": "9.8.7"}
        with pytest.raises(ServiceError):
            core.handle(alice, "update.install", {})
        assert Applier.runs == 1
    finally:
        core.close()
    plain = ServiceCore(tmp_path / "svc2")
    try:
        with pytest.raises(ServiceError):
            plain.handle(alice, "update.install", {})
    finally:
        plain.close()
