import datetime as dt
import os
import sys
from collections import namedtuple
from types import SimpleNamespace

import pytest

from sentinel_vision import devices

Part = namedtuple("Part", "device mountpoint fstype opts")


def test_removable_mounts_per_platform(monkeypatch):
    parts = [
        Part("C:\\", "C:\\", "NTFS", "rw,fixed"),
        Part("E:\\", "E:\\", "FAT32", "rw,removable"),
        Part("D:\\", "D:\\", "UDF", "ro,cdrom"),
        Part("/dev/sdb1", "/media/user/USB", "vfat", "rw"),
        Part("/dev/disk4s1", "/Volumes/KINGSTON", "msdos", "rw"),
        Part("/dev/sda1", "/", "ext4", "rw"),
    ]
    monkeypatch.setattr(devices.sys, "platform", "win32")
    assert devices.removable_mounts(parts) == ["E:\\"]
    monkeypatch.setattr(devices.sys, "platform", "linux")
    assert devices.removable_mounts(parts) == ["/media/user/USB"]
    monkeypatch.setattr(devices.sys, "platform", "darwin")
    assert devices.removable_mounts(parts) == ["/Volumes/KINGSTON"]


def test_drive_watcher_reports_only_new_drives():
    mounts = [["/media/a"]]
    seen = []
    w = devices.DriveWatcher(seen.append, lister=lambda: mounts[0])
    w._known = set(mounts[0])
    assert w.poll() == []
    mounts[0] = ["/media/a", "/media/usb"]
    assert w.poll() == ["/media/usb"] and seen == ["/media/usb"]
    assert w.poll() == []  # not reported twice


def test_usb_insertion_triggers_scan(sentinel, tmp_path, eicar):
    drive = tmp_path / "USB"
    drive.mkdir()
    (drive / "autorun.exe").write_bytes(eicar)
    results = sentinel.scan_drive(str(drive))
    assert results.infected == 1 and not (drive / "autorun.exe").exists()


def _settings(**kw):
    base = dict(schedule_quick_daily=True, schedule_full_weekly=True, schedule_hour=12, schedule_full_weekday=6)
    base.update(kw)
    return SimpleNamespace(**base)


def test_schedule_due_logic():
    s = _settings()
    sat_morning = dt.datetime(2026, 10, 10, 9, 0).timestamp()  # Saturday 09:00
    sat_noon = dt.datetime(2026, 10, 10, 12, 30).timestamp()
    sun_noon = dt.datetime(2026, 10, 11, 12, 5).timestamp()
    yesterday_run = dt.datetime(2026, 10, 9, 12, 1).timestamp()
    last_week_full = dt.datetime(2026, 10, 4, 12, 2).timestamp()
    assert devices.due_scans(s, yesterday_run, last_week_full, sat_morning) == []
    assert devices.due_scans(s, yesterday_run, last_week_full, sat_noon) == ["quick"]
    assert devices.due_scans(s, sat_noon, last_week_full, sun_noon) == ["full"]  # full replaces the quick scan
    assert devices.due_scans(s, sat_noon, sun_noon, sun_noon + 60) == []
    # computer was off over the weekend: missed slots are caught up once
    monday = dt.datetime(2026, 10, 12, 8, 0).timestamp()
    assert devices.due_scans(s, yesterday_run, last_week_full, monday) == ["full"]
    assert devices.due_scans(_settings(schedule_quick_daily=False, schedule_full_weekly=False), 0, 0, monday) == []


def test_privacy_monitor_reports_new_users_once():
    from sentinel_vision.devices import DeviceUse, PrivacyMonitor

    state = [[DeviceUse("camera", "C:\\Zoom\\zoom.exe", True)]]
    started = []
    m = PrivacyMonitor(started.append, source=lambda: state[0])
    m._active = {("camera", "C:\\Zoom\\zoom.exe")}
    assert m.poll() == []
    state[0] = [DeviceUse("camera", "C:\\Zoom\\zoom.exe", True), DeviceUse("microphone", "C:\\tmp\\x.exe", True)]
    assert [u.app for u in m.poll()] == ["C:\\tmp\\x.exe"]
    assert m.poll() == []


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="/proc based")
def test_linux_device_use_runs():
    assert isinstance(devices.device_use(), list)


def test_shredder(tmp_path, isolated_home):
    f = tmp_path / "secret.txt"
    f.write_bytes(b"top secret " * 1000)
    folder = tmp_path / "dir"
    (folder / "sub").mkdir(parents=True)
    (folder / "sub" / "a.bin").write_bytes(os.urandom(5000))
    res = dict(devices.shred([str(f), str(folder)]))
    assert res[str(f)] == "shredded" and not f.exists() and not folder.exists()
    sysfile = r"C:\Windows\notepad.exe" if sys.platform == "win32" else "/usr/bin/env"
    assert dict(devices.shred([sysfile]))[sysfile].startswith("refused")
    link = tmp_path / "link"
    try:
        link.symlink_to(tmp_path / "nowhere")
    except (OSError, NotImplementedError):
        return
    with pytest.raises(devices.ShredError):
        devices.shred_file(link)
