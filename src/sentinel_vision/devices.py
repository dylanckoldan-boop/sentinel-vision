"""Removable drives, scheduled scans and camera/microphone monitoring."""

from __future__ import annotations

import datetime as dt
import logging
import os
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import psutil

log = logging.getLogger(__name__)


# ----------------------------------------------------------------------------- removable drives


def removable_mounts(partitions=None) -> list[str]:
    parts = partitions if partitions is not None else psutil.disk_partitions(all=False)
    out = []
    for p in parts:
        mp = p.mountpoint
        opts = (p.opts or "").lower()
        if sys.platform == "win32":
            if "removable" in opts and "cdrom" not in opts:
                out.append(mp)
        elif sys.platform == "darwin":
            if mp.startswith("/Volumes/") and not mp.startswith("/Volumes/Recovery") and mp != "/Volumes/Macintosh HD":
                out.append(mp)
        elif mp.startswith(("/media/", "/run/media/", "/mnt/")):
            out.append(mp)
    return out


class DriveWatcher:
    """Calls ``on_new(mountpoint)`` for every removable drive that appears (not for those present at start)."""

    def __init__(self, on_new: Callable[[str], None], interval: float = 4.0, lister=removable_mounts) -> None:
        self.on_new = on_new
        self.interval = interval
        self.lister = lister
        self._known: set[str] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        try:
            self._known = set(self.lister())
        except Exception:
            self._known = set()
        self._thread = threading.Thread(target=self._run, name="drives", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def poll(self) -> list[str]:
        try:
            current = set(self.lister())
        except Exception:
            return []
        new = sorted(current - self._known)
        self._known = current
        for mp in new:
            try:
                self.on_new(mp)
            except Exception:
                log.exception("drive callback failed for %s", mp)
        return new

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.poll()


# ----------------------------------------------------------------------------- schedules


def _local(ts: float) -> dt.datetime:
    return dt.datetime.fromtimestamp(ts)


def last_quick_slot(now: dt.datetime, hour: int) -> dt.datetime:
    slot = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    return slot if now >= slot else slot - dt.timedelta(days=1)


def last_full_slot(now: dt.datetime, hour: int, weekday: int) -> dt.datetime:
    slot = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    slot -= dt.timedelta(days=(now.weekday() - weekday) % 7)
    return slot if now >= slot else slot - dt.timedelta(days=7)


def due_scans(settings, last_quick: float, last_full: float, now: float | None = None) -> list[str]:
    """Which scheduled scans should run now. A slot missed while the computer was off is caught up once."""
    n = _local(now if now is not None else time.time())
    out = []
    if settings.schedule_full_weekly:
        slot = last_full_slot(n, settings.schedule_hour, settings.schedule_full_weekday)
        if last_full < slot.timestamp():
            out.append("full")
    if settings.schedule_quick_daily and "full" not in out:
        slot = last_quick_slot(n, settings.schedule_hour)
        if max(last_quick, last_full) < slot.timestamp():  # a full scan also covers the daily quick scan
            out.append("quick")
    return out


# ----------------------------------------------------------------------------- camera & microphone


@dataclass(frozen=True)
class DeviceUse:
    kind: str  # camera | microphone
    app: str  # executable path or app id
    active: bool
    last_used: float = 0.0


def _filetime(v: int) -> float:
    return (v - 116444736000000000) / 10_000_000 if v else 0.0


def _windows_device_use() -> list[DeviceUse]:
    import winreg

    out: list[DeviceUse] = []
    base = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
    for cap, kind in (("webcam", "camera"), ("microphone", "microphone")):
        for sub in ("", "NonPackaged"):
            path = base + "\\" + cap + ("\\" + sub if sub else "")
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
            except OSError:
                continue
            with key:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(key, i)
                    except OSError:
                        break
                    i += 1
                    if name == "NonPackaged":
                        continue
                    try:
                        with winreg.OpenKey(key, name) as app:
                            start = winreg.QueryValueEx(app, "LastUsedTimeStart")[0]
                            stop = winreg.QueryValueEx(app, "LastUsedTimeStop")[0]
                    except OSError:
                        continue
                    app_name = name.replace("#", "\\") if sub else name
                    out.append(DeviceUse(kind, app_name, bool(start) and stop == 0, _filetime(int(start))))
    return out


def _linux_device_use() -> list[DeviceUse]:
    out: dict[tuple[str, str], DeviceUse] = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        kinds = set()
        for fd in fds:
            try:
                target = os.readlink(f"{fd_dir}/{fd}")
            except OSError:
                continue
            if target.startswith("/dev/video"):
                kinds.add("camera")
            elif target.startswith("/dev/snd/pcm") and target.endswith("c"):
                kinds.add("microphone")
        if kinds:
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
            except OSError:
                exe = f"pid {pid}"
            for k in kinds:
                out[(k, exe)] = DeviceUse(k, exe, True, time.time())
    return list(out.values())


def device_use() -> list[DeviceUse]:
    """Apps using (or that recently used) the camera or microphone. Empty where the OS offers no way to know."""
    try:
        if sys.platform == "win32":
            return _windows_device_use()
        if sys.platform.startswith("linux"):
            return _linux_device_use()
    except Exception:
        log.exception("device use query failed")
    return []


def privacy_supported() -> bool:
    return sys.platform == "win32" or sys.platform.startswith("linux")


class PrivacyMonitor:
    """Notifies when an app starts using the camera or microphone."""

    def __init__(self, on_start: Callable[[DeviceUse], None], interval: float = 3.0, source=device_use) -> None:
        self.on_start = on_start
        self.interval = interval
        self.source = source
        self._active: set[tuple[str, str]] = set()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.current: list[DeviceUse] = []

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running or not privacy_supported():
            return
        self._stop.clear()
        self._active = {(u.kind, u.app) for u in self.source() if u.active}
        self._thread = threading.Thread(target=self._run, name="privacy", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def poll(self) -> list[DeviceUse]:
        uses = self.source()
        self.current = uses
        active = {(u.kind, u.app): u for u in uses if u.active}
        started = [u for k, u in active.items() if k not in self._active]
        self._active = set(active)
        for u in started:
            try:
                self.on_start(u)
            except Exception:
                log.exception("privacy callback failed")
        return started

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.poll()


# ----------------------------------------------------------------------------- shredder


class ShredError(RuntimeError):
    pass


def shred_file(path: str | Path, passes: int = 1) -> None:
    """Overwrite a file with random data, rename it to a random name, then delete it.

    On SSDs and copy-on-write/journaling file systems the drive may keep old copies of blocks out of reach of
    any program; full-disk encryption is the only complete protection there. Shredding still removes the
    readable file and its name."""
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ShredError(f"not a regular file: {p}")
    size = p.stat().st_size
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    with open(p, "r+b", buffering=0) as fh:
        for _ in range(max(1, passes)):
            fh.seek(0)
            left = size
            while left > 0:
                n = min(left, 1 << 20)
                fh.write(os.urandom(n))
                left -= n
            fh.flush()
            os.fsync(fh.fileno())
        fh.truncate(0)
        os.fsync(fh.fileno())
    random_name = p.with_name(os.urandom(12).hex())
    os.replace(p, random_name)
    random_name.unlink()


def shred(paths: list[str | Path]) -> list[tuple[str, str]]:
    from sentinel_vision.config import data_dir
    from sentinel_vision.scanner import is_system_path

    results: list[tuple[str, str]] = []
    own = os.path.normcase(str(data_dir()))
    for item in paths:
        p = Path(item)
        norm = os.path.normcase(os.path.abspath(p))
        if is_system_path(str(p)) or norm == own or norm.startswith(own + os.sep):
            results.append((str(p), "refused: protected location"))
            continue
        targets = [p] if p.is_file() else [Path(r) / f for r, _d, fs in os.walk(p) for f in fs] if p.is_dir() else []
        if not targets:
            results.append((str(p), "not found"))
            continue
        for t in targets:
            try:
                shred_file(t)
                results.append((str(t), "shredded"))
            except (OSError, ShredError) as exc:
                results.append((str(t), f"failed: {exc}"))
        if p.is_dir():
            for root, dirs, _files in os.walk(p, topdown=False):
                for d in dirs:
                    try:
                        os.rmdir(os.path.join(root, d))
                    except OSError:
                        pass
            try:
                os.rmdir(p)
            except OSError:
                pass
    return results
