"""Ransomware shield.

Three independent tripwires watch the protected folders (Documents, Desktop, Pictures by default):

1. **Decoy files** — hidden files that no person or normal program has a reason to modify. Any change or
   rename means something is rewriting files indiscriminately.
2. **Content transformation** — a document stops being its file type (a .docx that is no longer a zip, a .txt
   full of random bytes) or is renamed to an unknown extension. A burst of these in a short window is the
   signature of mass encryption.
3. **Rollback vault** — every good version of a document is stored encrypted (see vault.py), so files can be
   restored even if an attack gets through.

When a tripwire fires, the most likely culprits — unsigned programs writing heavily, holding files in the
protected folders open, or running from download/temp folders — are **suspended** (frozen, not killed), and
the user decides: end and quarantine, or resume. Suspension is reversible; a wrong guess costs nothing.
"""

from __future__ import annotations

import hashlib
import io
import logging
import os
import queue
import sys
import tempfile
import threading
import time
import zipfile
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from sentinel_vision.engines import authenticode
from sentinel_vision.engines.authenticode import Signature
from sentinel_vision.engines.base import Severity
from sentinel_vision.scanner import is_system_path
from sentinel_vision.vault import VERSIONED_EXT, RollbackVault, extension, looks_encrypted

log = logging.getLogger(__name__)

# Placed at both ends of the alphabet, because ransomware usually walks folders in name order. Hidden (Windows
# hidden+system attribute; leading dot elsewhere) so they don't clutter the folder.
_DECOYS = ("!Budget 2026.docx", "!Accounts.xlsx", "zz Notes.txt")
CANARY_NAMES = _DECOYS if sys.platform == "win32" else tuple("." + n for n in _DECOYS)
BURST_WINDOW = 20.0
BURST_THRESHOLD = 8
TRIP_COOLDOWN = 60.0
SUSPEND_SCORE = 50
MAX_SUSPECTS = 3
RISKY_DIRS = tuple(
    os.path.normcase(p).rstrip("\\/")
    for p in {
        tempfile.gettempdir(),
        os.environ.get("TEMP", ""),
        os.environ.get("APPDATA", ""),
        os.environ.get("LOCALAPPDATA", ""),
        str(Path.home() / "Downloads"),
        str(Path.home() / "Desktop"),
        "/tmp",  # noqa: S108
        "/dev/shm",  # noqa: S108
        "/var/tmp",  # noqa: S108
    }
    if p
)


def default_folders() -> list[str]:
    home = Path.home()
    return [str(p) for p in (home / "Documents", home / "Desktop", home / "Pictures") if p.is_dir()]


def _decoy_bytes(name: str) -> bytes:
    """Realistic-looking content so ransomware treats the decoy like any other document."""
    ext = extension(name)
    if ext in ("docx", "xlsx"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(
                "[Content_Types].xml",
                '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
            )
            z.writestr("docProps/app.xml", "<Properties><Application>Microsoft Office</Application></Properties>")
            z.writestr(
                "word/document.xml" if ext == "docx" else "xl/workbook.xml",
                "<root>" + "Quarterly figures. " * 200 + "</root>",
            )
        return buf.getvalue()
    return ("Account notes\n" + "Reference number and contact details.\n" * 120).encode()


def _hide(path: Path) -> None:
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x2 | 0x4)  # type: ignore[attr-defined]  # HIDDEN|SYSTEM
        except Exception:
            pass


def _unhide(path: Path) -> None:
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x80)  # type: ignore[attr-defined]  # NORMAL
        except Exception:
            pass


@dataclass
class Suspect:
    pid: int
    name: str
    exe: str
    score: int
    reasons: list[str]
    state: str = "running"  # running | suspended | terminated | resumed | failed


@dataclass
class RansomwareIncident:
    ts: float
    trigger: str  # decoy | mass-encryption
    detail: str
    files: list[str] = field(default_factory=list)
    suspects: list[Suspect] = field(default_factory=list)


Listener = Callable[[RansomwareIncident], None]


class _Handler(FileSystemEventHandler):
    def __init__(self, sink: Callable[[str, str, str], None]) -> None:
        self.sink = sink

    def on_modified(self, e: FileSystemEvent) -> None:
        if not e.is_directory:
            self.sink("modified", os.fsdecode(e.src_path), "")

    def on_created(self, e: FileSystemEvent) -> None:
        if not e.is_directory:
            self.sink("created", os.fsdecode(e.src_path), "")

    def on_deleted(self, e: FileSystemEvent) -> None:
        if not e.is_directory:
            self.sink("deleted", os.fsdecode(e.src_path), "")

    def on_moved(self, e: FileSystemEvent) -> None:
        if not e.is_directory:
            self.sink("moved", os.fsdecode(e.src_path), os.fsdecode(e.dest_path))

    def on_closed(self, e: FileSystemEvent) -> None:
        if not e.is_directory:
            self.sink("modified", os.fsdecode(e.src_path), "")


class RansomwareShield:
    def __init__(self, settings, db, vault: RollbackVault) -> None:
        self.settings = settings
        self.db = db
        self.vault = vault
        self._listeners: list[Listener] = []
        self._observer: Observer | None = None
        self._queue: queue.Queue[tuple[str, str, str]] = queue.Queue(maxsize=50000)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._transforms: deque[tuple[float, str]] = deque()
        self._last_trip = 0.0
        self._io_prev: dict[int, tuple[float, int]] = {}
        self._io_rate: dict[int, float] = {}
        self._own_pid = os.getpid()
        self.canaries: dict[str, str] = {}  # normcase path -> sha256
        self.folders: list[str] = []
        self.incidents: list[RansomwareIncident] = []
        self.files_versioned = 0

    # ------------------------------------------------------------------ lifecycle
    def add_listener(self, fn: Listener) -> None:
        self._listeners.append(fn)

    @property
    def running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def start(self, folders: list[str] | None = None, baseline: bool = True) -> None:
        self.stop()
        self._stop.clear()
        self.folders = [os.path.abspath(f) for f in (folders or self.settings.ransomware_folders) if os.path.isdir(f)]
        if not self.folders:
            return
        self._plant_canaries()
        observer = Observer()
        handler = _Handler(self._sink)
        for f in self.folders:
            try:
                observer.schedule(handler, f, recursive=True)
            except OSError as exc:
                log.warning("cannot watch %s: %s", f, exc)
        observer.start()
        self._observer = observer
        self._threads = [
            threading.Thread(target=self._worker, name="rw-worker", daemon=True),
            threading.Thread(target=self._io_sampler, name="rw-io", daemon=True),
        ]
        if baseline:
            self._threads.append(threading.Thread(target=self._baseline, name="rw-baseline", daemon=True))
        for t in self._threads:
            t.start()
        self.db.log_event(
            "ransomware", f"Ransomware shield on: {len(self.folders)} folder(s), {len(self.canaries)} decoys"
        )

    def stop(self) -> None:
        self._stop.set()
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass
            self._observer = None
        for t in self._threads:
            t.join(timeout=3)
        self._threads = []

    # ------------------------------------------------------------------ decoys
    def _plant_canaries(self) -> None:
        self.canaries = {}
        for folder in self.folders:
            for name in CANARY_NAMES:
                path = Path(folder) / name
                data = _decoy_bytes(name)
                try:
                    if (
                        not path.exists()
                        or hashlib.sha256(path.read_bytes()).hexdigest() != hashlib.sha256(data).hexdigest()
                    ):
                        _unhide(path)
                        path.write_bytes(data)
                        _hide(path)
                    self.canaries[os.path.normcase(str(path))] = hashlib.sha256(data).hexdigest()
                except OSError as exc:
                    log.info("cannot place decoy %s: %s", path, exc)

    def remove_canaries(self) -> int:
        n = 0
        for p in list(self.canaries):
            try:
                _unhide(Path(p))
                Path(p).unlink()
                n += 1
            except OSError:
                pass
        self.canaries = {}
        return n

    def is_canary(self, path: str) -> bool:
        return os.path.normcase(os.path.abspath(path)) in self.canaries

    # ------------------------------------------------------------------ events
    def _sink(self, kind: str, src: str, dest: str) -> None:
        try:
            self._queue.put_nowait((kind, src, dest))
        except queue.Full:
            # an event flood is itself a strong signal
            self._record_transform("(event flood)")

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                kind, src, dest = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self.handle_event(kind, src, dest)
            except Exception:
                log.exception("ransomware shield failed on %s %s", kind, src)

    def handle_event(self, kind: str, src: str, dest: str = "") -> None:
        if os.path.basename(src).startswith(".") and os.path.basename(src).endswith(".svrestore"):
            return
        # 1. decoys
        if self.is_canary(src):
            if kind == "deleted":
                time.sleep(0.2)
                self._plant_canaries()  # a user cleaning up hidden files: just put them back
                return
            if kind == "moved" or not self._canary_intact(src):
                self.trip("decoy", f"Decoy file was {'renamed' if kind == 'moved' else 'modified'}: {src}", [src])
            return
        # 2. renames to unknown extensions
        if kind == "moved":
            if extension(src) in VERSIONED_EXT and extension(dest) not in VERSIONED_EXT:
                self._record_transform(dest)
                return
            src = dest
        if kind in ("modified", "created") and self.vault.eligible(src):
            try:
                with open(src, "rb") as fh:
                    head = fh.read(65536)
            except OSError:
                return
            if looks_encrypted(head, extension(src)):
                if self.vault.versions(src) or kind == "modified":
                    self._record_transform(src)
                return
            if self.vault.snapshot(src) is not None:
                self.files_versioned += 1

    def _canary_intact(self, path: str) -> bool:
        try:
            with open(path, "rb") as fh:
                return hashlib.sha256(fh.read()).hexdigest() == self.canaries.get(
                    os.path.normcase(os.path.abspath(path))
                )
        except OSError:
            return False

    def _record_transform(self, path: str) -> None:
        now = time.monotonic()
        self._transforms.append((now, path))
        while self._transforms and now - self._transforms[0][0] > BURST_WINDOW:
            self._transforms.popleft()
        if len(self._transforms) >= BURST_THRESHOLD:
            files = [p for _, p in self._transforms]
            self._transforms.clear()
            self.trip(
                "mass-encryption",
                f"{len(files)} documents were encrypted or renamed within {BURST_WINDOW:.0f} s",
                files,
            )

    # ------------------------------------------------------------------ response
    def trip(self, trigger: str, detail: str, files: list[str]) -> RansomwareIncident | None:
        now = time.time()
        if now - self._last_trip < TRIP_COOLDOWN:
            return None
        self._last_trip = now
        suspects = self.find_suspects()
        if self.settings.ransomware_auto_suspend:
            for s in suspects:
                if s.score >= SUSPEND_SCORE:
                    self._suspend(s)
        inc = RansomwareIncident(now, trigger, detail, files[:200], suspects)
        self.incidents.append(inc)
        del self.incidents[:-50]
        frozen = ", ".join(f"{s.name} ({s.pid})" for s in suspects if s.state == "suspended") or "none"
        self.db.log_event("ransomware", f"RANSOMWARE ALERT ({trigger}): {detail}. Suspended: {frozen}", "critical")
        self.db.add_detection(
            suspects[0].exe if suspects else (files[0] if files else "?"), None, "ransomware",
            f"Ransomware.{'Decoy' if trigger == 'decoy' else 'MassEncryption'}", int(Severity.CRITICAL),
            "suspended" if any(s.state == "suspended" for s in suspects) else "reported", "ransomware",
        )  # fmt: skip
        for fn in list(self._listeners):
            try:
                fn(inc)
            except Exception:
                log.exception("ransomware listener failed")
        return inc

    def _io_sampler(self) -> None:
        if not hasattr(psutil.Process, "io_counters"):
            return  # macOS: open-file evidence only
        while not self._stop.wait(3.0):
            now = time.monotonic()
            rates: dict[int, float] = {}
            prev = self._io_prev
            cur: dict[int, tuple[float, int]] = {}
            for p in psutil.process_iter(["pid"]):
                try:
                    wb = p.io_counters().write_bytes
                except (psutil.Error, OSError, AttributeError):
                    continue
                cur[p.pid] = (now, wb)
                if p.pid in prev:
                    t0, w0 = prev[p.pid]
                    if now > t0:
                        rates[p.pid] = max(0.0, (wb - w0) / (now - t0))
            self._io_prev, self._io_rate = cur, rates

    def find_suspects(self) -> list[Suspect]:
        prefixes = tuple(os.path.normcase(f).rstrip("\\/") + os.sep for f in self.folders)
        out: list[Suspect] = []
        for p in psutil.process_iter(["pid", "name", "exe", "create_time"]):
            pid = p.info["pid"]
            if pid in (0, 4, self._own_pid) or pid == os.getppid():
                continue
            exe = p.info.get("exe") or ""
            score, reasons = 0, []
            try:
                files = [f.path for f in p.open_files()]
            except (psutil.Error, OSError):
                files = []
            touching = [f for f in files if os.path.normcase(f).startswith(prefixes)]
            if touching:
                score += 40
                reasons.append(f"has {len(touching)} protected file(s) open")
            rate = self._io_rate.get(pid, 0.0)
            if rate > 2 * 1024 * 1024:
                score += 30
                reasons.append(f"writing {rate / 1048576:.1f} MB/s")
            elif rate > 256 * 1024:
                score += 15
                reasons.append(f"writing {rate / 1024:.0f} KB/s")
            if not score:
                continue
            exe_n = os.path.normcase(exe)
            if exe and any(exe_n.startswith(d + os.sep) for d in RISKY_DIRS):
                score += 20
                reasons.append("runs from a download/temp/app-data folder")
            created = p.info.get("create_time") or 0
            if created and time.time() - created < 900:
                score += 10
                reasons.append("started in the last 15 minutes")
            trusted = False
            if exe:
                sig = authenticode.verify(exe)
                trusted = sig is Signature.VALID
                if sig in (Signature.UNSIGNED, Signature.TAMPERED, Signature.UNTRUSTED):
                    score += 20
                    reasons.append("not signed by a trusted publisher")
            if trusted and is_system_path(exe):
                continue  # signed operating-system components are never suspended
            if trusted:
                score -= 20
                reasons.append("signed by a trusted publisher")
            out.append(Suspect(pid, p.info.get("name") or "?", exe, score, reasons))
        out.sort(key=lambda s: -s.score)
        return out[:MAX_SUSPECTS]

    def _suspend(self, s: Suspect) -> None:
        try:
            psutil.Process(s.pid).suspend()
            s.state = "suspended"
        except (psutil.Error, OSError) as exc:
            s.state = "failed"
            s.reasons.append(f"could not suspend: {exc}")

    @staticmethod
    def resume(s: Suspect) -> None:
        psutil.Process(s.pid).resume()
        s.state = "resumed"

    def terminate_and_quarantine(self, s: Suspect, quarantine) -> str:
        try:
            proc = psutil.Process(s.pid)
            proc.kill()
            proc.wait(timeout=5)
            s.state = "terminated"
        except psutil.NoSuchProcess:
            s.state = "terminated"
        if s.exe and os.path.isfile(s.exe) and not is_system_path(s.exe):
            time.sleep(0.5)
            quarantine.add(s.exe, "Ransomware.Behavior", "ransomware")
            return "terminated and quarantined"
        return "terminated"

    # ------------------------------------------------------------------ vault baseline
    def _baseline(self) -> None:
        """Store a first good copy of existing documents (newest first, within the vault limits)."""
        candidates: list[tuple[float, str]] = []
        for folder in self.folders:
            for root, dirs, files in os.walk(folder):
                if self._stop.is_set():
                    return
                dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", "__pycache__")]
                for f in files:
                    p = os.path.join(root, f)
                    if self.is_canary(p) or not self.vault.eligible(p):
                        continue
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    if st.st_size <= self.vault.max_file:
                        candidates.append((st.st_mtime, p))
                if len(candidates) > 200000:
                    break
        candidates.sort(reverse=True)
        budget = self.vault.max_total * 0.8
        for _mtime, p in candidates:
            if self._stop.is_set() or budget <= 0:
                return
            v = self.vault.snapshot(p)
            if v is not None:
                self.files_versioned += 1
                budget -= v.size
            time.sleep(0.002)  # stay light in the background
