"""Scan orchestration: walks paths, unpacks archives safely, runs every engine, takes action."""

from __future__ import annotations

import logging
import os
import stat
import sys
import tarfile
import tempfile
import threading
import time
import zipfile
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path

from sentinel_vision import policy
from sentinel_vision.config import Settings, data_dir
from sentinel_vision.db import Database
from sentinel_vision.engines import authenticode
from sentinel_vision.engines.authenticode import Signature
from sentinel_vision.engines.base import Detection, Engine, ScanObject, Severity
from sentinel_vision.engines.clamav import ClamAVEngine
from sentinel_vision.engines.hashes import HashEngine
from sentinel_vision.engines.heuristics import HeuristicEngine
from sentinel_vision.engines.yara_engine import YaraEngine
from sentinel_vision.quarantine import Quarantine, QuarantineError

log = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).resolve().parent
PSEUDO_FS_ALLOWED = ("/dev/shm", "/run/media", "/run/user")  # real files live here
PSEUDO_FS = ("/proc", "/sys", "/dev", "/run", "/snap", "/var/lib/docker", "/System/Volumes/Data/.Spotlight-V100")


EXACT_ENGINES = ("hash", "clamav", "cloud")


def _system_dirs() -> tuple[str, ...]:
    if sys.platform == "win32":
        return (os.path.normcase(os.path.abspath(policy.windows_dir())),)
    if sys.platform == "darwin":
        return ("/System", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/bin", "/sbin", "/Library/Apple")
    return (
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/lib64",
        "/usr/libexec",
        "/bin",
        "/sbin",
        "/lib",
        "/lib64",
        "/boot",
    )


SYSTEM_DIRS = _system_dirs()


def is_system_path(path: str) -> bool:
    """True for files that belong to the operating system itself."""
    norm = os.path.normcase(os.path.abspath(path.split("!", 1)[0]))
    return any(norm == d or norm.startswith(d.rstrip(os.sep) + os.sep) for d in SYSTEM_DIRS)


@dataclass
class ScanResult:
    path: str
    sha256: str = ""
    size: int = 0
    detections: list[Detection] = field(default_factory=list)
    error: str = ""
    skipped: str = ""
    action: str = ""  # "", "quarantined", "reported", "quarantine failed: ..."
    origin: str = "scan"
    kind: str = ""  # policy.file_kind: "program" | "script" | "data"
    where: str = ""  # policy.location: "program" | "appdata" | "user"
    in_archive: bool = False  # a member of an archive (can't run until someone extracts it)

    @property
    def infected(self) -> bool:
        return bool(self.detections)

    @property
    def needs_review_only(self) -> bool:
        """Only hints (machine-generated rules, dual-use tools, signed software): worth a look, not a threat."""
        return bool(self.detections) and all(d.details.get("report_only") for d in self.detections)

    @property
    def top(self) -> Detection | None:
        return max(self.detections, key=lambda d: d.severity) if self.detections else None


@dataclass
class ScanSummary:
    scanned: int = 0
    infected: int = 0  # files with any finding (threats + items to review)
    review: int = 0  # of which: hints only
    errors: int = 0
    skipped: int = 0
    bytes: int = 0
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    cancelled: bool = False
    results: list[ScanResult] = field(default_factory=list)  # only infected/error results are kept

    @property
    def threats(self) -> int:
        return self.infected - self.review

    @property
    def duration(self) -> float:
        return (self.finished or time.time()) - self.started


ProgressCB = Callable[[int, str], None]
ResultCB = Callable[[ScanResult], None]


class ArchiveLimitError(Exception):
    pass


class Scanner:
    def __init__(self, settings: Settings, db: Database, quarantine: Quarantine | None = None) -> None:
        self.settings = settings
        self.db = db
        self.quarantine = quarantine or Quarantine()
        self.reputation = None  # optional ReputationService (cloud hash lookups), set by core
        self._engines_lock = threading.Lock()
        self.engines: list[Engine] = []
        self.build_engines()

    # ------------------------------------------------------------------ engines
    def build_engines(self) -> None:
        s = self.settings
        engines: list[Engine] = []
        if s.hash_enabled:
            engines.append(HashEngine(self.db))
        if s.yara_enabled:
            engines.append(YaraEngine())
        if s.clamav_enabled:
            engines.append(ClamAVEngine(s.clamd_address))
        if s.heuristics_enabled:
            engines.append(HeuristicEngine(s.heuristic_threshold))
        with self._engines_lock:
            self.engines = engines

    def reload_signatures(self) -> None:
        for e in list(self.engines):
            try:
                e.reload()
            except Exception as exc:
                log.error("reload of %s failed: %s", e.name, exc)

    def engine_status(self) -> list[tuple[str, bool, str]]:
        return [(e.label, e.available(), e.status()) for e in self.engines]

    # ------------------------------------------------------------------ exclusions
    def _protected_dirs(self) -> list[str]:
        return [str(PACKAGE_DIR), str(data_dir().resolve())]

    def is_excluded(self, path: str) -> bool:
        norm = os.path.normcase(os.path.abspath(path))
        for ex in [*self._protected_dirs(), *self.settings.exclusions]:
            exn = os.path.normcase(os.path.abspath(os.path.expanduser(ex)))
            if norm == exn or norm.startswith(exn.rstrip(os.sep) + os.sep):
                return True
        if sys.platform != "win32":
            if any(norm == a or norm.startswith(a + "/") for a in PSEUDO_FS_ALLOWED):
                return False
            return any(norm == p or norm.startswith(p + "/") for p in PSEUDO_FS)
        return False

    # ------------------------------------------------------------------ core
    def scan_object(self, obj: ScanObject) -> tuple[list[Detection], list[str]]:
        detections: list[Detection] = []
        errors: list[str] = []
        for engine in list(self.engines):
            if not engine.available():
                continue
            try:
                detections += engine.scan(obj)
            except Exception as exc:
                errors.append(f"{engine.label}: {exc}")
                log.debug("engine %s failed on %s", engine.name, obj.display_path, exc_info=True)
        return detections, errors

    def scan_file(
        self, path: str | Path, origin: str = "scan", act: bool = True, use_cache: bool = True
    ) -> list[ScanResult]:
        """Scan one file (and the members of an archive). Returns one result per object with findings,
        plus the top-level result (always first)."""
        p = Path(path)
        res = ScanResult(path=str(p), origin=origin)
        try:
            st = p.lstat()
        except OSError as exc:
            res.error = str(exc)
            return [res]
        if not stat.S_ISREG(st.st_mode):
            res.skipped = "not a regular file"
            return [res]
        res.size = st.st_size
        if st.st_size > self.settings.max_file_size_mb * 1024 * 1024:
            res.skipped = f"larger than {self.settings.max_file_size_mb} MB"
            return [res]
        if use_cache:
            cached = self.db.cache_get(str(p), st.st_size, st.st_mtime)
            if cached:
                res.sha256 = cached
                res.skipped = "unchanged since last clean scan"
                return [res]
        try:
            obj = ScanObject(str(p), fs_path=p)
        except OSError as exc:
            res.error = str(exc)
            return [res]
        res.sha256 = obj.sha256
        res.detections, errs = self.scan_object(obj)
        if errs:
            res.error = "; ".join(errs)
        res.kind = policy.file_kind(obj.head, obj.name)
        res.where = policy.location(str(p))
        self._drop_generated_rule_noise(res)
        self._apply_publisher_trust(obj, res)
        self._apply_location_context(res)
        self._apply_cloud_reputation(obj, res, origin)

        member_results: list[ScanResult] = []
        if self.settings.scan_archives:
            try:
                member_results = list(self._scan_archive(obj, depth=1, origin=origin))
            except ArchiveLimitError as exc:
                res.detections.append(
                    Detection(
                        "archive",
                        "Archive.Bomb",
                        Severity.LOW,
                        f"Archive exceeds safety limits, so it was not checked completely: {exc}",
                        {"report_only": True},
                    )
                )
            except Exception as exc:
                log.debug("archive walk failed for %s: %s", p, exc)
        # Findings inside an archive belong to the archive file on disk.
        for m in member_results:
            for d in m.detections:
                res.detections.append(
                    Detection(d.engine, d.name, d.severity, f"{d.description} (inside {m.path})", d.details)
                )
        if not res.detections and not res.error:
            self.db.cache_put(str(p), st.st_size, st.st_mtime, obj.sha256)
        if res.detections:
            self.db.cache_drop(str(p))
            if act:
                self._act(res)
        return [res, *[m for m in member_results if m.detections]]

    def _scan_archive(self, obj: ScanObject, depth: int, origin: str) -> Iterator[ScanResult]:
        s = self.settings
        if depth > s.archive_max_depth:
            return
        head = obj.head
        members: Iterable[tuple[str, int, Callable[[], bytes]]]
        if head[:4] == b"PK\x03\x04":
            fh = obj.open()
            try:
                zf = zipfile.ZipFile(fh)
            except (zipfile.BadZipFile, OSError, ValueError):
                fh.close()
                return
            closer = lambda: (zf.close(), fh.close())  # noqa: E731
            try:
                infos = [i for i in zf.infolist() if not i.is_dir()]
                self._check_bomb(sum(i.file_size for i in infos), sum(i.compress_size for i in infos))
            except BaseException:
                closer()
                raise

            def zip_members():
                for info in infos:
                    if info.flag_bits & 0x1:
                        continue  # encrypted member: cannot inspect
                    yield info.filename, info.file_size, (lambda i=info: zf.read(i))

            members = zip_members()
        elif self._looks_like_tar(head):
            fh = obj.open()
            try:
                tf = tarfile.open(fileobj=fh, mode="r:*")
            except (tarfile.TarError, OSError, EOFError, ValueError):
                fh.close()
                return
            closer = lambda: (tf.close(), fh.close())  # noqa: E731
            try:
                infos = []
                for m in tf:  # stop listing early instead of walking a huge archive
                    if m.isfile():
                        infos.append(m)
                    if len(infos) >= s.archive_max_members:
                        break
                self._check_bomb(sum(m.size for m in infos), obj.size)
            except (tarfile.TarError, OSError, EOFError, ValueError):
                closer()
                return
            except BaseException:
                closer()
                raise

            def tar_members():
                for m in infos:
                    f = tf.extractfile(m)
                    if f is not None:
                        yield m.name, m.size, (lambda f=f, n=m.size: f.read(n))

            members = tar_members()
        else:
            return
        budget = s.archive_max_total_mb * 1024 * 1024
        try:
            for count, (name, size, read) in enumerate(members):
                # Very large archives (jars, icon packs, datasets) are scanned up to the limits; that is a
                # coverage limit, not a sign of malice, so it is never reported as a detection.
                if count >= s.archive_max_members or budget <= 0:
                    break
                if size > s.max_file_size_mb * 1024 * 1024 or size > budget:
                    continue
                data = read()
                budget -= len(data)
                display = f"{obj.display_path}!{name}"
                member = ScanObject(display, data=data)
                r = ScanResult(path=display, sha256=member.sha256, size=member.size, origin=origin)
                r.detections, errs = self.scan_object(member)
                if errs:
                    r.error = "; ".join(errs)
                # the same calm-results rules as for files on disk; the archive's own folder decides the context
                r.kind = policy.file_kind(member.head, name)
                r.where = policy.location(display)
                r.in_archive = True
                self._drop_generated_rule_noise(r)
                self._apply_location_context(r)
                yield r
                yield from self._scan_archive(member, depth + 1, origin)
        finally:
            closer()

    @staticmethod
    def _looks_like_tar(head: bytes) -> bool:
        return head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00" or head[257:262] == b"ustar"

    def _check_bomb(self, uncompressed: int, compressed: int) -> None:
        """Decompression bombs: an enormous declared size squeezed into a tiny archive."""
        s = self.settings
        ratio = uncompressed / max(1, compressed)
        if uncompressed > s.archive_bomb_total_mb * 1024 * 1024 and ratio > s.archive_max_ratio:
            raise ArchiveLimitError(
                f"{uncompressed // (1024 * 1024):,} MB packed into {max(1, compressed // 1024):,} KB ({ratio:,.0f}:1)"
            )

    CLOUD_ORIGINS = ("realtime", "process", "behavior", "usb")

    def _apply_cloud_reputation(self, obj: ScanObject, res: ScanResult, origin: str) -> None:
        """Opt-in hash lookups: catch malware published minutes ago, and clear heuristic-only suspicions about
        software catalogued as known-good. Only for new programs/scripts arriving through real-time paths, or
        any file that already has a heuristic finding."""
        rep_service = self.reputation
        if rep_service is None or not rep_service.enabled:
            return
        head = obj.head
        executable = head[:2] == b"MZ" or head[:4] in (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")
        script = obj.name.lower().rsplit(".", 1)[-1] in {"ps1", "vbs", "js", "jse", "hta", "bat", "cmd", "sh", "wsf"}
        heuristic_only = bool(res.detections) and all(d.engine == "heuristics" for d in res.detections)
        if not (heuristic_only or ((executable or script) and origin in self.CLOUD_ORIGINS)):
            return
        rep = rep_service.lookup(obj.sha256)
        if rep.malware:
            res.detections.append(
                Detection("cloud", rep.malware, Severity.CRITICAL, "Known malware sample (MalwareBazaar hash match)")
            )
        elif rep.known_good and heuristic_only:
            log.info("clearing heuristic finding on catalogued file %s (%s)", res.path, rep.known_good_source)
            res.detections = []

    @staticmethod
    def _drop_generated_rule_noise(res: ScanResult) -> None:
        """Machine-generated code-byte rules (Malpedia "*_Auto") occasionally collide with ordinary libraries; on
        operating-system files they are ignored. Everywhere else they still report."""
        if res.detections and is_system_path(res.path):
            res.detections = [
                d for d in res.detections if not (d.engine == "yara" and d.name.lower().endswith("_auto"))
            ]

    @staticmethod
    def _apply_publisher_trust(obj: ScanObject, res: ScanResult) -> None:
        """A program with a valid, trusted publisher signature (Windows Authenticode, including catalog signing):

        * heuristic guesses and report-only hints (generated rules, dual-use tools) are dropped: installers,
          launchers, VPN clients and security tools trip them constantly;
        * strong pattern (YARA) hits on operating-system files are dropped; elsewhere they are reported, not
          acted on automatically.

        Exact matches (known-malware hash, ClamAV, cloud lookup) are never softened: stolen certificates exist."""
        soft = [d for d in res.detections if d.engine not in EXACT_ENGINES]
        if not soft or obj.fs_path is None or obj.head[:2] != b"MZ":
            return
        if authenticode.verify(str(obj.fs_path)) is not Signature.VALID:
            return
        dropped = [d for d in soft if d.engine == "heuristics" or d.details.get("report_only")]
        pattern_hits = [d for d in soft if d.engine == "yara" and d.severity >= Severity.HIGH and d not in dropped]
        if is_system_path(res.path):
            dropped += pattern_hits
            pattern_hits = []
        for d in dropped:
            log.info("ignoring %s on validly signed %s", d.name, res.path)
        res.detections = [d for d in res.detections if d not in dropped]
        for d in pattern_hits:
            d.severity = Severity.MEDIUM
            d.description += " (file has a valid publisher signature — reported, not quarantined)"
            d.details["signed"] = True
            d.details["report_only"] = True

    @staticmethod
    def _apply_location_context(res: ScanResult) -> None:
        """Installed programs' folders and the operating system can only be changed with administrator rights, and
        their scripts, add-ins, libraries and test data trip patterns and heuristics constantly (Office's own
        JavaScript, Git's runtime, automation tools that generate PowerShell, browser resource bundles). There:

        * heuristic guesses below High are not shown;
        * other pattern and heuristic findings are shown as items to review, never as threats;
        * exact matches (known-malware hash, ClamAV, cloud lookup) stay threats and are acted on as usual.

        App data and package caches (AppData, ProgramData, ~/Library, ~/.cache…): archives, packages and other data
        there (update packages, extension bundles, package-manager caches) are never run as they are, so pattern
        and heuristic findings in them are items to review. Programs and scripts there stay threats."""
        if not res.detections:
            return
        if res.where == "appdata" and (res.kind == "data" or res.in_archive):
            for d in res.detections:
                if d.engine not in EXACT_ENGINES and not d.details.get("report_only"):
                    d.details["report_only"] = True
                    d.description += " (in an app's data or package cache: reported for review)"
            return
        if not (res.where == "program" or is_system_path(res.path)):
            return
        quiet = [d for d in res.detections if d.engine == "heuristics" and d.severity < Severity.HIGH]
        for d in quiet:
            log.info("ignoring %s in installed program folder %s", d.name, res.path)
        res.detections = [d for d in res.detections if d not in quiet]
        for d in res.detections:
            if d.engine not in EXACT_ENGINES and not d.details.get("report_only"):
                d.details["report_only"] = True
                d.description += " (in an installed program's folder: reported for review)"

    # ------------------------------------------------------------------ actions
    def should_quarantine(self, res: ScanResult) -> bool:
        s = self.settings
        if not s.auto_quarantine:
            return False
        actionable = [d for d in res.detections if not d.details.get("report_only")]
        if not actionable:
            return False  # hints only (generated rules, dual-use tools, signed software)
        if any(d.engine in EXACT_ENGINES for d in actionable):
            return True  # known-malware hash / ClamAV signature / cloud hash match
        if is_system_path(res.path):
            # Operating-system files are only removed automatically on an exact match; a pattern or heuristic hit
            # there is far more likely a false positive, and removing it could break the OS.
            return False
        if res.where == "program":
            return False  # installed software (admin-only folder): report, let the user decide
        if res.where == "appdata" and res.kind == "data":
            return False  # caches and app databases are never run; a pattern match in them is reported only
        if any(d.is_signature for d in actionable):
            return True
        return s.auto_quarantine_heuristics and any(d.severity >= Severity.HIGH for d in actionable)

    def _act(self, res: ScanResult) -> None:
        top = res.top
        assert top is not None
        if self.should_quarantine(res):
            try:
                self.quarantine.add(res.path, top.name, top.engine)
                res.action = "quarantined"
            except (QuarantineError, OSError) as exc:
                res.action = f"quarantine failed: {exc}"
        else:
            res.action = "reported"
        for d in res.detections:
            self.db.add_detection(res.path, res.sha256, d.engine, d.name, int(d.severity), res.action, res.origin)
        self.db.log_event(
            "detection",
            f"{top.name} in {res.path} ({top.engine}) → {res.action}",
            "critical" if top.severity >= Severity.HIGH else "warning",
        )

    def quarantine_result(self, res: ScanResult) -> None:
        """Manual quarantine from the UI."""
        top = res.top
        self.quarantine.add(res.path, top.name if top else "Manual", top.engine if top else "user")
        res.action = "quarantined"
        self.db.log_event("quarantine", f"Manually quarantined {res.path}", "info")

    # ------------------------------------------------------------------ walking
    def iter_files(self, roots: Iterable[str | Path], cancel: threading.Event | None = None) -> Iterator[str]:
        seen_dirs: set[tuple[int, int]] = set()
        for root in roots:
            root = os.path.abspath(os.path.expanduser(str(root)))
            if self.is_excluded(root):
                continue
            if os.path.isfile(root):
                yield root
                continue
            stack = [root]
            while stack:
                if cancel is not None and cancel.is_set():
                    return
                d = stack.pop()
                try:
                    st = os.stat(d)
                    key = (st.st_dev, st.st_ino)
                    if key in seen_dirs and st.st_ino != 0:
                        continue
                    seen_dirs.add(key)
                    with os.scandir(d) as it:
                        entries = list(it)
                except OSError:
                    continue
                for e in entries:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            if not self.is_excluded(e.path):
                                stack.append(e.path)
                        elif e.is_file(follow_symlinks=False) and not self.is_excluded(e.path):
                            yield e.path
                    except OSError:
                        continue

    def scan_paths(
        self,
        roots: Iterable[str | Path],
        progress: ProgressCB | None = None,
        on_result: ResultCB | None = None,
        cancel: threading.Event | None = None,
        origin: str = "scan",
        use_cache: bool = True,
        max_files: int = 0,
        act: bool = True,
    ) -> ScanSummary:
        """``act=False`` reports only (nothing is quarantined or recorded) — used by the false-positive audit."""
        summary = ScanSummary()
        cancel = cancel or threading.Event()
        lock = threading.Lock()
        max_inflight = self.settings.scan_threads * 4

        def handle(fut: Future) -> None:
            try:
                results: list[ScanResult] = fut.result()
            except Exception as exc:  # should not happen; scan_file catches
                results = [ScanResult(path="?", error=str(exc))]
            top = results[0]
            with lock:
                summary.scanned += 1
                summary.bytes += top.size
                if top.skipped:
                    summary.skipped += 1
                if top.error:
                    summary.errors += 1
                if top.infected:
                    summary.infected += 1
                    if top.needs_review_only:
                        summary.review += 1
                if top.infected or top.error:
                    summary.results.append(top)
                n = summary.scanned
            if progress:
                progress(n, top.path)
            if on_result and (top.infected or top.error):
                on_result(top)

        with ThreadPoolExecutor(max_workers=self.settings.scan_threads, thread_name_prefix="scan") as pool:
            inflight: set[Future] = set()
            for submitted, path in enumerate(self.iter_files(roots, cancel)):
                if max_files and submitted >= max_files:
                    break
                if cancel.is_set():
                    break
                inflight.add(pool.submit(self.scan_file, path, origin, act, use_cache))
                if len(inflight) >= max_inflight:
                    done, inflight = wait(inflight, return_when=FIRST_COMPLETED)
                    for f in done:
                        handle(f)
            if cancel.is_set():
                for f in inflight:
                    f.cancel()
            for f in inflight:
                if not f.cancelled():
                    handle(f)
        summary.cancelled = cancel.is_set()
        summary.finished = time.time()
        self.db.log_event(
            "scan",
            f"{origin} scan {'cancelled' if summary.cancelled else 'finished'}: {summary.scanned:,} files, "
            f"{summary.infected} infected, {summary.errors} errors in {summary.duration:.1f}s",
            "warning" if summary.infected else "info",
        )
        return summary

    # ------------------------------------------------------------------ presets
    @staticmethod
    def quick_scan_roots() -> list[str]:
        home = Path.home()
        roots = [home / "Downloads", home / "Desktop", Path(tempfile.gettempdir())]
        if sys.platform == "win32":
            for var in ("APPDATA", "LOCALAPPDATA", "PROGRAMDATA"):
                v = os.environ.get(var)
                if v:
                    roots.append(Path(v) / "Microsoft/Windows/Start Menu/Programs/Startup")
            if os.environ.get("LOCALAPPDATA"):
                roots.append(Path(os.environ["LOCALAPPDATA"]) / "Temp")
        elif sys.platform == "darwin":
            roots += [home / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
        else:
            roots += [home / ".config/autostart", Path("/etc/cron.d"), Path("/dev/shm"), Path("/var/tmp")]
        return [str(r) for r in roots if r.exists()]

    @staticmethod
    def full_scan_roots() -> list[str]:
        if sys.platform == "win32":
            import psutil

            return [p.mountpoint for p in psutil.disk_partitions(all=False) if "cdrom" not in p.opts]
        return ["/"]

    def running_executables(self) -> dict[str, list[tuple[int, str]]]:
        import psutil

        exes: dict[str, list[tuple[int, str]]] = {}
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            exe = proc.info.get("exe")
            if exe and os.path.isfile(exe):
                exes.setdefault(exe, []).append((proc.info["pid"], proc.info.get("name") or ""))
        return exes

    def scan_processes(
        self,
        progress: ProgressCB | None = None,
        on_result: ResultCB | None = None,
        cancel: threading.Event | None = None,
    ) -> ScanSummary:
        """Scan the executable image of every running process (the files are in use, so detections
        are reported — the user decides whether to terminate the process and quarantine)."""
        exes = self.running_executables()
        summary = ScanSummary()
        for i, (exe, procs) in enumerate(exes.items(), 1):
            if cancel is not None and cancel.is_set():
                summary.cancelled = True
                break
            res = self.scan_file(exe, origin="process", act=False)[0]
            summary.scanned += 1
            if progress:
                progress(i, exe)
            if res.infected:
                res.action = "reported"
                top = res.top
                for d in res.detections:
                    d.details["processes"] = procs
                    self.db.add_detection(
                        res.path, res.sha256, d.engine, d.name, int(d.severity), "reported", "process"
                    )
                self.db.log_event(
                    "detection",
                    f"Running process {', '.join(f'{n} ({p})' for p, n in procs)} is {top.name if top else '?'}",
                    "critical",
                )
                summary.infected += 1
                if res.needs_review_only:
                    summary.review += 1
                summary.results.append(res)
                if on_result:
                    on_result(res)
        summary.finished = time.time()
        return summary


def kill_process(pid: int) -> None:
    import psutil

    p = psutil.Process(pid)
    p.terminate()
    try:
        p.wait(timeout=5)
    except psutil.TimeoutExpired:
        p.kill()


def bytes_human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
