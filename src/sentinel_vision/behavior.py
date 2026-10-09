"""Behaviour monitoring.

Process watcher
    Every new process is checked against attack-technique rules (Office spawning shells, encoded or
    download-and-run PowerShell, shadow-copy deletion, living-off-the-land downloaders, reverse shells,
    crypto-miners…) and its executable is scanned by every engine. Signature-confirmed malware and
    ransomware recovery-inhibition commands can be terminated automatically.

Persistence watcher
    Auto-start locations (Run keys, Startup folders, scheduled tasks, LaunchAgents/Daemons, XDG
    autostart, systemd units, cron, shell profiles) are snapshotted and diffed, so a program that
    installs itself to survive a reboot is reported — including changes made while the app was closed.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

import psutil

from sentinel_vision.engines.base import Severity
from sentinel_vision.scanner import Scanner, kill_process

log = logging.getLogger(__name__)

OFFICE = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "mspub.exe",
    "onenote.exe",
    "visio.exe",
    "eqnedt32.exe",
}
SHELLS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "schtasks.exe",
    "msiexec.exe",
    "installutil.exe",
    "regasm.exe",
    "regsvcs.exe",
    "msbuild.exe",
    "wmic.exe",
}
SCRIPT_HOSTS = {"wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "pwsh.exe", "cmd.exe"}
TEMP_DIRS = tuple(
    os.path.normcase(p).rstrip("\\/")
    for p in {tempfile.gettempdir(), os.environ.get("TEMP", ""), "/tmp", "/dev/shm", "/var/tmp"}  # noqa: S108
    if p
)
OWN_MARKERS = ("sentinelvision", "sentinel-vision", "sentinel_vision", "io.github.dylanckoldan-boop.sentinel-vision")


@dataclass
class Finding:
    severity: Severity
    name: str
    description: str
    terminate: bool = False  # eligible for automatic termination (ransomware recovery inhibition)


@dataclass
class BehaviorEvent:
    ts: float
    severity: int
    name: str
    description: str
    pid: int | None = None
    process: str = ""
    path: str = ""
    action: str = "reported"
    details: dict = field(default_factory=dict)


Listener = Callable[[BehaviorEvent], None]


# ----------------------------------------------------------------------------- process rules


def _has(text: str, *needles: str) -> bool:
    return all(n in text for n in needles)


def _any(text: str, *needles: str) -> bool:
    return any(n in text for n in needles)


def evaluate_process(name: str, cmdline: str, exe: str = "", parent: str = "") -> list[Finding]:
    """Pure function: attack-technique rules for one process. Inputs are case-insensitive."""
    n, c, p = name.lower(), " ".join(cmdline.lower().split()), parent.lower()
    exe_n = os.path.normcase(exe)
    out: list[Finding] = []

    # Ransomware: destroying backups/recovery before encryption (MITRE T1490).
    if (
        (_has(c, "vssadmin", "delete", "shadow"))
        or (_has(c, "shadowcopy", "delete") and _any(c, "wmic", "win32_shadowcopy"))
        or (_has(c, "win32_shadowcopy") and _any(c, "remove-", ".delete("))
        or (_has(c, "wbadmin", "delete") and _any(c, "catalog", "systemstatebackup", "backup"))
        or (
            _has(c, "bcdedit")
            and (_has(c, "recoveryenabled", "no") or _has(c, "bootstatuspolicy", "ignoreallfailures"))
        )
    ):
        out.append(
            Finding(
                Severity.CRITICAL,
                "Behavior.Ransomware.InhibitRecovery",
                "Deletes shadow copies / backups or disables recovery — typical of ransomware",
                True,
            )
        )

    # Office documents launching shells or LOLBins (macro malware, exploits).
    if p in OFFICE and n in SHELLS:
        out.append(
            Finding(
                Severity.HIGH,
                "Behavior.Office.SpawnsShell",
                f"{parent} started {name} — typical of a malicious document",
            )
        )

    # PowerShell abuse.
    if n in ("powershell.exe", "pwsh.exe", "powershell", "pwsh"):
        compact = re.sub(r"[\s`^'\"+]", "", c)
        cradle = _any(compact, "iex(", "invoke-expression", "iex$") and _any(
            compact, "downloadstring", "net.webclient", "invoke-webrequest", "iwr", "downloaddata", "start-bitstransfer"
        )
        encoded = re.search(r"\s-(e|ec|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[a-z0-9+/=]{40,}", c)
        hidden = re.search(r"\s-(w|wi|win|window|windowstyle)\s+(h|hidden|1)\b", c)
        if cradle:
            out.append(
                Finding(
                    Severity.HIGH,
                    "Behavior.PowerShell.DownloadExecute",
                    "PowerShell downloads code and runs it in memory",
                )
            )
        elif encoded and hidden:
            out.append(
                Finding(
                    Severity.HIGH, "Behavior.PowerShell.HiddenEncoded", "Hidden PowerShell running an encoded command"
                )
            )
        elif encoded:
            out.append(Finding(Severity.MEDIUM, "Behavior.PowerShell.Encoded", "PowerShell running an encoded command"))
        if _any(
            compact, "set-mppreference-disable", "disablerealtimemonitoring$true", "add-mppreference-exclusionpath"
        ):
            out.append(Finding(Severity.HIGH, "Behavior.DefenseEvasion.Defender", "Tries to weaken Microsoft Defender"))

    # Living-off-the-land binaries used as downloaders / proxies.
    if n == "certutil.exe" and _any(c, "-urlcache", "/urlcache", "-verifyctl") and "http" in c:
        out.append(Finding(Severity.HIGH, "Behavior.LOLBin.Certutil", "certutil used to download a file"))
    if n == "mshta.exe" and _any(c, "http:", "https:", "javascript:", "vbscript:"):
        out.append(Finding(Severity.HIGH, "Behavior.LOLBin.Mshta", "mshta runs remote or inline script"))
    if n == "regsvr32.exe" and _has(c, "/i:") and _any(c, "http:", "https:", "scrobj"):
        out.append(Finding(Severity.HIGH, "Behavior.LOLBin.Regsvr32", "regsvr32 loads a remote scriptlet (Squiblydoo)"))
    if n == "rundll32.exe" and _any(c, "javascript:", "mshtml,runhtmlapplication"):
        out.append(Finding(Severity.HIGH, "Behavior.LOLBin.Rundll32", "rundll32 executes script"))
    if n == "bitsadmin.exe" and _has(c, "/transfer") and "http" in c:
        out.append(Finding(Severity.MEDIUM, "Behavior.LOLBin.Bitsadmin", "bitsadmin used to download a file"))

    # Unix-like shells.
    if "/dev/tcp/" in c or re.search(r"\b(nc|ncat|netcat)\b.*\s-e\s", c) or re.search(r"\bsh\s+-i\b.*[<>]&", c):
        out.append(
            Finding(Severity.HIGH, "Behavior.ReverseShell", "Reverse shell giving a remote attacker a command line")
        )
    if re.search(r"(curl|wget)\s[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", c):
        out.append(Finding(Severity.LOW, "Behavior.PipeToShell", "Downloads a script and pipes it into a shell"))
    if n == "osascript" and _has(c, "do shell script") and _any(c, "curl", "base64", "/tmp/"):
        out.append(
            Finding(
                Severity.MEDIUM, "Behavior.AppleScript.Dropper", "AppleScript runs a download/decoded shell command"
            )
        )

    # Crypto-mining.
    if _any(c, "stratum+tcp://", "stratum+ssl://", "stratum2+tcp://") or n in ("xmrig", "xmrig.exe"):
        out.append(Finding(Severity.HIGH, "Behavior.CoinMiner", "Cryptocurrency miner"))

    # Payload executed from a temp folder by a script host or Office.
    if exe_n and (p in SCRIPT_HOSTS or p in OFFICE) and any(exe_n.startswith(t + os.sep) for t in TEMP_DIRS):
        out.append(
            Finding(Severity.MEDIUM, "Behavior.TempExecution", f"{parent} launched a program from a temp folder")
        )
    return out


# ----------------------------------------------------------------------------- persistence sources


def _file_entries(paths: Iterable[Path], recursive: bool = False) -> dict[str, str]:
    out: dict[str, str] = {}
    for base in paths:
        try:
            if base.is_file():
                st = base.stat()
                out[f"file:{base}"] = f"{st.st_size}:{int(st.st_mtime)}"
                continue
            if not base.is_dir():
                continue
            it = base.rglob("*") if recursive else base.iterdir()
            for f in it:
                try:
                    if f.is_file() and not f.is_symlink():
                        st = f.stat()
                        out[f"file:{f}"] = f"{st.st_size}:{int(st.st_mtime)}"
                except OSError:
                    continue
        except OSError:
            continue
    return out


def _windows_registry_entries() -> dict[str, str]:
    import winreg

    out: dict[str, str] = {}
    keys = [
        (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
    ]
    watched_winlogon = {"shell", "userinit"}
    for hive, label, sub in keys:
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ) as k:
                i = 0
                while True:
                    try:
                        name, value, _t = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    if sub.endswith("Winlogon") and name.lower() not in watched_winlogon:
                        continue
                    out[f"reg:{label}\\{sub}\\{name}"] = str(value)
        except OSError:
            continue
    return out


def persistence_snapshot() -> dict[str, str]:
    home = Path.home()
    if sys.platform == "win32":
        snap = _windows_registry_entries()
        appdata, programdata = os.environ.get("APPDATA", ""), os.environ.get("PROGRAMDATA", "")
        folders = []
        if appdata:
            folders.append(Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup")
        if programdata:
            folders.append(Path(programdata) / "Microsoft/Windows/Start Menu/Programs/StartUp")
        snap.update(_file_entries(folders))
        windir = os.environ.get("WINDIR", r"C:\Windows")
        snap.update(_file_entries([Path(windir) / "System32" / "Tasks"], recursive=True))
        return snap
    if sys.platform == "darwin":
        return _file_entries(
            [
                home / "Library/LaunchAgents",
                Path("/Library/LaunchAgents"),
                Path("/Library/LaunchDaemons"),
                Path("/Library/StartupItems"),
                home / ".zshrc",
                home / ".bash_profile",
                home / ".profile",
            ]
        )
    cfg = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    return _file_entries(
        [
            cfg / "autostart",
            Path("/etc/xdg/autostart"),
            cfg / "systemd/user",
            Path("/etc/systemd/system"),
            Path("/etc/cron.d"),
            Path("/etc/crontab"),
            Path("/var/spool/cron/crontabs"),
            Path("/etc/rc.local"),
            Path("/etc/ld.so.preload"),
            home / ".bashrc",
            home / ".profile",
            home / ".bash_profile",
            home / ".zshrc",
            home / ".ssh/authorized_keys",
        ]
    )


def _command_target(value: str) -> str:
    v = os.path.expandvars(value.strip())
    if v.startswith('"'):
        end = v.find('"', 1)
        return v[1:end] if end > 0 else ""
    m = re.match(r"^(.+?\.(exe|bat|cmd|com|scr|vbs|js|ps1|dll))\b", v, re.I)
    return m.group(1) if m else v.split(" ", 1)[0]


# ----------------------------------------------------------------------------- monitor


class BehaviorMonitor:
    PROCESS_INTERVAL = 1.0
    PERSISTENCE_INTERVAL = 20.0

    def __init__(
        self,
        scanner: Scanner,
        settings,
        snapshot_fn: Callable[[], dict[str, str]] = persistence_snapshot,
    ) -> None:
        self.scanner = scanner
        self.db = scanner.db
        self.settings = settings
        self.snapshot_fn = snapshot_fn
        self._listeners: list[Listener] = []
        self._seen: dict[int, float] = {}
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._exe_queue: queue.Queue[tuple[str, int, str]] = queue.Queue(maxsize=2000)
        self._scanned_exes: dict[str, tuple[int, float]] = {}
        self._own_pid = os.getpid()
        # In a frozen build our own GUI/CLI executables live next to sys.executable.
        self._own_dir = os.path.normcase(str(Path(sys.executable).parent)) if getattr(sys, "frozen", False) else ""
        self.events: list[BehaviorEvent] = []
        self._lock = threading.Lock()
        self.processes_checked = 0

    # ------------------------------------------------------------------ lifecycle
    def add_listener(self, fn: Listener) -> None:
        self._listeners.append(fn)

    @property
    def running(self) -> bool:
        return any(t.is_alive() for t in self._threads)

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._threads = [
            threading.Thread(
                target=self._loop, args=(self.poll_processes, self.PROCESS_INTERVAL), name="bh-proc", daemon=True
            ),
            threading.Thread(
                target=self._loop,
                args=(self.poll_persistence, self.PERSISTENCE_INTERVAL),
                name="bh-persist",
                daemon=True,
            ),
            threading.Thread(target=self._exe_worker, name="bh-exe", daemon=True),
        ]
        for t in self._threads:
            t.start()
        self.db.log_event("behavior", "Behavior monitoring on")

    def stop(self) -> None:
        was = self.running
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        self._threads = []
        if was:
            self.db.log_event("behavior", "Behavior monitoring off", "warning")

    def _loop(self, fn: Callable[[], object], interval: float) -> None:
        while not self._stop.is_set():
            try:
                fn()
            except Exception:
                log.exception("behavior poll failed")
            self._stop.wait(interval)

    # ------------------------------------------------------------------ reporting
    def _emit(self, ev: BehaviorEvent) -> None:
        with self._lock:
            self.events.append(ev)
            del self.events[:-500]
        level = "critical" if ev.severity >= Severity.HIGH else "warning" if ev.severity >= Severity.MEDIUM else "info"
        who = f"{ev.process} (PID {ev.pid})" if ev.pid else ev.path
        try:
            self.db.log_event("behavior", f"{ev.name}: {who} — {ev.description} → {ev.action}", level)
            if ev.severity >= Severity.MEDIUM:
                self.db.add_detection(
                    ev.path or ev.process, None, "behavior", ev.name, int(ev.severity), ev.action, "behavior"
                )
        except Exception:
            log.exception("could not record behavior event")
        if ev.severity >= Severity.MEDIUM:
            for fn in list(self._listeners):
                try:
                    fn(ev)
                except Exception:
                    log.exception("behavior listener failed")

    # ------------------------------------------------------------------ processes
    def poll_processes(self) -> list[BehaviorEvent]:
        new: list[BehaviorEvent] = []
        alive: dict[int, float] = {}
        first = not self._seen
        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time"]):
            info = proc.info
            pid, ct = info.get("pid"), info.get("create_time") or 0.0
            if pid is None:
                continue
            alive[pid] = ct
            if self._seen.get(pid) == ct or pid == self._own_pid:
                continue
            self.processes_checked += 1
            name = info.get("name") or ""
            exe = info.get("exe") or ""
            cmd = info.get("cmdline") or []
            cmdline = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
            parent = ""
            try:
                ppid = info.get("ppid")
                if ppid:
                    parent = psutil.Process(ppid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            if self._own_dir and os.path.normcase(exe).startswith(self._own_dir + os.sep):
                continue
            for f in evaluate_process(name, cmdline, exe, parent):
                action = "reported"
                if f.terminate and self.settings.behavior_block_ransomware:
                    action = self._terminate(pid)
                ev = BehaviorEvent(
                    time.time(),
                    int(f.severity),
                    f.name,
                    f.description,
                    pid,
                    name,
                    exe,
                    action,
                    {"cmdline": cmdline[:2000], "parent": parent},
                )
                new.append(ev)
                self._emit(ev)
            if exe and not first:
                try:
                    self._exe_queue.put_nowait((exe, pid, name))
                except queue.Full:
                    pass
        self._seen = alive
        return new

    def _terminate(self, pid: int) -> str:
        try:
            kill_process(pid)
            return "terminated"
        except Exception as exc:
            return f"terminate failed: {exc}"

    def _exe_worker(self) -> None:
        while not self._stop.is_set():
            try:
                exe, pid, name = self._exe_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self.check_executable(exe, pid, name)

    def check_executable(self, exe: str, pid: int | None, name: str) -> BehaviorEvent | None:
        """Scan a newly started program; kill + quarantine it if a signature engine confirms malware."""
        try:
            st = os.stat(exe)
        except OSError:
            return None
        key = os.path.normcase(exe)
        stamp = (st.st_size, st.st_mtime)
        if self._scanned_exes.get(key) == stamp:
            return None
        self._scanned_exes[key] = stamp
        if len(self._scanned_exes) > 20000:
            self._scanned_exes.clear()
        res = self.scanner.scan_file(exe, origin="process", act=False)[0]
        if not res.infected:
            return None
        top = res.top
        confirmed = any(
            d.engine in ("hash", "clamav") or (d.engine == "yara" and d.severity >= Severity.CRITICAL)
            for d in res.detections
        )
        action = "reported"
        if confirmed and self.settings.behavior_kill_malicious and pid:
            action = self._terminate(pid)
            if action == "terminated" and self.settings.auto_quarantine:
                time.sleep(0.5)  # let the OS release the image file
                try:
                    self.scanner.quarantine.add(exe, top.name if top else "Malware", top.engine if top else "behavior")
                    action = "terminated + quarantined"
                except Exception as exc:
                    action = f"terminated (quarantine failed: {exc})"
        ev = BehaviorEvent(
            time.time(),
            int(top.severity if top else Severity.HIGH),
            top.name if top else "Malware",
            f"Running program detected by {', '.join(sorted({d.engine for d in res.detections}))}",
            pid,
            name,
            exe,
            action,
        )
        self._emit(ev)
        return ev

    # ------------------------------------------------------------------ persistence
    def _is_own(self, key: str, value: str) -> bool:
        k = (key + " " + value).lower().replace(" ", "")
        return any(m in k for m in OWN_MARKERS)

    def poll_persistence(self) -> list[BehaviorEvent]:
        current = self.snapshot_fn()
        raw = self.db.get_meta("persistence_baseline")
        if raw is None:
            self.db.set_meta("persistence_baseline", json.dumps(current))
            return []
        try:
            baseline: dict[str, str] = json.loads(raw)
        except ValueError:
            baseline = {}
        events: list[BehaviorEvent] = []
        for key, value in current.items():
            if key in baseline and baseline[key] == value:
                continue
            if self._is_own(key, value):
                continue
            added = key not in baseline
            kind, _, where = key.partition(":")
            target = where if kind == "file" else _command_target(value)
            desc = ("New auto-start entry: " if added else "Auto-start entry changed: ") + where
            if kind == "reg":
                desc += f" → {value[:300]}"
            sev = Severity.MEDIUM if added else Severity.LOW
            action = "reported"
            if target and os.path.isfile(target) and not self.scanner.is_excluded(target):
                res = self.scanner.scan_file(target, origin="behavior")[0]
                if res.infected:
                    sev = Severity.HIGH
                    top = res.top
                    desc += f" — target is {top.name if top else 'malicious'}"
                    action = res.action or "reported"
            ev = BehaviorEvent(
                time.time(),
                int(sev),
                "Behavior.Persistence",
                desc,
                None,
                "",
                target or where,
                action,
                {"entry": key, "value": value},
            )
            events.append(ev)
            self._emit(ev)
        self.db.set_meta("persistence_baseline", json.dumps(current))
        return events

    def reset_persistence_baseline(self) -> None:
        self.db.set_meta("persistence_baseline", json.dumps(self.snapshot_fn()))
