"""Live network monitor: every connection on the machine, mapped to its process and checked against
threat intelligence, plus system-wide throughput history."""

from __future__ import annotations

import logging
import os
import socket
import tempfile
import threading
import time
from collections import deque, namedtuple
from collections.abc import Callable
from dataclasses import dataclass, field, replace

import psutil

from sentinel_vision.config import Settings
from sentinel_vision.db import Database
from sentinel_vision.engines.base import Severity
from sentinel_vision.network.threatintel import IntelStore

log = logging.getLogger(__name__)

RawConn = namedtuple("RawConn", "fd family type laddr raddr status pid")
HISTORY = 240  # samples kept for the throughput graph
TEMP_DIRS = tuple(
    os.path.normcase(p)
    for p in {
        tempfile.gettempdir(),
        os.environ.get("TEMP", ""),
        os.environ.get("TMP", ""),
        "/tmp",
        "/dev/shm",
        "/var/tmp",
    }
    if p
)


@dataclass
class Connection:
    proto: str
    local: str
    remote: str
    rip: str
    rport: int
    lport: int
    status: str
    pid: int | None
    process: str = ""
    exe: str = ""
    first_seen: float = field(default_factory=time.time)
    threat: str = ""
    severity: int = -1  # -1 = clean, else Severity value

    @property
    def key(self) -> tuple:
        return (self.proto, self.local, self.remote, self.pid)


@dataclass
class Snapshot:
    ts: float
    connections: list[Connection]
    up_bps: float
    down_bps: float
    total_sent: int
    total_recv: int
    history: list[tuple[float, float, float]]
    established: int
    listening: int
    threats: int
    error: str = ""


Listener = Callable[[Connection], None]


def _fmt(addr) -> str:
    if not addr:
        return ""
    ip, port = addr.ip, addr.port
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def _is_public(ip: str) -> bool:
    import ipaddress

    try:
        a = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved)


class NetworkMonitor:
    def __init__(self, settings: Settings, intel: IntelStore, db: Database) -> None:
        self.settings = settings
        self.intel = intel
        self.db = db
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: dict[tuple, Connection] = {}
        self._alerted: set[tuple] = set()
        self._proc_cache: dict[int, tuple[float, str, str]] = {}
        self._history: deque[tuple[float, float, float]] = deque(maxlen=HISTORY)
        self._last_io: tuple[float, int, int] | None = None
        self._snapshot = Snapshot(time.time(), [], 0, 0, 0, 0, [], 0, 0, 0)
        self._listeners: list[Listener] = []
        self.whitelist: set[str] = set()

    # ------------------------------------------------------------------ lifecycle
    def add_listener(self, fn: Listener) -> None:
        self._listeners.append(fn)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="netmon", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def snapshot(self) -> Snapshot:
        with self._lock:
            return replace(self._snapshot, connections=list(self._snapshot.connections), history=list(self._history))

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll()
            except Exception as exc:  # never let the monitor thread die
                log.exception("network poll failed")
                with self._lock:
                    self._snapshot.error = str(exc)
            self._stop.wait(max(0.5, self.settings.network_poll_seconds))

    # ------------------------------------------------------------------ polling
    def _process(self, pid: int | None) -> tuple[str, str]:
        if not pid:
            return ("System" if pid == 0 else "", "")
        try:
            p = psutil.Process(pid)
            ct = p.create_time()
            cached = self._proc_cache.get(pid)
            if cached and cached[0] == ct:
                return cached[1], cached[2]
            name = p.name()
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                exe = ""
            self._proc_cache[pid] = (ct, name, exe)
            return name, exe
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "", ""

    def _raw_connections(self) -> tuple[list, str]:
        try:
            return psutil.net_connections(kind="inet"), ""
        except psutil.AccessDenied:
            # macOS (and hardened Linux) need elevation for the system-wide view; fall back to the
            # processes we are allowed to inspect.
            out = []
            for p in psutil.process_iter(["pid"]):
                try:
                    getter = getattr(p, "net_connections", None) or p.connections
                    for c in getter(kind="inet"):
                        out.append(RawConn(c.fd, c.family, c.type, c.laddr, c.raddr, c.status, p.pid))
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    continue
            return out, "Limited view: run as administrator to see connections of every process."

    def classify(self, c: Connection) -> None:
        if c.rip and c.rip not in self.whitelist:
            src = self.intel.lookup(c.rip)
            if src:
                c.threat, c.severity = f"Known malicious IP ({src})", int(Severity.HIGH)
                return
        ports = set(self.settings.suspicious_ports)
        if c.rip and c.rport in ports and _is_public(c.rip):
            c.threat, c.severity = f"Remote port {c.rport} is commonly used by malware/backdoors", int(Severity.LOW)
        elif c.status == "LISTEN" and c.lport in ports:
            c.threat, c.severity = f"Listening on port {c.lport}, commonly used by backdoors", int(Severity.MEDIUM)
        if c.exe and c.rip and _is_public(c.rip):
            exe = os.path.normcase(c.exe)
            if any(exe.startswith(t.rstrip(os.sep) + os.sep) for t in TEMP_DIRS):
                c.threat, c.severity = (
                    "Program running from a temp folder is talking to the internet",
                    int(Severity.MEDIUM),
                )

    def poll(self) -> Snapshot:
        now = time.time()
        raw, err = self._raw_connections()
        current: dict[tuple, Connection] = {}
        for rc in raw:
            proto = "TCP" if rc.type == socket.SOCK_STREAM else "UDP"
            if rc.family == socket.AF_INET6:
                proto += "6"
            rip = rc.raddr.ip if rc.raddr else ""
            name, exe = self._process(rc.pid)
            c = Connection(
                proto=proto,
                local=_fmt(rc.laddr),
                remote=_fmt(rc.raddr),
                rip=rip,
                rport=rc.raddr.port if rc.raddr else 0,
                lport=rc.laddr.port if rc.laddr else 0,
                status=rc.status if rc.status and rc.status != "NONE" else ("—" if proto.startswith("UDP") else ""),
                pid=rc.pid,
                process=name,
                exe=exe,
            )
            prev = self._seen.get(c.key)
            if prev:
                c.first_seen = prev.first_seen
            self.classify(c)
            current[c.key] = c
            if c.severity >= int(Severity.MEDIUM) and c.key not in self._alerted:
                self._alerted.add(c.key)
                self._alert(c)
        self._seen = current
        if len(self._alerted) > 50000:
            self._alerted = {k for k in self._alerted if k in current}

        io = psutil.net_io_counters()
        up = down = 0.0
        if self._last_io:
            dt = max(1e-3, now - self._last_io[0])
            up = max(0.0, (io.bytes_sent - self._last_io[1]) / dt)
            down = max(0.0, (io.bytes_recv - self._last_io[2]) / dt)
        self._last_io = (now, io.bytes_sent, io.bytes_recv)
        conns = sorted(current.values(), key=lambda x: (-x.severity, x.process.lower(), x.remote))
        snap = Snapshot(
            ts=now,
            connections=conns,
            up_bps=up,
            down_bps=down,
            total_sent=io.bytes_sent,
            total_recv=io.bytes_recv,
            history=[],
            established=sum(1 for c in conns if c.status == "ESTABLISHED"),
            listening=sum(1 for c in conns if c.status == "LISTEN"),
            threats=sum(1 for c in conns if c.severity >= int(Severity.MEDIUM)),
            error=err,
        )
        with self._lock:
            self._history.append((now, up, down))
            self._snapshot = snap
        return snap

    def _alert(self, c: Connection) -> None:
        msg = f"{c.process or 'Unknown process'} (PID {c.pid}) ↔ {c.remote or c.local}: {c.threat}"
        level = "critical" if c.severity >= int(Severity.HIGH) else "warning"
        try:
            self.db.log_event("network", msg, level)
            if c.severity >= int(Severity.HIGH):
                self.db.add_detection(
                    c.exe or c.process or "?", None, "network", c.threat, c.severity, "reported", "network"
                )
        except Exception:
            log.exception("could not record network alert")
        for fn in list(self._listeners):
            try:
                fn(c)
            except Exception:
                log.exception("network listener failed")
