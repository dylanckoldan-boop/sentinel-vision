"""Memory scan: YARA rules against the memory of running processes, to find fileless malware and payloads that
were unpacked or injected at run time and never exist as a file on disk.

Findings are report-only (never killed automatically): memory of legitimate security tools, debuggers and
browsers can contain the very strings rules look for. Processes of known security products, validly signed
operating-system components and this app itself are skipped. Reading another process's memory needs the same
user (Windows, macOS with relaxed protections) or administrator/root rights; inaccessible processes are counted.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import psutil

from sentinel_vision.engines import authenticode
from sentinel_vision.engines.authenticode import Signature
from sentinel_vision.engines.base import Severity
from sentinel_vision.engines.yara_engine import _severity_from_meta
from sentinel_vision.scanner import is_system_path

log = logging.getLogger(__name__)

SECURITY_PRODUCTS = frozenset(
    """msmpeng.exe mpdefendercoreservice.exe nissrv.exe mssense.exe sentinelagent.exe csfalconservice.exe
    clamd clamscan freshclam clamd.exe clamscan.exe freshclam.exe avp.exe ekrn.exe bdagent.exe vsserv.exe
    ccsvchst.exe norton.exe nortonsecurity.exe mcshield.exe mfemms.exe mbamservice.exe mbam.exe avgsvc.exe
    avastsvc.exe sophosui.exe savservice.exe xprotect xprotectservice yara yara64.exe""".split()
)
MAX_RSS = 3 * 1024**3
TIMEOUT = 60


@dataclass
class MemoryHit:
    pid: int
    name: str
    exe: str
    rules: list[tuple[str, int]]  # (rule, severity)

    @property
    def severity(self) -> int:
        return max(s for _, s in self.rules)


@dataclass
class MemoryScanSummary:
    scanned: int = 0
    skipped: int = 0
    denied: int = 0
    hits: list[MemoryHit] = field(default_factory=list)
    duration: float = 0.0
    cancelled: bool = False


def _skip(proc: psutil.Process, info: dict) -> str:
    if proc.pid in (0, 4, os.getpid()):
        return "system/self"
    name = (info.get("name") or "").lower()
    if name in SECURITY_PRODUCTS or "sentinelvision" in name or "sentinel-vision" in name:
        return "security product"
    mem = info.get("memory_info")
    if mem is not None and mem.rss > MAX_RSS:
        return "too large"
    exe = info.get("exe") or ""
    if exe and is_system_path(exe) and authenticode.verify(exe) is Signature.VALID:
        return "signed system component"
    return ""


def scan_processes(
    scanner,
    progress: Callable[[int, str], None] | None = None,
    cancel: threading.Event | None = None,
    pids: list[int] | None = None,
) -> MemoryScanSummary:
    started = time.time()
    summary = MemoryScanSummary()
    yara_engine = next((e for e in scanner.engines if e.name == "yara" and e.available()), None)
    if yara_engine is None:
        summary.duration = time.time() - started
        return summary
    rules = yara_engine._thread_rules()
    procs = list(psutil.process_iter(["pid", "name", "exe", "memory_info"]))
    if pids is not None:
        procs = [p for p in procs if p.pid in set(pids)]
    for i, proc in enumerate(procs, 1):
        if cancel is not None and cancel.is_set():
            summary.cancelled = True
            break
        info = proc.info
        if progress:
            progress(i, f"{info.get('name') or '?'} ({proc.pid})")
        reason = _skip(proc, info)
        if reason:
            summary.skipped += 1
            continue
        try:
            matches = rules.match(pid=proc.pid, timeout=TIMEOUT, fast=True)
        except Exception as exc:  # yara.Error for access denied / process gone / timeout
            text = str(exc).lower()
            if "access" in text or "denied" in text or "permission" in text or "could not attach" in text:
                summary.denied += 1
            else:
                summary.skipped += 1
            continue
        summary.scanned += 1
        found = [(m.rule, int(_severity_from_meta(m.meta))) for m in matches]
        found = [f for f in found if f[1] >= int(Severity.MEDIUM) and not f[0].lower().endswith("_auto")]
        if found:
            hit = MemoryHit(proc.pid, info.get("name") or "?", info.get("exe") or "", found)
            summary.hits.append(hit)
            top = max(found, key=lambda f: f[1])
            scanner.db.add_detection(hit.exe or hit.name, None, "memory", top[0], top[1], "reported", "memory")
            scanner.db.log_event("memory", f"{top[0]} found in the memory of {hit.name} (PID {hit.pid})", "critical")
    summary.duration = time.time() - started
    scanner.db.log_event(
        "memory",
        f"Memory scan: {summary.scanned} processes scanned, {len(summary.hits)} with findings, "
        f"{summary.denied} not accessible, {summary.skipped} skipped",
        "warning" if summary.hits else "info",
    )
    return summary
