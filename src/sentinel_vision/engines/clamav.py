"""ClamAV engine.

Prefers a running ``clamd`` daemon (fast; signatures stay loaded) and streams data to it with the
INSTREAM protocol, so it works for archive members and files clamd itself may not be allowed to read.
Falls back to the ``clamscan`` command-line scanner (slow: it loads the database on every call).
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import struct
import subprocess
import sys
from pathlib import Path

from sentinel_vision.engines.base import Detection, Engine, ScanObject, Severity

log = logging.getLogger(__name__)

UNIX_SOCKETS = [
    "/var/run/clamav/clamd.ctl",
    "/run/clamav/clamd.ctl",
    "/var/run/clamd.scan/clamd.sock",
    "/run/clamd.scan/clamd.sock",
    "/tmp/clamd.socket",
    "/opt/homebrew/var/run/clamav/clamd.sock",
    "/usr/local/var/run/clamav/clamd.sock",
]
TCP_DEFAULT = ("127.0.0.1", 3310)
WINDOWS_CLAMSCAN = [r"C:\Program Files\ClamAV\clamscan.exe", r"C:\Program Files (x86)\ClamAV\clamscan.exe"]
SOCKET_TIMEOUT = 120
STREAM_CHUNK = 64 * 1024


class ClamAVError(RuntimeError):
    pass


def parse_clamd_reply(reply: str) -> str | None:
    """Return the signature name from a clamd reply, or None if clean.

    Replies look like ``stream: OK`` or ``stream: Win.Test.EICAR_HDB-1 FOUND``.
    """
    reply = reply.strip("\x00\r\n ")
    if reply.endswith("FOUND"):
        body = reply[: -len("FOUND")].strip()
        return body.rsplit(": ", 1)[-1].strip() or "ClamAV.Unknown"
    if reply.endswith("OK"):
        return None
    raise ClamAVError(reply or "empty reply from clamd")


class ClamAVEngine(Engine):
    name = "clamav"
    label = "ClamAV"

    def __init__(self, address: str = "") -> None:
        self.address = address
        self._mode: str | None = None  # "unix" | "tcp" | "clamscan"
        self._target: str | tuple[str, int] | None = None
        self.detect()

    # ------------------------------------------------------------------ discovery
    def _connect(self, mode: str, target) -> socket.socket:
        if mode == "unix":
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)  # type: ignore[attr-defined]
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT)
        s.connect(target)
        return s

    def _ping(self, mode: str, target) -> bool:
        try:
            with self._connect(mode, target) as s:
                s.settimeout(3)
                s.sendall(b"zPING\0")
                return s.recv(64).strip(b"\0\r\n ") == b"PONG"
        except OSError:
            return False

    def detect(self) -> None:
        self._mode, self._target = None, None
        candidates: list[tuple[str, object]] = []
        addr = self.address.strip()
        if addr:
            if ":" in addr and not addr.startswith("/") and not (len(addr) > 1 and addr[1] == ":"):
                host, port = addr.rsplit(":", 1)
                candidates.append(("tcp", (host, int(port))))
            else:
                candidates.append(("unix", addr))
        else:
            if hasattr(socket, "AF_UNIX") and sys.platform != "win32":
                candidates += [("unix", p) for p in UNIX_SOCKETS if os.path.exists(p)]
            candidates.append(("tcp", TCP_DEFAULT))
        for mode, target in candidates:
            if self._ping(mode, target):
                self._mode, self._target = mode, target
                return
        exe = shutil.which("clamscan") or next((p for p in WINDOWS_CLAMSCAN if os.path.exists(p)), None)
        if exe:
            self._mode, self._target = "clamscan", exe

    def reload(self) -> None:
        self.detect()

    def available(self) -> bool:
        return self._mode is not None

    def status(self) -> str:
        if self._mode in ("unix", "tcp"):
            return f"clamd ({self._target})"
        if self._mode == "clamscan":
            return "clamscan (slow mode — start clamd for speed)"
        return "not installed"

    def version(self) -> str:
        if self._mode in ("unix", "tcp"):
            try:
                with self._connect(self._mode, self._target) as s:
                    s.sendall(b"zVERSION\0")
                    return s.recv(256).decode(errors="replace").strip("\0\r\n ")
            except OSError:
                return ""
        return ""

    # ------------------------------------------------------------------ scanning
    def scan(self, obj: ScanObject) -> list[Detection]:
        if self._mode in ("unix", "tcp"):
            name = self._instream(obj)
        elif self._mode == "clamscan":
            name = self._clamscan(obj)
        else:
            return []
        if not name:
            return []
        sev = Severity.MEDIUM if name.startswith(("PUA.", "Heuristics.")) else Severity.CRITICAL
        return [Detection(self.name, name, sev, "Detected by ClamAV signature database.")]

    def _instream(self, obj: ScanObject) -> str | None:
        try:
            with self._connect(self._mode, self._target) as s:  # type: ignore[arg-type]
                s.sendall(b"zINSTREAM\0")
                with obj.open() as fh:
                    while chunk := fh.read(STREAM_CHUNK):
                        s.sendall(struct.pack("!L", len(chunk)) + chunk)
                s.sendall(struct.pack("!L", 0))
                reply = b""
                while not reply.endswith(b"\0"):
                    part = s.recv(4096)
                    if not part:
                        break
                    reply += part
        except OSError as exc:
            raise ClamAVError(f"clamd communication failed: {exc}") from exc
        text = reply.decode(errors="replace")
        if "size limit exceeded" in text.lower():
            return None  # clamd's StreamMaxLength; other engines still cover the file
        return parse_clamd_reply(text)

    def _clamscan(self, obj: ScanObject) -> str | None:
        args = [str(self._target), "--no-summary", "--infected", "--stdout"]
        kwargs: dict = {"capture_output": True, "timeout": 600}
        if sys.platform == "win32":
            kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
        if obj.fs_path is not None:
            proc = subprocess.run([*args, str(Path(obj.fs_path))], **kwargs)
        else:
            proc = subprocess.run([*args, "-"], input=obj.data, **kwargs)
        if proc.returncode == 0:
            return None
        if proc.returncode == 1:
            for line in proc.stdout.decode(errors="replace").splitlines():
                if line.rstrip().endswith("FOUND"):
                    return parse_clamd_reply(line)
            return "ClamAV.Unknown"
        raise ClamAVError(proc.stderr.decode(errors="replace").strip() or f"clamscan exit {proc.returncode}")
