"""Talking to the protected Windows service.

Requests travel over a local named pipe (``\\\\.\\pipe\\SentinelVisionService``) that refuses remote clients. The
client checks the pipe really belongs to a service: services run in Windows session 0, and a program running as
the user can't create anything there, so it can't impersonate the service to collect files.

Framing (both directions): 4-byte big-endian header length, UTF-8 JSON header, 4-byte payload length, payload.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import struct
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path

from sentinel_vision.quarantine import (
    DEFAULT_EXTERNAL_SOURCE,
    O_BIN,
    QuarantineError,
    QuarantineItem,
    restore_target,
)
from sentinel_vision.servicecore import MAX_FRAME, Caller, ServiceCore, ServiceError
from sentinel_vision.vault import VaultError, VaultFiles, Version

log = logging.getLogger(__name__)

PIPE_NAME = r"\\.\pipe\SentinelVisionService"
SERVICE_NAME = "SentinelVisionService"
UPLOAD_CHUNK = 4 * 1024 * 1024


# ---------------------------------------------------------------------------------------------- framing
def _no_constants(name: str):
    raise ServiceError("bad_request", f"{name} is not allowed")


def encode(header: dict, payload: bytes = b"") -> bytes:
    h = json.dumps(header, allow_nan=False).encode("utf-8")  # NaN and Infinity are not JSON (SV-A03)
    return struct.pack(">I", len(h)) + h + struct.pack(">I", len(payload)) + payload


def decode(read_exact) -> tuple[dict, bytes]:
    (hl,) = struct.unpack(">I", read_exact(4))
    if hl > 1024 * 1024:
        raise ServiceError("protocol", "header too large")
    try:
        header = json.loads(read_exact(hl).decode("utf-8"), parse_constant=_no_constants)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ServiceError("bad_request", "request is not valid JSON") from exc
    if type(header) is not dict:
        raise ServiceError("bad_request", "request must be an object")
    (pl,) = struct.unpack(">I", read_exact(4))
    if pl > MAX_FRAME:
        raise ServiceError("protocol", "payload too large")
    return header, read_exact(pl) if pl else b""


def error_reply(exc: Exception) -> dict:
    if isinstance(exc, ServiceError):
        return {"ok": False, "code": exc.code, "message": str(exc), "extra": exc.extra}
    return {"ok": False, "code": "internal", "message": f"{type(exc).__name__}: {exc}", "extra": {}}


def _raise_for(reply: dict) -> None:
    if not reply.get("ok"):
        raise ServiceError(
            reply.get("code", "error"), reply.get("message", "service error"), **(reply.get("extra") or {})
        )


# ---------------------------------------------------------------------------------------------- transports
def _with_retry(fn):
    """Requests refused as "too_many" with a short retry_after are retried for up to five seconds."""
    deadline = time.time() + 5
    while True:
        try:
            return fn()
        except ServiceError as exc:
            wait = float(exc.extra.get("retry_after", 0) or 0)
            if exc.code != "too_many" or not 0 < wait <= 2 or time.time() + wait > deadline:
                raise
            time.sleep(wait)


class LocalTransport:
    """In-process transport (tests, and platforms without the service)."""

    def __init__(self, core: ServiceCore, caller: Caller) -> None:
        self.core, self.caller = core, caller

    def call(self, op: str, args: dict | None = None, payload: bytes = b"") -> tuple[dict, bytes]:
        result, data = _with_retry(lambda: self.core.handle(self.caller, op, args or {}, payload))
        # round-trip through JSON like the real pipe does, so tests see the same types
        return json.loads(json.dumps(result)), data

    def close(self) -> None:
        pass


class PipeTransport:  # pragma: no cover - Windows only, exercised by the Windows CI job
    def __init__(self, timeout: float = 5.0) -> None:
        import pywintypes
        import win32file
        import win32pipe

        self._lock = threading.Lock()
        deadline = time.time() + timeout
        while True:
            try:
                self.h = win32file.CreateFile(
                    PIPE_NAME,
                    # exactly what the pipe grants signed-in users: read, write data, set the read mode
                    win32file.GENERIC_READ | 0x0002 | 0x0100,  # FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    # SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION: the service may learn who we are (to keep each
                    # account's data separate) but can never act as us
                    0x00100000 | 0x00010000,
                    None,
                )
                break
            except pywintypes.error as exc:
                if exc.winerror == 231 and time.time() < deadline:  # ERROR_PIPE_BUSY
                    win32pipe.WaitNamedPipe(PIPE_NAME, 1000)
                    continue
                if exc.winerror == 2 and time.time() < deadline:  # not listening yet (service starting)
                    time.sleep(0.5)
                    continue
                raise OSError(f"protection service not reachable: {exc.strerror}") from exc
        if _server_session(self.h) != 0:
            win32file.CloseHandle(self.h)
            raise OSError("the pipe is not owned by a Windows service; refusing to use it")
        win32pipe.SetNamedPipeHandleState(self.h, win32pipe.PIPE_READMODE_BYTE, None, None)

    def _read_exact(self, n: int) -> bytes:
        import win32file

        buf = bytearray()
        while len(buf) < n:
            _, chunk = win32file.ReadFile(self.h, min(n - len(buf), 1024 * 1024))
            if not chunk:
                raise OSError("protection service closed the connection")
            buf += chunk
        return bytes(buf)

    def call(self, op: str, args: dict | None = None, payload: bytes = b"") -> tuple[dict, bytes]:
        import win32file

        def once():
            with self._lock:
                win32file.WriteFile(self.h, encode({"op": op, "args": args or {}}, payload))
                reply, data = decode(self._read_exact)
            _raise_for(reply)
            return reply.get("result", {}), data

        return _with_retry(once)

    def close(self) -> None:
        import win32file

        try:
            win32file.CloseHandle(self.h)
        except Exception:
            pass


def _server_session(handle) -> int:  # pragma: no cover - Windows only
    import ctypes

    sid = ctypes.c_ulong(0xFFFFFFFF)
    ok = ctypes.windll.kernel32.GetNamedPipeServerSessionId(int(handle), ctypes.byref(sid))  # type: ignore[attr-defined]
    return int(sid.value) if ok else -1


class ResilientTransport:  # pragma: no cover - Windows only
    """Reconnects once if the service restarted (for example during an update)."""

    def __init__(self, timeout: float) -> None:
        self.timeout = timeout
        self._t = PipeTransport(timeout)

    def call(self, op: str, args: dict | None = None, payload: bytes = b"") -> tuple[dict, bytes]:
        try:
            return self._t.call(op, args, payload)
        except ServiceError:
            raise
        except Exception:
            self._t.close()
            self._t = PipeTransport(max(self.timeout, 15.0))
            return self._t.call(op, args, payload)

    def close(self) -> None:
        self._t.close()


def service_installed() -> bool:
    """True for the Windows installer's build (the service program sits next to the app)."""
    return (
        bool(getattr(sys, "frozen", False)) and (Path(sys.executable).parent / "sentinel-vision-service.exe").exists()
    )


# why the last connect() failed ("" when it succeeded); "impostor" when a pipe not owned by a Windows service answered
last_problem = ""


def developer_mode() -> bool:
    """Developer switches (environment variables) only work when running from source, never in an installed build:
    any program running as the user can set environment variables (audit finding SV-F04)."""
    return not getattr(sys, "frozen", False)


def connect(timeout: float = 2.0, wait_for_start: bool = True):
    """A transport to the protection service, or None when it isn't installed/running (or not on Windows).

    When the service is installed but this returns None, the app runs in *degraded* mode (see core.Sentinel), never
    in the unprotected local mode."""
    global last_problem
    last_problem = ""
    if sys.platform != "win32":
        return None
    if developer_mode() and os.environ.get("SENTINEL_VISION_NO_SERVICE") == "1":
        return None
    if service_installed() and wait_for_start:
        timeout = max(timeout, 20.0)  # installed: it may still be starting (sign-in, just after an update)
    try:
        t = ResilientTransport(timeout)
        t.call("ping")
        return t
    except Exception as exc:
        last_problem = "impostor" if "not owned by a Windows service" in str(exc) else str(exc)
        log.warning("protection service not available: %s", exc)
        return None


# ---------------------------------------------------------------------------------------------- degraded mode
OFFLINE_MESSAGE = (
    "the protection service isn't reachable, so this can't be done right now (nothing is stored outside the "
    "protected storage)"
)


class OfflineQuarantine:
    """Stands in for the quarantine while the installed protection service can't be reached. Nothing is ever
    written to the user's own folder, where other programs could read or change it (audit finding SV-A01)."""

    def add(self, path, threat: str, engine: str):
        raise QuarantineError(OFFLINE_MESSAGE)

    def add_external(self, path, reason: str = "", source: str = DEFAULT_EXTERNAL_SOURCE) -> str:
        raise QuarantineError(OFFLINE_MESSAGE)

    def add_stream(self, fh, original_path: str, threat: str, engine: str):
        raise QuarantineError(OFFLINE_MESSAGE)

    def list(self) -> list:
        return []

    def get(self, item_id: str):
        raise QuarantineError(OFFLINE_MESSAGE)

    def iter_plain(self, item_id: str):
        raise QuarantineError(OFFLINE_MESSAGE)

    def restore(self, item_id: str, dest=None, overwrite: bool = False):
        raise QuarantineError(OFFLINE_MESSAGE)

    def delete(self, item_id: str) -> None:
        raise QuarantineError(OFFLINE_MESSAGE)

    def total_size(self) -> int:
        return 0


class OfflineVault(VaultFiles):
    """Stands in for the rollback vault while the protection service can't be reached: stores nothing."""

    def __init__(self) -> None:
        self.max_file = 50 * 1024 * 1024
        self.max_total = 0

    def eligible(self, path) -> bool:
        return False

    def snapshot(self, path, force: bool = False):
        return None

    def store(self, key: str, data: bytes, mtime: float, force: bool = False):
        return None

    def read(self, version_id: int):
        raise VaultError(OFFLINE_MESSAGE)

    def rollback_plan(self, since: float, folder_key: str = "") -> list:
        return []

    def versions(self, path) -> list:
        return []

    def files(self, limit: int = 5000) -> list:
        return []

    def stats(self) -> tuple[int, int, int]:
        return 0, 0, 0

    def used_bytes(self) -> int:
        return 0

    def restore(self, version_id: int, dest=None):
        raise VaultError(OFFLINE_MESSAGE)

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------------------------- vault
class RemoteVault(VaultFiles):
    """The rollback vault, stored by the protected service. Files are read and written here, as the user."""

    def __init__(self, transport, max_file_mb: int = 50) -> None:
        self.t = transport
        self.max_file = max_file_mb * 1024 * 1024
        self._max_total = 0

    @staticmethod
    def _v(d: dict | None) -> Version | None:
        return Version(**d) if d else None

    @property
    def max_total(self) -> int:
        if not self._max_total:
            self.stats()
        return self._max_total

    @max_total.setter
    def max_total(self, value: int) -> None:
        self._max_total = value  # the service applies the protected limit; this only mirrors it

    def store(self, key: str, data: bytes, mtime: float, force: bool = False) -> Version | None:
        if len(data) > self.max_file:
            return None
        # a forced copy (kept just before a restore overwrites a file) uses "preserve", which never evicts anything
        try:
            r, _ = self.t.call("vault.preserve" if force else "vault.store", {"key": key, "mtime": mtime}, data)
        except ServiceError as exc:
            raise VaultError(str(exc)) from exc
        return self._v(r["version"])

    def read(self, version_id: int) -> tuple[Version, bytes]:
        try:
            r, data = self.t.call("vault.read", {"id": int(version_id)})
        except ServiceError as exc:
            raise VaultError(str(exc)) from exc
        return Version(**r["version"]), data

    def get(self, version_id: int) -> Version:
        try:
            return Version(**self.t.call("vault.get", {"id": int(version_id)})[0]["version"])
        except ServiceError as exc:
            raise VaultError(str(exc)) from exc

    def versions(self, path: str | Path) -> list[Version]:
        return [Version(**v) for v in self.t.call("vault.versions", {"key": self._key(path)})[0]["versions"]]

    def files(self, limit: int = 5000) -> list[tuple[str, int, float]]:
        return [tuple(r) for r in self.t.call("vault.files", {"limit": limit})[0]["files"]]  # type: ignore[misc]

    def stats(self) -> tuple[int, int, int]:
        r = self.t.call("vault.stats")[0]
        self._max_total = int(r["max_total"])
        return tuple(r["stats"])  # type: ignore[return-value]

    def rollback_plan(self, since: float, folder_key: str = "") -> list[tuple[str, int | None]]:
        return [tuple(x) for x in self.t.call("vault.plan", {"since": since, "folder": folder_key})[0]["plan"]]  # type: ignore[misc]

    def used_bytes(self) -> int:
        return self.stats()[2]

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------------------------- quarantine
class RemoteQuarantine:
    """The quarantine, stored by the protected service (same interface as :class:`Quarantine`)."""

    def __init__(self, transport) -> None:
        self.t = transport

    def add(self, path: str | Path, threat: str, engine: str) -> QuarantineItem:
        src = Path(path)
        if not src.is_file() or src.is_symlink():
            raise QuarantineError(f"not a regular file: {src}")
        token = self.t.call(
            "quarantine.begin", {"original_path": str(src.resolve()), "threat": threat, "engine": engine}
        )[0]["token"]
        sha = hashlib.sha256()
        try:
            with open(src, "rb") as fh:
                while chunk := fh.read(UPLOAD_CHUNK):
                    sha.update(chunk)
                    self.t.call("quarantine.chunk", {"token": token}, chunk)
            item = QuarantineItem(
                **self.t.call("quarantine.commit", {"token": token, "sha256": sha.hexdigest()})[0]["item"]
            )
        except ServiceError as exc:
            try:
                self.t.call("quarantine.abort", {"token": token})
            except ServiceError:
                pass
            raise QuarantineError(str(exc)) from exc
        try:
            src.unlink()
        except OSError as exc:
            self.delete(item.id)
            raise QuarantineError(f"could not remove original file: {exc}") from exc
        return item

    def add_external(self, path: str | Path, reason: str = "", source: str = DEFAULT_EXTERNAL_SOURCE) -> str:
        """Quarantine a file another program found, into the protected store. Returns the id."""
        from sentinel_vision.quarantine import external_labels, external_target

        threat, engine = external_labels(reason, source)
        return self.add(external_target(path), threat, engine).id

    def list(self) -> list[QuarantineItem]:
        return [QuarantineItem(**d) for d in self.t.call("quarantine.list")[0]["items"]]

    def get(self, item_id: str) -> QuarantineItem:
        try:
            return QuarantineItem(**self.t.call("quarantine.get", {"id": item_id})[0]["item"])
        except ServiceError as exc:
            raise QuarantineError(str(exc)) from exc

    def _open(self, item_id: str) -> dict:
        from sentinel_vision.quarantine import QuarantineNeedsApproval

        try:
            return self.t.call("quarantine.open", {"id": item_id})[0]
        except ServiceError as exc:
            if exc.code == "elevation_required":
                raise QuarantineNeedsApproval(item_id, str(exc)) from exc
            raise QuarantineError(str(exc)) from exc

    def iter_plain(self, item_id: str, opened: dict | None = None):
        r = opened or self._open(item_id)
        token, expected = r["token"], r["item"]["sha256"]
        sha, offset = hashlib.sha256(), 0
        try:
            while True:
                meta, chunk = self.t.call("quarantine.read", {"token": token, "offset": offset})
                sha.update(chunk)
                offset += len(chunk)
                if meta["eof"]:
                    if sha.hexdigest() != expected:
                        raise QuarantineError("restored data does not match original hash")
                    yield chunk
                    return
                yield chunk
        finally:
            try:
                self.t.call("quarantine.close", {"token": token})
            except ServiceError:
                pass

    def restore(self, item_id: str, dest: str | Path | None = None, overwrite: bool = False) -> Path:
        from sentinel_vision.quarantine import write_restored

        item = self.get(item_id)
        target = restore_target(item, dest, overwrite)
        opened = self._open(item_id)  # before writing anything: may need administrator approval
        write_restored(self.iter_plain(item_id, opened), target)
        self.delete(item_id)
        return target

    def delete(self, item_id: str) -> None:
        try:
            self.t.call("quarantine.delete", {"id": item_id})
        except ServiceError as exc:
            raise QuarantineError(str(exc)) from exc

    def total_size(self) -> int:
        return sum(i.size for i in self.list())


# ---------------------------------------------------------------------------------------------- migration
def _unused_name(path: Path) -> Path:
    candidate, n = path, 1
    while candidate.exists():
        n += 1
        candidate = path.with_name(f"{path.name}-{n}")
    return candidate


def migrate_local_data(transport, local_vault_root: Path, local_quarantine_root: Path) -> tuple[int, int]:
    """Move a vault and quarantine kept in the user's own folder (older versions) into the protected service.
    Idempotent: each item is removed locally only after the service confirmed it. Returns (versions, items)."""
    from sentinel_vision.quarantine import Quarantine
    from sentinel_vision.vault import RollbackVault

    moved_v = moved_q = 0
    if (local_vault_root / "vault.key").exists():
        lv = RollbackVault(local_vault_root, max_file_mb=2048, max_total_mb=1 << 20)
        skipped = 0
        try:
            for v in lv.all_versions():
                try:
                    _, data = lv.read(v.id)
                except VaultError:
                    continue
                try:
                    transport.call("vault.preserve", {"key": v.path, "mtime": v.mtime}, data)
                except ServiceError as exc:  # e.g. a file outside today's protected folders: skipped
                    log.info("version of %s not moved: %s", v.path, exc)
                    skipped += 1
                    continue
                moved_v += 1
        finally:
            lv.close()
        if skipped:
            # never destroy versions the service didn't take: keep them, under a name that isn't migrated again
            kept = _unused_name(local_vault_root.with_name(local_vault_root.name + "-not-moved"))
            local_vault_root.rename(kept)
            log.warning(
                "%d document version(s) were not moved into protected storage; they are kept in %s", skipped, kept
            )
        else:
            _remove_tree(local_vault_root)
    if (local_quarantine_root / "vault.key").exists():
        lq = Quarantine(local_quarantine_root)
        rq = RemoteQuarantine(transport)
        for item in lq.list():
            token = transport.call(
                "quarantine.begin", {"original_path": item.original_path, "threat": item.threat, "engine": item.engine}
            )[0]["token"]
            try:
                for chunk in lq.iter_plain(item.id):
                    for i in range(0, len(chunk), UPLOAD_CHUNK):
                        transport.call("quarantine.chunk", {"token": token}, chunk[i : i + UPLOAD_CHUNK])
                transport.call("quarantine.commit", {"token": token, "sha256": item.sha256})
            except (QuarantineError, ServiceError) as exc:
                log.warning("could not move quarantined item %s: %s", item.id, exc)
                try:
                    transport.call("quarantine.abort", {"token": token})
                except ServiceError:
                    pass
                continue
            lq.delete(item.id)
            moved_q += 1
        if not lq.list():
            _remove_tree(local_quarantine_root)
        _ = rq
    return moved_v, moved_q


def _remove_tree(root: Path) -> None:
    import shutil

    shutil.rmtree(root, ignore_errors=True)


__all__ = [
    "LocalTransport",
    "PipeTransport",
    "RemoteQuarantine",
    "RemoteVault",
    "connect",
    "decode",
    "encode",
    "error_reply",
    "migrate_local_data",
    "O_BIN",
    "asdict",
]
