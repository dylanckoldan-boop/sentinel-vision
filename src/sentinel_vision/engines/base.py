"""Shared types for detection engines."""

from __future__ import annotations

import hashlib
import io
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

CHUNK = 1024 * 1024
HEAD_BYTES = 8 * 1024 * 1024  # heuristics look at the first 8 MiB


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass
class Detection:
    engine: str
    name: str
    severity: Severity
    description: str = ""
    details: dict = field(default_factory=dict)

    @property
    def is_signature(self) -> bool:
        """Signature-grade (as opposed to purely heuristic) detections may be auto-quarantined."""
        if self.details.get("report_only"):
            return False
        return self.engine in {"hash", "clamav", "cloud"} or (self.engine == "yara" and self.severity >= Severity.HIGH)


class ScanObject:
    """A thing to scan: a file on disk, or bytes pulled out of an archive.

    Hashes are computed once in a single streaming pass and shared by all engines.
    """

    def __init__(self, display_path: str, fs_path: Path | None = None, data: bytes | None = None) -> None:
        if (fs_path is None) == (data is None):
            raise ValueError("exactly one of fs_path or data is required")
        self.display_path = display_path
        self.fs_path = fs_path
        self.data = data
        self.size = len(data) if data is not None else fs_path.stat().st_size  # type: ignore[union-attr]
        self._head: bytes | None = None
        self.md5 = self.sha1 = self.sha256 = ""
        self._hash()

    @property
    def name(self) -> str:
        return self.display_path.replace("\\", "/").rsplit("/", 1)[-1].split("!")[-1]

    def _hash(self) -> None:
        md5, sha1, sha256 = hashlib.md5(usedforsecurity=False), hashlib.sha1(usedforsecurity=False), hashlib.sha256()
        head = bytearray()
        for chunk in self.iter_chunks():
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            if len(head) < HEAD_BYTES:
                head += chunk[: HEAD_BYTES - len(head)]
        self.md5, self.sha1, self.sha256 = md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
        self._head = bytes(head)

    def iter_chunks(self) -> Iterator[bytes]:
        if self.data is not None:
            for i in range(0, len(self.data), CHUNK):
                yield self.data[i : i + CHUNK]
            return
        with open(self.fs_path, "rb") as fh:  # type: ignore[arg-type]
            while chunk := fh.read(CHUNK):
                yield chunk

    @property
    def head(self) -> bytes:
        return self._head or b""

    def read_all(self, limit: int) -> bytes:
        if self.data is not None:
            return self.data[:limit]
        with open(self.fs_path, "rb") as fh:  # type: ignore[arg-type]
            return fh.read(limit)

    def open(self) -> io.BufferedIOBase:
        if self.data is not None:
            return io.BytesIO(self.data)
        return open(self.fs_path, "rb")  # type: ignore[arg-type]


class Engine(ABC):
    name: str = "engine"
    label: str = "Engine"

    @abstractmethod
    def available(self) -> bool: ...

    @abstractmethod
    def scan(self, obj: ScanObject) -> list[Detection]: ...

    def status(self) -> str:
        return "ready" if self.available() else "unavailable"

    def reload(self) -> None:
        """Called after signature updates."""
