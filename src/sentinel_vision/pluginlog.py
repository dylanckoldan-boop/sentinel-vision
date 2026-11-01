"""Append-only, hash-chained record logs for plugins (for example Foldward's audit trail and revocation list).

On Windows with the protection service, each log is kept by the service in its protected folder
(``%ProgramData%\\SentinelVision\\Service\\users\\<account>\\plugins\\<name>\\log.jsonl``): a plugin running with the
user's rights can add records and read them back, but nothing running with the user's rights can change or delete
them. Elsewhere (macOS, Linux, the portable build) the same format is kept in the user's data folder, where it is
tamper-*evident* (the hash chain shows edits) but not tamper-proof.

Each line is one JSON object::

    {"seq": 1, "ts": 1792650000.0, "record": {...}, "prev": "<hash of entry seq-1>", "hash": "<sha256>"}

``hash`` is the SHA-256 of the entry without its ``hash`` field (keys sorted, compact separators), so removing,
reordering or editing any entry breaks the chain from that point on.

Any program running as the user can add records to any of the user's plugin logs, so a log can also be filled on
purpose to keep a plugin's later records out (INT-N01). The limit counts whole entries, :meth:`AppendOnlyLog.size`
tells how full a log is, and the protection service warns once a log passes ``WARN_SHARE`` of the limit.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
MAX_RECORD = 64 * 1024  # bytes of JSON per record
MAX_LOG = 50 * 1024 * 1024  # bytes per log, whole entries counted; appends are refused beyond this (nothing is dropped)
WARN_SHARE = 0.8  # a log this full is reported to the user (INT-N01)
MAX_READ = 1000
GENESIS = "0" * 64


class PluginLogError(ValueError):
    pass


def check_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise PluginLogError("plugin names are 1-40 lower-case letters, digits, - or _")
    return name


def entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def verify_chain(entries: list[dict], prev: str = GENESIS, first_seq: int = 1) -> bool:
    """True when ``entries`` form an unbroken chain starting after ``prev`` at ``first_seq``."""
    for i, e in enumerate(entries):
        if e.get("seq") != first_seq + i or e.get("prev") != prev or e.get("hash") != entry_hash(e):
            return False
        prev = e["hash"]
    return True


class AppendOnlyLog:
    """One log file. Thread-safe within a process; the service is the only writer of protected logs."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._tail: tuple[int, str] | None = None

    def _last(self) -> tuple[int, str]:
        if self._tail is None:
            seq, h = 0, GENESIS
            try:
                with open(self.path, "rb") as fh:
                    fh.seek(0, os.SEEK_END)
                    size = fh.tell()
                    fh.seek(max(0, size - 2 * MAX_RECORD - 4096))
                    lines = [ln for ln in fh.read().splitlines() if ln.strip()]
                if lines:
                    last = json.loads(lines[-1])
                    seq, h = int(last["seq"]), str(last["hash"])
            except FileNotFoundError:
                pass
            except (OSError, ValueError, KeyError) as exc:
                raise PluginLogError(f"log is damaged: {exc}") from exc
            self._tail = (seq, h)
        return self._tail

    def size(self) -> int:
        """How many bytes the log takes now (0 before its first record)."""
        try:
            return self.path.stat().st_size
        except FileNotFoundError:
            return 0

    def append(self, record: dict, **extra) -> dict:
        """Add a record. Returns its ``seq`` and ``hash`` and the log's size afterwards (``bytes``)."""
        if not isinstance(record, dict):
            raise PluginLogError("a record is a JSON object")
        try:
            size = len(json.dumps(record, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise PluginLogError(f"record is not JSON: {exc}") from exc
        if size > MAX_RECORD:
            raise PluginLogError(f"record is larger than {MAX_RECORD // 1024} KB")
        with self._lock:
            seq, prev = self._last()
            entry = {"seq": seq + 1, "ts": round(time.time(), 3), **extra, "record": record, "prev": prev}
            entry["hash"] = entry_hash(entry)
            line = (json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
            used = self.size()
            if used + len(line) > MAX_LOG:  # the whole entry counts, so a log never grows past the limit
                raise PluginLogError("log is full (50 MB); nothing was written")
            fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._tail = (entry["seq"], entry["hash"])
        return {"seq": entry["seq"], "hash": entry["hash"], "bytes": used + len(line)}

    def read(self, since: int = 0, limit: int = MAX_READ) -> list[dict]:
        limit = max(1, min(int(limit), MAX_READ))
        out: list[dict] = []
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    e = json.loads(line)
                    if e.get("seq", 0) > since:
                        out.append(e)
                        if len(out) >= limit:
                            break
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as exc:
            raise PluginLogError(f"log is damaged: {exc}") from exc
        return out

    def verify(self) -> tuple[bool, int]:
        """(chain intact, number of entries) for the whole log."""
        prev, seq = GENESIS, 0
        while True:
            batch = self.read(seq, MAX_READ)
            if not batch:
                return True, seq
            if not verify_chain(batch, prev, seq + 1):
                return False, seq
            prev, seq = batch[-1]["hash"], batch[-1]["seq"]
