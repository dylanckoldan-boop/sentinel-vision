"""SQLite storage: hash signatures, detection history, event log, scan cache."""

from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from sentinel_vision.config import data_dir

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS hashes (
    hash   TEXT PRIMARY KEY,         -- lowercase hex (md5, sha1 or sha256)
    name   TEXT NOT NULL,
    source TEXT NOT NULL,
    added  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS detections (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       REAL NOT NULL,
    path     TEXT NOT NULL,
    sha256   TEXT,
    engine   TEXT NOT NULL,
    name     TEXT NOT NULL,
    severity INTEGER NOT NULL,
    action   TEXT NOT NULL,
    origin   TEXT NOT NULL            -- scan | realtime | process | network
);
CREATE INDEX IF NOT EXISTS detections_ts ON detections(ts);
CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    level   TEXT NOT NULL,
    kind    TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE TABLE IF NOT EXISTS scan_cache (
    path    TEXT PRIMARY KEY,
    size    INTEGER NOT NULL,
    mtime   REAL NOT NULL,
    sha256  TEXT NOT NULL,
    sigver  INTEGER NOT NULL
);
"""


@dataclass
class DetectionRow:
    id: int
    ts: float
    path: str
    sha256: str | None
    engine: str
    name: str
    severity: int
    action: str
    origin: str


class Database:
    """Thread-safe wrapper. One connection guarded by a lock keeps things simple and correct."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (data_dir() / "sentinel.db")
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ meta
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, value))
            self._conn.commit()

    @property
    def signature_version(self) -> int:
        return int(self.get_meta("sigver", "1") or 1)

    def bump_signature_version(self) -> int:
        v = self.signature_version + 1
        self.set_meta("sigver", str(v))
        return v

    # ------------------------------------------------------------------ hashes
    def lookup_hashes(self, hashes: Iterable[str]) -> tuple[str, str, str] | None:
        """Return (hash, name, source) for the first hash found in the blocklist."""
        hs = [h.lower() for h in hashes if h]
        if not hs:
            return None
        placeholders = ",".join("?" * len(hs))  # only "?" markers are interpolated; values are bound
        q = f"SELECT hash, name, source FROM hashes WHERE hash IN ({placeholders}) LIMIT 1"  # noqa: S608
        with self._lock:
            row = self._conn.execute(q, hs).fetchone()
        return tuple(row) if row else None  # type: ignore[return-value]

    def add_hashes(self, rows: Iterable[tuple[str, str]], source: str) -> int:
        now = time.time()
        data = [(h.lower(), name or "Malware.Generic", source, now) for h, name in rows]
        with self._lock:
            before = self._conn.total_changes
            self._conn.executemany("INSERT OR IGNORE INTO hashes(hash, name, source, added) VALUES (?, ?, ?, ?)", data)
            self._conn.commit()
            return self._conn.total_changes - before

    def hash_count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM hashes").fetchone()[0]

    # ------------------------------------------------------------------ detections
    def add_detection(
        self, path: str, sha256: str | None, engine: str, name: str, severity: int, action: str, origin: str
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO detections(ts, path, sha256, engine, name, severity, action, origin)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (time.time(), path, sha256, engine, name, int(severity), action, origin),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def recent_detections(self, limit: int = 500) -> list[DetectionRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, ts, path, sha256, engine, name, severity, action, origin"
                " FROM detections ORDER BY ts DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [DetectionRow(*r) for r in rows]

    def detection_count(self, since: float = 0) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(DISTINCT path) FROM detections WHERE ts >= ?", (since,)).fetchone()[
                0
            ]

    def clear_detections(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM detections")
            self._conn.commit()

    # ------------------------------------------------------------------ events
    def log_event(self, kind: str, message: str, level: str = "info") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events(ts, level, kind, message) VALUES (?, ?, ?, ?)",
                (time.time(), level, kind, message),
            )
            # keep the log bounded
            self._conn.execute("DELETE FROM events WHERE id <= (SELECT MAX(id) - 20000 FROM events)")
            self._conn.commit()

    def recent_events(self, limit: int = 500) -> list[tuple[float, str, str, str]]:
        with self._lock:
            return self._conn.execute(
                "SELECT ts, level, kind, message FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    # ------------------------------------------------------------------ scan cache
    def cache_get(self, path: str, size: int, mtime: float) -> str | None:
        """Return the sha256 of a file that was clean under the current signatures, if unchanged."""
        with self._lock:
            row = self._conn.execute(
                "SELECT sha256 FROM scan_cache WHERE path=? AND size=? AND mtime=? AND sigver=?",
                (path, size, mtime, self.signature_version),
            ).fetchone()
        return row[0] if row else None

    def cache_put(self, path: str, size: int, mtime: float, sha256: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO scan_cache(path, size, mtime, sha256, sigver) VALUES (?, ?, ?, ?, ?)",
                (path, size, mtime, sha256, self.signature_version),
            )
            self._conn.commit()

    def cache_drop(self, path: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM scan_cache WHERE path=?", (path,))
            self._conn.commit()
