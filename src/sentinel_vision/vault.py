"""Rollback vault: encrypted, versioned copies of your documents, for recovery after ransomware or mistakes.

Every time a document in a protected folder changes, its new content is stored (deduplicated by SHA-256 and
encrypted with AES-256-GCM, a 256-bit symmetric cipher that stays secure against quantum computers). If
ransomware encrypts your files, *Roll back* restores every file to its last good version from before the attack.

Content that already looks encrypted (a .docx that is no longer a zip archive, a text file full of random
bytes…) is never recorded as a "good" version, so an attack can't push the clean copies out of the vault.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sentinel_vision.config import sub_dir
from sentinel_vision.engines.heuristics import shannon_entropy

MAGIC = b"SVB1"
O_BIN = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)

# extension -> accepted leading bytes (None = text format, checked for readability instead)
FORMATS: dict[str, tuple[bytes, ...] | None] = {
    "docx": (b"PK\x03\x04",), "xlsx": (b"PK\x03\x04",), "pptx": (b"PK\x03\x04",), "odt": (b"PK\x03\x04",),
    "ods": (b"PK\x03\x04",), "odp": (b"PK\x03\x04",), "zip": (b"PK\x03\x04", b"PK\x05\x06"), "epub": (b"PK\x03\x04",),
    "docm": (b"PK\x03\x04",), "xlsm": (b"PK\x03\x04",), "pages": (b"PK\x03\x04",), "numbers": (b"PK\x03\x04",),
    "key": (b"PK\x03\x04",),
    "doc": (b"\xd0\xcf\x11\xe0",), "xls": (b"\xd0\xcf\x11\xe0",), "ppt": (b"\xd0\xcf\x11\xe0",),
    "pdf": (b"%PDF",), "png": (b"\x89PNG",), "jpg": (b"\xff\xd8\xff",), "jpeg": (b"\xff\xd8\xff",),
    "gif": (b"GIF8",), "bmp": (b"BM",), "tif": (b"II*\x00", b"MM\x00*"), "tiff": (b"II*\x00", b"MM\x00*"),
    "psd": (b"8BPS",), "heic": None, "webp": (b"RIFF",), "mp3": (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"),
    "wav": (b"RIFF",), "rtf": (b"{\\rtf",), "sqlite": (b"SQLite format 3\x00",), "7z": (b"7z\xbc\xaf\x27\x1c",),
    "txt": None, "csv": None, "md": None, "json": None, "xml": None, "html": None, "htm": None, "tex": None,
    "py": None, "js": None, "ts": None, "java": None, "c": None, "cpp": None, "h": None, "cs": None, "go": None,
    "rs": None, "rb": None, "php": None, "sql": None, "yaml": None, "yml": None, "ini": None, "log": None,
    "svg": None, "ipynb": None,
}  # fmt: skip
VERSIONED_EXT = frozenset(FORMATS) - {"heic"}


def extension(path: str | Path) -> str:
    name = Path(path).name.lower()
    return name.rsplit(".", 1)[-1] if "." in name else ""


def looks_encrypted(head: bytes, ext: str) -> bool:
    """True when content no longer matches its file type the way ransomware output doesn't."""
    if not head:
        return False
    fmt = FORMATS.get(ext, ...)
    if fmt is ...:
        return False
    if fmt is None:
        sample = head[:65536]
        if sample.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
            return False
        try:
            sample.decode("utf-8")
            return False
        except UnicodeDecodeError as exc:
            if exc.start >= len(sample) - 4:  # cut in the middle of a multi-byte character
                return False
        printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
        return printable / len(sample) < 0.7 and shannon_entropy(sample) > 6.5
    return not head.startswith(fmt)


@dataclass
class Version:
    id: int
    path: str
    sha256: str
    size: int
    mtime: float
    ts: float
    suspect: int = 0


SCHEMA = """
CREATE TABLE IF NOT EXISTS versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL, mtime REAL NOT NULL, ts REAL NOT NULL,
    suspect INTEGER NOT NULL DEFAULT 0  -- 1 = content looked encrypted (kept only so a restore can be undone)
);
CREATE INDEX IF NOT EXISTS versions_path ON versions(path, ts);
CREATE INDEX IF NOT EXISTS versions_sha ON versions(sha256);
CREATE INDEX IF NOT EXISTS versions_ts ON versions(ts);
"""


class VaultError(RuntimeError):
    pass


class RollbackVault:
    def __init__(
        self, root: Path | None = None, max_file_mb: int = 50, max_total_mb: int = 5120, keep_versions: int = 10
    ) -> None:
        self.root = root or sub_dir("vault")
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "blobs").mkdir(exist_ok=True)
        self.max_file = max_file_mb * 1024 * 1024
        self.max_total = max_total_mb * 1024 * 1024
        self.keep_versions = max(1, keep_versions)
        key_file = self.root / "vault.key"
        if not key_file.exists():
            fd = os.open(str(key_file), os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_BIN, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(AESGCM.generate_key(bit_length=256))
        key = key_file.read_bytes()
        if len(key) != 32:
            raise VaultError("vault key is corrupt")
        self._aes = AESGCM(key)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(self.root / "index.db"), check_same_thread=False, timeout=30)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ------------------------------------------------------------------ blobs
    def _blob(self, sha: str) -> Path:
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise VaultError("invalid content id")
        return self.root / "blobs" / sha[:2] / f"{sha}.svb"

    def _put_blob(self, sha: str, data: bytes) -> None:
        target = self._blob(sha)
        if target.exists():
            return
        target.parent.mkdir(exist_ok=True)
        nonce = secrets.token_bytes(12)
        blob = MAGIC + nonce + self._aes.encrypt(nonce, data, sha.encode())
        tmp = target.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_BIN, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        os.replace(tmp, target)

    def _get_blob(self, sha: str) -> bytes:
        try:
            blob = self._blob(sha).read_bytes()
        except OSError as exc:
            raise VaultError(f"stored copy is missing: {exc}") from exc
        if blob[:4] != MAGIC or len(blob) < 4 + 12 + 16:
            raise VaultError("stored copy has the wrong format")
        try:
            data = self._aes.decrypt(blob[4:16], blob[16:], sha.encode())
        except Exception as exc:
            raise VaultError("stored copy failed its integrity check") from exc
        if hashlib.sha256(data).hexdigest() != sha:
            raise VaultError("stored copy does not match its hash")
        return data

    # ------------------------------------------------------------------ snapshots
    @staticmethod
    def _key(path: str | Path) -> str:
        return os.path.normcase(os.path.abspath(str(path)))

    def eligible(self, path: str | Path) -> bool:
        return extension(path) in VERSIONED_EXT

    def snapshot(self, path: str | Path, force: bool = False) -> Version | None:
        """Store the current content of ``path`` if it changed. Returns the new version, or None.

        Content that looks encrypted is refused unless ``force`` (used to preserve the current file before a
        restore overwrites it)."""
        p = Path(path)
        try:
            st = p.stat()
        except OSError:
            return None
        if not p.is_file() or st.st_size > self.max_file or (not force and not self.eligible(p)):
            return None
        try:
            data = p.read_bytes()
        except OSError:
            return None
        suspect = looks_encrypted(data[:65536], extension(p))
        if suspect and not force:
            return None
        sha = hashlib.sha256(data).hexdigest()
        key = self._key(p)
        with self._lock:
            last = self._db.execute(
                "SELECT sha256 FROM versions WHERE path=? ORDER BY ts DESC, id DESC LIMIT 1", (key,)
            ).fetchone()
            if last and last[0] == sha:
                return None
            self._put_blob(sha, data)
            now = time.time()
            cur = self._db.execute(
                "INSERT INTO versions(path, sha256, size, mtime, ts, suspect) VALUES (?, ?, ?, ?, ?, ?)",
                (key, sha, len(data), st.st_mtime, now, int(suspect)),
            )
            self._db.commit()
            vid = int(cur.lastrowid)
            self._prune(key)
        return Version(vid, key, sha, len(data), st.st_mtime, now, int(suspect))

    def _prune(self, key: str | None = None) -> None:
        with self._lock:
            if key is not None:
                self._db.execute(
                    "DELETE FROM versions WHERE path=? AND id NOT IN "
                    "(SELECT id FROM versions WHERE path=? ORDER BY ts DESC, id DESC LIMIT ?)",
                    (key, key, self.keep_versions),
                )
            # total size: drop the oldest non-latest versions first
            while self.used_bytes() > self.max_total:
                row = self._db.execute(
                    "SELECT v.id FROM versions v WHERE v.id NOT IN "
                    "(SELECT MAX(id) FROM versions GROUP BY path) ORDER BY v.ts ASC LIMIT 1"
                ).fetchone()
                if not row:
                    break
                self._db.execute("DELETE FROM versions WHERE id=?", (row[0],))
            self._db.commit()
            self._gc()

    def _gc(self) -> None:
        live = {r[0] for r in self._db.execute("SELECT DISTINCT sha256 FROM versions")}
        for f in (self.root / "blobs").glob("*/*.svb"):
            if f.stem not in live:
                f.unlink(missing_ok=True)

    def used_bytes(self) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COALESCE(SUM(size), 0) FROM (SELECT DISTINCT sha256, size FROM versions)"
            ).fetchone()
        return int(row[0])

    # ------------------------------------------------------------------ queries
    def versions(self, path: str | Path) -> list[Version]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, path, sha256, size, mtime, ts, suspect FROM versions WHERE path=? "
                "ORDER BY ts DESC, id DESC",
                (self._key(path),),
            ).fetchall()
        return [Version(*r) for r in rows]

    def files(self, limit: int = 5000) -> list[tuple[str, int, float]]:
        """(path, number of versions, newest version time), newest first."""
        with self._lock:
            return self._db.execute(
                "SELECT path, COUNT(*), MAX(ts) FROM versions GROUP BY path ORDER BY MAX(ts) DESC LIMIT ?", (limit,)
            ).fetchall()

    def stats(self) -> tuple[int, int, int]:
        """(files, versions, bytes stored)"""
        with self._lock:
            files, versions = self._db.execute("SELECT COUNT(DISTINCT path), COUNT(*) FROM versions").fetchone()
        return int(files), int(versions), self.used_bytes()

    def get(self, version_id: int) -> Version:
        with self._lock:
            row = self._db.execute(
                "SELECT id, path, sha256, size, mtime, ts, suspect FROM versions WHERE id=?", (int(version_id),)
            ).fetchone()
        if not row:
            raise VaultError("unknown version")
        return Version(*row)

    # ------------------------------------------------------------------ restore
    def restore(self, version_id: int, dest: str | Path | None = None) -> Path:
        """Write a stored version back. The file it replaces is kept in the vault first, so a restore can be
        undone."""
        v = self.get(version_id)
        data = self._get_blob(v.sha256)
        target = Path(dest) if dest else Path(v.path)
        if target.is_dir():
            target = target / Path(v.path).name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            self.snapshot(target, force=True)
        tmp = target.with_name(f".{target.name}.svrestore")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_BIN, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, target)
        try:
            os.utime(target, (v.mtime, v.mtime))
        except OSError:
            pass
        return target

    def rollback(self, since: float, folder: str | Path | None = None) -> list[tuple[str, str]]:
        """Restore every file changed at or after ``since`` (optionally only inside ``folder``) to its newest
        good version from before ``since``. Returns (path, result) pairs."""
        prefix = self._key(folder).rstrip(os.sep) + os.sep if folder else ""
        with self._lock:
            changed = [r[0] for r in self._db.execute("SELECT DISTINCT path FROM versions WHERE ts >= ?", (since,))]
        results: list[tuple[str, str]] = []
        for path in sorted(changed):
            if prefix and not path.startswith(prefix):
                continue
            with self._lock:
                row = self._db.execute(
                    "SELECT id FROM versions WHERE path=? AND ts < ? AND suspect=0 ORDER BY ts DESC, id DESC LIMIT 1",
                    (path, since),
                ).fetchone()
            if not row:
                results.append((path, "no earlier version"))
                continue
            try:
                self.restore(row[0])
                results.append((path, "restored"))
            except (OSError, VaultError) as exc:
                results.append((path, f"failed: {exc}"))
        return results

    def restore_latest_good(self, paths: list[str]) -> list[tuple[str, str]]:
        """Restore each path to its newest stored version (used after an attack was detected)."""
        out = []
        for p in paths:
            vs = [v for v in self.versions(p) if not v.suspect]
            if not vs:
                out.append((p, "no stored version"))
                continue
            try:
                self.restore(vs[0].id)
                out.append((p, "restored"))
            except (OSError, VaultError) as exc:
                out.append((p, f"failed: {exc}"))
        return out
