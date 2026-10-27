"""Rollback vault: encrypted, versioned copies of your documents, for recovery after ransomware or mistakes.

Every time a document in a protected folder changes, its new content is stored (deduplicated by SHA-256 and
encrypted with AES-256-GCM, a 256-bit symmetric cipher that stays secure against quantum computers). If
ransomware encrypts your files, *Roll back* restores every file to its last good version from before the attack.

Content that already looks encrypted (a .docx that is no longer a zip archive, a text file full of random
bytes…) is never recorded as a "good" version, so an attack can't push the clean copies out of the vault.
"""

from __future__ import annotations

import hashlib
import logging
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

log = logging.getLogger(__name__)
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


ZIP_EXT = frozenset(e for e, m in FORMATS.items() if m and m[0] == b"PK\x03\x04")
SAMPLE = 4096


def _text_scrambled(block: bytes) -> bool:
    if len(block) < 512:
        return False
    try:
        block.decode("utf-8")
        return False
    except UnicodeDecodeError as exc:
        if exc.start >= len(block) - 4:
            return False
    printable = sum(1 for b in block if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(block) < 0.7 and shannon_entropy(block) > 6.5


def damaged(head: bytes, mid: bytes, tail: bytes, ext: str) -> bool:
    """Like :func:`looks_encrypted`, but also catches ransomware that leaves the start of a file intact and encrypts
    only parts of it ("intermittent encryption"): the end of a zip-based document must still hold its central
    directory, a PDF must still end with %%EOF, a PNG with IEND, and text must stay text throughout."""
    if looks_encrypted(head, ext):
        return True
    if not head or not tail:
        return False
    if ext in ZIP_EXT:
        return b"PK\x05\x06" not in tail  # end-of-central-directory record
    if ext == "pdf":
        return b"%%EOF" not in tail
    if ext == "png":
        return b"IEND" not in tail[-64:]
    if FORMATS.get(ext, ...) is None and ext in FORMATS:
        return _text_scrambled(mid) or _text_scrambled(tail)
    return False


def sample_file(path: str | Path, head_size: int = 65536) -> tuple[bytes, bytes, bytes]:
    """Start, middle and end of a file (tail covers a zip comment of up to 64 KB)."""
    with open(path, "rb") as fh:
        head = fh.read(head_size)
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        if size <= head_size:
            return head, head[len(head) // 2 : len(head) // 2 + SAMPLE], head[-66000:]
        fh.seek(size // 2)
        mid = fh.read(SAMPLE)
        fh.seek(max(0, size - 66000))
        tail = fh.read()
    return head, mid, tail


def damaged_bytes(data: bytes, ext: str) -> bool:
    n = len(data)
    return damaged(data[:65536], data[n // 2 : n // 2 + SAMPLE], data[-66000:], ext)


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


class VaultRefused(VaultError):
    """A new version was refused to protect the ones already stored (vault full of young versions, or far more
    new versions than any person makes: possible flooding by ransomware)."""


# Retention (audit finding SV-A02): a flood of junk versions must never push out good ones.
KEEP_ALL_SECONDS = 24 * 3600  # every version younger than this is kept, whatever happens
HOURLY_UNTIL = 7 * 24 * 3600  # then one per hour for a week
DAILY_UNTIL = 30 * 24 * 3600  # then one per day for 30 days (older ones go, except a file's newest version)
FILE_RATE = 30  # new versions per file per hour
ACCOUNT_RATE = 2000  # new versions per account (vault) per hour, of files already in the vault
FIRST_RATE = 50_000  # first versions of files per hour (these can't push anything out; the start-up pass uses them)


def _is_link(p: Path) -> bool:
    """A symbolic link, or on Windows a junction or other reparse point."""
    try:
        if p.is_symlink():
            return True
        return bool(getattr(os.lstat(p), "st_file_attributes", 0) & 0x400)
    except OSError:
        return False


class VaultFiles:
    """File-level operations (snapshot, restore, rollback) on top of a storage back end.

    The back end is either :class:`RollbackVault` (local storage) or the protected Windows service
    (``service_client.RemoteVault``). Files are always read and written here, by the user's own process: the
    service only stores and returns bytes, so it can never be used to write into places the user can't.
    """

    max_file: int
    max_total: int

    # storage back end ------------------------------------------------------------------------------------
    def store(self, key: str, data: bytes, mtime: float, force: bool = False) -> Version | None:  # pragma: no cover
        raise NotImplementedError

    def read(self, version_id: int) -> tuple[Version, bytes]:  # pragma: no cover
        raise NotImplementedError

    def rollback_plan(self, since: float, folder_key: str = "") -> list[tuple[str, int | None]]:  # pragma: no cover
        raise NotImplementedError

    def versions(self, path: str | Path) -> list[Version]:  # pragma: no cover
        raise NotImplementedError

    # file operations -------------------------------------------------------------------------------------
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
        return self.store(self._key(p), data, st.st_mtime, force)

    # folders a restore to the original place may write into (set by the app: the protected folders); None = any
    allowed_roots = None

    def restore(self, version_id: int, dest: str | Path | None = None) -> Path:
        """Write a stored version back. The file it replaces is kept in the vault first, so a restore can be
        undone. Never writes through a link or junction; without a destination the user chose, only inside the
        protected folders (audit finding SV-F02)."""
        v, data = self.read(version_id)
        target = Path(dest) if dest else Path(v.path)
        if target.is_dir() and not _is_link(target):
            target = target / Path(v.path).name
        target = Path(os.path.abspath(target))
        if dest is None and self.allowed_roots is not None:
            roots = [os.path.normcase(os.path.abspath(r)) for r in self.allowed_roots() if r]
            norm = os.path.normcase(str(target))
            if not any(norm.startswith(r.rstrip(os.sep) + os.sep) for r in roots):
                raise VaultError(f"{target} is outside your protected folders; choose where to restore it instead")
        for p in [target, *target.parents]:
            if _is_link(p):
                raise VaultError(f"{p} is a link or junction, so nothing is restored through it")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            try:
                self.snapshot(target, force=True)
            except VaultError as exc:  # e.g. outside the protected folders, or the vault is full
                log.warning("current %s not kept before restoring: %s", target, exc)
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
        results: list[tuple[str, str]] = []
        for path, vid in self.rollback_plan(since, self._key(folder) if folder else ""):
            if vid is None:
                results.append((path, "no earlier version"))
                continue
            try:
                self.restore(vid)
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


class RollbackVault(VaultFiles):
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
        self._recent: dict[str, list[float]] = {}  # key -> times of new versions in the last hour
        self._recent_all: list[float] = []
        self._recent_first: list[float] = []
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

    # ------------------------------------------------------------------ storage
    def store(self, key: str, data: bytes, mtime: float, force: bool = False, preserve: bool = False) -> Version | None:
        """Keep ``data`` as the newest version of ``key`` (a normalised path) unless it is unchanged, too large, or
        looks encrypted (refused unless ``force``).

        ``preserve`` (the copy kept just before a restore overwrites a file) never removes anything to make room.
        Raises :class:`VaultRefused` instead of removing young versions (see the retention constants)."""
        if len(data) > self.max_file:
            return None
        suspect = damaged_bytes(data, extension(key))
        if suspect and not force:
            return None
        sha = hashlib.sha256(data).hexdigest()
        with self._lock:
            last = self._db.execute(
                "SELECT sha256 FROM versions WHERE path=? ORDER BY ts DESC, id DESC LIMIT 1", (key,)
            ).fetchone()
            if last and last[0] == sha:
                return None
            now = time.time()
            self._check_rate(key, now, first=last is None)
            if not self._db.execute("SELECT 1 FROM versions WHERE sha256=? LIMIT 1", (sha,)).fetchone():
                fits = self.used_bytes() + len(data) <= self.max_total
                if not fits and (preserve or not self._make_room(len(data), now)):
                    raise VaultRefused(
                        "the rollback vault is full of recent versions; this version was not kept (nothing was "
                        "removed). Raise the vault size limit or check for a program changing many files."
                    )
            self._put_blob(sha, data)
            cur = self._db.execute(
                "INSERT INTO versions(path, sha256, size, mtime, ts, suspect) VALUES (?, ?, ?, ?, ?, ?)",
                (key, sha, len(data), float(mtime), now, int(suspect)),
            )
            self._db.commit()
            self._recent.setdefault(key, []).append(now)
            (self._recent_first if last is None else self._recent_all).append(now)
            vid = int(cur.lastrowid)
            if not preserve:
                self._thin(key, now)
        return Version(vid, key, sha, len(data), float(mtime), now, int(suspect))

    def _check_rate(self, key: str, now: float, first: bool = False) -> None:
        hour = now - 3600
        self._recent[key] = recent = [t for t in self._recent.get(key, []) if t > hour]
        self._recent_all = [t for t in self._recent_all if t > hour]
        self._recent_first = [t for t in self._recent_first if t > hour]
        if first:
            if len(self._recent_first) >= FIRST_RATE:
                raise VaultRefused(f"more than {FIRST_RATE} new files in an hour (possible vault flooding)")
            return
        if len(recent) >= FILE_RATE:
            raise VaultRefused(f"more than {FILE_RATE} new versions of this file in an hour (possible vault flooding)")
        if len(self._recent_all) >= ACCOUNT_RATE:
            raise VaultRefused(f"more than {ACCOUNT_RATE} new versions in an hour (possible vault flooding)")

    def _thin(self, key: str, now: float) -> None:
        """Age-based retention for one file: everything from the last 24 hours; then the newest version of each
        hour for a week and of each day for 30 days, at most ``keep_versions`` of those; never the newest one."""
        rows = self._db.execute("SELECT id, ts FROM versions WHERE path=? ORDER BY ts DESC, id DESC", (key,)).fetchall()
        drop, buckets, old_kept = [], set(), 0
        for i, (vid, ts) in enumerate(rows):
            age = now - ts
            if i == 0 or age < KEEP_ALL_SECONDS:
                continue
            bucket = ("h", int(ts // 3600)) if age < HOURLY_UNTIL else ("d", int(ts // 86400))
            if age >= DAILY_UNTIL or bucket in buckets or old_kept >= self.keep_versions:
                drop.append(vid)
                continue
            buckets.add(bucket)
            old_kept += 1
        if drop:
            self._db.executemany("DELETE FROM versions WHERE id=?", [(d,) for d in drop])
            self._db.commit()
            self._gc()

    def _make_room(self, size: int, now: float) -> bool:
        """Make room for ``size`` more bytes by removing versions older than 24 hours (suspect ones first, then
        the oldest), never a file's newest version. False when that isn't enough (young versions are never
        removed)."""
        rows = self._db.execute(
            "SELECT id FROM versions WHERE ts < ? AND id NOT IN (SELECT MAX(id) FROM versions GROUP BY path) "
            "ORDER BY suspect DESC, ts ASC",
            (now - KEEP_ALL_SECONDS,),
        ).fetchall()
        for (vid,) in rows:
            if self.used_bytes() + size <= self.max_total:
                break
            self._db.execute("DELETE FROM versions WHERE id=?", (vid,))
        self._db.commit()
        self._gc()
        return self.used_bytes() + size <= self.max_total

    def read(self, version_id: int) -> tuple[Version, bytes]:
        v = self.get(version_id)
        return v, self._get_blob(v.sha256)

    def rollback_plan(self, since: float, folder_key: str = "") -> list[tuple[str, int | None]]:
        prefix = folder_key.rstrip(os.sep) + os.sep if folder_key else ""
        with self._lock:
            changed = [r[0] for r in self._db.execute("SELECT DISTINCT path FROM versions WHERE ts >= ?", (since,))]
            plan: list[tuple[str, int | None]] = []
            for path in sorted(changed):
                if prefix and not path.startswith(prefix):
                    continue
                row = self._db.execute(
                    "SELECT id FROM versions WHERE path=? AND ts < ? AND suspect=0 ORDER BY ts DESC, id DESC LIMIT 1",
                    (path, since),
                ).fetchone()
                plan.append((path, int(row[0]) if row else None))
        return plan

    def all_versions(self) -> list[Version]:
        """Every stored version, oldest first (used to move a local vault into the protected service)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, path, sha256, size, mtime, ts, suspect FROM versions ORDER BY ts ASC, id ASC"
            ).fetchall()
        return [Version(*r) for r in rows]

    def _prune(self, key: str | None = None) -> None:
        """Apply retention (after the size limit or the versions setting changed)."""
        with self._lock:
            now = time.time()
            keys = [key] if key else [r[0] for r in self._db.execute("SELECT DISTINCT path FROM versions")]
            for k in keys:
                self._thin(k, now)
            if self.used_bytes() > self.max_total:
                self._make_room(0, now)

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
