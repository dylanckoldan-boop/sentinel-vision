"""Encrypted quarantine vault.

Quarantined files are encrypted with AES-256-GCM so they can never be executed, opened by accident,
or re-detected by other security software. Data is processed in 1 MiB chunks; each chunk's nonce and
associated data bind it to its position and to the end of the stream, so chunks cannot be reordered,
dropped or truncated without detection. Restores are verified against the original SHA-256.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import struct
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sentinel_vision.config import sub_dir

MAGIC = b"SVQ1"
CHUNK = 1024 * 1024
O_BIN = getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)


class QuarantineError(RuntimeError):
    pass


class QuarantineNeedsApproval(QuarantineError):
    """Restoring this item needs administrator approval (Windows protection service, audit finding SV-A04)."""

    def __init__(self, item_id: str, message: str) -> None:
        super().__init__(message)
        self.item_id = item_id


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    sha256: str
    size: int
    threat: str
    engine: str
    ts: float

    @property
    def vault_file(self) -> Path:
        return sub_dir("quarantine") / f"{self.id}.svq"


# ---------------------------------------------------------------------------------------------- external requests
EXTERNAL_SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,39}$")
# the companion program that asks by default (Foldward, formerly Agent Guard; older items say "agent-guard")
DEFAULT_EXTERNAL_SOURCE = "foldward"


def external_labels(reason: str, source: str) -> tuple[str, str]:
    """(threat, engine) recorded for a file another program asked to quarantine (for example Foldward)."""
    if not EXTERNAL_SOURCE_RE.match(source or ""):
        raise QuarantineError("source must be a short lower-case name (letters, digits, . _ -)")
    text = " ".join(str(reason or "").split())[:200]
    return (text or f"Sent to quarantine by {source}"), f"external:{source}"


def external_target(path: str | Path) -> Path:
    """The file another program asked to quarantine, after checks: an existing regular file (not a link), not part
    of the operating system, and not part of Sentinel Vision itself (its program or its data)."""
    from sentinel_vision.config import data_dir
    from sentinel_vision.scanner import is_system_path

    src = Path(path)
    if src.is_symlink() or not src.is_file():
        raise QuarantineError(f"not an existing regular file: {src}")
    full = src.resolve()
    if is_system_path(str(full)):
        raise QuarantineError("operating-system files are never quarantined on request")
    own = [data_dir().resolve()]
    if getattr(sys, "frozen", False):
        own.append(Path(sys.executable).resolve().parent)
    if any(full == d or d in full.parents for d in own):
        raise QuarantineError("Sentinel Vision's own files can't be quarantined")
    return full


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_BIN, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


class Quarantine:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or sub_dir("quarantine")
        self.root.mkdir(parents=True, exist_ok=True)
        key_file = self.root / "vault.key"
        if not key_file.exists():
            _write_private(key_file, AESGCM.generate_key(bit_length=256))
        key = key_file.read_bytes()
        if len(key) != 32:
            raise QuarantineError("quarantine key is corrupt")
        self._aes = AESGCM(key)

    # ------------------------------------------------------------------ helpers
    def _meta_path(self, item_id: str) -> Path:
        return self.root / f"{item_id}.json"

    def _vault_path(self, item_id: str) -> Path:
        return self.root / f"{item_id}.svq"

    @staticmethod
    def _nonce(prefix: bytes, index: int) -> bytes:
        return prefix + struct.pack(">I", index)

    # ------------------------------------------------------------------ public API
    def add(self, path: str | Path, threat: str, engine: str) -> QuarantineItem:
        """Encrypt ``path`` into the vault, then remove the original."""
        src = Path(path)
        if not src.is_file() or src.is_symlink():
            raise QuarantineError(f"not a regular file: {src}")
        with open(src, "rb") as fh:
            item = self.add_stream(fh, str(src.resolve()), threat, engine)
        try:
            src.unlink()
        except OSError as exc:
            # Could not remove the original (locked / permissions): roll back so state stays honest.
            self.delete(item.id)
            raise QuarantineError(f"could not remove original file: {exc}") from exc
        return item

    def add_external(self, path: str | Path, reason: str = "", source: str = DEFAULT_EXTERNAL_SOURCE) -> str:
        """Quarantine a file another program found (moved: encrypted here, original removed). Returns the id."""
        threat, engine = external_labels(reason, source)
        return self.add(external_target(path), threat, engine).id

    def add_stream(self, fh, original_path: str, threat: str, engine: str) -> QuarantineItem:
        """Encrypt the content read from ``fh`` into the vault (the caller removes the original)."""
        item_id = uuid.uuid4().hex
        prefix = secrets.token_bytes(8)
        sha = hashlib.sha256()
        size = 0
        vault = self._vault_path(item_id)
        fd = os.open(str(vault), os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_BIN, 0o600)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(MAGIC + prefix)
                index = 0
                chunk = fh.read(CHUNK)
                while True:
                    nxt = fh.read(CHUNK)
                    final = not nxt
                    sha.update(chunk)
                    size += len(chunk)
                    aad = item_id.encode() + struct.pack(">I?", index, final)
                    ct = self._aes.encrypt(self._nonce(prefix, index), chunk, aad)
                    out.write(struct.pack(">I?", len(ct), final) + ct)
                    if final:
                        break
                    chunk, index = nxt, index + 1
        except Exception:
            vault.unlink(missing_ok=True)
            raise
        item = QuarantineItem(item_id, original_path, sha.hexdigest(), size, str(threat), str(engine), time.time())
        _write_private(self._meta_path(item_id), json.dumps(asdict(item), indent=2).encode())
        return item

    def list(self) -> list[QuarantineItem]:
        items = []
        for meta in self.root.glob("*.json"):
            try:
                d = json.loads(meta.read_text(encoding="utf-8"))
                items.append(QuarantineItem(**d))
            except (OSError, ValueError, TypeError):
                continue
        return sorted(items, key=lambda i: i.ts, reverse=True)

    def get(self, item_id: str) -> QuarantineItem:
        if not item_id.isalnum():
            raise QuarantineError("invalid id")
        try:
            return QuarantineItem(**json.loads(self._meta_path(item_id).read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError) as exc:
            raise QuarantineError(f"unknown quarantine item {item_id}") from exc

    def iter_plain(self, item_id: str):
        """Decrypted content of an item, chunk by chunk; raises QuarantineError on any tampering. The final
        chunk is only yielded after the whole stream and the original SHA-256 have been verified."""
        item = self.get(item_id)
        sha = hashlib.sha256()
        with open(self._vault_path(item.id), "rb") as fh:
            if fh.read(4) != MAGIC:
                raise QuarantineError("vault file has wrong format")
            prefix = fh.read(8)
            index, final = 0, False
            while not final:
                hdr = fh.read(5)
                if len(hdr) != 5:
                    raise QuarantineError("vault file is truncated")
                n, final = struct.unpack(">I?", hdr)  # `final` is authenticated through the AAD below
                ct = fh.read(n)
                if len(ct) != n:
                    raise QuarantineError("vault file is truncated")
                try:
                    pt = self._aes.decrypt(
                        self._nonce(prefix, index), ct, item.id.encode() + struct.pack(">I?", index, final)
                    )
                except Exception as exc:
                    raise QuarantineError("vault file failed integrity check") from exc
                sha.update(pt)
                if final:
                    if fh.read(1):
                        raise QuarantineError("unexpected data after end of vault stream")
                    if sha.hexdigest() != item.sha256:
                        raise QuarantineError("restored data does not match original hash")
                yield pt
                index += 1

    def _decrypt_to(self, item: QuarantineItem, dest: Path) -> None:
        write_restored(self.iter_plain(item.id), dest)

    def restore(self, item_id: str, dest: str | Path | None = None, overwrite: bool = False) -> Path:
        """Decrypt an item back to disk (original location by default). Returns the restored path."""
        item = self.get(item_id)
        target = restore_target(item, dest, overwrite)
        self._decrypt_to(item, target)
        self.delete(item_id)
        return target

    def delete(self, item_id: str) -> None:
        self.get(item_id)
        self._vault_path(item_id).unlink(missing_ok=True)
        self._meta_path(item_id).unlink(missing_ok=True)

    def total_size(self) -> int:
        return sum(i.size for i in self.list())


def restore_target(item: QuarantineItem, dest: str | Path | None, overwrite: bool) -> Path:
    target = Path(dest) if dest else Path(item.original_path)
    if target.is_dir():
        target = target / Path(item.original_path).name
    if not target.parent.is_dir():
        raise QuarantineError(f"destination folder does not exist: {target.parent}")
    if target.exists() and not overwrite:
        stem, suffix, n = target.stem, target.suffix, 1
        while target.exists():
            target = target.with_name(f"{stem} (restored {n}){suffix}")
            n += 1
    return target


def write_restored(chunks, dest: Path) -> None:
    """Write verified chunks to ``dest`` atomically (nothing is left behind if verification fails)."""
    tmp = dest.with_name(f".{dest.name}.svrestore")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_BIN, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            for chunk in chunks:
                out.write(chunk)
        os.replace(tmp, dest)
    finally:
        if tmp.exists():
            tmp.unlink()
