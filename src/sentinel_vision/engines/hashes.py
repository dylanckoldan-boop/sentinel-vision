"""Exact-match hash blocklist (MD5 / SHA-1 / SHA-256) backed by SQLite."""

from __future__ import annotations

from sentinel_vision.db import Database
from sentinel_vision.engines.base import Detection, Engine, ScanObject, Severity

# The EICAR anti-malware test file (harmless, industry-standard test string).
BUILTIN_HASHES: list[tuple[str, str]] = [
    ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Test-File"),
    ("3395856ce81f2b7382dee72602f798b642f14140", "EICAR-Test-File"),
    ("44d88612fea8a8f36de82e1278abb02f", "EICAR-Test-File"),
]


class HashEngine(Engine):
    name = "hash"
    label = "Hash blocklist"

    def __init__(self, db: Database) -> None:
        self.db = db
        if not self.db.get_meta("builtin_hashes"):
            self.db.add_hashes(BUILTIN_HASHES, "builtin")
            self.db.set_meta("builtin_hashes", "1")

    def available(self) -> bool:
        return True

    def status(self) -> str:
        return f"{self.db.hash_count():,} hashes"

    def scan(self, obj: ScanObject) -> list[Detection]:
        hit = self.db.lookup_hashes([obj.sha256, obj.sha1, obj.md5])
        if not hit:
            return []
        h, name, source = hit
        return [
            Detection(
                engine=self.name,
                name=name,
                severity=Severity.CRITICAL,
                description=f"Exact match with known malware hash from {source}.",
                details={"hash": h, "source": source},
            )
        ]
