"""YARA pattern engine: bundled rules + downloaded community rules + user rules."""

from __future__ import annotations

import io
import logging
import threading
from pathlib import Path

from sentinel_vision import policy
from sentinel_vision.config import bundled_rules_dir, sub_dir
from sentinel_vision.engines.base import Detection, Engine, ScanObject, Severity

log = logging.getLogger(__name__)

try:
    import yara  # type: ignore

    HAVE_YARA = True
except Exception:  # pragma: no cover - depends on environment
    yara = None
    HAVE_YARA = False

EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}
MATCH_TIMEOUT = 60
RULE_SUFFIXES = {".yar", ".yara"}


def rule_dirs() -> list[Path]:
    return [bundled_rules_dir(), sub_dir("rules/downloaded"), sub_dir("rules/custom")]


def _severity_from_meta(meta: dict) -> Severity:
    sev = meta.get("severity")
    if isinstance(sev, str):
        s = sev.strip().lower()
        for level in Severity:
            if level.name.lower() == s:
                return level
    if isinstance(sev, int) and 0 <= sev <= 4:
        return Severity(sev)
    score = meta.get("score")
    if isinstance(score, str) and score.isdigit():
        score = int(score)
    if isinstance(score, int):
        if score >= 75:
            return Severity.HIGH
        if score >= 60:
            return Severity.MEDIUM
        if score >= 40:
            return Severity.LOW
        return Severity.INFO
    return Severity.MEDIUM


def _filetype(head: bytes) -> str:
    if head[:2] == b"MZ":
        return "EXE"
    if head[:4] == b"\x7fELF":
        return "ELF"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "MACHO"
    return ""


class YaraEngine(Engine):
    name = "yara"
    label = "YARA rules"

    def __init__(self) -> None:
        self._rules = None
        self._rule_count = 0
        self._bad_files: list[str] = []
        self._blob = b""
        self._generation = 0
        self._tls = threading.local()
        self._lock = threading.Lock()
        self.reload()

    def available(self) -> bool:
        return HAVE_YARA and self._rules is not None

    def status(self) -> str:
        if not HAVE_YARA:
            return "yara-python not installed"
        if self._rules is None:
            return "no rules loaded"
        extra = f", {len(self._bad_files)} file(s) skipped" if self._bad_files else ""
        return f"{self._rule_count:,} rules{extra}"

    @property
    def rule_count(self) -> int:
        return self._rule_count

    @property
    def skipped_files(self) -> list[str]:
        return list(self._bad_files)

    def reload(self) -> None:
        if not HAVE_YARA:
            return
        files = sorted(
            p
            for d in rule_dirs()
            if d.is_dir()
            for p in d.rglob("*")
            if p.suffix.lower() in RULE_SUFFIXES
            and p.is_file()
            and not any(part.startswith(".") for part in p.relative_to(d).parts)  # staging / backups
        )
        good: dict[str, str] = {}
        bad: list[str] = []
        for i, p in enumerate(files):
            ns = f"ns{i}_{p.stem}"
            try:
                yara.compile(filepath=str(p), externals=EXTERNALS)
                good[ns] = str(p)
            except Exception as exc:  # syntax errors, missing modules...
                log.warning("Skipping YARA file %s: %s", p, exc)
                bad.append(f"{p.name}: {exc}")
        rules = None
        blob = b""
        count = 0
        if good:
            rules = yara.compile(filepaths=good, externals=EXTERNALS)
            count = sum(1 for _ in rules)
            buf = io.BytesIO()
            rules.save(file=buf)
            blob = buf.getvalue()
        with self._lock:
            self._rules, self._rule_count, self._bad_files = rules, count, bad
            self._blob, self._generation = blob, self._generation + 1

    def _thread_rules(self):
        """libyara stores externals on the Rules object, so concurrent matches with different externals
        on one object race. Each scanning thread therefore gets its own copy of the compiled rules."""
        with self._lock:
            gen, blob = self._generation, self._blob
        if not blob:
            return None
        tl = self._tls
        if getattr(tl, "generation", None) != gen:
            tl.rules = yara.load(file=io.BytesIO(blob))
            tl.generation = gen
        return tl.rules

    def scan(self, obj: ScanObject) -> list[Detection]:
        rules = self._thread_rules()
        if rules is None:
            return []
        name = obj.name
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        externals = {
            "filename": name,
            "filepath": obj.display_path,
            "extension": ext,
            "filetype": _filetype(obj.head),
            "owner": "",
        }
        try:
            if obj.fs_path is not None:
                matches = rules.match(filepath=str(obj.fs_path), externals=externals, timeout=MATCH_TIMEOUT, fast=True)
            else:
                matches = rules.match(data=obj.data, externals=externals, timeout=MATCH_TIMEOUT, fast=True)
        except Exception as exc:
            if "timeout" in str(exc).lower() or "TimeoutError" in type(exc).__name__:
                log.info("YARA timeout on %s", obj.display_path)
                return []
            raise
        out: list[Detection] = []
        for m in matches:
            sev = _severity_from_meta(m.meta)
            if sev == Severity.INFO:
                continue
            kind = policy.classify_rule(m.rule, m.tags, m.meta)
            if kind == policy.MEMORY:
                continue  # written for process memory (the memory scan uses it); on files it is noise
            desc = str(m.meta.get("description", "")) or f"Matched YARA rule {m.rule}"
            details = {
                "tags": list(m.tags),
                "author": m.meta.get("author", ""),
                "namespace": m.namespace,
                "rule_class": kind,
            }
            if kind == policy.GENERATED:
                sev = min(sev, Severity.MEDIUM)
                details["report_only"] = True
                desc = f"Code resembles a sample of this malware family (machine-generated rule, a hint only): {desc}"
            elif kind == policy.TOOL:
                sev = Severity.LOW
                details["report_only"] = True
                desc = f"Possibly unwanted or dual-use tool; legitimate software also uses it: {desc}"
            elif kind == policy.NOISY:
                sev = min(sev, Severity.MEDIUM)
                details["report_only"] = True
            out.append(Detection(engine=self.name, name=m.rule, severity=sev, description=desc, details=details))
        return out
