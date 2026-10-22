"""Detection policy: how much a finding is trusted, and where automatic action is allowed.

Lessons from real-world full scans (Steam, Samsung, Adobe, Office, Git, VPN clients, browser and app caches):

* Rules written for process *memory* match ordinary files (a Steam chat cache) and must not be used on files.
* Machine-generated code-byte rules (Malpedia "*_Auto") match libraries that malware also bundles (image codecs,
  SDL, ...). They are useful hints, never proof.
* "Tool" rules flag dual-use software (e.g. NSSM, a service manager many legitimate apps ship). That is "possibly
  unwanted", not malware.
* Pattern rules match text inside caches and app databases (a browser cache entry, a chat history that discusses
  malware). Data files are never run, so pattern hits on them are reported, not quarantined.
* Installed programs (Program Files, /Applications) can only be changed with administrator rights; low-confidence
  findings there are almost always false alarms.

Exact matches (known-malware hashes, ClamAV signatures, cloud hash lookups) are never softened by this module.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------------------------- rule classes
MEMORY = "memory"
GENERATED = "generated"
TOOL = "tool"
NOISY = "noisy"
NORMAL = "normal"

_TOOL_RE = re.compile(r"(^|_)(tool|tools|pua|pup|riskware|greyware|adware)(_|$)")
NOISY_RULES = {
    # broad web-content rules: HTML pages that assemble a download in the browser are everywhere in caches
    "elceef_html_smuggling_a",
    "elceef_html_smuggling_b",
}


def classify_rule(name: str, tags: list[str] | tuple[str, ...] = (), meta: dict | None = None) -> str:
    n = name.lower()
    t = {str(x).lower() for x in tags}
    scope = str((meta or {}).get("scope", "")).lower()
    if "_memory" in n or n.startswith("memory_") or n.endswith("_mem") or "memory" in t or scope == "memory":
        return MEMORY
    if n.endswith("_auto"):
        return GENERATED
    if _TOOL_RE.search(n) or t & {"tool", "pua", "pup", "riskware"}:
        return TOOL
    if n in NOISY_RULES or "html_smuggling" in n:
        return NOISY
    return NORMAL


# ---------------------------------------------------------------------------------------------- file kinds
SCRIPT_EXT = {
    "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "bat", "cmd", "sh", "bash", "zsh", "py",
    "pl", "rb", "php", "applescript", "scpt", "lnk", "url", "jar", "msi", "scr", "cpl", "com", "pif",
}  # fmt: skip
PROGRAM_MAGIC = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"#!")


def file_kind(head: bytes, name: str) -> str:
    """ "program" (native executable or library), "script" (something a user or OS can launch) or "data"."""
    if head[:2] == b"MZ" or any(head.startswith(m) for m in PROGRAM_MAGIC[1:5]):
        return "program"
    ext = name.lower().rsplit(".", 1)[-1] if "." in name else ""
    if ext in SCRIPT_EXT or head[:2] == b"#!":
        return "script"
    return "data"


# ---------------------------------------------------------------------------------------------- locations
def _norm(p: str) -> str:
    return os.path.normcase(os.path.abspath(p))


def _under(path: str, roots: list[str]) -> bool:
    n = _norm(path.split("!", 1)[0])
    return any(n == r or n.startswith(r.rstrip(os.sep) + os.sep) for r in roots)


def _env_dirs(*names: str) -> list[str]:
    return [_norm(v) for v in (os.environ.get(n) for n in names) if v]


def program_dirs() -> list[str]:
    """Folders where installed software lives and that only an administrator can change."""
    if sys.platform == "win32":
        return _env_dirs("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432")
    if sys.platform == "darwin":
        return [_norm(p) for p in ("/Applications", "/Library/Application Support", "/opt/homebrew/Cellar")]
    return [_norm(p) for p in ("/opt", "/usr/local", "/usr/share", "/snap", "/var/lib/flatpak")]


def appdata_dirs() -> list[str]:
    """Per-user and shared application state: caches, browser profiles, app databases. Temp folders are excluded
    on purpose (downloads and droppers land there)."""
    home = Path.home()
    if sys.platform == "win32":
        return _env_dirs("APPDATA", "LOCALAPPDATA", "ProgramData")
    if sys.platform == "darwin":
        return [_norm(str(home / "Library/Caches")), _norm(str(home / "Library/Application Support")),
                _norm(str(home / "Library/Containers")), _norm(str(home / "Library/Group Containers"))]  # fmt: skip
    return [_norm(str(home / d)) for d in (".cache", ".config", ".local/share", ".mozilla", ".var/app")]


def temp_dirs() -> list[str]:
    import tempfile

    dirs = {_norm(tempfile.gettempdir())}
    if sys.platform == "win32" and os.environ.get("LOCALAPPDATA"):
        dirs.add(_norm(os.path.join(os.environ["LOCALAPPDATA"], "Temp")))
    return sorted(dirs)


def location(path: str) -> str:
    """ "program", "appdata" or "user" (documents, downloads, desktop, temp, removable drives, everything else)."""
    if _under(path, temp_dirs()):
        return "user"
    if _under(path, program_dirs()):
        return "program"
    if _under(path, appdata_dirs()):
        return "appdata"
    return "user"


__all__ = [
    "GENERATED",
    "MEMORY",
    "NOISY",
    "NORMAL",
    "TOOL",
    "appdata_dirs",
    "classify_rule",
    "file_kind",
    "location",
    "program_dirs",
]
