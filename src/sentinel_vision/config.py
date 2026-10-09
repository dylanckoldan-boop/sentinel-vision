"""Settings, file locations and threat-feed definitions.

Everything Sentinel Vision writes lives under one data directory:

* the user's platform data dir (``platformdirs``) by default, or
* ``$SENTINEL_VISION_HOME`` when set (portable installs, tests, CI).
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from platformdirs import user_data_dir

from sentinel_vision import APP_ID

# --------------------------------------------------------------------------- paths


def data_dir() -> Path:
    override = os.environ.get("SENTINEL_VISION_HOME")
    base = Path(override) if override else Path(user_data_dir(APP_ID, appauthor=False))
    base.mkdir(parents=True, exist_ok=True)
    _restrict(base)
    return base


def _restrict(path: Path) -> None:
    """Best-effort: make our private directories owner-only (no-op on Windows ACLs)."""
    if os.name != "nt":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def sub_dir(name: str) -> Path:
    p = data_dir() / name
    p.mkdir(parents=True, exist_ok=True)
    _restrict(p)
    return p


def bundled_rules_dir() -> Path:
    return Path(__file__).resolve().parent / "rules"


# --------------------------------------------------------------------------- feeds


@dataclass
class Feed:
    """A downloadable threat-intelligence source.

    ``kind`` decides the parser:
      hash_list        one hash per line (md5/sha1/sha256 auto-detected), '#' comments
      malwarebazaar    MalwareBazaar CSV export (sha256/md5/sha1 + signature name)
      ip_list          one IP or CIDR per line, '#' or ';' comments
      spamhaus_json    Spamhaus DROP JSON-lines (``{"cidr": ...}``)
      ip_port          ``ip:port`` per line (ThreatFox style)
      yara_zip         zip archive of .yar/.yara rule files
    ``{abusech_key}`` in a URL is replaced by the configured abuse.ch Auth-Key.
    """

    name: str
    url: str
    kind: str
    enabled: bool = True
    requires_key: bool = False
    description: str = ""


DEFAULT_FEEDS: list[Feed] = [
    Feed(
        "YARA Forge (core)",
        "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip",
        "yara_zip",
        description="Curated, high-quality community YARA rules (thousands of families).",
    ),
    Feed(
        "MalwareBazaar recent hashes",
        "https://mb-api.abuse.ch/v2/files/exports/{abusech_key}/recent.csv",
        "malwarebazaar",
        requires_key=True,
        description="Malware samples submitted to abuse.ch in the last 48 hours. Free Auth-Key required.",
    ),
    Feed(
        "Feodo Tracker botnet C2",
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "ip_list",
        description="Active botnet command-and-control servers (Emotet, QakBot, Dridex...).",
    ),
    Feed(
        "ThreatFox recent IOCs",
        "https://threatfox.abuse.ch/export/csv/ip-port/recent/",
        "ip_port",
        description="Recent malware C2 ip:port indicators from ThreatFox.",
    ),
    Feed(
        "Spamhaus DROP",
        "https://www.spamhaus.org/drop/drop_v4.json",
        "spamhaus_json",
        description="Hijacked netblocks operated by professional criminals.",
    ),
    Feed(
        "Emerging Threats compromised hosts",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "ip_list",
        description="Hosts observed actively attacking or compromised.",
    ),
    Feed(
        "CINS Army bad actors",
        "https://cinsscore.com/list/ci-badguys.txt",
        "ip_list",
        enabled=False,
        description="Large list of poorly reputed IPs (noisier; off by default).",
    ),
]


# --------------------------------------------------------------------------- settings


def _default_watch_paths() -> list[str]:
    home = Path.home()
    candidates = [home / "Downloads", home / "Desktop", home / "Documents", Path(tempfile.gettempdir())]
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Microsoft/Windows/Start Menu/Programs/Startup")
    elif sys.platform == "darwin":
        candidates.append(home / "Library/LaunchAgents")
    else:
        candidates.append(home / ".config/autostart")
    return [str(p) for p in candidates if p.exists()]


@dataclass
class Settings:
    # engines
    hash_enabled: bool = True
    yara_enabled: bool = True
    clamav_enabled: bool = True
    heuristics_enabled: bool = True
    heuristic_threshold: int = 60  # 0-100 score needed to report a heuristic detection
    clamd_address: str = ""  # "" = auto-detect; "/path/to/socket" or "host:port"

    # scanning
    max_file_size_mb: int = 256
    scan_archives: bool = True
    archive_max_depth: int = 2
    archive_max_members: int = 5000  # members inspected per archive (coverage limit, never a detection)
    archive_max_total_mb: int = 512  # bytes decompressed per archive (coverage limit, never a detection)
    archive_bomb_total_mb: int = 1024  # declared size above this AND ratio above archive_max_ratio = bomb
    archive_max_ratio: int = 100
    scan_threads: int = max(2, min(8, (os.cpu_count() or 4)))
    exclusions: list[str] = field(default_factory=list)

    # actions
    auto_quarantine: bool = True  # signature hits (hash / YARA high / ClamAV) are quarantined automatically
    auto_quarantine_heuristics: bool = False  # heuristics alone only report, never auto-quarantine

    # real-time protection
    realtime_enabled: bool = True
    watch_paths: list[str] = field(default_factory=_default_watch_paths)

    # network monitor
    network_enabled: bool = True
    network_poll_seconds: float = 1.5
    suspicious_ports: list[int] = field(
        default_factory=lambda: [23, 1337, 2323, 3389, 4444, 4445, 5555, 6666, 6667, 6697, 12345, 31337, 50050]
    )

    # updates
    abusech_auth_key: str = ""
    auto_update_hours: int = 6
    feeds: list[Feed] = field(default_factory=lambda: [Feed(**asdict(f)) for f in DEFAULT_FEEDS])
    run_freshclam: bool = True

    # behaviour monitoring
    behavior_enabled: bool = True
    behavior_kill_malicious: bool = True  # end programs that signature engines confirm as malware
    behavior_block_ransomware: bool = True  # end processes that delete shadow copies / disable recovery

    # application
    check_app_updates: bool = True
    minimize_to_tray: bool = True

    # ------------------------------------------------------------------ persistence
    _lock = threading.Lock()

    @staticmethod
    def path() -> Path:
        return data_dir() / "settings.json"

    @classmethod
    def load(cls) -> Settings:
        p = cls.path()
        s = cls()
        if not p.exists():
            return s
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return s  # corrupt settings never stop protection: fall back to defaults
        known = {f.name for f in fields(cls)}
        for k, v in raw.items():
            if k not in known:
                continue
            if k == "feeds" and isinstance(v, list):
                feed_fields = {f.name for f in fields(Feed)}
                v = [
                    Feed(**{fk: fv for fk, fv in item.items() if fk in feed_fields})
                    for item in v
                    if isinstance(item, dict)
                ]
            default = getattr(s, k)
            if (
                default is not None
                and not isinstance(v, type(default))
                and not (isinstance(default, float) and isinstance(v, int))
            ):
                continue  # ignore wrongly typed values
            setattr(s, k, v)
        return s

    def save(self) -> None:
        data = {f.name: getattr(self, f.name) for f in fields(self)}
        data["feeds"] = [asdict(f) for f in self.feeds]
        p = self.path()
        with self._lock:
            fd, tmp = tempfile.mkstemp(dir=p.parent, prefix=".settings-", suffix=".json")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2)
                os.replace(tmp, p)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)

    def feed_url(self, feed: Feed) -> str | None:
        if "{abusech_key}" in feed.url:
            if not self.abusech_auth_key.strip():
                return None
            return feed.url.replace("{abusech_key}", self.abusech_auth_key.strip())
        return feed.url
