"""IP reputation: parses blocklist feeds and answers "is this address known-bad?" in O(prefix lengths)."""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import threading
from pathlib import Path

from sentinel_vision.config import sub_dir

HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
IPPORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")

# ----------------------------------------------------------------------------- parsers


def _clean_lines(text: str):
    for line in text.splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if line:
            yield line


def parse_hash_list(text: str, default_name: str = "Malware.Generic") -> list[tuple[str, str]]:
    out = []
    for line in _clean_lines(text):
        token = line.split()[0].strip('"').lower()
        if HEX_RE.match(token):
            out.append((token, default_name))
    return out


def parse_malwarebazaar_csv(text: str) -> list[tuple[str, str]]:
    """MalwareBazaar CSV: header is a comment line containing ``sha256_hash``; values are quoted."""
    header: list[str] | None = None
    rows: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            if "sha256_hash" in s:
                header = next(csv.reader([s.lstrip("# ").strip()]), None)
                header = [h.strip().strip('"') for h in header] if header else None
            continue
        rows.append(line)
    if header is None:
        header = [
            "first_seen_utc",
            "sha256_hash",
            "md5_hash",
            "sha1_hash",
            "reporter",
            "file_name",
            "file_type_guess",
            "mime_type",
            "signature",
        ]
    out: list[tuple[str, str]] = []
    for rec in csv.reader(io.StringIO("\n".join(rows)), skipinitialspace=True):
        row = dict(zip(header, (v.strip() for v in rec)))
        sig = row.get("signature", "") or ""
        name = f"MalwareBazaar.{sig}" if sig and sig.lower() not in ("n/a", "null", "") else "MalwareBazaar.Generic"
        for key in ("sha256_hash", "md5_hash", "sha1_hash"):
            h = (row.get(key) or "").lower()
            if HEX_RE.match(h):
                out.append((h, name))
    return out


def _as_network(token: str) -> str | None:
    try:
        return str(ipaddress.ip_network(token.strip(), strict=False))
    except ValueError:
        return None


def parse_ip_list(text: str) -> list[str]:
    out = []
    for line in _clean_lines(text):
        net = _as_network(line.split()[0].split(",")[0])
        if net:
            out.append(net)
    return out


def parse_spamhaus_json(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        net = _as_network(obj.get("cidr", "")) if isinstance(obj, dict) else None
        if net:
            out.append(net)
    return out


def parse_ip_port(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        for ip, _port in IPPORT_RE.findall(line):
            net = _as_network(ip)
            if net:
                out.append(net)
    return out


def parse_threatfox_json(text: str) -> list[str]:
    """ThreatFox API ``get_iocs`` response: keep the ``ip:port`` indicators (malware command-and-control servers)."""
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict) or data.get("query_status") not in ("ok", None):
        return []
    out = []
    for item in data.get("data") or []:
        if not isinstance(item, dict) or item.get("ioc_type") != "ip:port":
            continue
        ip = str(item.get("ioc", "")).rsplit(":", 1)[0].strip("[]")
        net = _as_network(ip)
        if net:
            out.append(net)
    return out


IP_PARSERS = {
    "ip_list": parse_ip_list,
    "spamhaus_json": parse_spamhaus_json,
    "ip_port": parse_ip_port,
    "threatfox_api": parse_threatfox_json,
}


# ----------------------------------------------------------------------------- store


class IntelStore:
    """Holds the union of all IP feeds. Lookup checks each prefix length present (≤ 33 / 129 probes)."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or sub_dir("feeds")
        self._lock = threading.Lock()
        self._v4: dict[int, dict[int, str]] = {}
        self._v6: dict[int, dict[int, str]] = {}
        self.count = 0
        self.reload()

    @staticmethod
    def _slug(name: str) -> str:
        return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "feed"

    def save_feed(self, name: str, networks: list[str]) -> Path:
        path = self.root / f"{self._slug(name)}.ips"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(f"# source: {name}\n" + "\n".join(sorted(set(networks))) + "\n", encoding="utf-8")
        tmp.replace(path)
        return path

    def reload(self) -> None:
        v4: dict[int, dict[int, str]] = {}
        v6: dict[int, dict[int, str]] = {}
        count = 0
        for f in sorted(self.root.glob("*.ips")):
            try:
                lines = f.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            source = lines[0][len("# source: ") :] if lines and lines[0].startswith("# source: ") else f.stem
            for line in lines[1:]:
                count += self._add(v4, v6, line.strip(), source)
        with self._lock:
            self._v4, self._v6, self.count = v4, v6, count

    @staticmethod
    def _add(v4, v6, token: str, source: str) -> int:
        if not token:
            return 0
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return 0
        table = v4 if net.version == 4 else v6
        table.setdefault(net.prefixlen, {}).setdefault(int(net.network_address), source)
        return 1

    def add_runtime(self, token: str, source: str = "user") -> None:
        with self._lock:
            self.count += self._add(self._v4, self._v6, token, source)

    def lookup(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip.split("%", 1)[0])
        except ValueError:
            return None
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        table = self._v4 if addr.version == 4 else self._v6
        bits = 32 if addr.version == 4 else 128
        val = int(addr)
        for plen, nets in table.items():
            key = (val >> (bits - plen)) << (bits - plen) if plen else 0
            src = nets.get(key)
            if src:
                return src
        return None
