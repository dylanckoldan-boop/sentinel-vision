"""Cloud reputation lookups (opt-in) and password breach checks. Files themselves are never uploaded.

* **CIRCL hashlookup** (free, no account): tells whether a SHA-256 belongs to known software (NIST NSRL and
  other catalogues). Used to clear heuristic suspicions about known-good files.
* **MalwareBazaar** (free abuse.ch Auth-Key): tells whether a SHA-256 is a known malware sample, catching
  threats published minutes ago — before any signature update.
* **Have I Been Pwned – Pwned Passwords**: k-anonymity range query. Only the first 5 characters of the
  password's SHA-1 leave the device (with response padding), so neither HIBP nor anyone watching the network
  learns the password or whether it was found.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from sentinel_vision import __version__
from sentinel_vision.updater import _HTTPSOnlyRedirect, _ssl_context

CIRCL_URL = "https://hashlookup.circl.lu/lookup/sha256/{}"
MB_API = "https://mb-api.abuse.ch/api/v1/"
HIBP_RANGE = "https://api.pwnedpasswords.com/range/{}"
TIMEOUT = 15
CACHE_TTL = 7 * 86400


class ReputationError(RuntimeError):
    pass


def _request(url: str, data: bytes | None = None, headers: dict[str, str] | None = None, limit: int = 4 << 20):
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ssl_context()), _HTTPSOnlyRedirect())
    req = urllib.request.Request(
        url, data=data, headers={"User-Agent": f"SentinelVision/{__version__}", **(headers or {})}
    )
    try:
        with opener.open(req, timeout=TIMEOUT) as resp:
            body = resp.read(limit + 1)
            if len(body) > limit:
                raise ReputationError("response too large")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        return exc.code, b""


@dataclass
class Reputation:
    sha256: str
    known_good: bool = False
    known_good_source: str = ""
    malware: str = ""  # signature / family name if known malicious
    checked: bool = False
    error: str = ""


class ReputationService:
    def __init__(self, settings, db) -> None:
        self.settings = settings
        self.db = db
        self._lock = threading.Lock()
        self._cache: dict[str, tuple[float, Reputation]] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.settings.cloud_lookup)

    def lookup(self, sha256: str) -> Reputation:
        sha256 = sha256.lower()
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError("not a SHA-256")
        now = time.time()
        with self._lock:
            hit = self._cache.get(sha256)
        if hit and now - hit[0] < CACHE_TTL:
            return hit[1]
        rep = Reputation(sha256)
        try:
            status, body = _request(CIRCL_URL.format(sha256), headers={"Accept": "application/json"})
            if status == 200:
                info = json.loads(body.decode("utf-8", "replace") or "{}")
                rep.known_good = True
                rep.known_good_source = str(info.get("source") or info.get("FileName") or "CIRCL hashlookup")[:120]
            key = self.settings.abusech_auth_key.strip()
            if key:
                payload = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
                status, body = _request(MB_API, data=payload, headers={"Auth-Key": key})
                if status == 200:
                    info = json.loads(body.decode("utf-8", "replace") or "{}")
                    if info.get("query_status") == "ok" and info.get("data"):
                        sig = info["data"][0].get("signature") or "Generic"
                        rep.malware = f"MalwareBazaar.{sig}"
            rep.checked = True
        except (OSError, ValueError, ReputationError) as exc:
            rep.error = str(exc)
        if rep.checked:
            with self._lock:
                self._cache[sha256] = (now, rep)
                if len(self._cache) > 50000:
                    self._cache.clear()
        return rep


def password_breach_count(password: str) -> int:
    """How many times the password appears in known breaches (0 = not found). Raises OSError on network errors."""
    if not password:
        raise ValueError("empty password")
    digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    status, body = _request(HIBP_RANGE.format(prefix), headers={"Add-Padding": "true"})
    if status != 200:
        raise OSError(f"breach service returned HTTP {status}")
    return parse_range_response(body.decode("utf-8", "replace"), suffix)


def parse_range_response(text: str, suffix: str) -> int:
    for line in text.splitlines():
        h, _, count = line.strip().partition(":")
        if h.upper() == suffix.upper():
            try:
                return int(count)
            except ValueError:
                return 1
    return 0


def password_strength(password: str) -> tuple[int, str]:
    """Rough strength estimate (0-4) without sending anything anywhere."""
    import math

    pools = 0
    if any(c.islower() for c in password):
        pools += 26
    if any(c.isupper() for c in password):
        pools += 26
    if any(c.isdigit() for c in password):
        pools += 10
    if any(not c.isalnum() for c in password):
        pools += 33
    bits = len(password) * math.log2(pools) if pools else 0
    if len(set(password)) <= 2:
        bits = min(bits, 10)
    levels = [(28, 0, "very weak"), (36, 1, "weak"), (60, 2, "fair"), (80, 3, "strong")]
    for limit, score, label in levels:
        if bits < limit:
            return score, label
    return 4, "very strong"
