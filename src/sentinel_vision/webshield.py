"""Web Shield: malicious and phishing websites.

* **Domain intelligence** — malware-distribution and phishing domain lists are downloaded by the updater into a
  local SQLite table (hundreds of thousands of entries, no memory cost).
* **Link checker** — any URL can be checked against that intelligence plus heuristics that catch brand-new
  phishing sites no list knows yet: look-alike brand names (paypa1, rnicrosoft), mixed-script and punycode
  homographs, brands buried in subdomains, raw IP addresses, credentials in URLs and more.
* **System-wide blocking** (optional, needs administrator rights once) — known-bad domains are added to a clearly
  marked, removable section of the operating system's hosts file, so every browser and app is protected.
  Hosts of major platforms are never blocked as a whole, so a bad list entry can't take down legitimate services.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from sentinel_vision.config import data_dir

BEGIN = "# >>> Sentinel Vision Web Shield (managed block - do not edit) >>>"
END = "# <<< Sentinel Vision Web Shield <<<"
MAX_HOSTS_ENTRIES = 60000
DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.(xn--[a-z0-9-]{2,59}|[a-z]{2,63})$"
)

# Never blocked at the host level: core services of large platforms. (Phishing *pages* hosted on them are paths,
# which a hosts file cannot block anyway; the link checker still flags them.)
PROTECTED_DOMAINS = frozenset(
    """google.com googleapis.com gstatic.com googleusercontent.com youtube.com gmail.com microsoft.com live.com
    office.com office365.com microsoftonline.com sharepoint.com onedrive.com windows.com windowsupdate.com
    azure.com azureedge.net apple.com icloud.com amazon.com amazonaws.com cloudfront.net cloudflare.com
    github.com githubusercontent.com gitlab.com facebook.com fbcdn.net instagram.com whatsapp.com twitter.com
    x.com linkedin.com dropbox.com box.com zoom.us slack.com discord.com discordapp.com paypal.com ebay.com
    wikipedia.org mozilla.org akamaihd.net akamai.net fastly.net yahoo.com bing.com duckduckgo.com reddit.com
    netflix.com spotify.com adobe.com salesforce.com shopify.com wordpress.com docusign.net docusign.com
    python.org pypi.org npmjs.com digicert.com letsencrypt.org
    abuse.ch spamhaus.org emergingthreats.net proofpoint.com phishing.army openphish.com cinsscore.com circl.lu
    pwnedpasswords.com haveibeenpwned.com clamav.net abuseipdb.com""".split()
    # the second group: the publishers Sentinel Vision itself downloads from, so a poisoned list can never cut
    # the app off from its own updates
)
# User-content hosting: subdomains are individual sites (blockable), the apex itself never is.
SHARED_HOSTING = frozenset(
    """000webhostapp.com weebly.com wixsite.com github.io gitlab.io netlify.app vercel.app pages.dev workers.dev
    web.app firebaseapp.com herokuapp.com blogspot.com glitch.me repl.co replit.app ngrok.io ngrok-free.app
    azurewebsites.net appspot.com square.site godaddysites.com webflow.io framer.app sites.google.com""".split()
)
BRANDS = (
    "paypal microsoft apple amazon google facebook instagram netflix whatsapp outlook office365 icloud "
    "linkedin dropbox docusign chase wellsfargo bankofamerica coinbase binance metamask steam roblox "
    "dhl fedex usps adobe yahoo"
).split()
# Official sites whose names contain a brand without being exactly it: never brand-flagged.
OFFICIAL_DOMAINS = PROTECTED_DOMAINS | frozenset(
    """microsoftonline.com outlook.com hotmail.com msn.com xbox.com skype.com steamcommunity.com steampowered.com
    steamstatic.com appleid.apple.com apple-cloudkit.com paypalobjects.com paypal-community.com amazon.co.uk
    amazon.de amazon.ca primevideo.com coinbase.com binance.com metamask.io roblox.com fedex.com usps.com dhl.com
    wellsfargo.com bankofamerica.com chase.com netflix.net whatsapp.net linkedin.cn icloud.com.cn
    googlemail.com google.co.uk youtube-nocookie.com dropboxusercontent.com yahoo.co.jp adobelogin.com""".split()
)
SUSPICIOUS_TLDS = frozenset("zip mov xyz top tk ml ga cf gq icu cyou rest bar click cfd sbs lol quest".split())
SHORTENERS = frozenset("bit.ly tinyurl.com t.co is.gd goo.gl ow.ly rebrand.ly cutt.ly shorturl.at tiny.cc".split())
CONFUSABLE = str.maketrans(
    {
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "$": "s", "@": "a",
        # Cyrillic / Greek letters that look Latin
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
        "һ": "h", "ԁ": "d", "ɡ": "g", "ո": "n", "ν": "v", "ο": "o", "ρ": "p", "α": "a", "ι": "i", "κ": "k",
    }
)  # fmt: skip


def registrable(host: str) -> str:
    """Approximate registrable domain (eTLD+1) without a public-suffix download."""
    parts = host.split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "com", "net", "org", "gov", "ac", "edu"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _under(host: str, domains: frozenset[str]) -> str | None:
    parts = host.split(".")
    for i in range(len(parts) - 1):
        cand = ".".join(parts[i:])
        if cand in domains:
            return cand
    return None


def blockable(host: str) -> bool:
    """May this exact hostname be blocked system-wide?"""
    if not DOMAIN_RE.match(host):
        return False
    if _under(host, PROTECTED_DOMAINS):
        return False
    shared = _under(host, SHARED_HOSTING)
    return not (shared and host == shared)


def normalize_host(text: str) -> str:
    t = text.strip().lower()
    fields = t.split()
    if len(fields) >= 2 and fields[0] in ("0.0.0.0", "127.0.0.1", "::", "::1"):  # noqa: S104 - hosts-file format
        t = fields[1]
    elif fields:
        t = fields[0]
    if "://" in t:
        try:
            t = urlsplit(t).hostname or ""
        except ValueError:
            return ""
    t = t.split("/")[0].split(":")[0].rstrip(".")
    try:
        t = t.encode("idna").decode("ascii") if any(ord(c) > 127 for c in t) else t
    except UnicodeError:
        return ""
    return t if DOMAIN_RE.match(t) else ""


URL_IN_LINE = re.compile(r"(?i)\bhttps?://[^\s\"',<>]+")


def parse_domain_list(text: str) -> list[str]:
    """Hosts files, plain domain lists, URL lists and CSV exports with a URL column (e.g. URLhaus)."""
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = URL_IN_LINE.search(line)
        if m:
            h = normalize_host(m.group(0))
            if h:
                out.append(h)
            continue
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("!", "[")):
            continue
        h = normalize_host(line)
        if h:
            out.append(h)
    return out


# ----------------------------------------------------------------------------- store


class DomainIntel:
    """Known-bad domains in SQLite: source + category ('malware' | 'phishing')."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (data_dir() / "webshield.db")
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS domains (host TEXT PRIMARY KEY, category TEXT NOT NULL, source TEXT NOT NULL)"
        )
        self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def replace_source(self, source: str, category: str, hosts: list[str]) -> int:
        # Lists sometimes name shared platforms (a phishing page on sites.google.com…); those hosts are never
        # stored, so they can't be flagged or blocked as a whole. The link checker's heuristics still apply.
        hosts = [h for h in hosts if blockable(h)]
        with self._lock:
            self._db.execute("DELETE FROM domains WHERE source=?", (source,))
            self._db.executemany(
                "INSERT OR IGNORE INTO domains(host, category, source) VALUES (?, ?, ?)",
                ((h, category, source) for h in hosts),
            )
            self._db.commit()
            return self._db.execute("SELECT COUNT(*) FROM domains WHERE source=?", (source,)).fetchone()[0]

    def lookup(self, host: str) -> tuple[str, str, str] | None:
        """(matched host, category, source) for host or any parent domain."""
        parts = host.split(".")
        cands = [".".join(parts[i:]) for i in range(len(parts) - 1)]
        if not cands:
            return None
        marks = ",".join("?" * len(cands))  # only "?" placeholders are interpolated; values are bound
        q = f"SELECT host, category, source FROM domains WHERE host IN ({marks})"  # noqa: S608
        with self._lock:
            rows = self._db.execute(q, cands).fetchall()
        if not rows:
            return None
        rows.sort(key=lambda r: -len(r[0]))  # most specific match
        for r in rows:
            if r[0] == host or blockable(r[0]):  # a listed parent counts only if it is itself blockable
                return tuple(r)  # type: ignore[return-value]
        return None

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM domains").fetchone()[0]

    def hosts_for_blocking(self, limit: int = MAX_HOSTS_ENTRIES) -> list[str]:
        with self._lock:
            rows = self._db.execute(
                "SELECT host FROM domains ORDER BY CASE category WHEN 'malware' THEN 0 ELSE 1 END, host"
            ).fetchall()
        out = []
        for (h,) in rows:
            if blockable(h):
                out.append(h)
                if len(out) >= limit:
                    break
        return out


# ----------------------------------------------------------------------------- link checker


@dataclass
class LinkVerdict:
    url: str
    host: str
    verdict: str  # dangerous | suspicious | caution | safe-looking
    score: int
    reasons: list[str] = field(default_factory=list)


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _scripts(label: str) -> set[str]:
    out = set()
    for ch in label:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            out.add(name.split(" ")[0] if name else "?")
    return out


def check_url(url: str, intel: DomainIntel | None = None) -> LinkVerdict:
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        host_unicode = (parts.hostname or "").rstrip(".")
    except ValueError:
        return LinkVerdict(url, "", "suspicious", 40, ["The link is malformed"])
    reasons: list[str] = []
    score = 0
    if not host_unicode:
        return LinkVerdict(url, "", "suspicious", 40, ["The link has no website name"])
    try:
        host = host_unicode.encode("idna").decode("ascii").lower()
    except UnicodeError:
        host = host_unicode.lower()
        score += 30
        reasons.append("The website name contains characters that can't be represented safely")
    try:
        display = host.encode("ascii").decode("idna").lower()
    except UnicodeError:
        display = host_unicode.lower()

    if intel is not None:
        hit = intel.lookup(host)
        if hit:
            score += 100
            reasons.append(f"Listed as a {hit[1]} site by {hit[2]}")

    try:
        ipaddress.ip_address(host.strip("[]"))
        score += 35
        reasons.append("Uses a raw IP address instead of a website name")
    except ValueError:
        pass
    if parts.username or "@" in parts.netloc:
        score += 50
        reasons.append("Contains '@' before the website name, which hides the real destination")
    if "xn--" in host:
        labels = display.split(".")
        mixed = any(len(_scripts(lbl) - {"DIGIT"}) > 1 for lbl in labels)
        score += 40 if mixed else 15
        reasons.append(
            "Mixes letters from different alphabets to imitate another site"
            if mixed
            else "Uses international characters (check it is the site you expect)"
        )
    reg = registrable(host)
    reg_label = reg.split(".")[0]
    # look-alike of a brand (paypa1.com, rnicrosoft-support.com, pаypal.com with a Cyrillic 'а')
    uni_label = registrable(display).split(".")[0]
    norm = uni_label.translate(CONFUSABLE).replace("rn", "m").replace("vv", "w").replace("-", "")
    official = _under(host, OFFICIAL_DOMAINS) is not None
    for brand in BRANDS:
        if reg_label == brand or official:
            break
        if (
            norm == brand
            or (len(brand) >= 5 and _levenshtein(norm, brand) == 1)
            or (brand in norm and brand not in reg_label)
        ):
            score += 60
            reasons.append(f"The name imitates '{brand}'")
            break
    else:
        sub = host[: -len(reg)].strip(".") if host.endswith(reg) else ""
        for brand in BRANDS:
            if brand in sub.replace("-", "") or (brand in reg_label and reg_label != brand and len(brand) >= 5):
                score += 35
                reasons.append(f"Puts '{brand}' in a website it doesn't belong to ({reg})")
                if any(
                    w in host for w in ("login", "signin", "verify", "secure", "account", "support", "update", "wallet")
                ):
                    score += 20
                    reasons.append("Combines the brand with account/login wording, a classic phishing pattern")
                break
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Uses the .{tld} ending, which is popular with scam sites")
    if host.count(".") >= 4:
        score += 10
        reasons.append("Has an unusually long chain of subdomains")
    if host.count("-") >= 3:
        score += 10
        reasons.append("Has many hyphens, typical of throw-away scam domains")
    if registrable(host) in SHORTENERS or host in SHORTENERS:
        score += 10
        reasons.append("Is a link shortener: the real destination is hidden")
    path_q = (parts.path + "?" + parts.query).lower()
    path_only = parts.path.lower()
    if parts.scheme == "http" and any(
        k in path_q for k in ("login", "signin", "verify", "account", "password", "wallet")
    ):
        score += 20
        reasons.append("Asks for account details without encryption (http)")
    if any(path_only.endswith(ext) for ext in (".exe", ".scr", ".msi", ".js", ".vbs", ".hta", ".iso", ".lnk", ".apk")):
        score += 20
        reasons.append("Downloads a program or script directly")
    if score >= 90:
        verdict = "dangerous"
    elif score >= 45:
        verdict = "suspicious"
    elif score >= 15:
        verdict = "caution"
    else:
        verdict = "safe-looking"
    if not reasons:
        reasons.append("No known threat and no warning signs (this is not a guarantee)")
    return LinkVerdict(url, host, verdict, min(score, 100), reasons)


# ----------------------------------------------------------------------------- hosts file


def hosts_path() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def render_block(hosts: list[str]) -> str:
    lines = [BEGIN, f"# {len(hosts)} known malware/phishing domains, updated {time.strftime('%Y-%m-%d %H:%M')}"]
    lines += [f"0.0.0.0 {h}" for h in hosts if blockable(h)]
    lines.append(END)
    return "\n".join(lines) + "\n"


def strip_block(text: str) -> str:
    out, inside = [], False
    for line in text.splitlines(keepends=True):
        if line.strip() == BEGIN:
            inside = True
            continue
        if line.strip() == END:
            inside = False
            continue
        if not inside:
            out.append(line)
    return "".join(out)


def apply_hosts(hosts: list[str], path: Path | None = None) -> int:
    """Write (or replace) the managed block. Requires administrator/root. Returns entries written."""
    path = path or hosts_path()
    # a very large hosts file makes name look-ups slow for every program, so the block is always capped
    hosts = list(dict.fromkeys(h for h in hosts if blockable(h)))[:MAX_HOSTS_ENTRIES]
    original = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    base = strip_block(original)
    if base and not base.endswith("\n"):
        base += "\n"
    block = render_block(hosts) if hosts else ""
    new = base + block
    backup = path.with_name(path.name + ".sentinel-vision.bak")
    if not backup.exists() and original:
        shutil.copy2(path, backup)
    newline = "\r\n" if sys.platform == "win32" else "\n"
    tmp = path.with_name(path.name + ".sv-tmp")
    tmp.write_text(new, encoding="utf-8", newline=newline)
    if path.exists():
        shutil.copymode(path, tmp)
    try:
        os.replace(tmp, path)
    except OSError:
        # bind-mounted (containers) or locked hosts files can't be replaced atomically: rewrite in place
        tmp.unlink(missing_ok=True)
        with open(path, "w", encoding="utf-8", newline=newline) as fh:
            fh.write(new)
    flush_dns()
    return new.count("\n0.0.0.0 ") if block else 0


def remove_hosts(path: Path | None = None) -> None:
    apply_hosts([], path)


def hosts_status(path: Path | None = None) -> int:
    """Number of entries currently enforced (0 = not active)."""
    path = path or hosts_path()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    if BEGIN not in text:
        return 0
    block = text.split(BEGIN, 1)[1].split(END, 1)[0]
    return sum(1 for ln in block.splitlines() if ln.startswith("0.0.0.0 "))


def flush_dns() -> None:
    cmds: list[list[str]] = []
    if sys.platform == "win32":
        cmds = [["ipconfig", "/flushdns"]]
    elif sys.platform == "darwin":
        cmds = [["dscacheutil", "-flushcache"], ["killall", "-HUP", "mDNSResponder"]]
    elif shutil.which("resolvectl"):
        cmds = [["resolvectl", "flush-caches"]]
    for c in cmds:
        try:
            subprocess.run(c, capture_output=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _cli_base() -> list[str]:
    if getattr(sys, "frozen", False):
        name = "sentinel-vision-cli.exe" if sys.platform == "win32" else "sentinel-vision-cli"
        return [str(Path(sys.executable).with_name(name))]
    return [sys.executable, "-m", "sentinel_vision"]


def elevated_command(args: list[str]) -> list[str] | None:
    """Command line that re-runs the CLI with ``args`` as administrator (None on Windows: use ShellExecute)."""
    base = _cli_base()
    if sys.platform == "darwin":
        script = " ".join(_sh_quote(a) for a in [*base, *args])
        return ["osascript", "-e", f'do shell script "{script}" with administrator privileges']
    if sys.platform.startswith("linux") and shutil.which("pkexec"):
        return ["pkexec", *base, *args]
    return None


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''").replace("\\", "\\\\").replace('"', '\\"') + "'"


def run_elevated(args: list[str]) -> int:
    """Run the CLI elevated and wait. Returns its exit code (raises OSError if elevation is unavailable)."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        base = _cli_base()
        exe, params = base[0], subprocess.list2cmdline([*base[1:], *args])

        class SHELLEXECUTEINFOW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD), ("fMask", ctypes.c_ulong), ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR), ("lpFile", wintypes.LPCWSTR), ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR), ("nShow", ctypes.c_int), ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p), ("lpClass", wintypes.LPCWSTR), ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD), ("hIcon", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
            ]  # fmt: skip

        info = SHELLEXECUTEINFOW()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
        info.lpVerb = "runas"
        info.lpFile = exe
        info.lpParameters = params
        info.nShow = 0
        if not ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info)):  # type: ignore[attr-defined]
            raise OSError("administrator permission was not granted")
        ctypes.windll.kernel32.WaitForSingleObject(info.hProcess, 600000)  # type: ignore[attr-defined]  # time to read the confirmation
        code = wintypes.DWORD()
        ctypes.windll.kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))  # type: ignore[attr-defined]
        ctypes.windll.kernel32.CloseHandle(info.hProcess)  # type: ignore[attr-defined]
        return int(code.value)
    cmd = elevated_command(args)
    if cmd is None:
        raise OSError("no graphical way to ask for administrator rights (install pkexec, or run the CLI with sudo)")
    return subprocess.run(cmd, timeout=180).returncode
