"""Signature & threat-intel updater.

Security properties:
* HTTPS only, certificate verification always on (bundled certifi trust store only; see _ssl_context).
* Hard size limits on every download; archives are inspected member-by-member and only
  plain ``.yar``/``.yara`` files are extracted, flattened to a safe basename (no path traversal).
* New rules replace old ones atomically and are compile-checked before use; a broken update
  never removes working protection.
"""

from __future__ import annotations

import io
import logging
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sentinel_vision import __version__
from sentinel_vision.config import Feed, Settings, sub_dir
from sentinel_vision.db import Database
from sentinel_vision.network.threatintel import IP_PARSERS, IntelStore, parse_hash_list, parse_malwarebazaar_csv

log = logging.getLogger(__name__)

MAX_DOWNLOAD = 400 * 1024 * 1024
MAX_RULE_FILE = 64 * 1024 * 1024
TIMEOUT = 90


@dataclass
class FeedResult:
    feed: str
    ok: bool
    message: str


def _ssl_context() -> ssl.SSLContext:
    """TLS for every download: certificate checks always on, and only the certificate authorities in the bundled,
    regularly updated certifi list are trusted.

    The operating system's store is deliberately not used. Python reads the trusted certificates from the Windows
    store but never Windows' list of *blocked* ones, so an authority Microsoft has distrusted (as with the eMudhra
    key compromise in October 2026) would still be trusted by a Python program that reads the system store.
    Fails closed: without certifi no download is made."""
    import certifi  # a declared dependency, bundled with the app

    ctx = ssl.create_default_context(cafile=certifi.where())  # with cafile, the system store is not loaded
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class _HTTPSOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError(f"refusing non-HTTPS redirect to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(
    url: str, headers: dict[str, str] | None = None, limit: int = MAX_DOWNLOAD, body: bytes | None = None
) -> bytes:
    if not url.lower().startswith("https://"):
        raise ValueError("only HTTPS feeds are allowed")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ssl_context()), _HTTPSOnlyRedirect())
    req = urllib.request.Request(
        url, data=body, headers={"User-Agent": f"SentinelVision/{__version__}", **(headers or {})}
    )
    with opener.open(req, timeout=TIMEOUT) as resp:
        buf = io.BytesIO()
        while chunk := resp.read(1024 * 256):
            buf.write(chunk)
            if buf.tell() > limit:
                raise ValueError(f"download exceeds {limit // (1024 * 1024)} MB limit")
        return buf.getvalue()


def _maybe_unzip_text(data: bytes) -> str:
    if data[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            parts = []
            for info in z.infolist():
                if info.is_dir() or info.file_size > MAX_DOWNLOAD:
                    continue
                parts.append(z.read(info).decode("utf-8", errors="replace"))
            return "\n".join(parts)
    return data.decode("utf-8", errors="replace")


def extract_yara_zip(data: bytes, dest: Path) -> int:
    """Extract only .yar/.yara members into ``dest`` (flattened). Returns number of files written."""
    n = 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            base = re.sub(r"[^A-Za-z0-9._-]", "_", Path(info.filename.replace("\\", "/")).name)
            if not base.lower().endswith((".yar", ".yara")) or base.startswith("."):
                continue
            if info.file_size > MAX_RULE_FILE:
                continue
            target = dest / base
            i = 1
            while target.exists():
                target = dest / f"{Path(base).stem}_{i}{Path(base).suffix}"
                i += 1
            target.write_bytes(z.read(info))
            n += 1
    return n


class Updater:
    def __init__(self, settings: Settings, db: Database, intel: IntelStore, domains=None) -> None:
        self.settings = settings
        self.db = db
        self.intel = intel
        self.domains = domains  # webshield.DomainIntel

    @property
    def last_update(self) -> float:
        return float(self.db.get_meta("last_update", "0") or 0)

    def due(self) -> bool:
        hours = self.settings.auto_update_hours
        return hours > 0 and time.time() - self.last_update > hours * 3600

    def run(self, progress: Callable[[str], None] | None = None) -> list[FeedResult]:
        say = progress or (lambda _m: None)
        results: list[FeedResult] = []
        changed_sigs = False
        for feed in self.settings.feeds:
            if not feed.enabled:
                continue
            url = self.settings.feed_url(feed)
            if url is None:
                results.append(FeedResult(feed.name, False, "skipped: add your free abuse.ch Auth-Key in Settings"))
                continue
            say(f"Downloading {feed.name}…")
            try:
                msg, sig = self._update_feed(feed, url)
                changed_sigs |= sig
                results.append(FeedResult(feed.name, True, msg))
            except Exception as exc:
                log.warning("feed %s failed: %s", feed.name, exc)
                results.append(FeedResult(feed.name, False, str(exc)))
        if self.settings.run_freshclam and self.settings.clamav_enabled:
            r = self._freshclam(say)
            if r:
                results.append(r)
        self.intel.reload()
        if changed_sigs:
            self.db.bump_signature_version()  # previously "clean" files get rescanned
        self.db.set_meta("last_update", str(time.time()))
        ok = sum(r.ok for r in results)
        self.db.log_event("update", f"Update finished: {ok}/{len(results)} sources OK", "info" if ok else "warning")
        say("Update finished")
        return results

    def _update_feed(self, feed: Feed, url: str) -> tuple[str, bool]:
        headers = {}
        if "abuse.ch" in url and self.settings.abusech_auth_key:
            headers["Auth-Key"] = self.settings.abusech_auth_key.strip()
        body = None
        if feed.kind == "threatfox_api":
            body = b'{"query": "get_iocs", "days": 7}'
            headers["Content-Type"] = "application/json"
        data = download(url, headers, body=body)
        if feed.kind in ("domains_malware", "domains_phishing"):
            from sentinel_vision.webshield import parse_domain_list

            if self.domains is None:
                return "skipped (web shield not available)", False
            hosts = parse_domain_list(_maybe_unzip_text(data))
            if not hosts:
                raise ValueError("feed contained no domains (format changed or access denied?)")
            stored = self.domains.replace_source(feed.name, feed.kind.split("_", 1)[1], hosts)
            return f"{stored:,} domains", False
        if feed.kind == "yara_zip":
            return self._install_yara(feed, data), True
        if feed.kind in IP_PARSERS:
            nets = IP_PARSERS[feed.kind](_maybe_unzip_text(data))
            if not nets:
                raise ValueError("feed contained no IP addresses (format changed or access denied?)")
            self.intel.save_feed(feed.name, nets)
            return f"{len(nets):,} addresses", False
        if feed.kind in ("hash_list", "malwarebazaar"):
            text = _maybe_unzip_text(data)
            rows = parse_malwarebazaar_csv(text) if feed.kind == "malwarebazaar" else parse_hash_list(text, feed.name)
            if not rows:
                raise ValueError("feed contained no hashes (format changed or access denied?)")
            added = self.db.add_hashes(rows, feed.name)
            return f"{len(rows):,} hashes ({added:,} new)", added > 0
        raise ValueError(f"unknown feed kind {feed.kind!r}")

    def _install_yara(self, feed: Feed, data: bytes) -> str:
        from sentinel_vision.engines.yara_engine import EXTERNALS, HAVE_YARA

        root = sub_dir("rules/downloaded")
        slug = re.sub(r"[^a-z0-9]+", "-", feed.name.lower()).strip("-")
        staging = Path(tempfile.mkdtemp(prefix=f".{slug}-", dir=root))
        try:
            n = extract_yara_zip(data, staging)
            if n == 0:
                raise ValueError("archive contained no YARA rules")
            good = 0
            if HAVE_YARA:
                import yara  # type: ignore

                for f in staging.iterdir():
                    try:
                        yara.compile(filepath=str(f), externals=EXTERNALS)
                        good += 1
                    except Exception as exc:
                        log.warning("dropping uncompilable rule file %s: %s", f.name, exc)
                        f.unlink()
                if good == 0:
                    raise ValueError("no rule file compiled; keeping previous rules")
            final = root / slug
            old = root / f".{slug}.old"
            if old.exists():
                shutil.rmtree(old, ignore_errors=True)
            if final.exists():
                final.rename(old)
            staging.rename(final)
            shutil.rmtree(old, ignore_errors=True)
            return f"{good or n} rule file(s) installed"
        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def _freshclam(self, say: Callable[[str], None]) -> FeedResult | None:
        exe = shutil.which("freshclam")
        if not exe and sys.platform == "win32":
            for p in (r"C:\Program Files\ClamAV\freshclam.exe", r"C:\Program Files (x86)\ClamAV\freshclam.exe"):
                if Path(p).exists():
                    exe = p
        if not exe:
            return None
        say("Updating ClamAV signatures (freshclam)…")
        try:
            proc = subprocess.run([exe, "--stdout"], capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return FeedResult("ClamAV (freshclam)", False, str(exc))
        out = (proc.stdout + proc.stderr).strip().splitlines()
        tail = out[-1] if out else ""
        if proc.returncode == 0:
            return FeedResult("ClamAV (freshclam)", True, "signatures up to date")
        if "locked" in tail.lower() or "permission" in tail.lower() or "running" in tail.lower():
            return FeedResult("ClamAV (freshclam)", True, "managed by the system freshclam service")
        return FeedResult("ClamAV (freshclam)", False, tail or f"exit code {proc.returncode}")
