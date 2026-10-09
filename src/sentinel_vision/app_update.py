"""Application self-update via GitHub Releases.

* Checks ``/releases/latest`` of the official repository (HTTPS, size-limited).
* On Windows installer builds, downloads the new ``Setup.exe`` and verifies its SHA-256 against the
  release's ``SHA256SUMS.txt`` before running it. The installer closes the running app, upgrades it in
  place (settings, quarantine and history are kept) and relaunches it.
* Everywhere else the user is pointed at the release page.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
from dataclasses import dataclass
from pathlib import Path

from sentinel_vision import __version__
from sentinel_vision.autostart import is_installed_build
from sentinel_vision.updater import download

REPO = "dylanckoldan-boop/sentinel-vision"
API_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases"
INSTALLER_RE = re.compile(r"^SentinelVision-(\d+\.\d+\.\d+)-Setup\.exe$")


class AppUpdateError(RuntimeError):
    pass


@dataclass
class ReleaseInfo:
    version: str
    page_url: str
    notes: str
    installer_url: str = ""
    installer_name: str = ""
    sums_url: str = ""


def parse_version(v: str) -> tuple[int, ...]:
    m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", v.strip())
    if not m:
        raise ValueError(f"not a version: {v!r}")
    return tuple(int(x) for x in m.groups())


def is_newer(candidate: str, current: str = __version__) -> bool:
    try:
        return parse_version(candidate) > parse_version(current)
    except ValueError:
        return False


def parse_release(payload: dict) -> ReleaseInfo:
    tag = str(payload.get("tag_name", ""))
    info = ReleaseInfo(
        version=tag.lstrip("v"),
        page_url=str(payload.get("html_url") or RELEASES_PAGE),
        notes=str(payload.get("body") or "")[:4000],
    )
    for asset in payload.get("assets", []) or []:
        name = str(asset.get("name", ""))
        url = str(asset.get("browser_download_url", ""))
        if not url.startswith("https://"):
            continue
        if INSTALLER_RE.match(name):
            info.installer_url, info.installer_name = url, name
        elif name == "SHA256SUMS.txt":
            info.sums_url = url
    return info


def check_latest() -> ReleaseInfo | None:
    """Return the latest release if it is newer than this build, else None."""
    try:
        raw = download(API_LATEST, {"Accept": "application/vnd.github+json"}, limit=2 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:  # no release published yet
            return None
        raise AppUpdateError(f"GitHub returned HTTP {exc.code}") from exc
    try:
        payload = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise AppUpdateError("unexpected response from GitHub") from exc
    if payload.get("draft") or payload.get("prerelease"):
        return None
    info = parse_release(payload)
    return info if is_newer(info.version) else None


def can_self_install(info: ReleaseInfo) -> bool:
    return sys.platform == "win32" and is_installed_build() and bool(info.installer_url and info.sums_url)


def expected_hash(sums_text: str, filename: str) -> str:
    for line in sums_text.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and parts[1].lstrip("*") == filename and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            return parts[0].lower()
    raise AppUpdateError(f"{filename} is not listed in SHA256SUMS.txt")


def download_installer(info: ReleaseInfo) -> Path:
    if not can_self_install(info):
        raise AppUpdateError("automatic installation is only available for the Windows installer build")
    sums = download(info.sums_url, limit=1024 * 1024).decode("utf-8", errors="replace")
    want = expected_hash(sums, info.installer_name)
    data = download(info.installer_url, limit=500 * 1024 * 1024)
    got = hashlib.sha256(data).hexdigest()
    if got != want:
        raise AppUpdateError("downloaded installer failed its SHA-256 check; the update was not run")
    folder = Path(tempfile.mkdtemp(prefix="sentinel-vision-update-"))
    target = folder / info.installer_name
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    return target


def run_installer(path: Path) -> None:
    """Start the verified installer. It closes this app itself, upgrades, then relaunches it."""
    flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(  # noqa: S603 - fixed argument list, verified file
        [str(path), "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/RELAUNCH=1"],
        creationflags=flags,
        close_fds=True,
    )
