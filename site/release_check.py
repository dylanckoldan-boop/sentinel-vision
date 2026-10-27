"""Facts about the published release that the website shows, verified before they are shown (audit finding SV-C04).

The download section shows the installer's SHA-256 and the signing key's ID. They are taken from the latest GitHub
release's ``SHA256SUMS.txt`` only after its post-quantum signature verifies against the keys pinned in
``src/sentinel_vision/trust.py``; any failure stops the build. ``--offline`` (local previews only) skips the check and
shows no fingerprints.

Needs ``cryptography`` (requirements/sign.lock). Uses only the standard library for HTTPS.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API = "https://api.github.com/repos/{owner}/sentinel-vision/releases/latest"
INSTALLER = re.compile(r"^SentinelVision-(\d+\.\d+\.\d+)-Setup\.exe$")
LIMIT = 2 * 1024 * 1024


class ReleaseCheckError(RuntimeError):
    pass


@dataclass(frozen=True)
class ReleaseFacts:
    version: str
    page_url: str
    sums: dict[str, str]  # file name -> SHA-256
    key_id: str

    @property
    def installer(self) -> tuple[str, str]:
        name = f"SentinelVision-{self.version}-Setup.exe"
        if name not in self.sums:
            raise ReleaseCheckError(f"{name} is not listed in the release's SHA256SUMS.txt")
        return name, self.sums[name]


def _get(url: str, accept: str = "application/octet-stream") -> bytes:
    if not url.startswith("https://"):
        raise ReleaseCheckError(f"refusing a non-HTTPS URL: {url}")
    headers = {"Accept": accept, "User-Agent": "sentinel-vision-site-build"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token and url.startswith("https://api.github.com/"):  # only to the API, never to asset download hosts
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (https only, checked above)
        data = r.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ReleaseCheckError(f"{url} is unexpectedly large")
    return data


def parse_sums(text: str) -> dict[str, str]:
    sums = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) == 2 and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            sums[parts[1].lstrip("*")] = parts[0].lower()
    if not sums:
        raise ReleaseCheckError("SHA256SUMS.txt lists no files")
    return sums


def verify(sums_raw: bytes, signature: bytes) -> str:
    """Return the signing key's ID, or raise if the signature isn't valid for a pinned key."""
    sys.path.insert(0, str(ROOT / "src"))
    from sentinel_vision.pqsign import CONTEXT_RELEASE, SignatureError
    from sentinel_vision.pqsign import verify as pq_verify
    from sentinel_vision.trust import release_keys

    keys = release_keys()
    if not keys:
        raise ReleaseCheckError("no release keys are pinned in trust.py")
    try:
        return pq_verify(signature, sums_raw, CONTEXT_RELEASE, keys).key_id
    except SignatureError as exc:
        raise ReleaseCheckError(f"the release's SHA256SUMS.txt signature is invalid: {exc}") from exc


def from_payload(payload: dict, fetch=_get) -> ReleaseFacts:
    if payload.get("draft") or payload.get("prerelease"):
        raise ReleaseCheckError("the latest release is a draft or pre-release")
    version = str(payload.get("tag_name", "")).lstrip("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ReleaseCheckError(f"unexpected release tag {payload.get('tag_name')!r}")
    assets = {str(a.get("name")): str(a.get("browser_download_url", "")) for a in payload.get("assets") or []}
    if "SHA256SUMS.txt" not in assets or "SHA256SUMS.txt.sig" not in assets:
        raise ReleaseCheckError(f"release {version} has no signed SHA256SUMS.txt")
    sums_raw = fetch(assets["SHA256SUMS.txt"])
    key_id = verify(sums_raw, fetch(assets["SHA256SUMS.txt.sig"]))
    facts = ReleaseFacts(version, str(payload.get("html_url", "")), parse_sums(sums_raw.decode("utf-8")), key_id)
    facts.installer  # noqa: B018 (raises if the installer isn't listed)
    return facts


def latest(owner: str) -> ReleaseFacts:
    try:
        payload = json.loads(_get(API.format(owner=owner), "application/vnd.github+json"))
    except (OSError, ValueError) as exc:
        raise ReleaseCheckError(f"couldn't read the latest release from GitHub: {exc}") from exc
    return from_payload(payload)
