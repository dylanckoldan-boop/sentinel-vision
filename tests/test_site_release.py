"""The website only shows a release fingerprint after the release's signature verifies (audit finding SV-C04)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from sentinel_vision import pqsign, trust

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site"))
import release_check  # noqa: E402

SETUP = "SentinelVision-9.9.9-Setup.exe"
SUMS = f"{'ab' * 32}  {SETUP}\n{'cd' * 32}  SentinelVision-9.9.9-linux.tar.gz\n".encode()


@pytest.fixture
def key(monkeypatch):
    k = pqsign.PrivateKey.generate()
    monkeypatch.setattr(trust, "RELEASE_KEYS_B64", [k.public_key().to_b64()])
    return k


def _payload(files: dict[str, bytes]) -> tuple[dict, callable]:
    urls = {f"https://example.invalid/{n}": data for n, data in files.items()}
    payload = {
        "tag_name": "v9.9.9",
        "html_url": "https://github.com/x/sentinel-vision/releases/tag/v9.9.9",
        "assets": [{"name": n, "browser_download_url": f"https://example.invalid/{n}"} for n in files],
    }
    return payload, urls.__getitem__


def test_a_correctly_signed_release_gives_the_installer_fingerprint_and_key(key):
    payload, fetch = _payload(
        {"SHA256SUMS.txt": SUMS, "SHA256SUMS.txt.sig": pqsign.sign(key, SUMS, pqsign.CONTEXT_RELEASE)}
    )
    facts = release_check.from_payload(payload, fetch)
    assert facts.version == "9.9.9"
    assert facts.installer == (SETUP, "ab" * 32)
    assert facts.key_id == key.public_key().key_id


def test_a_tampered_list_an_unknown_key_or_no_signature_stops_the_build(key):
    sig = pqsign.sign(key, SUMS, pqsign.CONTEXT_RELEASE)
    tampered = SUMS.replace(b"ab", b"ef", 1)
    for files in (
        {"SHA256SUMS.txt": tampered, "SHA256SUMS.txt.sig": sig},
        {
            "SHA256SUMS.txt": SUMS,
            "SHA256SUMS.txt.sig": pqsign.sign(pqsign.PrivateKey.generate(), SUMS, "release-checksums"),
        },
        {"SHA256SUMS.txt": SUMS},
    ):
        payload, fetch = _payload(files)
        with pytest.raises(release_check.ReleaseCheckError):
            release_check.from_payload(payload, fetch)


def test_a_release_without_the_windows_installer_or_a_pre_release_is_refused(key):
    sums = SUMS.replace(SETUP.encode(), b"Other.exe")
    payload, fetch = _payload(
        {"SHA256SUMS.txt": sums, "SHA256SUMS.txt.sig": pqsign.sign(key, sums, pqsign.CONTEXT_RELEASE)}
    )
    with pytest.raises(release_check.ReleaseCheckError, match="not listed"):
        release_check.from_payload(payload, fetch)
    payload["prerelease"] = True
    with pytest.raises(release_check.ReleaseCheckError, match="pre-release"):
        release_check.from_payload(payload, fetch)


def test_only_https_is_fetched():
    with pytest.raises(release_check.ReleaseCheckError):
        release_check._get("http://example.invalid/SHA256SUMS.txt")
