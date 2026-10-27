"""The website's list of every network request (site/build.py LEDGER) must name every host the app can contact.
A new URL in the app fails this test until the ledger (and HOST_PUBLISHER below) are updated."""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# every host the app's code can contact -> the name the ledger uses for its publisher
HOST_PUBLISHER = {
    "github.com": "GitHub",
    "api.github.com": "GitHub",
    "raw.githubusercontent.com": "GitHub",
    "mb-api.abuse.ch": "abuse.ch",
    "urlhaus-api.abuse.ch": "abuse.ch",
    "threatfox-api.abuse.ch": "abuse.ch",
    "feodotracker.abuse.ch": "abuse.ch",
    "www.spamhaus.org": "Spamhaus",
    "rules.emergingthreats.net": "Emerging Threats",
    "phishing.army": "Phishing Army",
    "openphish.com": "OpenPhish",
    "cinsscore.com": "CINS Army",
    "hashlookup.circl.lu": "CIRCL",
    "api.pwnedpasswords.com": "Have I Been Pwned",
    "www.abuseipdb.com": "AbuseIPDB",
}
NOT_CONTACTED = {"schemas.openxmlformats.org"}  # XML namespace names in document parsing, never requested


def _ledger() -> str:
    text = (ROOT / "site" / "build.py").read_text(encoding="utf-8")
    return text[text.index("LEDGER = [") : text.index("def ledger_table")]


def test_every_host_in_the_app_is_in_the_ledger():
    hosts = set()
    for p in (ROOT / "src").rglob("*.py"):
        hosts |= set(re.findall(r"https?://([A-Za-z0-9.-]+)", p.read_text(encoding="utf-8")))
    unknown = sorted(hosts - set(HOST_PUBLISHER) - NOT_CONTACTED)
    assert unknown == [], f"add these hosts to the website ledger and to HOST_PUBLISHER: {unknown}"
    ledger = _ledger()
    missing = sorted({name for h, name in HOST_PUBLISHER.items() if h in hosts and name not in ledger})
    assert missing == [], f"the website ledger does not name: {missing}"


def test_licences_page_lists_every_runtime_dependency():
    """Audit finding SV-E01: the website's Licences page names every package the app depends on."""
    tomllib = pytest.importorskip("tomllib")  # Python 3.11+; the other versions in CI cover it

    deps = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    names = {re.split(r"[<>=;\[ ]", d, maxsplit=1)[0].lower() for d in deps}
    text = (ROOT / "site" / "build.py").read_text(encoding="utf-8")
    block = text[text.index("COMPONENTS = [") : text.index("def locked_version")]
    listed = set(re.findall(r'^\s+\("([a-z0-9-]+)", "', block, re.M))
    lock = (ROOT / "requirements" / "build.lock").read_text(encoding="utf-8")
    assert names - listed == set(), f"add to COMPONENTS in site/build.py: {sorted(names - listed)}"
    assert all(re.search(rf"^{n}==", lock, re.M) for n in listed), "every listed package is in build.lock"


def test_vendored_licence_texts_are_the_official_ones():
    import hashlib

    lic = ROOT / "packaging" / "licenses"
    official = {
        "GPL-3.0.txt": "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986",
        "LGPL-3.0.txt": "e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118",
    }
    for name, digest in official.items():
        assert hashlib.sha256((lic / name).read_bytes()).hexdigest() == digest, name
