"""The website's list of every network request (site/build.py LEDGER) must name every host the app can contact.
A new URL in the app fails this test until the ledger (and HOST_PUBLISHER below) are updated."""

import re
from pathlib import Path

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
