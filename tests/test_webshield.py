import hashlib

import pytest

from sentinel_vision import reputation, webshield
from sentinel_vision.webshield import DomainIntel, blockable, check_url, normalize_host, parse_domain_list


@pytest.fixture
def intel(tmp_path):
    d = DomainIntel(tmp_path / "ws.db")
    yield d
    d.close()


def test_list_parsing_handles_every_common_format():
    text = """# comment
127.0.0.1\tmalware-one.test.com
0.0.0.0 malware-two.example.org
https://phish.example.net/login/verify.php?x=1
plain-domain.co.uk
! adblock comment
www.WithCaps.Example.com.
not a domain
"""
    assert parse_domain_list(text) == [
        "malware-one.test.com",
        "malware-two.example.org",
        "phish.example.net",
        "plain-domain.co.uk",
        "www.withcaps.example.com",
    ]
    assert normalize_host("xn--pypal-4ve.com") == "xn--pypal-4ve.com"
    assert normalize_host("päypal.com") == "xn--pypal-gra.com"


def test_protected_and_shared_hosting_rules():
    assert not blockable("google.com") and not blockable("docs.google.com") and not blockable("sites.google.com")
    assert not blockable("github.io")  # shared hosting apex
    assert blockable("evil-user.github.io")  # an individual site on it
    assert blockable("totally-legit-bank.xyz")
    assert not blockable("bad host with spaces")


def test_intel_lookup_store_filter_and_parent_match(intel):
    n = intel.replace_source(
        "unit", "phishing", ["phish.example.net", "docs.google.com", "evil.github.io", "badparent.com"]
    )
    assert n == 3  # docs.google.com is never stored
    assert intel.lookup("phish.example.net")[1] == "phishing"
    assert intel.lookup("login.badparent.com")[0] == "badparent.com"
    assert intel.lookup("docs.google.com") is None
    assert intel.lookup("other.github.io") is None
    intel.replace_source("unit", "phishing", ["only-this.example.net"])  # replacing a source drops old entries
    assert intel.lookup("phish.example.net") is None and intel.count() == 1


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://www.paypal.com/signin", "safe-looking"),
        ("https://github.com/dylanckoldan-boop/sentinel-vision", "safe-looking"),
        ("http://paypa1.com/login", "suspicious"),
        ("https://rnicrosoft-support.com", "suspicious"),
        ("https://secure-paypal.account-verify.xyz/login", "suspicious"),
        ("http://192.0.2.10/bank/login.php", "suspicious"),
        ("https://www.google.com@evil.example/", "suspicious"),
        ("https://xn--pypal-4ve.com", "suspicious"),  # Cyrillic 'а' in "pаypal"
        ("https://example.com/setup.exe", "caution"),
    ],
)
def test_link_checker_heuristics(url, expected):
    order = ["safe-looking", "caution", "suspicious", "dangerous"]
    got = check_url(url).verdict
    assert order.index(got) >= order.index(expected), (url, got, check_url(url).reasons)
    if expected == "safe-looking":
        assert got == "safe-looking", check_url(url).reasons


def test_link_checker_uses_intel(intel):
    intel.replace_source("unit", "malware", ["dropper.example.org"])
    v = check_url("https://cdn.dropper.example.org/payload", intel)
    assert v.verdict == "dangerous" and any("malware" in r for r in v.reasons)


def test_hosts_block_is_idempotent_and_removable(tmp_path, monkeypatch):
    monkeypatch.setattr(webshield, "flush_dns", lambda: None)
    hosts = tmp_path / "hosts"
    original = "127.0.0.1 localhost\n# user entry\n10.0.0.5 nas.local\n"
    hosts.write_text(original)
    assert webshield.apply_hosts(["bad.example.com", "google.com", "evil.github.io"], hosts) == 2
    assert webshield.hosts_status(hosts) == 2
    webshield.apply_hosts(["bad.example.com", "worse.example.com", "x.example.net"], hosts)  # refresh
    text = hosts.read_text()
    assert text.count(webshield.BEGIN) == 1 and webshield.hosts_status(hosts) == 3
    assert "nas.local" in text and "google.com" not in text
    webshield.remove_hosts(hosts)
    assert hosts.read_text() == original and webshield.hosts_status(hosts) == 0
    assert (tmp_path / "hosts.sentinel-vision.bak").read_text() == original


def test_hosts_for_blocking_prioritises_malware(intel):
    intel.replace_source("p", "phishing", ["a-phish.example.com", "b-phish.example.com"])
    intel.replace_source("m", "malware", ["z-malware.example.com"])
    assert intel.hosts_for_blocking(limit=2) == ["z-malware.example.com", "a-phish.example.com"]


# ----------------------------------------------------------------------------- reputation & breaches


def test_pwned_password_range_parsing_and_privacy(monkeypatch):
    sha = hashlib.sha1(b"password123").hexdigest().upper()
    sent = {}

    def fake_request(url, data=None, headers=None, limit=0):
        sent["url"], sent["headers"] = url, headers
        return 200, f"{'0' * 35}:0\r\n{sha[5:]}:2470\r\n".encode()

    monkeypatch.setattr(reputation, "_request", fake_request)
    assert reputation.password_breach_count("password123") == 2470
    assert sent["url"].endswith("/" + sha[:5]) and sha[5:] not in sent["url"]  # only the 5-char prefix leaves
    assert sent["headers"]["Add-Padding"] == "true"
    assert reputation.parse_range_response("ABC:1\n", "DEF") == 0


def test_password_strength():
    assert reputation.password_strength("aaaa")[0] == 0
    assert reputation.password_strength("correct horse battery staple 42!")[0] == 4


def test_cloud_reputation_flags_malware_and_clears_known_good(sentinel, workdir, monkeypatch):
    from sentinel_vision.reputation import Reputation, ReputationService

    svc = ReputationService(sentinel.settings, sentinel.db)
    sentinel.settings.cloud_lookup = True
    sentinel.scanner.reputation = svc
    sentinel.settings.auto_quarantine = False
    bad = workdir / "fresh.exe"
    bad.write_bytes(b"MZ" + b"\0" * 300 + b"brand new sample")
    monkeypatch.setattr(svc, "lookup", lambda h: Reputation(h, malware="MalwareBazaar.TestFamily", checked=True))
    res = sentinel.scanner.scan_file(bad, origin="realtime", use_cache=False)[0]
    assert any(d.engine == "cloud" and d.name == "MalwareBazaar.TestFamily" for d in res.detections)
    assert sentinel.scanner.should_quarantine(res) is False  # auto_quarantine off in this test
    sentinel.settings.auto_quarantine = True
    assert sentinel.scanner.should_quarantine(res) is True
    # heuristic-only finding on a catalogued (known-good) file is cleared
    sus = workdir / "invoice.pdf.exe"
    sus.write_bytes(b"MZ" + b"\0" * 200)
    monkeypatch.setattr(svc, "lookup", lambda h: Reputation(h, known_good=True, known_good_source="NSRL", checked=True))
    assert sentinel.scanner.scan_file(sus, origin="scan", act=False, use_cache=False)[0].detections == []
    # disabled -> no lookups at all
    sentinel.settings.cloud_lookup = False
    monkeypatch.setattr(svc, "lookup", lambda h: (_ for _ in ()).throw(AssertionError("must not be called")))
    sentinel.scanner.scan_file(bad, origin="realtime", act=False, use_cache=False)


def test_hosts_block_is_capped_so_name_lookups_stay_fast(tmp_path, monkeypatch):
    monkeypatch.setattr(webshield, "flush_dns", lambda: None)
    monkeypatch.setattr(webshield, "MAX_HOSTS_ENTRIES", 50)
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    many = [f"bad{i}.example.com" for i in range(500)] + ["bad1.example.com"]
    assert webshield.apply_hosts(many, hosts) == 50
    assert webshield.hosts_status(hosts) == 50
    assert "0.0.0.0 bad0.example.com" in hosts.read_text()  # order kept: the first (most important) entries win
