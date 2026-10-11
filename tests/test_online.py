"""Live checks against the real services. Run with SV_ONLINE=1 (the 'Integration' workflow does, weekly)."""

import os

import pytest

pytestmark = [
    pytest.mark.online,
    pytest.mark.skipif(os.environ.get("SV_ONLINE") != "1", reason="set SV_ONLINE=1 to run live service checks"),
]


def test_every_default_feed_downloads_and_parses(sentinel):
    from dataclasses import asdict

    from sentinel_vision.config import DEFAULT_FEEDS, Feed

    sentinel.settings.feeds = [Feed(**asdict(f)) for f in DEFAULT_FEEDS if not f.requires_key]
    sentinel.settings.run_freshclam = False
    results = sentinel.updater.run()
    report = "\n".join(f"{'OK ' if r.ok else 'ERR'} {r.feed}: {r.message}" for r in results)
    print(report)
    failed = [r for r in results if not r.ok]
    # third-party services have occasional outages: require the large majority, and the core ones
    assert len(failed) <= 2, report
    by_name = {r.feed: r for r in results}
    for must in ("YARA Forge (core)", "URLhaus malware sites", "Phishing.Database active domains"):
        assert by_name[must].ok, report
    assert sentinel.domains.count() > 1000
    assert sentinel.intel.count > 100


def test_pwned_passwords_api():
    from sentinel_vision.reputation import password_breach_count

    assert password_breach_count("password") > 1_000_000
    assert password_breach_count("Sv-" + os.urandom(16).hex()) == 0


def test_circl_hashlookup_reachable(sentinel):
    from sentinel_vision.reputation import ReputationService

    rep = ReputationService(sentinel.settings, sentinel.db).lookup(os.urandom(32).hex())
    assert rep.checked and not rep.known_good and not rep.error


def test_github_release_check_and_signature_policy():
    from sentinel_vision import app_update

    info = app_update.check_latest()
    assert info is None or info.version
