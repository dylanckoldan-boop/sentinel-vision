# Regression tests from the October 2026 audit (findings SV-A01 ... SV-F07).
# Every test except the guard at the end fails on v0.4.1 (commit 30fe1a1) and must pass once its finding is fixed.
# Run `ruff format` after adding the file (it is written with single quotes so it can be pasted from a doc).

import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path

import pytest

from sentinel_vision.servicecore import Caller, ServiceCore, ServiceError

ROOT = Path(__file__).resolve().parents[1]
ALICE = Caller("S-1-5-21-1000-1000-1000-1001", pid=10, session=1)
ALICE_ADMIN = Caller("S-1-5-21-1000-1000-1000-1001", elevated=True, session=1)
BASE = {
    "realtime_enabled": True,
    "heuristic_threshold": 60,
    "vault_max_mb": 5120,
    "vault_keep_versions": 10,
    "max_file_size_mb": 200,
    "exclusions": [],
}


@pytest.fixture
def core(tmp_path):
    c = ServiceCore(tmp_path / "service")
    c.handle(ALICE_ADMIN, "policy.set", {"policy": dict(BASE)})
    yield c
    c.close()


# SV-A03 / SV-F01
@pytest.mark.parametrize(
    "field,value",
    [
        ("vault_max_mb", math.nan),
        ("vault_keep_versions", math.nan),
        ("heuristic_threshold", math.nan),
        ("max_file_size_mb", math.inf),
        ("realtime_enabled", "false"),
        ("realtime_enabled", 0),
        ("exclusions", "C:/"),
        ("exclusions", [1, 2]),
        ("heuristic_threshold", 0),
        ("vault_max_mb", 10**12),
    ],
)
def test_policy_rejects_non_finite_and_wrong_types(core, field, value):
    before = core.policy(ALICE.sid)
    with pytest.raises(ServiceError) as exc:
        core.handle(ALICE, "policy.set", {"policy": {field: value}})
    assert exc.value.code == "bad_request"
    assert core.policy(ALICE.sid) == before


def test_wire_format_rejects_nan():
    from sentinel_vision.service_client import decode

    header = json.dumps({"op": "policy.set", "args": {"policy": {"vault_max_mb": math.nan}}}).encode()
    buf = [len(header).to_bytes(4, "big") + header + (0).to_bytes(4, "big")]

    def read_exact(n):
        out, buf[0] = buf[0][:n], buf[0][n:]
        return out

    with pytest.raises((ServiceError, ValueError)):
        decode(read_exact)


# SV-A02
def test_vault_flood_cannot_evict_good_versions(tmp_path):
    docs = tmp_path / "Documents"
    core = ServiceCore(tmp_path / "service")
    core.handle(ALICE_ADMIN, "policy.set", {"policy": {**BASE, "ransomware_folders": [str(docs)]}})
    key = os.path.normcase(os.path.abspath(docs / "taxes.txt"))
    good = b"My real tax notes" * 50
    core.handle(ALICE, "vault.store", {"key": key, "mtime": 1.0}, good)
    for i in range(50):  # plausible-looking text passes the 'looks encrypted' check
        try:
            core.handle(ALICE, "vault.store", {"key": key, "mtime": 2.0 + i}, f"junk {i} ".encode() * 40)
        except ServiceError:
            pass  # refusing the flood is an acceptable outcome
    for _ in range(10):
        try:
            core.handle(ALICE, "vault.store", {"key": key, "mtime": 99.0, "force": True}, os.urandom(4096))
        except ServiceError:
            pass
    versions = core.handle(ALICE, "vault.versions", {"key": key})[0]["versions"]
    assert hashlib.sha256(good).hexdigest() in {v["sha256"] for v in versions}
    core.close()


# SV-A04
def test_quarantine_open_requires_elevation(core):
    begin = {"original_path": "C:/x/evil.exe", "threat": "T", "engine": "hash"}
    token = core.handle(ALICE, "quarantine.begin", begin)[0]["token"]
    core.handle(ALICE, "quarantine.chunk", {"token": token}, b"MZ-pretend-malware")
    item = core.handle(ALICE, "quarantine.commit", {"token": token})[0]["item"]
    with pytest.raises(ServiceError) as exc:
        core.handle(ALICE, "quarantine.open", {"id": item["id"]})
    assert exc.value.code == "elevation_required"
    assert core.handle(ALICE_ADMIN, "quarantine.open", {"id": item["id"]})[0]["size"] == 18


# SV-A05
def test_pipe_acl_does_not_grant_generic_write():
    from sentinel_vision.winservice import PIPE_SDDL

    aces = [a for a in re.findall("[(]([^)]*)[)]", PIPE_SDDL) if a.endswith(";AU")]
    assert aces, "Authenticated Users must still be able to connect"
    for ace in aces:
        rights = ace.split(";")[2]
        assert not any(r in rights for r in ("GW", "GA", "FA", "FW")), ace
        if rights.lower().startswith("0x"):
            mask = int(rights, 16)
            assert not mask & 0x4, "FILE_APPEND_DATA is FILE_CREATE_PIPE_INSTANCE on a pipe"
            assert not mask & (0x40000000 | 0x10000000), ace


# SV-A01
def test_installed_build_never_falls_back_to_local_storage(monkeypatch):
    from sentinel_vision import service_client
    from sentinel_vision.config import Settings
    from sentinel_vision.core import ProtectionChangeNeedsAdmin, Sentinel
    from sentinel_vision.quarantine import Quarantine
    from sentinel_vision.vault import RollbackVault

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(service_client, "service_installed", lambda: True)
    monkeypatch.setattr(service_client, "connect", lambda *a, **k: None)  # the service cannot be reached
    s = Settings()
    s.feeds, s.clamav_enabled = [], False
    sv = Sentinel(s)
    try:
        assert not isinstance(sv.quarantine, Quarantine), "must not quarantine into the user-writable folder"
        assert not isinstance(sv.vault, RollbackVault), "must not keep the vault in the user-writable folder"
        sv.settings.realtime_enabled = False
        with pytest.raises(ProtectionChangeNeedsAdmin):
            sv.save_settings()
    finally:
        sv.shutdown()


# SV-F04
def test_installed_build_ignores_developer_variables(monkeypatch, tmp_path):
    from sentinel_vision import config, service_client

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(service_client, "service_installed", lambda: True)
    monkeypatch.setattr(config, "user_data_dir", lambda *a, **k: str(tmp_path / "real-data"))
    monkeypatch.setenv("SENTINEL_VISION_HOME", str(tmp_path / "attacker"))
    assert Path(config.data_dir()) == tmp_path / "real-data"

    calls = []

    class FakeTransport:
        def __init__(self, timeout):
            calls.append(timeout)

        def call(self, op, args=None, payload=b""):
            return {}, b""

        def close(self):
            pass

    monkeypatch.setattr(service_client, "ResilientTransport", FakeTransport)
    monkeypatch.setenv("SENTINEL_VISION_NO_SERVICE", "1")
    real_platform = sys.platform
    monkeypatch.setattr(sys, "platform", "win32")  # only around connect(): it checks the platform first
    try:
        transport = service_client.connect()
    finally:
        monkeypatch.setattr(sys, "platform", real_platform)
    assert transport is not None and calls, "the protection service must be used even with the variable set"


# SV-A06
def test_data_folder_is_scanned_for_programs(sentinel, eicar):
    from sentinel_vision.config import data_dir

    planted = data_dir() / "logs" / "update-helper.exe"
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_bytes(eicar)
    summary = sentinel.scanner.scan_paths([str(data_dir())], act=False, use_cache=False)
    assert any(Path(r.path) == planted and r.detections for r in summary.results)


# SV-A09
def test_feed_network_floor():
    from sentinel_vision.systemblock import safe_networks

    assert safe_networks(["8.0.0.0/8", "13.0.0.0/15"]) == []
    assert safe_networks(["45.12.0.0/16"]) == ["45.12.0.0/16"]


def test_feed_hosts_are_never_blocked():
    from sentinel_vision.webshield import blockable

    for host in (
        "urlhaus-api.abuse.ch",
        "www.spamhaus.org",
        "rules.emergingthreats.net",
        "phishing.army",
        "openphish.com",
        "cinsscore.com",
        "hashlookup.circl.lu",
        "api.pwnedpasswords.com",
        "database.clamav.net",
    ):
        assert not blockable(host), host


# SV-F06
def test_settings_out_of_range_fall_back_to_defaults():
    from sentinel_vision.config import Settings

    defaults = Settings()
    raw = {"max_file_size_mb": 0, "heuristic_threshold": 500, "exclusions": [1, 2]}
    Settings.path().write_text(json.dumps(raw), encoding="utf-8")
    s = Settings.load()
    assert s.max_file_size_mb == defaults.max_file_size_mb
    assert s.heuristic_threshold == defaults.heuristic_threshold
    assert s.exclusions == defaults.exclusions


# SV-F07 (characters built with chr() so this file never contains one)
BIDI = re.compile("[" + chr(0x202A) + "-" + chr(0x202E) + chr(0x2066) + "-" + chr(0x2069) + "]")
TEXT_SUFFIXES = {".py", ".md", ".yml", ".yaml", ".toml", ".yar", ".yara", ".html", ".css", ".iss", ".ps1", ".spec"}


def test_no_bidi_control_characters_in_source():
    offenders = []
    for folder in ("src", "tests", "tools", "site", "packaging", "docs", ".github"):
        for p in (ROOT / folder).rglob("*"):
            if p.is_file() and p.suffix in TEXT_SUFFIXES:
                if BIDI.search(p.read_text(encoding="utf-8", errors="ignore")):
                    offenders.append(str(p.relative_to(ROOT)))
    assert offenders == []


# SV-C02 / SV-E03
def test_ledger_names_every_publisher():
    text = (ROOT / "site" / "build.py").read_text(encoding="utf-8")
    ledger = text[text.index("LEDGER = [") : text.index("def ledger_table")]
    publishers = (
        "YARA Forge",
        "Phishing.Database",
        "abuse.ch",
        "Spamhaus",
        "Emerging Threats",
        "Phishing Army",
        "OpenPhish",
        "CINS Army",
        "ClamAV",
        "CIRCL",
        "Have I Been Pwned",
        "AbuseIPDB",
        "GitHub",
    )
    for name in publishers:
        assert name in ledger, name


# SV-D03 guard: passes today and keeps the 'no AI services' statement true
AI_HOSTS = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "openrouter.ai",
)


def test_no_ai_service_hosts_in_source():
    for p in (ROOT / "src").rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        for host in AI_HOSTS:
            assert host not in text, f"{host} in {p}"
