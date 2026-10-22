"""The protected service's rules (platform independent)."""

import dataclasses
import hashlib
import os

import pytest

from sentinel_vision.config import Settings
from sentinel_vision.servicecore import (
    Caller,
    ServiceCore,
    ServiceError,
    SystemApplier,
    apply_policy,
    policy_from_settings,
    weakened,
)

ALICE = Caller("S-1-5-21-1000-1000-1000-1001", pid=10, session=1)
ALICE_ADMIN = Caller("S-1-5-21-1000-1000-1000-1001", elevated=True, session=1)
BOB = Caller("S-1-5-21-1000-1000-1000-1002", pid=11, session=2)


class FakeApplier(SystemApplier):
    def __init__(self):
        self.calls = []

    def apply_hosts(self):
        self.calls.append("hosts+")
        return "ok"

    def remove_hosts(self):
        self.calls.append("hosts-")
        return "ok"

    def apply_firewall(self):
        self.calls.append("fw+")
        return "ok"

    def remove_firewall(self):
        self.calls.append("fw-")
        return "ok"


@pytest.fixture
def core(tmp_path):
    c = ServiceCore(tmp_path / "svc", FakeApplier())
    yield c
    c.close()


def test_weakened_rules():
    base = {"realtime_enabled": True, "exclusions": [], "ransomware_folders": ["C:/Docs"], "heuristic_threshold": 60}
    assert weakened(base, {"realtime_enabled": False}) == ["realtime_enabled"]
    assert weakened(base, {"exclusions": ["C:/Games"]}) == ["exclusions"]
    assert weakened(base, {"ransomware_folders": []}) == ["ransomware_folders"]
    assert weakened(base, {"heuristic_threshold": 90}) == ["heuristic_threshold"]
    # strengthening is never "weaker"
    assert weakened(base, {"ransomware_folders": ["C:/Docs", "D:/Photos"], "heuristic_threshold": 40}) == []
    assert weakened({"auto_update_hours": 6}, {"auto_update_hours": 0}) == ["auto_update_hours"]


def test_weakening_needs_admin_and_is_recorded(core):
    s = Settings()
    core.handle(ALICE, "policy.set", {"policy": policy_from_settings(s)})  # first registration
    pol = policy_from_settings(s)
    pol["realtime_enabled"] = False
    with pytest.raises(ServiceError) as e:
        core.handle(ALICE, "policy.set", {"policy": pol})
    assert e.value.code == "elevation_required" and "realtime_enabled" in e.value.extra["fields"]
    assert core.policy(ALICE.sid)["realtime_enabled"] is True  # unchanged
    events = core.handle(ALICE, "events", {})[0]["events"]
    assert any(ev["kind"] == "refused" for ev in events)
    # with the administrator prompt approved it is accepted
    core.handle(ALICE_ADMIN, "policy.set", {"policy": pol})
    assert core.policy(ALICE.sid)["realtime_enabled"] is False
    # turning it back on never needs approval
    pol["realtime_enabled"] = True
    core.handle(ALICE, "policy.set", {"policy": pol})
    assert core.policy(ALICE.sid)["realtime_enabled"] is True


def test_protected_policy_wins_over_a_tampered_settings_file():
    s = Settings()
    pol = policy_from_settings(s)
    tampered = Settings()
    tampered.realtime_enabled = False
    tampered.exclusions = ["C:\\"]
    apply_policy(tampered, pol)
    assert tampered.realtime_enabled is True and tampered.exclusions == []


def test_machine_wide_blocking_on_freely_off_with_admin(core):
    core.handle(ALICE, "policy.set", {"policy": {}, "global": {"webshield_block_hosts": True}})
    assert core.applier.calls == ["hosts+"]
    with pytest.raises(ServiceError):
        core.handle(BOB, "policy.set", {"policy": {}, "global": {"webshield_block_hosts": False}})
    core.handle(ALICE_ADMIN, "policy.set", {"policy": {}, "global": {"webshield_block_hosts": False}})
    assert core.applier.calls == ["hosts+", "hosts-"]


def test_users_cannot_see_each_others_vault_or_quarantine(core):
    v = core.handle(ALICE, "vault.store", {"key": "c:\\docs\\a.txt", "mtime": 1}, b"alice secret")[0]["version"]
    assert core.handle(ALICE, "vault.read", {"id": v["id"]})[1] == b"alice secret"
    with pytest.raises(ServiceError):
        core.handle(BOB, "vault.read", {"id": v["id"]})
    assert core.handle(BOB, "vault.files", {})[0]["files"] == []
    with pytest.raises(ServiceError):
        core.handle(BOB, "policy.get", {"sid": ALICE.sid})


def test_quarantine_round_trip_through_the_service(core):
    data = os.urandom(3 * 1024 * 1024 + 17)
    tok = core.handle(ALICE, "quarantine.begin", {"original_path": "C:/x/evil.exe", "threat": "T", "engine": "hash"})[
        0
    ]["token"]
    for i in range(0, len(data), 1024 * 1024):
        core.handle(ALICE, "quarantine.chunk", {"token": tok}, data[i : i + 1024 * 1024])
    item = core.handle(ALICE, "quarantine.commit", {"token": tok, "sha256": hashlib.sha256(data).hexdigest()})[0][
        "item"
    ]
    assert [i["id"] for i in core.handle(ALICE, "quarantine.list", {})[0]["items"]] == [item["id"]]
    assert core.handle(BOB, "quarantine.list", {})[0]["items"] == []
    # stored encrypted
    stored = (core.root / "users" / ALICE.sid / "quarantine" / f"{item['id']}.svq").read_bytes()
    assert data[:4096] not in stored
    o = core.handle(ALICE, "quarantine.open", {"id": item["id"]})[0]
    got, off = b"", 0
    while True:
        meta, chunk = core.handle(ALICE, "quarantine.read", {"token": o["token"], "offset": off})
        got += chunk
        off += len(chunk)
        if meta["eof"]:
            break
    core.handle(ALICE, "quarantine.close", {"token": o["token"]})
    assert got == data
    with pytest.raises(ServiceError):
        core.handle(BOB, "quarantine.open", {"id": item["id"]})


def test_stopping_protection_needs_admin(core):
    with pytest.raises(ServiceError):
        core.handle(ALICE, "pause", {})
    core.handle(ALICE_ADMIN, "pause", {"sid": ALICE.sid, "session": 1})
    assert (ALICE.sid, 1) in core.paused


def test_bad_account_ids_are_rejected(core):
    with pytest.raises(ServiceError):
        core.handle(Caller("..\\..\\Windows"), "vault.files", {})


def test_remote_vault_and_quarantine_behave_like_local_ones(core, tmp_path):
    from sentinel_vision.service_client import LocalTransport, RemoteQuarantine, RemoteVault

    t = LocalTransport(core, ALICE)
    vault = RemoteVault(t)
    docs = tmp_path / "Documents"
    docs.mkdir()
    f = docs / "notes.txt"
    f.write_text("version one\n" * 50)
    assert vault.snapshot(f) is not None
    f.write_text("version two\n" * 50)
    vault.snapshot(f)
    vs = vault.versions(f)
    assert len(vs) == 2
    vault.restore(vs[-1].id)
    assert f.read_text().startswith("version one")
    assert vault.stats()[0] == 1

    q = RemoteQuarantine(t)
    bad = tmp_path / "evil.exe"
    bad.write_bytes(b"MZ" + os.urandom(5000))
    original = bad.read_bytes()
    item = q.add(bad, "Test.Threat", "hash")
    assert not bad.exists() and [i.id for i in q.list()] == [item.id]
    out = q.restore(item.id)
    assert out.read_bytes() == original and q.list() == []


def test_migrating_a_local_vault_and_quarantine(core, tmp_path):
    from sentinel_vision.quarantine import Quarantine
    from sentinel_vision.service_client import LocalTransport, RemoteQuarantine, RemoteVault, migrate_local_data
    from sentinel_vision.vault import RollbackVault

    lv = RollbackVault(tmp_path / "old-vault")
    doc = tmp_path / "a.txt"
    doc.write_text("hello\n" * 100)
    lv.snapshot(doc)
    lv.close()
    lq = Quarantine(tmp_path / "old-q")
    mal = tmp_path / "m.exe"
    mal.write_bytes(b"MZ" + os.urandom(100))
    lq.add(mal, "X", "hash")
    t = LocalTransport(core, ALICE)
    assert migrate_local_data(t, tmp_path / "old-vault", tmp_path / "old-q") == (1, 1)
    assert not (tmp_path / "old-vault").exists() and not (tmp_path / "old-q").exists()
    assert RemoteVault(t).stats()[0] == 1 and len(RemoteQuarantine(t).list()) == 1
    assert migrate_local_data(t, tmp_path / "old-vault", tmp_path / "old-q") == (0, 0)  # idempotent


def test_frames_round_trip():
    import io

    from sentinel_vision.service_client import decode, encode

    buf = io.BytesIO(encode({"op": "vault.read", "args": {"id": 3}}, b"\x00payload"))
    assert decode(buf.read) == ({"op": "vault.read", "args": {"id": 3}}, b"\x00payload")


def test_sentinel_with_the_service(core, tmp_path, isolated_home):
    from sentinel_vision.core import ProtectionChangeNeedsAdmin, Sentinel
    from sentinel_vision.service_client import LocalTransport, RemoteQuarantine, RemoteVault

    def make(settings=None, caller=ALICE):
        s = settings or Settings()
        s.realtime_enabled = s.network_enabled = False
        s.feeds = []
        return Sentinel(s, service=LocalTransport(core, caller))

    sv = make()
    assert isinstance(sv.vault, RemoteVault) and isinstance(sv.quarantine, RemoteQuarantine)
    assert core.policy(ALICE.sid)  # registered on first start
    # turning protection off from the app (no administrator approval) is refused and nothing is saved
    sv.settings.ransomware_enabled = False
    with pytest.raises(ProtectionChangeNeedsAdmin) as e:
        sv.save_settings()
    assert "ransomware_enabled" in e.value.fields
    # refused attempts reach the app as events it can show
    assert any(ev["kind"] == "refused" for ev in sv.service_tick())
    sv.reload_protected_settings()
    assert sv.settings.ransomware_enabled is True
    # turning more protection on is fine
    sv.settings.exclusions = []
    sv.settings.ransomware_folders = [*sv.settings.ransomware_folders, str(tmp_path)]
    sv.save_settings()
    sv.shutdown()
    # malware edits the settings file to switch protection off: the protected copy wins at the next start
    tampered = Settings.load()
    tampered.ransomware_enabled = False
    tampered.exclusions = ["C:\\\\"]
    tampered.save()
    sv2 = make(Settings.load())
    assert sv2.settings.ransomware_enabled is True and sv2.settings.exclusions == []
    sv2.shutdown()


def test_firewall_rules_never_block_local_or_huge_ranges():
    from sentinel_vision import systemblock

    nets = ["192.168.1.0/24", "10.0.0.0/8", "127.0.0.1/32", "0.0.0.0/0", "1.0.0.0/4", "203.0.113.0/24",
            "198.51.100.7/32", "45.12.0.0/16", "2a00:1:2::/48", "not-an-ip", "224.0.0.1/32"]  # fmt: skip
    safe = systemblock.safe_networks(nets)
    assert safe == ["2a00:1:2::/48", "45.12.0.0/16"]  # documentation ranges are not global either
    cmds, rules = systemblock.firewall_commands(["45.12.0.0/16"] * 3 + [f"45.{i}.0.0/16" for i in range(13, 200)], 2)
    assert rules == 1
    assert sum(1 for c in cmds if c[3] == "delete") == 4  # previous 2 rules, both directions
    assert all("remoteip=" in c[-1] for c in cmds if c[3] == "add")


def test_elevated_helper_shows_and_applies_only_confirmed_changes(core, tmp_path):
    import json

    from sentinel_vision import protect
    from sentinel_vision.service_client import LocalTransport

    s = Settings()
    core.handle(ALICE, "policy.set", {"policy": policy_from_settings(s)})
    weaker = policy_from_settings(s)
    weaker["realtime_enabled"] = False
    weaker["exclusions"] = ["C:\\\\Games"]
    f = tmp_path / "change.json"
    f.write_text(json.dumps({"sid": ALICE.sid, "policy": weaker, "global": {}}))
    shown = []
    # not elevated: refused outright
    assert protect.privileged_main(["protect-apply", str(f)], transport=LocalTransport(core, ALICE)) == protect.FAILED
    # elevated, user says no
    no = protect.privileged_main(
        ["protect-apply", str(f)],
        confirm_fn=lambda t, x: shown.append(x) or False,
        transport=LocalTransport(core, ALICE_ADMIN),
    )
    assert no == protect.DECLINED and core.policy(ALICE.sid)["realtime_enabled"] is True
    assert "Turn off real-time file protection" in shown[0] and "Add to exclusions: C:\\\\Games" in shown[0]
    # elevated, user says yes
    yes = protect.privileged_main(
        ["protect-apply", str(f)], confirm_fn=lambda t, x: True, transport=LocalTransport(core, ALICE_ADMIN)
    )
    assert yes == protect.APPLIED and core.policy(ALICE.sid)["realtime_enabled"] is False
    # pausing protection
    assert (
        protect.privileged_main(
            ["protect-pause", "--sid", ALICE.sid, "--session", "1"],
            confirm_fn=lambda t, x: True,
            transport=LocalTransport(core, ALICE_ADMIN),
        )
        == protect.APPLIED
    )
    assert (ALICE.sid, 1) in core.paused


def test_second_account_starts_fine_when_machine_wide_blocking_is_on(core, isolated_home):
    from sentinel_vision.core import Sentinel
    from sentinel_vision.service_client import LocalTransport

    s = Settings()
    s.realtime_enabled = s.network_enabled = False
    s.feeds = []
    s.webshield_block_hosts = True
    a = Sentinel(s, service=LocalTransport(core, ALICE))
    assert core.global_policy()["webshield_block_hosts"] is True
    a.shutdown()
    s2 = Settings()  # Bob's own settings have blocking off
    s2.realtime_enabled = s2.network_enabled = False
    s2.feeds = []
    b = Sentinel(s2, service=LocalTransport(core, BOB))  # must not be refused
    assert b.settings.webshield_block_hosts is True  # shows the machine-wide state
    assert core.global_policy()["webshield_block_hosts"] is True
    b.shutdown()


def test_machine_wide_lists_put_malware_sites_first(tmp_path, monkeypatch):
    from sentinel_vision import systemblock, updater
    from sentinel_vision.config import DEFAULT_FEEDS

    phishing = "\n".join(f"aaa-phish{i}.example.com" for i in range(30))
    malware = "\n".join(f"zzz-malware{i}.example.net" for i in range(5))

    def fake_download(url, *a, **k):
        feed = next(f for f in DEFAULT_FEEDS if f.url == url)
        if feed.kind == "domains_phishing":
            return phishing.encode()
        if feed.kind == "domains_malware":
            return malware.encode()
        return b"45.12.0.0/16\n"

    monkeypatch.setattr(updater, "download", fake_download)
    feeds = [f for f in DEFAULT_FEEDS if f.kind != "domains_malware"]
    feeds.append(dataclasses.replace(next(f for f in DEFAULT_FEEDS if f.kind == "domains_malware"), requires_key=False))
    monkeypatch.setattr("sentinel_vision.config.DEFAULT_FEEDS", feeds)
    systemblock.refresh_lists(tmp_path)
    domains = systemblock.load_list(tmp_path, "domains.txt")
    assert domains[:5] == sorted(malware.split()) and len(domains) == 35
