"""SV-N01: junk first versions can't fill the rollback vault for good, and a full vault is a lasting warning."""

from __future__ import annotations

import pytest

from sentinel_vision import vault as vault_mod
from sentinel_vision.vault import RESERVE_SHARE, RollbackVault, VaultRefused


@pytest.fixture
def clock(monkeypatch):
    now = [2_000_000_000.0]
    monkeypatch.setattr(vault_mod.time, "time", lambda: now[0])
    return now


@pytest.fixture
def small(tmp_path):
    v = RollbackVault(tmp_path / "vault", max_file_mb=1, max_total_mb=1, keep_versions=3)
    yield v
    v.close()


def _junk(i: int, size: int = 50_000) -> bytes:
    return bytes([i % 251]) * size + i.to_bytes(4, "big")  # unique, low-entropy (never mistaken for encryption)


def test_a_flood_of_first_versions_cant_block_edits_of_established_documents(small, tmp_path, clock):
    doc = small._key(tmp_path / "taxes.txt")
    small.store(doc, b"real" * 25_000, clock[0])  # the document's first version, 100 KB
    clock[0] += 3600
    refused = 0
    for i in range(200):  # a program stores "first versions" of made-up file names
        clock[0] += 60
        try:
            small.store(small._key(tmp_path / f"junk{i}.bin"), _junk(i), clock[0])
        except VaultRefused:
            refused += 1

    assert refused > 0
    assert small.used_bytes() <= small.max_total * (1 - RESERVE_SHARE)  # the reserve stayed free
    assert small.full_since() is not None

    clock[0] += 25 * 3600  # the next day: an edit of the real document is still kept
    since = small.full_since()
    kept = small.store(doc, b"edit" * 25_000, clock[0])

    assert kept is not None
    assert [small.read(v.id)[1][:4] for v in small.versions(doc)] == [b"edit", b"real"]
    assert small.full_since() == since  # new files are still refused, so the warning stays


def test_a_tiny_file_that_still_fits_does_not_clear_the_warning(small, tmp_path, clock):
    small.store(small._key(tmp_path / "big.bin"), _junk(1, 700_000), clock[0])
    with pytest.raises(VaultRefused):
        small.store(small._key(tmp_path / "next.bin"), _junk(2, 200_000), clock[0])
    since = small.full_since()

    assert small.store(small._key(tmp_path / "tiny.txt"), b"x", clock[0]) is not None
    assert since is not None and small.full_since() == since


def test_first_versions_count_against_a_byte_budget_per_hour(tmp_path, clock):
    v = RollbackVault(tmp_path / "vault", max_file_mb=1, max_total_mb=8, keep_versions=3)
    try:
        budget = max(int(v.max_total * vault_mod.FIRST_BYTES_SHARE), 2 * v.max_file)
        stored = 0
        with pytest.raises(VaultRefused, match="new files in an hour"):
            for i in range(10):
                v.store(v._key(tmp_path / f"f{i}.bin"), _junk(i, 1_000_000), clock[0])
                stored += 1_000_004
        assert stored <= budget
        clock[0] += 3601  # an hour later the budget is free again
        assert v.store(v._key(tmp_path / "later.bin"), _junk(99, 1_000_000), clock[0]) is not None
    finally:
        v.close()


def test_the_full_mark_lasts_until_there_is_room(tmp_path, clock):
    root = tmp_path / "vault"
    v = RollbackVault(root, max_file_mb=1, max_total_mb=1, keep_versions=3)
    v.store(v._key(tmp_path / "a.txt"), _junk(1, 600_000), clock[0])
    with pytest.raises(VaultRefused):
        v.store(v._key(tmp_path / "b.txt"), _junk(2, 600_000), clock[0])
    since = v.full_since()
    v.close()

    v = RollbackVault(root, max_file_mb=1, max_total_mb=1, keep_versions=3)  # survives a restart
    try:
        assert since is not None and v.full_since() == since
        v.max_total *= 4  # the size limit was raised
        v._prune()
        assert v.full_since() is None
    finally:
        v.close()


def test_the_service_reports_the_full_mark(tmp_path):
    from sentinel_vision.servicecore import ServiceCore
    from test_servicecore import ALICE, FakeApplier

    core = ServiceCore(tmp_path / "svc", FakeApplier())
    try:
        assert core.handle(ALICE, "vault.stats", {})[0]["full_since"] is None
    finally:
        core.close()


def test_the_dashboard_warns_while_the_vault_is_full():
    import types

    from sentinel_vision.gui.pages.dashboard import DashboardPage

    off = types.SimpleNamespace(running=True)
    s = types.SimpleNamespace(
        db=types.SimpleNamespace(detection_count=lambda since: 0),
        updater=types.SimpleNamespace(last_update=0),
        network=types.SimpleNamespace(snapshot=lambda: types.SimpleNamespace(threats=0)),
        ransomware=types.SimpleNamespace(incidents=[], running=True),
        realtime=off,
        behavior=off,
        settings=types.SimpleNamespace(
            realtime_enabled=True, ransomware_enabled=True, ransomware_folders=["/docs"], behavior_enabled=True
        ),
        vault=types.SimpleNamespace(full_since=lambda: 1_900_000_000.0),
    )

    level, title, _detail = DashboardPage._state(types.SimpleNamespace(s=s))

    assert (level, title) == ("warn", "The rollback vault is full")
