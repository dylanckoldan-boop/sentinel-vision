"""Audit findings SV-F02 (vault keys and restore targets) and SV-F03 (transfer, client and rate limits)."""

import os

import pytest

from sentinel_vision import servicecore
from sentinel_vision.servicecore import ServiceCore, ServiceError
from test_servicecore import ALICE, FakeApplier


@pytest.fixture
def core(tmp_path):
    c = ServiceCore(tmp_path / "svc", FakeApplier())
    c.handle(ALICE, "policy.set", {"policy": {"ransomware_folders": [str(tmp_path / "Documents")]}})
    yield c
    c.close()


def _key(p):
    return os.path.normcase(os.path.abspath(p))


# ------------------------------------------------------------------------------------------------ SV-F02
@pytest.mark.parametrize(
    "key",
    ["C:\\Windows\\System32\\x.dll", "..\\..\\x", "\\\\server\\share\\x", "/etc/cron.d/x", "relative/x.txt", ""],
)
def test_vault_only_keeps_files_in_protected_folders(core, key):
    with pytest.raises(ServiceError) as exc:
        core.handle(ALICE, "vault.store", {"key": key, "mtime": 1.0}, b"data")
    assert exc.value.code == "bad_request"


def test_vault_refuses_paths_that_escape_a_protected_folder(core, tmp_path):
    sneaky = str(tmp_path / "Documents") + os.sep + ".." + os.sep + "Startup" + os.sep + "run.bat"
    with pytest.raises(ServiceError):
        core.handle(ALICE, "vault.store", {"key": sneaky, "mtime": 1.0}, b"echo hi")
    ok = core.handle(ALICE, "vault.store", {"key": _key(tmp_path / "Documents" / "a.txt"), "mtime": 1.0}, b"hi")
    assert ok[0]["version"]


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_restore_never_writes_through_a_link(tmp_path):
    from sentinel_vision.vault import RollbackVault, VaultError

    docs = tmp_path / "Documents"
    (docs / "sub").mkdir(parents=True)
    f = docs / "sub" / "a.txt"
    f.write_text("good\n" * 50)
    v = RollbackVault(tmp_path / "vault")
    v.allowed_roots = lambda: [str(docs)]
    try:
        vid = v.snapshot(f).id
        f.unlink()
        (docs / "sub").rmdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        try:
            os.symlink(elsewhere, docs / "sub", target_is_directory=True)
        except OSError:
            pytest.skip("cannot create symlinks here")
        with pytest.raises(VaultError):
            v.restore(vid)
        assert not (elsewhere / "a.txt").exists()
    finally:
        v.close()


def test_restore_to_the_original_place_only_inside_protected_folders(tmp_path):
    from sentinel_vision.vault import RollbackVault, VaultError

    docs, other = tmp_path / "Documents", tmp_path / "Other"
    docs.mkdir()
    other.mkdir()
    f = other / "a.txt"
    f.write_text("x\n" * 50)
    v = RollbackVault(tmp_path / "vault")
    try:
        vid = v.snapshot(f).id
        v.allowed_roots = lambda: [str(docs)]
        with pytest.raises(VaultError):
            v.restore(vid)  # its original place is no longer protected
        assert v.restore(vid, docs).read_text() == "x\n" * 50  # a destination the user picked is fine
    finally:
        v.close()


# ------------------------------------------------------------------------------------------------ SV-F03
def _begin(core):
    return core.handle(ALICE, "quarantine.begin", {"original_path": "C:/x/a.exe", "threat": "T", "engine": "e"})[0]


def test_at_most_four_transfers_and_idle_ones_expire(core, monkeypatch):
    tokens = [_begin(core)["token"] for _ in range(servicecore.MAX_TRANSFERS)]
    with pytest.raises(ServiceError) as exc:
        _begin(core)
    assert exc.value.code == "too_many"
    later = servicecore.time.time() + servicecore.TRANSFER_IDLE + 1
    monkeypatch.setattr(servicecore.time, "time", lambda: later)
    assert _begin(core)["token"]  # the idle ones were removed
    assert not any((core.root / "transfers" / t).exists() for t in tokens)


def test_data_in_transit_is_limited(core, monkeypatch):
    monkeypatch.setattr(servicecore, "MAX_IN_TRANSIT", 1000)
    tok = _begin(core)["token"]
    core.handle(ALICE, "quarantine.chunk", {"token": tok}, b"x" * 900)
    with pytest.raises(ServiceError) as exc:
        core.handle(ALICE, "quarantine.chunk", {"token": tok}, b"x" * 200)
    assert exc.value.code == "too_large"


def test_changing_requests_are_rate_limited(core, monkeypatch):
    frozen = servicecore.time.time()
    monkeypatch.setattr(servicecore.time, "time", lambda: frozen)
    core._buckets.clear()
    for _ in range(servicecore.RATE_BURST):
        core.handle(ALICE, "plugin.append", {"name": "agent-guard", "record": {"n": 1}})
    with pytest.raises(ServiceError) as exc:
        core.handle(ALICE, "plugin.append", {"name": "agent-guard", "record": {"n": 2}})
    assert exc.value.code == "too_many"
    core.handle(ALICE, "ping", {})  # reading is never limited


def test_agent_guard_can_append_ten_records_a_second(core, monkeypatch):
    clock = [servicecore.time.time()]
    monkeypatch.setattr(servicecore.time, "time", lambda: clock[0])
    for _ in range(600):  # one minute at 10 per second
        core.handle(ALICE, "plugin.append", {"name": "agent-guard", "record": {"ok": True}})
        clock[0] += 0.1


def test_the_client_waits_and_retries_when_rate_limited(core):
    from sentinel_vision.service_client import LocalTransport

    t = LocalTransport(core, ALICE)
    for _ in range(servicecore.RATE_BURST + 20):  # more than the burst: later ones wait briefly
        t.call("plugin.append", {"name": "agent-guard", "record": {}})


def test_system_refresh_at_most_every_ten_minutes(core):
    core.handle(ALICE, "system.refresh", {})
    with pytest.raises(ServiceError) as exc:
        core.handle(ALICE, "system.refresh", {})
    assert exc.value.code == "too_many"


def test_unknown_arguments_and_operations_are_refused(core):
    for op, args in (("ping", {"x": 1}), ("vault.store", {"key": "/a", "force": True}), ("no.such", {})):
        with pytest.raises(ServiceError):
            core.handle(ALICE, op, args)
