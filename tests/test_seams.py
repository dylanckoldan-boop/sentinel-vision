"""Seams for companion programs such as Foldward (formerly Agent Guard): `quarantine add`, `net block`, plugin log,
plugin host.
Sentinel Vision never imports those programs; they call the command line or plug into documented entry points."""

import os
import re
import sys

import pytest

from sentinel_vision.quarantine import Quarantine, QuarantineError
from test_servicecore import ALICE, ALICE_ADMIN, BOB, FakeApplier


@pytest.fixture
def core(tmp_path):
    from sentinel_vision.servicecore import ServiceCore

    c = ServiceCore(tmp_path / "svc", FakeApplier())
    yield c
    c.close()


def _file(folder, name="tool.bin", data=b"agent payload " * 100):
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / name
    p.write_bytes(data)
    return p


# ------------------------------------------------------------------------------------------------ quarantine add
def test_add_external_moves_the_file_and_records_who_asked(tmp_path):
    q = Quarantine(tmp_path / "q")
    f = _file(tmp_path / "work")
    item_id = q.add_external(str(f), "agent fetched an unsigned binary", "foldward")
    assert not f.exists()  # moved, like automatic quarantine
    item = q.get(item_id)
    assert item.threat == "agent fetched an unsigned binary" and item.engine == "external:foldward"
    restored = q.restore(item_id)
    assert restored.read_bytes() == b"agent payload " * 100


def test_add_external_through_the_protected_service(core, tmp_path):
    from sentinel_vision.service_client import LocalTransport, RemoteQuarantine

    q = RemoteQuarantine(LocalTransport(core, ALICE))
    f = _file(tmp_path / "work")
    item_id = q.add_external(f, "", "foldward")
    assert not f.exists()
    assert q.get(item_id).threat == "Sent to quarantine by foldward"
    assert [i.id for i in RemoteQuarantine(LocalTransport(core, BOB)).list()] == []  # other accounts can't see it
    core.handle(ALICE_ADMIN, "quarantine.release", {"sid": ALICE.sid, "id": item_id})  # restoring needs approval
    assert q.restore(item_id).read_bytes() == b"agent payload " * 100


def test_add_external_refuses_what_it_must_not_touch(tmp_path, monkeypatch, isolated_home):
    from sentinel_vision import scanner
    from sentinel_vision.config import data_dir

    q = Quarantine(tmp_path / "q")
    with pytest.raises(QuarantineError):
        q.add_external(tmp_path / "missing.bin")
    with pytest.raises(QuarantineError):
        q.add_external(tmp_path)  # a folder
    with pytest.raises(QuarantineError):
        q.add_external(_file(data_dir() / "x"), "", "foldward")  # Sentinel Vision's own data
    f = _file(tmp_path / "w")
    with pytest.raises(QuarantineError):
        q.add_external(f, "", "Agent Guard; rm -rf")  # source names are short identifiers
    if hasattr(os, "symlink"):
        link = tmp_path / "w" / "link.bin"
        try:
            os.symlink(f, link)
        except OSError:
            pass
        else:
            with pytest.raises(QuarantineError):
                q.add_external(link)
    monkeypatch.setattr(scanner, "is_system_path", lambda p: True)
    with pytest.raises(QuarantineError):
        q.add_external(f)  # operating-system files are never quarantined on request
    assert f.exists()


def test_cli_quarantine_add_list_restore(tmp_path, capsys, isolated_home):
    from sentinel_vision.cli import main

    f = _file(tmp_path / "work", "dropped.exe", b"MZ fake program")
    assert main(["quarantine", "add", str(f), "--reason", "test"]) == 0
    item_id = capsys.readouterr().out.strip()
    assert len(item_id) == 32 and not f.exists()
    assert main(["quarantine", "list"]) == 0
    assert item_id in capsys.readouterr().out
    assert main(["quarantine", "restore", item_id]) == 0
    assert f.read_bytes() == b"MZ fake program"
    assert main(["quarantine", "add", str(tmp_path / "nope.bin")]) == 2
    assert "error" in capsys.readouterr().err


# ------------------------------------------------------------------------------------------------ net block
@pytest.mark.parametrize("ip", ["10.0.0.5", "127.0.0.1", "192.168.1.1", "::1", "0.0.0.0", "203.0.113.7", "224.0.0.1",
                                "169.254.1.1", "not-an-ip", "1.2.3.4; del C:\\"])  # fmt: skip
def test_net_block_refuses_anything_but_public_addresses(ip):
    from sentinel_vision.network.firewall import FirewallError, block_commands

    with pytest.raises(FirewallError):
        block_commands(ip)


def test_net_block_cli(monkeypatch, capsys, isolated_home):
    from sentinel_vision.cli import main
    from sentinel_vision.network import firewall

    seen = []
    real = firewall.block_ip
    monkeypatch.setattr(firewall, "block_ip", lambda ip: seen.append(ip) or f"Blocked {ip} in the system firewall.")
    assert main(["net", "block", "45.12.10.9"]) == 0 and seen == ["45.12.10.9"]
    monkeypatch.setattr(firewall, "block_ip", real)
    assert main(["net", "block", "192.168.0.1"]) == 2  # refused by the real validation, before any firewall call
    assert main(["net", "block"]) == 2


def test_netsh_rule_names_are_passed_the_way_netsh_expects(monkeypatch):
    from sentinel_vision.network import firewall

    monkeypatch.setattr(sys, "platform", "win32")
    line = firewall.command_line(firewall.block_commands("45.12.10.9")[0])
    assert line == (
        'netsh advfirewall firewall add rule name="SentinelVision block 45.12.10.9" dir=out action=block '
        "remoteip=45.12.10.9"
    )


# ------------------------------------------------------------------------------------------------ plugin log
def test_plugin_log_is_append_only_and_tamper_evident(tmp_path):
    from sentinel_vision.pluginlog import AppendOnlyLog, PluginLogError

    log = AppendOnlyLog(tmp_path / "log.jsonl")
    for i in range(5):
        assert log.append({"event": "revoke", "agent": f"a{i}"})["seq"] == i + 1
    assert [e["record"]["agent"] for e in log.read(2)] == ["a2", "a3", "a4"]
    assert log.verify() == (True, 5)
    assert AppendOnlyLog(tmp_path / "log.jsonl").append({"x": 1})["seq"] == 6  # continues after a restart
    # editing or deleting a line is detected
    lines = (tmp_path / "log.jsonl").read_text().splitlines()
    (tmp_path / "log.jsonl").write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    assert AppendOnlyLog(tmp_path / "log.jsonl").verify()[0] is False
    (tmp_path / "log.jsonl").write_text("\n".join([lines[0].replace("a0", "zz")] + lines[1:]) + "\n")
    assert AppendOnlyLog(tmp_path / "log.jsonl").verify()[0] is False
    with pytest.raises(PluginLogError):
        log.append(["not", "an", "object"])
    with pytest.raises(PluginLogError):
        log.append({"big": "x" * 70_000})


def test_plugin_log_through_the_service_is_per_account_and_cannot_be_rewritten(core):
    from sentinel_vision.plugin_api import PluginLog
    from sentinel_vision.service_client import LocalTransport
    from sentinel_vision.servicecore import ServiceError

    alice = PluginLog("foldward", LocalTransport(core, ALICE))
    assert alice.protected
    assert alice.append({"event": "quarantined", "id": "abc"}) == 1
    assert alice.append({"event": "revoked", "agent": "x"}) == 2
    entries = alice.read()
    assert [e["record"]["event"] for e in entries] == ["quarantined", "revoked"] and entries[0]["pid"] == ALICE.pid
    assert alice.verify() == (True, 2)
    assert PluginLog("foldward", LocalTransport(core, BOB)).read() == []  # each account has its own log
    with pytest.raises(ServiceError):  # reading someone else's log needs administrator rights
        core.handle(BOB, "plugin.read", {"name": "foldward", "sid": ALICE.sid})
    for bad in ("../../policy", "Agent Guard", "", "a" * 41):
        with pytest.raises(ServiceError):
            core.handle(ALICE, "plugin.append", {"name": bad, "record": {}})
    # there is no request that edits or deletes records
    assert not [
        op for op in dir(core) if op.startswith("op_plugin") and op not in ("op_plugin_append", "op_plugin_read")
    ]


def test_the_log_limit_counts_whole_entries(tmp_path, monkeypatch):
    """INT-N01: the limit counted only the record, so a log grew past it and tiny records still fitted."""
    from sentinel_vision import pluginlog
    from sentinel_vision.pluginlog import AppendOnlyLog, PluginLogError

    monkeypatch.setattr(pluginlog, "MAX_LOG", 2000)
    log = AppendOnlyLog(tmp_path / "log.jsonl")
    assert log.size() == 0
    sizes = []
    with pytest.raises(PluginLogError, match="^log is full"):
        for i in range(100):
            sizes.append(log.append({"n": i})["bytes"])
    assert sizes[-1] == log.size() == (tmp_path / "log.jsonl").stat().st_size <= 2000
    with pytest.raises(PluginLogError, match="^log is full"):
        log.append({})  # an empty record is still a whole entry
    assert log.size() == sizes[-1] and log.verify() == (True, len(sizes))


def test_a_filling_plugin_log_is_reported_with_the_programs_that_wrote_it(core, monkeypatch):
    """INT-N01: any program running as the user can add records, so a log that is nearly full or full is reported
    to that user, naming the processes that added most of it; at most once a day (nearly full) or an hour (full)."""
    from sentinel_vision import pluginlog
    from sentinel_vision.servicecore import Caller, ServiceError

    monkeypatch.setattr(pluginlog, "MAX_LOG", 3000)
    flooder = Caller(ALICE.sid, pid=4242, session=1)

    def warnings(caller):
        return [e["detail"] for e in core.handle(caller, "events", {})[0]["events"] if e["kind"] == "warning"]

    core.handle(ALICE, "plugin.append", {"name": "foldward", "record": {"event": "pacify"}})
    assert warnings(ALICE) == []
    with pytest.raises(ServiceError, match="log is full"):
        for _ in range(100):
            core.handle(flooder, "plugin.append", {"name": "foldward", "record": {"pad": "x" * 100}})
    nearly, full = warnings(ALICE)
    assert "'foldward' is 8" in nearly or "'foldward' is 9" in nearly
    assert "'foldward' is full" in full and "process 4242" in full and "on purpose" in full
    assert full.index("process 4242") < full.index(f"process {ALICE.pid}")  # most records first
    with pytest.raises(ServiceError):
        core.handle(ALICE, "plugin.append", {"name": "foldward", "record": {"event": "pacify"}})
    assert len(warnings(ALICE)) == 2  # not repeated within the hour
    assert warnings(BOB) == []  # only the account whose log it is
    report = core.handle(ALICE, "plugin.read", {"name": "foldward", "limit": 1, "verify": True})[0]
    assert report["intact"] is True and report["limit"] == 3000 and 2800 < report["bytes"] <= 3000


def test_plugin_log_verify_reports_how_full_the_log_is(core, capsys, isolated_home):
    import json

    from sentinel_vision.cli import main
    from sentinel_vision.config import sub_dir
    from sentinel_vision.plugin_api import PluginLog
    from sentinel_vision.pluginlog import MAX_LOG
    from sentinel_vision.service_client import LocalTransport

    assert main(["plugin-log", "append", "foldward", "--json", '{"event": "test"}']) == 0
    capsys.readouterr()
    assert main(["plugin-log", "verify", "foldward"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert (
        report["bytes"] == (sub_dir("plugins") / "foldward" / "log.jsonl").stat().st_size and report["limit"] == MAX_LOG
    )

    through_service = PluginLog("foldward", LocalTransport(core, ALICE))
    through_service.append({"event": "test"})
    r = through_service.verify_report()
    assert r["intact"] is True and r["entries"] == 1 and r["bytes"] > 0 and r["limit"] == MAX_LOG


def test_plugin_log_verify_reports_an_unreachable_service_as_an_error(monkeypatch, capsys):
    from sentinel_vision import plugin_api
    from sentinel_vision.cli import main
    from sentinel_vision.servicecore import ServiceError

    class Down:
        def call(self, op, args=None, payload=b""):
            raise ServiceError("unavailable", "the protection service didn't answer")

    monkeypatch.setattr(plugin_api, "plugin_log", lambda name: plugin_api.PluginLog(name, Down()))

    assert main(["plugin-log", "verify", "foldward"]) == 2  # an error, not a traceback
    assert capsys.readouterr().err.startswith("error:")


def test_service_warnings_are_shown_to_the_user():
    pytest.importorskip("PySide6")
    import types

    from sentinel_vision.gui.app import MainWindow

    shown = []
    window = types.SimpleNamespace(
        _service_task=object(), sentinel=types.SimpleNamespace(alert=lambda *a: shown.append(a))
    )
    MainWindow._service_events(window, [{"kind": "warning", "detail": "The protected record log 'foldward' is full."}])

    assert shown == [("Protected record log", "The protected record log 'foldward' is full.", "warning")]


def test_plugin_log_refuses_to_fall_back_when_the_service_is_installed_but_down(monkeypatch):
    from sentinel_vision import plugin_api, service_client

    monkeypatch.setattr(service_client, "connect", lambda *a, **k: None)
    monkeypatch.setattr(service_client, "service_installed", lambda: True)
    with pytest.raises(plugin_api.PluginLogError):
        plugin_api.plugin_log("foldward")


def test_plugin_log_cli(capsys, isolated_home):
    import json

    from sentinel_vision.cli import main

    assert main(["plugin-log", "append", "foldward", "--json", '{"event": "test"}']) == 0
    assert capsys.readouterr().out.strip() == "1"
    assert main(["plugin-log", "read", "foldward"]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[0])["record"] == {"event": "test"}
    assert main(["plugin-log", "verify", "foldward"]) == 0
    assert json.loads(capsys.readouterr().out)["intact"] is True
    assert main(["plugin-log", "append", "foldward", "--json", "not json"]) == 2
    assert main(["plugin-log", "append", "../x", "--json", "{}"]) == 2


def test_plugin_dir_is_private_and_named_safely(isolated_home):
    from sentinel_vision.config import plugin_dir
    from sentinel_vision.pluginlog import PluginLogError

    d = plugin_dir("foldward")
    assert d.is_dir() and d.name == "foldward"
    with pytest.raises(PluginLogError):
        plugin_dir("../escape")


# ------------------------------------------------------------------------------------------------ Foldward rename
def test_quarantine_add_names_foldward_by_default(tmp_path, isolated_home, capsys):
    """Foldward (formerly Agent Guard) no longer passes --source: the default names it."""
    from sentinel_vision import cli
    from sentinel_vision.quarantine import DEFAULT_EXTERNAL_SOURCE

    assert DEFAULT_EXTERNAL_SOURCE == "foldward"
    assert cli.build_parser().parse_args(["quarantine", "add", "x"]).source == DEFAULT_EXTERNAL_SOURCE
    q = Quarantine(tmp_path / "q")
    item = q.get(q.add_external(_file(tmp_path / "w")))
    assert item.engine == "external:foldward" and item.threat == "Sent to quarantine by foldward"
    # items added under the old name keep it, and a caller can still name itself explicitly
    old = q.get(q.add_external(_file(tmp_path / "w2"), "", "agent-guard"))
    assert old.engine == "external:agent-guard"
    f = _file(tmp_path / "w3")
    assert cli.main(["quarantine", "add", str(f), "--reason", "unsigned binary"]) == 0
    item_id = capsys.readouterr().out.strip()
    assert re.fullmatch(r"[0-9a-f]{32}", item_id)  # Foldward relies on the 32-character hex id


def test_the_legacy_agent_guard_log_stays_readable_and_verifiable_next_to_foldward(core, isolated_home, capsys):
    """Records written under the old name are never orphaned: both logs are kept, read and verified separately,
    and writing to one never touches the other (they are separate hash chains, so nothing is copied across)."""
    import json

    from sentinel_vision.cli import main
    from sentinel_vision.plugin_api import PluginLog
    from sentinel_vision.service_client import LocalTransport

    t = LocalTransport(core, ALICE)
    legacy = PluginLog("agent-guard", t)
    legacy.append({"event": "quarantined", "id": "a" * 32})
    legacy.append({"event": "revoked", "agent": "x"})
    new = PluginLog("foldward", t)
    assert new.read() == []  # a new, empty chain
    new.append({"event": "quarantined", "id": "b" * 32})
    assert legacy.verify() == (True, 2) and new.verify() == (True, 1)
    assert [e["record"]["event"] for e in PluginLog("agent-guard", t).read()] == ["quarantined", "revoked"]

    # the same through the command line, with the exit codes Foldward relies on (0 intact)
    for name, count in (("agent-guard", 1), ("foldward", 2)):
        for i in range(count):
            assert main(["plugin-log", "append", name, "--json", json.dumps({"n": i})]) == 0
        capsys.readouterr()
        assert main(["plugin-log", "verify", name]) == 0
        assert json.loads(capsys.readouterr().out)["intact"] is True
    assert main(["plugin-log", "read", "agent-guard"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 1
