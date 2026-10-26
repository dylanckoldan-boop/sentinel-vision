"""Seams for companion programs such as Agent Guard: `quarantine add`, `net block`, plugin log, plugin host.
Sentinel Vision never imports those programs; they call the command line or plug into documented entry points."""

import os
import sys

import pytest

from sentinel_vision.quarantine import Quarantine, QuarantineError
from test_servicecore import ALICE, BOB, FakeApplier


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
    item_id = q.add_external(str(f), "agent fetched an unsigned binary", "agent-guard")
    assert not f.exists()  # moved, like automatic quarantine
    item = q.get(item_id)
    assert item.threat == "agent fetched an unsigned binary" and item.engine == "external:agent-guard"
    restored = q.restore(item_id)
    assert restored.read_bytes() == b"agent payload " * 100


def test_add_external_through_the_protected_service(core, tmp_path):
    from sentinel_vision.service_client import LocalTransport, RemoteQuarantine

    q = RemoteQuarantine(LocalTransport(core, ALICE))
    f = _file(tmp_path / "work")
    item_id = q.add_external(f, "", "agent-guard")
    assert not f.exists()
    assert q.get(item_id).threat == "Sent to quarantine by agent-guard"
    assert [i.id for i in RemoteQuarantine(LocalTransport(core, BOB)).list()] == []  # other accounts can't see it
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
        q.add_external(_file(data_dir() / "x"), "", "agent-guard")  # Sentinel Vision's own data
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

    alice = PluginLog("agent-guard", LocalTransport(core, ALICE))
    assert alice.protected
    assert alice.append({"event": "quarantined", "id": "abc"}) == 1
    assert alice.append({"event": "revoked", "agent": "x"}) == 2
    entries = alice.read()
    assert [e["record"]["event"] for e in entries] == ["quarantined", "revoked"] and entries[0]["pid"] == ALICE.pid
    assert alice.verify() == (True, 2)
    assert PluginLog("agent-guard", LocalTransport(core, BOB)).read() == []  # each account has its own log
    with pytest.raises(ServiceError):  # reading someone else's log needs administrator rights
        core.handle(BOB, "plugin.read", {"name": "agent-guard", "sid": ALICE.sid})
    for bad in ("../../policy", "Agent Guard", "", "a" * 41):
        with pytest.raises(ServiceError):
            core.handle(ALICE, "plugin.append", {"name": bad, "record": {}})
    # there is no request that edits or deletes records
    assert not [
        op for op in dir(core) if op.startswith("op_plugin") and op not in ("op_plugin_append", "op_plugin_read")
    ]


def test_plugin_log_refuses_to_fall_back_when_the_service_is_installed_but_down(monkeypatch):
    from sentinel_vision import plugin_api, service_client

    monkeypatch.setattr(service_client, "connect", lambda *a, **k: None)
    monkeypatch.setattr(service_client, "service_installed", lambda: True)
    with pytest.raises(plugin_api.PluginLogError):
        plugin_api.plugin_log("agent-guard")


def test_plugin_log_cli(capsys, isolated_home):
    import json

    from sentinel_vision.cli import main

    assert main(["plugin-log", "append", "agent-guard", "--json", '{"event": "test"}']) == 0
    assert capsys.readouterr().out.strip() == "1"
    assert main(["plugin-log", "read", "agent-guard"]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[0])["record"] == {"event": "test"}
    assert main(["plugin-log", "verify", "agent-guard"]) == 0
    assert json.loads(capsys.readouterr().out)["intact"] is True
    assert main(["plugin-log", "append", "agent-guard", "--json", "not json"]) == 2
    assert main(["plugin-log", "append", "../x", "--json", "{}"]) == 2


def test_plugin_dir_is_private_and_named_safely(isolated_home):
    from sentinel_vision.config import plugin_dir
    from sentinel_vision.pluginlog import PluginLogError

    d = plugin_dir("agent-guard")
    assert d.is_dir() and d.name == "agent-guard"
    with pytest.raises(PluginLogError):
        plugin_dir("../escape")
