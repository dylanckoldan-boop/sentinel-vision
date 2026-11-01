"""The command-line contract with companion programs (docs/plugin-contract.json), checked against the real tool.

Foldward keeps a copy of the contract and replays its examples in its own tests, so a change here that isn't
reflected in the contract file (and in plugin_api.API_VERSION when it breaks callers) fails this test first."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

from sentinel_vision import __version__, plugin_api

CONTRACT = json.loads((Path(__file__).resolve().parent.parent / "docs" / "plugin-contract.json").read_text("utf-8"))


def _cases(name: str) -> dict:
    [command] = [c for c in CONTRACT["commands"] if c["name"] == name]
    return {c["case"]: c for c in command["cases"]}


def _run(capsys, argv: list[str]) -> tuple[int, str, str]:
    from sentinel_vision.cli import main

    try:
        code = main(argv)
    except SystemExit as exc:  # argparse's --version
        code = int(exc.code or 0)
    out = capsys.readouterr()
    return code, out.out, out.err


def _check(case: dict, code: int, out: str) -> None:
    assert code == case["exit"], f"{case['case']}: exit {code}, the contract says {case['exit']}"
    if "stdout_pattern" in case:
        assert re.fullmatch(case["stdout_pattern"], out), f"{case['case']}: unexpected output {out!r}"
    if "json_keys" in case:
        assert sorted(json.loads(out)) == sorted(case["json_keys"])


def test_the_contract_describes_this_version():
    assert CONTRACT["sentinel_vision"] == __version__
    assert CONTRACT["plugin_api_version"] == plugin_api.API_VERSION
    assert set(CONTRACT["exit_codes"]) == {"0", "1", "2", "3"}


def test_the_contract_examples_follow_the_contract():
    for command in CONTRACT["commands"]:
        for case in command["cases"]:
            if "stdout_pattern" in case:
                assert re.fullmatch(case["stdout_pattern"], case["example"]), (command["name"], case["case"])
            if "json_keys" in case:
                assert sorted(json.loads(case["example"])) == sorted(case["json_keys"]), (command["name"], case["case"])


def test_version(capsys):
    code, out, _ = _run(capsys, ["--version"])
    _check(_cases("version")["ok"], code, out)


def test_quarantine_add(tmp_path, capsys, isolated_home, monkeypatch):
    from sentinel_vision import scanner

    cases = _cases("quarantine add")
    f = tmp_path / "work" / "agent.bin"
    f.parent.mkdir()
    f.write_bytes(b"MZ fake agent")
    code, out, _ = _run(capsys, ["quarantine", "add", "--reason", "contained by Foldward", "--", str(f)])
    _check(cases["moved"], code, out)
    assert not f.exists()

    code, out, err = _run(capsys, ["quarantine", "add", "--reason", "x", "--", str(tmp_path / "missing.bin")])
    _check(cases["error"], code, out)
    assert err.startswith("error:")

    g = tmp_path / "work" / "system.bin"
    g.write_bytes(b"MZ")
    monkeypatch.setattr(scanner, "is_system_path", lambda p: True)
    code, out, err = _run(capsys, ["quarantine", "add", "--reason", "x", "--", str(g)])
    _check(cases["refused"], code, out)
    assert "operating-system files" in err and g.exists()


@pytest.mark.parametrize(
    ("argv", "path"),
    [
        (["quarantine", "add", "--reason", "r", "--", "-agent.bin"], "-agent.bin"),  # the contract's form
        (["quarantine", "add", "--reason", "r", "--source", "foldward", "--", "/x/a.bin"], "/x/a.bin"),
        (["quarantine", "add", "/x/a.bin", "--reason", "r"], "/x/a.bin"),  # the form documented before 0.5.2
        (["quarantine", "add", "--reason", "r", "/x/a.bin"], "/x/a.bin"),
    ],
)
def test_quarantine_add_parses_on_every_supported_python(argv, path):
    # argparse before 3.12.7 rejected an option before an optional positional; each action now has its own parser
    from sentinel_vision.cli import build_parser

    args = build_parser().parse_args(argv)

    assert (args.action, args.id, args.reason) == ("add", path, "r")


@pytest.mark.skipif(sys.platform == "win32", reason="creating links needs extra rights on Windows")
def test_quarantine_add_refuses_a_link(tmp_path, capsys, isolated_home):
    target = tmp_path / "real.bin"
    target.write_bytes(b"MZ")
    link = tmp_path / "link.bin"
    os.symlink(target, link)

    code, out, _ = _run(capsys, ["quarantine", "add", "--reason", "x", "--", str(link)])

    _check(_cases("quarantine add")["refused"], code, out)
    assert target.exists()


def test_plugin_log(capsys, isolated_home, monkeypatch):
    from sentinel_vision import pluginlog
    from sentinel_vision.config import sub_dir

    append, verify = _cases("plugin-log append"), _cases("plugin-log verify")
    code, out, _ = _run(capsys, ["plugin-log", "append", "foldward", "--json", '{"event": "pacify"}'])
    _check(append["appended"], code, out)
    code, out, _ = _run(capsys, ["plugin-log", "append", "foldward", "--json", "not json"])
    _check(append["error"], code, out)
    code, out, _ = _run(capsys, ["plugin-log", "verify", "foldward"])
    _check(verify["intact"], code, out)

    monkeypatch.setattr(pluginlog, "MAX_LOG", 1)  # since 0.5.3 a companion program can tell a full log apart
    code, out, err = _run(capsys, ["plugin-log", "append", "foldward", "--json", '{"event": "pacify"}'])
    _check(append["full"], code, out)
    assert err == append["full"]["example_stderr"]
    monkeypatch.undo()

    _run(capsys, ["plugin-log", "append", "foldward", "--json", '{"event": "second"}'])
    log = sub_dir("plugins") / "foldward" / "log.jsonl"
    lines = log.read_text("utf-8").splitlines()
    first = json.loads(lines[0])
    first["record"] = {"event": "changed afterwards"}
    log.write_text("\n".join([json.dumps(first), *lines[1:]]) + "\n", "utf-8")
    code, out, _ = _run(capsys, ["plugin-log", "verify", "foldward"])
    _check(verify["broken"], code, out)


def test_net_block(capsys, isolated_home, monkeypatch):
    from sentinel_vision.network import firewall

    cases = _cases("net block")
    real = firewall.block_ip
    monkeypatch.setattr(firewall, "block_ip", lambda ip: f"Blocked {ip} in the system firewall.")
    code, out, _ = _run(capsys, ["net", "block", "--", "45.12.10.9"])
    _check(cases["blocked"], code, out)
    monkeypatch.setattr(firewall, "block_ip", real)
    for bad in ("192.168.0.1", "-h"):  # refused by the real validation, before any firewall call
        code, out, _ = _run(capsys, ["net", "block", "--", bad])
        _check(cases["error"], code, out)


def test_scan(workdir, eicar, capsys):
    cases = _cases("scan")
    clean = workdir / "ok.txt"
    clean.write_text("ok")
    code, out, _ = _run(capsys, ["scan", "--no-quarantine", "--json", "--", str(clean)])
    _check(cases["clean"], code, out)
    assert json.loads(out)["threats"] == 0

    bad = workdir / "agent.com"
    bad.write_bytes(eicar)
    code, out, _ = _run(capsys, ["scan", "--no-quarantine", "--json", "--", str(bad)])
    _check(cases["threats"], code, out)
    assert json.loads(out)["threats"] >= 1
    assert bad.exists()
