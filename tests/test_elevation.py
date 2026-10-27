"""Audit finding SV-A08: only code that only an administrator can change is ever run with administrator rights."""

import sys
from types import SimpleNamespace

import pytest

from sentinel_vision import webshield


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership rules")
def test_user_owned_program_is_refused_with_instructions(tmp_path, monkeypatch):
    exe = tmp_path / "bin" / "sentinel-vision-cli"
    exe.parent.mkdir()
    exe.write_text("#!/bin/sh\n")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "bin" / "SentinelVision"))
    # a drag-and-drop install: the program belongs to the user, not root
    monkeypatch.setattr(webshield.os, "stat", lambda p: SimpleNamespace(st_uid=501, st_mode=0o100755))
    assert "not owned by root" in webshield.elevation_problem(str(exe))
    with pytest.raises(OSError) as exc:
        webshield.elevated_command(["webshield-apply"])
    assert "sudo " in str(exc.value) and "webshield-apply" in str(exc.value)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership rules")
def test_root_owned_program_is_allowed(tmp_path, monkeypatch):
    exe = tmp_path / "sentinel-vision-cli"
    exe.write_text("x")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(webshield.os, "stat", lambda p: SimpleNamespace(st_uid=0, st_mode=0o40755))
    assert webshield.elevation_problem(str(exe)) == ""
    monkeypatch.setattr(webshield.os, "stat", lambda p: SimpleNamespace(st_uid=0, st_mode=0o40777))
    assert "other users" in webshield.elevation_problem(str(exe))


def test_running_from_source_is_never_elevated(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    assert "never" in webshield.elevation_problem(sys.executable)
    if sys.platform != "win32":
        with pytest.raises(OSError):
            webshield.elevated_command(["webshield-apply"])
