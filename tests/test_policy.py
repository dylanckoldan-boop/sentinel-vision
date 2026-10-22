"""Detection policy: the false alarms from a real Windows full scan must not come back, and real threats must
still be acted on."""

import os

import pytest

from sentinel_vision import policy
from sentinel_vision.engines.base import Detection, ScanObject, Severity
from sentinel_vision.engines.heuristics import HeuristicEngine
from sentinel_vision.scanner import ScanResult


@pytest.mark.parametrize(
    "name,expected",
    [
        ("FIREEYE_RT_APT_Backdoor_Win_Gorat_Memory", policy.MEMORY),
        ("MALPEDIA_Win_Triback_Loader_Auto", policy.GENERATED),
        ("MALPEDIA_Win_Snake_Disk_Auto", policy.GENERATED),
        ("SEKOIA_Tool_Nssm_Strings", policy.TOOL),
        ("ELCEEF_HTML_Smuggling_A", policy.NOISY),
        ("SV_HackTool_Mimikatz", policy.NORMAL),
        ("SV_CoinMiner_Config", policy.NORMAL),
    ],
)
def test_rule_classes(name, expected):
    assert policy.classify_rule(name) == expected


def _custom_rule(isolated_home, text: str):
    from sentinel_vision.config import sub_dir
    from sentinel_vision.engines.yara_engine import YaraEngine

    d = sub_dir("rules/custom")
    (d / "t.yar").write_text(text)
    return YaraEngine()


def test_rule_classes_change_what_the_engine_reports(isolated_home):
    eng = _custom_rule(
        isolated_home,
        """
rule T_Win_Gorat_Memory { meta: severity = "critical" strings: $a = "ZZTOKEN" condition: $a }
rule MALPEDIA_Win_T_Auto { meta: severity = "high" strings: $a = "ZZTOKEN" condition: $a }
rule SEKOIA_Tool_T_Strings { meta: severity = "high" strings: $a = "ZZTOKEN" condition: $a }
rule ELCEEF_HTML_Smuggling_A { meta: severity = "high" strings: $a = "ZZTOKEN" condition: $a }
rule T_Real_Malware { meta: severity = "high" strings: $a = "ZZTOKEN" condition: $a }
""",
    )
    found = {d.name: d for d in eng.scan(ScanObject("f.bin", data=b"..ZZTOKEN.."))}
    assert "T_Win_Gorat_Memory" not in found  # memory-only rules never run on files
    assert found["MALPEDIA_Win_T_Auto"].details["report_only"] and not found["MALPEDIA_Win_T_Auto"].is_signature
    assert found["SEKOIA_Tool_T_Strings"].severity == Severity.LOW
    assert not found["SEKOIA_Tool_T_Strings"].is_signature
    assert not found["ELCEEF_HTML_Smuggling_A"].is_signature
    assert found["T_Real_Malware"].is_signature  # ordinary strong rules still count


@pytest.fixture
def fake_windows_dirs(tmp_path, monkeypatch):
    dirs = {
        "APPDATA": tmp_path / "Roaming",
        "LOCALAPPDATA": tmp_path / "Local",
        "ProgramData": tmp_path / "ProgramData",
        "ProgramFiles": tmp_path / "Program Files",
        "ProgramFiles(x86)": tmp_path / "Program Files (x86)",
    }
    for k, v in dirs.items():
        v.mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(k, str(v))
    monkeypatch.setattr(policy.sys, "platform", "win32")
    import tempfile

    (dirs["LOCALAPPDATA"] / "Temp").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(dirs["LOCALAPPDATA"] / "Temp"))
    return dirs


def test_locations(fake_windows_dirs):
    d = fake_windows_dirs
    assert policy.location(str(d["ProgramFiles(x86)"] / "Steam" / "libavif-16.dll")) == "program"
    assert policy.location(str(d["LOCALAPPDATA"] / "Google" / "Chrome" / "Cache" / "f_003a82")) == "appdata"
    assert policy.location(str(d["LOCALAPPDATA"] / "Temp" / "dropper.exe")) == "user"  # temp is never trusted
    assert policy.location(os.path.expanduser("~/Downloads/invoice.exe")) == "user"


def test_file_kinds():
    assert policy.file_kind(b"MZ\x90\x00", "a.dll") == "program"
    assert policy.file_kind(b"var x = 1;", "olAppHost.js") == "script"
    assert policy.file_kind(b"\x00\x01binary", "f_003a82") == "data"
    assert policy.file_kind(b"{json}", "0D8272A1877B54F367B8.cachedmsg") == "data"


def _res(path, kind, where, *dets):
    return ScanResult(path, detections=list(dets), kind=kind, where=where)


def test_quarantine_decisions(sentinel, fake_windows_dirs):
    d = fake_windows_dirs
    sc = sentinel.scanner
    strong = Detection("yara", "SV_Something_Bad", Severity.HIGH)
    exact = Detection("hash", "Known.Bad", Severity.CRITICAL)
    hint = Detection("yara", "MALPEDIA_X_Auto", Severity.MEDIUM, details={"report_only": True})
    cache = str(d["LOCALAPPDATA"] / "Packages" / "Claude" / "blob" / "4b")
    steam = str(d["ProgramFiles(x86)"] / "Steam" / "userdata" / "x.cachedmsg")
    dropped = str(d["APPDATA"] / "evil" / "update.exe")
    # a pattern match in a cache / app database: reported, not quarantined (the Claude and Chrome cases)
    assert sc.should_quarantine(_res(cache, "data", "appdata", strong)) is False
    # anything in an installed program's folder: reported (the Steam case)
    assert sc.should_quarantine(_res(steam, "data", "program", strong)) is False
    # a program dropped into AppData by malware is still quarantined
    assert sc.should_quarantine(_res(dropped, "program", "appdata", strong)) is True
    # hints alone never quarantine
    assert sc.should_quarantine(_res(dropped, "program", "user", hint)) is False
    # exact known-malware matches are always acted on, wherever they are
    assert sc.should_quarantine(_res(steam, "data", "program", exact)) is True
    assert sc.should_quarantine(_res(cache, "data", "appdata", exact)) is True


def test_location_context_hides_low_confidence_guesses_in_program_folders():
    from sentinel_vision.scanner import Scanner

    office_js = _res(
        r"C:\Program Files\Microsoft Office\root\Office16\olAppHost.js",
        "script",
        "program",
        Detection("heuristics", "Heuristic.CoinMiner", Severity.MEDIUM),
    )
    Scanner._apply_location_context(office_js)
    assert office_js.detections == []
    downloads = _res("C:/Users/x/Downloads/a.js", "script", "user", Detection("heuristics", "H.X", Severity.MEDIUM))
    Scanner._apply_location_context(downloads)
    assert downloads.detections  # outside program folders, guesses are still shown


def test_coinminer_heuristic_needs_a_real_pool_and_miner_settings():
    h = HeuristicEngine(threshold=60)
    mention = b"// this script references xmrig and stratum+tcp:// for documentation"
    assert not [d for d in h.scan(ScanObject("a.js", data=mention)) if d.name == "Heuristic.CoinMiner"]
    cfg = b'{"pools":[{"url":"stratum+tcp://pool.example.org:3333"}],"donate-level":1,"algo":"rx/0"}'
    assert [d for d in h.scan(ScanObject("config.json", data=cfg)) if d.name == "Heuristic.CoinMiner"]


def test_findings_in_program_and_system_folders_are_items_to_review():
    from sentinel_vision.scanner import Scanner

    tool = _res(
        "/opt/ansible/modules/psexec.py",
        "script",
        "program",
        Detection("yara", "SV_PowerShell_Download_Cradle", Severity.HIGH),
        Detection("hash", "Known.Bad", Severity.CRITICAL),
    )
    Scanner._apply_location_context(tool)
    yara_hit = next(d for d in tool.detections if d.engine == "yara")
    exact = next(d for d in tool.detections if d.engine == "hash")
    assert yara_hit.details.get("report_only") and not yara_hit.is_signature
    assert not exact.details.get("report_only") and exact.is_signature  # known malware stays a threat
