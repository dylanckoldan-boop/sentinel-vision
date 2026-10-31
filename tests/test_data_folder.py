"""Audit finding SV-A06: the data folder is scanned, except Sentinel Vision's own files."""

from sentinel_vision.config import data_dir, sub_dir


def test_own_files_are_skipped_and_anything_else_is_scanned(sentinel):
    sc = sentinel.scanner
    root = data_dir()
    rule = sub_dir("rules/downloaded") / "forge.yar"
    rule.write_text('rule X { strings: $a = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}$EICAR" condition: $a }')
    assert sc.is_excluded(str(rule))  # rule text full of malware strings is never "detected"
    for own in ("sentinel.db", "settings.json", "logs/sentinel.log", "logs/sentinel.log.1", "vault/blobs/ab/x.svb",
                "quarantine/1.svq", "feeds/networks.txt"):  # fmt: skip
        assert sc.is_excluded(str(root / own)), own
    for other in ("logs/update-helper.exe", "rules/run.ps1", "plugins/foldward/tool.py", "evil.dll"):
        assert not sc.is_excluded(str(root / other)), other


def test_a_program_in_the_data_folder_is_reported(sentinel):
    planted = data_dir() / "logs" / "helper.exe"
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_bytes(b"MZ" + b"\0" * 200)
    results = sentinel.scanner.scan_file(planted, act=False)
    names = [d.name for r in results for d in r.detections]
    assert "Suspicious.UnexpectedFileInDataFolder" in names
    assert planted.exists()  # reported for review, not removed on location alone
