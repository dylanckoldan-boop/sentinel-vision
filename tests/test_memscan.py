import subprocess
import sys
import time

import pytest

from sentinel_vision import memscan

MARKER = "SV_MEMTEST_" + "Q7" * 12  # assembled at runtime; never present in this file as one string


def test_memory_scan_finds_injected_marker_in_running_process(sentinel):
    from sentinel_vision.config import sub_dir

    (sub_dir("rules/custom") / "memtest.yar").write_text(
        'rule SV_Memtest_Marker { meta: severity = "high" strings: $m = "' + MARKER + '" condition: $m }'
    )
    sentinel.scanner.reload_signatures()
    code = "import time\npayload = ''.join(['SV_MEMTEST_', 'Q7' * 12]) * 50\ntime.sleep(60)\n"
    proc = subprocess.Popen([sys.executable, "-c", code])
    try:
        time.sleep(1.5)
        summary = memscan.scan_processes(sentinel.scanner, pids=[proc.pid])
        if summary.denied and sys.platform == "darwin":
            pytest.skip("macOS requires root to read another process's memory")
        assert summary.scanned == 1, summary
        assert summary.hits and summary.hits[0].pid == proc.pid
        assert summary.hits[0].rules[0][0] == "SV_Memtest_Marker"
        assert any(d.origin == "memory" for d in sentinel.db.recent_detections())
        assert proc.poll() is None  # report-only: never killed
    finally:
        proc.kill()
        proc.wait()


def test_memory_scan_skips_itself(sentinel):
    import os

    summary = memscan.scan_processes(sentinel.scanner, pids=[os.getpid()])
    assert summary.scanned == 0 and summary.skipped == 1
