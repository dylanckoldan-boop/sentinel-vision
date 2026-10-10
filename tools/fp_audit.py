"""False-positive audit: scan known-clean software and report every detection.

Usage:
    python tools/fp_audit.py [--update] [--max-files N] [--fail-on signature|any|never] DIR [DIR ...]

Runs in report-only mode (nothing is quarantined) with an isolated data directory. Prints a Markdown
report (also appended to $GITHUB_STEP_SUMMARY in CI). Exit code 1 when detections of the --fail-on
class are found:
    signature  hash / ClamAV / YARA high+critical hits (default — these would be auto-quarantined)
    any        any detection, heuristics included
    never      always exit 0
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--update", action="store_true", help="download YARA Forge rules first")
    ap.add_argument("--max-files", type=int, default=0, help="stop after N files (0 = no limit)")
    ap.add_argument("--fail-on", choices=["signature", "any", "never"], default="signature")
    args = ap.parse_args()

    os.environ.setdefault("SENTINEL_VISION_HOME", tempfile.mkdtemp(prefix="sv-fp-audit-"))
    from sentinel_vision.config import Settings
    from sentinel_vision.core import Sentinel

    settings = Settings()
    settings.auto_quarantine = False
    settings.realtime_enabled = settings.network_enabled = False
    settings.feeds = [f for f in settings.feeds if f.kind == "yara_zip"]
    sv = Sentinel(settings)
    if args.update:
        for r in sv.updater.run():
            print(f"{'OK ' if r.ok else 'ERR'} {r.feed}: {r.message}", file=sys.stderr)
        sv.after_update()

    engines = ", ".join(f"{n} ({t})" for n, ok, t in sv.scanner.engine_status() if ok)
    started = time.time()
    scanned = 0
    findings = []
    for path in sv.scanner.iter_files(args.paths):
        if args.max_files and scanned >= args.max_files:
            break
        res = sv.scanner.scan_file(path, act=False, use_cache=False)[0]
        scanned += 1
        if res.infected:
            findings.append(res)

    def is_sig(r) -> bool:
        return any(d.is_signature for d in r.detections)

    sig = [r for r in findings if is_sig(r)]
    heur = [r for r in findings if not is_sig(r)]
    by_name = Counter(d.name for r in findings for d in r.detections)

    lines = [
        "## Sentinel Vision false-positive audit",
        "",
        f"- Platform: `{sys.platform}` · scanned **{scanned:,}** files in {time.time() - started:,.0f}s",
        f"- Paths: {', '.join(f'`{p}`' for p in args.paths)}",
        f"- Engines: {engines}",
        f"- Signature-grade detections (would be auto-quarantined): **{len(sig)}**",
        f"- Heuristic-only detections (report-only): **{len(heur)}**",
        "",
    ]
    if findings:
        lines += ["| File | Detections |", "|---|---|"]
        for r in findings[:300]:
            dets = "; ".join(f"{d.engine}: {d.name} ({d.severity.label})" for d in r.detections)
            lines.append(f"| `{r.path}` | {dets} |")
        lines += ["", "Top detection names:", ""]
        lines += [f"- {name}: {n}" for name, n in by_name.most_common(20)]
    report = "\n".join(lines)
    print(report)
    if os.environ.get("GITHUB_ACTIONS"):
        # annotations are readable from the API and the run page without opening logs
        brief = [
            f"{scanned:,} files · signature-grade: {len(sig)} · heuristic-only: {len(heur)}",
            *[f"{r.path}: " + "; ".join(f"{d.engine}:{d.name}" for d in r.detections) for r in findings[:15]],
        ]
        level = "error" if sig else "notice"
        enc = "\n".join(brief).replace("%", "%25").replace("\r", "").replace("\n", "%0A")
        print(f"::{level} title=False-positive audit ({sys.platform})::{enc}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")
    sv.shutdown()
    if args.fail_on == "never":
        return 0
    if args.fail_on == "any":
        return 1 if findings else 0
    return 1 if sig else 0


if __name__ == "__main__":
    raise SystemExit(main())
