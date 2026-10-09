"""Command-line interface (headless servers, scripting, CI).

    sentinel-vision-cli scan PATH... [--no-quarantine] [--json]
    sentinel-vision-cli quick | processes
    sentinel-vision-cli update
    sentinel-vision-cli quarantine list | restore ID [--to DIR] | delete ID
    sentinel-vision-cli net [--watch]
    sentinel-vision-cli daemon          # real-time, behavior + network monitoring without a GUI
    sentinel-vision-cli status
    sentinel-vision-cli autostart [on|off|status]
    sentinel-vision-cli check-update

Exit codes: 0 clean, 1 threats found, 2 error.
"""

from __future__ import annotations

import argparse
import json
import signal
import sys
import threading
import time

from sentinel_vision import APP_NAME, __version__
from sentinel_vision.core import Sentinel, setup_logging
from sentinel_vision.scanner import ScanResult, ScanSummary, bytes_human

RED, YEL, GRN, DIM, RST = "\033[31m", "\033[33m", "\033[32m", "\033[2m", "\033[0m"


def _c(code: str, text: str) -> str:
    return f"{code}{text}{RST}" if sys.stdout.isatty() else text


def _print_result(r: ScanResult) -> None:
    if r.infected:
        print(_c(RED, f"[THREAT] {r.path}"))
        for d in r.detections:
            print(f"         {d.engine:<10} {d.name}  ({d.severity.label})")
        print(f"         action: {r.action}")
    elif r.error:
        print(_c(YEL, f"[ERROR]  {r.path}: {r.error}"))


def _summary(s: ScanSummary) -> None:
    color = RED if s.infected else GRN
    print(
        _c(
            color,
            f"\n{s.scanned:,} files scanned ({bytes_human(s.bytes)}) in {s.duration:.1f}s — "
            f"{s.infected} infected, {s.errors} errors, {s.skipped} skipped",
        )
    )


def cmd_scan(sv: Sentinel, args) -> int:
    if args.no_quarantine:
        sv.settings.auto_quarantine = False
    cancel = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: cancel.set())
    results: list[ScanResult] = []
    if args.command == "processes":
        s = sv.scanner.scan_processes(on_result=results.append, cancel=cancel)
    else:
        roots = sv.scanner.quick_scan_roots() if args.command == "quick" else args.paths
        on = results.append if args.json else (lambda r: (results.append(r), _print_result(r)))
        s = sv.scanner.scan_paths(roots, on_result=on, cancel=cancel, use_cache=not args.rescan)
        if args.command == "quick":
            p = sv.scanner.scan_processes(on_result=on, cancel=cancel)
            s.scanned += p.scanned
            s.infected += p.infected
    if args.json:
        print(
            json.dumps(
                {
                    "scanned": s.scanned,
                    "infected": s.infected,
                    "errors": s.errors,
                    "duration": s.duration,
                    "results": [
                        {
                            "path": r.path,
                            "sha256": r.sha256,
                            "action": r.action,
                            "error": r.error,
                            "detections": [
                                {
                                    "engine": d.engine,
                                    "name": d.name,
                                    "severity": d.severity.label,
                                    "description": d.description,
                                }
                                for d in r.detections
                            ],
                        }
                        for r in results
                    ],
                },
                indent=2,
            )
        )
    else:
        if args.command == "processes":
            for r in results:
                _print_result(r)
        _summary(s)
    return 1 if s.infected else 0


def cmd_update(sv: Sentinel, _args) -> int:
    results = sv.updater.run(lambda m: print(_c(DIM, m)))
    sv.after_update()
    for r in results:
        print(f"{_c(GRN, '✓') if r.ok else _c(RED, '✗')} {r.feed}: {r.message}")
    return 0 if any(r.ok for r in results) else 2


def cmd_quarantine(sv: Sentinel, args) -> int:
    q = sv.quarantine
    if args.action == "list":
        items = q.list()
        for i in items:
            print(f"{i.id}  {time.strftime('%Y-%m-%d %H:%M', time.localtime(i.ts))}  {i.threat:<40} {i.original_path}")
        print(_c(DIM, f"{len(items)} item(s)"))
    elif args.action == "restore":
        print(f"Restored to {q.restore(args.id, args.to)}")
    elif args.action == "delete":
        q.delete(args.id)
        print("Deleted.")
    return 0


def cmd_net(sv: Sentinel, args) -> int:
    def show() -> None:
        snap = sv.network.poll()
        rows = [c for c in snap.connections if c.rip or c.status == "LISTEN"]
        print(f"{'PROCESS':<22}{'PID':>7}  {'PROTO':<6}{'LOCAL':<24}{'REMOTE':<28}{'STATE':<13}ASSESSMENT")
        for c in rows:
            line = (
                f"{c.process[:21]:<22}{c.pid or '':>7}  {c.proto:<6}{c.local[:23]:<24}"
                f"{c.remote[:27]:<28}{c.status[:12]:<13}{c.threat}"
            )
            print(_c(RED, line) if c.severity >= 2 else _c(YEL, line) if c.severity == 1 else line)
        print(
            _c(
                DIM,
                f"↓ {bytes_human(snap.down_bps)}/s  ↑ {bytes_human(snap.up_bps)}/s · "
                f"{snap.established} established · {snap.listening} listening · {snap.threats} alerts",
            )
        )
        if snap.error:
            print(_c(YEL, snap.error))

    sv.network.poll()
    time.sleep(1)
    if not args.watch:
        show()
        return 0
    try:
        while True:
            print("\033[2J\033[H", end="")
            show()
            time.sleep(sv.settings.network_poll_seconds)
    except KeyboardInterrupt:
        return 0


def cmd_daemon(sv: Sentinel, _args) -> int:
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    sv.realtime.on_result = lambda r: _print_result(r)
    sv.network.add_listener(lambda c: print(_c(RED, f"[NET] {c.process} ({c.pid}) → {c.remote}: {c.threat}")))
    sv.behavior.add_listener(
        lambda e: print(_c(RED, f"[BEHAVIOR] {e.name}: {e.process or e.path} — {e.description} → {e.action}"))
    )
    sv.start_protection()
    print(f"{APP_NAME} daemon running. Watching: {', '.join(sv.realtime.watching) or 'nothing'}")
    print(
        f"  behavior monitoring: {'on' if sv.behavior.running else 'off'} · "
        f"network monitoring: {'on' if sv.network.running else 'off'}"
    )
    for e in sv.realtime.errors:
        print(_c(YEL, e))
    while not stop.wait(60):
        if sv.updater.due():
            sv.updater.run()
            sv.after_update()
    sv.shutdown()
    return 0


def cmd_autostart(_sv: Sentinel, args) -> int:
    from sentinel_vision import autostart

    if args.state in ("on", "off"):
        autostart.set_enabled(args.state == "on")
    st = autostart.status()
    scope = f" ({st.scope})" if st.enabled else ""
    print(f"Start at sign-in: {'on' if st.enabled else 'off'}{scope}")
    if st.enabled:
        print(f"  command: {st.command}")
    return 0


def cmd_check_update(_sv: Sentinel, _args) -> int:
    from sentinel_vision import app_update

    info = app_update.check_latest()
    if info is None:
        print(f"Sentinel Vision {__version__} is the latest version.")
        return 0
    print(f"Sentinel Vision {info.version} is available (installed: {__version__}).")
    print(f"  {info.page_url}")
    return 0


def cmd_status(sv: Sentinel, _args) -> int:
    print(f"{APP_NAME} {__version__}")
    for name, ok, text in sv.scanner.engine_status():
        print(f"  {_c(GRN if ok else YEL, '●')} {name:<16} {text}")
    last = sv.updater.last_update
    print(f"  definitions updated: {time.strftime('%Y-%m-%d %H:%M', time.localtime(last)) if last else 'never'}")
    print(f"  malicious networks:  {sv.intel.count:,}")
    print(f"  quarantined items:   {len(sv.quarantine.list())}")
    try:
        from sentinel_vision import autostart

        print(f"  start at sign-in:    {'on' if autostart.is_enabled() else 'off'}")
    except Exception as exc:  # status must never fail because of this
        print(f"  start at sign-in:    unknown ({exc})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sentinel-vision-cli", description=f"{APP_NAME} command-line scanner")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)
    for name, helptext in (
        ("scan", "scan files or folders"),
        ("quick", "quick scan"),
        ("processes", "scan running programs"),
    ):
        sp = sub.add_parser(name, help=helptext)
        if name == "scan":
            sp.add_argument("paths", nargs="+")
        sp.add_argument("--no-quarantine", action="store_true", help="report only")
        sp.add_argument("--rescan", action="store_true", help="ignore the clean-file cache")
        sp.add_argument("--json", action="store_true")
    sub.add_parser("update", help="download latest definitions")
    q = sub.add_parser("quarantine", help="manage quarantine")
    q.add_argument("action", choices=["list", "restore", "delete"])
    q.add_argument("id", nargs="?")
    q.add_argument("--to", help="restore into this folder")
    n = sub.add_parser("net", help="show live connections")
    n.add_argument("--watch", action="store_true")
    sub.add_parser("daemon", help="run real-time, behavior and network protection without GUI")
    sub.add_parser("status", help="engine status")
    a = sub.add_parser("autostart", help="start the app automatically at sign-in")
    a.add_argument("state", nargs="?", choices=["on", "off", "status"], default="status")
    sub.add_parser("check-update", help="check GitHub for a newer version of Sentinel Vision")
    return p


def _safe_console() -> None:
    """Never crash on characters the console/pipe encoding can't show (e.g. cp1252 on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _safe_console()
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    if args.command == "quarantine" and args.action != "list" and not args.id:
        print("quarantine restore/delete needs an ID (see `quarantine list`)", file=sys.stderr)
        return 2
    try:
        sv = Sentinel()
        handler = {
            "scan": cmd_scan,
            "quick": cmd_scan,
            "processes": cmd_scan,
            "update": cmd_update,
            "quarantine": cmd_quarantine,
            "net": cmd_net,
            "daemon": cmd_daemon,
            "status": cmd_status,
            "autostart": cmd_autostart,
            "check-update": cmd_check_update,
        }[args.command]
        return handler(sv, args)
    except KeyboardInterrupt:
        return 2
    except Exception as exc:
        print(_c(RED, f"error: {exc}"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
