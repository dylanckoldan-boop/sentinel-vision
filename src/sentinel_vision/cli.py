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
    sentinel-vision-cli checkup [--json]          # security checkup with score
    sentinel-vision-cli memscan                   # fileless-malware memory scan
    sentinel-vision-cli rollback list | versions FILE | restore ID | since "YYYY-MM-DD HH:MM" [--folder DIR]
    sentinel-vision-cli webshield status | check URL | enable | refresh | disable
    sentinel-vision-cli password-check            # k-anonymity breach check
    sentinel-vision-cli shred PATH... [--yes]

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
    sv.ransomware.add_listener(
        lambda inc: print(
            _c(
                RED,
                f"[RANSOMWARE] {inc.detail}; suspended: "
                f"{', '.join(f'{s.name} ({s.pid})' for s in inc.suspects if s.state == 'suspended') or 'none'}",
            )
        )
    )
    sv.alert_listeners.append(
        lambda title, text, level: print(_c(RED if level == "danger" else YEL, f"[{title}] {text}"))
    )
    while not stop.wait(60):
        if sv.updater.due():
            sv.updater.run()
            sv.after_update()
        sv.run_due_scans()
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


def cmd_checkup(sv: Sentinel, args) -> int:
    from sentinel_vision import advisor

    checks = advisor.run_checkup(sv, None if args.json else (lambda m: print(_c(DIM, m))))
    if args.json:
        print(json.dumps({"score": advisor.score(checks), "checks": [c.__dict__ for c in checks]}, indent=2))
        return 0
    marks = {"pass": (GRN, "✓"), "warn": (YEL, "!"), "fail": (RED, "✗"), "unknown": (DIM, "?"), "info": (DIM, "i")}
    for c in checks:
        color, mark = marks.get(c.status, (DIM, "?"))
        print(f"{_c(color, mark)} {c.title}: {c.detail}")
        if c.status in ("warn", "fail") and c.fix:
            print(_c(DIM, f"    fix: {c.fix}"))
    sc = advisor.score(checks)
    print(_c(GRN if sc >= 80 else YEL if sc >= 50 else RED, f"\nSecurity score: {sc}/100"))
    return 0


def cmd_memscan(sv: Sentinel, _args) -> int:
    from sentinel_vision import memscan

    summary = memscan.scan_processes(sv.scanner)
    for h in summary.hits:
        print(_c(RED, f"[MEMORY] {h.name} (PID {h.pid}) {h.exe}"))
        for rule, _sev in h.rules:
            print(f"         {rule}")
    print(
        f"{summary.scanned} processes scanned, {len(summary.hits)} with findings, {summary.denied} not accessible "
        f"(run as administrator to include them), {summary.skipped} skipped, {summary.duration:.0f}s"
    )
    return 1 if summary.hits else 0


def cmd_rollback(sv: Sentinel, args) -> int:
    v = sv.vault
    if args.action == "list":
        files, versions, used = v.stats()
        for path, n, ts in v.files(200):
            print(f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))}  {n:>3} version(s)  {path}")
        print(_c(DIM, f"{files} files, {versions} versions, {bytes_human(used)} stored"))
        return 0
    if args.action == "versions":
        for ver in v.versions(args.target):
            flag = "  (looked encrypted)" if ver.suspect else ""
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ver.ts))
            print(f"{ver.id:>7}  {when}  {bytes_human(ver.size)}{flag}")
        return 0
    if args.action == "restore":
        print(f"Restored to {v.restore(int(args.target), args.to)}")
        return 0
    since = time.mktime(time.strptime(args.target, "%Y-%m-%d %H:%M"))
    results = v.rollback(since, args.folder)
    for path, result in results:
        print(f"{_c(GRN if result == 'restored' else YEL, result):<20} {path}")
    print(f"{sum(r == 'restored' for _, r in results)} file(s) restored")
    return 0


def cmd_webshield(sv: Sentinel, args) -> int:
    from sentinel_vision import webshield

    if args.action == "check":
        if not args.url:
            print("usage: webshield check URL", file=sys.stderr)
            return 2
        verdict = webshield.check_url(args.url, sv.domains)
        color = {"dangerous": RED, "suspicious": RED, "caution": YEL}.get(verdict.verdict, GRN)
        print(_c(color, f"{verdict.verdict.upper()} ({verdict.score}/100)  {verdict.host}"))
        for r in verdict.reasons:
            print(f"  - {r}")
        return 1 if verdict.verdict in ("dangerous", "suspicious") else 0
    if args.action == "status":
        print(f"Known malicious/phishing domains: {sv.domains.count():,}")
        print(f"System-wide blocking: {webshield.hosts_status():,} domains in {webshield.hosts_path()}")
        return 0
    if args.action == "enable":
        sv.settings.webshield_block_hosts = True
        sv.settings.save()
    if args.action == "disable":
        sv.settings.webshield_block_hosts = False
        sv.settings.save()
    sub = (
        ["webshield-apply", "--db", str(sv.domains.path)]
        if args.action in ("enable", "refresh")
        else ["webshield-remove"]
    )
    if _is_admin():
        return _webshield_privileged(sub)
    return webshield.run_elevated(sub)


def _is_admin() -> bool:
    from sentinel_vision.network.firewall import is_admin

    return is_admin()


def _webshield_privileged(argv: list[str]) -> int:
    """Runs as administrator/root. Touches nothing but the hosts file (and reads the domain database)."""
    from pathlib import Path

    from sentinel_vision import webshield

    if argv[0] == "webshield-remove":
        webshield.remove_hosts()
        print("Web Shield blocking removed from the hosts file.")
        return 0
    db_path = Path(argv[argv.index("--db") + 1])
    if not db_path.is_file():
        print(f"domain database not found: {db_path}", file=sys.stderr)
        return 2
    intel = webshield.DomainIntel(db_path)
    try:
        n = webshield.apply_hosts(intel.hosts_for_blocking())
    finally:
        intel.close()
    print(f"Web Shield blocking active: {n:,} domains.")
    return 0


def cmd_password_check(_sv: Sentinel, _args) -> int:
    import getpass

    from sentinel_vision.reputation import password_breach_count, password_strength

    pw = getpass.getpass("Password to check (not shown, never sent): ")
    _score, label = password_strength(pw)
    count = password_breach_count(pw)
    if count:
        print(_c(RED, f"Found in {count:,} known data breaches. Stop using this password everywhere."))
    else:
        print(_c(GRN, "Not found in known breaches."))
    print(f"Estimated strength: {label}")
    return 1 if count else 0


def cmd_shred(_sv: Sentinel, args) -> int:
    from sentinel_vision.devices import shred

    if not args.yes:
        answer = input(f"Permanently destroy {len(args.paths)} item(s)? This cannot be undone. Type YES: ")
        if answer.strip() != "YES":
            print("Cancelled.")
            return 2
    failed = 0
    for path, result in shred(args.paths):
        failed += result != "shredded"
        print(f"{result:<12} {path}")
    return 1 if failed else 0


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
    c = sub.add_parser("checkup", help="security checkup of this computer, with a score")
    c.add_argument("--json", action="store_true")
    sub.add_parser("memscan", help="scan the memory of running programs for fileless malware")
    r = sub.add_parser("rollback", help="ransomware rollback vault")
    r.add_argument("action", choices=["list", "versions", "restore", "since"])
    r.add_argument("target", nargs="?", help="file path (versions), version id (restore) or 'YYYY-MM-DD HH:MM'")
    r.add_argument("--to", help="restore into this folder instead of the original location")
    r.add_argument("--folder", help="with 'since': only files in this folder")
    w = sub.add_parser("webshield", help="malicious/phishing website protection")
    w.add_argument("action", choices=["status", "check", "enable", "refresh", "disable"])
    w.add_argument("url", nargs="?")
    sub.add_parser("password-check", help="check whether a password appeared in data breaches (k-anonymity)")
    sh = sub.add_parser("shred", help="securely delete files or folders")
    sh.add_argument("paths", nargs="+")
    sh.add_argument("--yes", action="store_true", help="don't ask for confirmation")
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
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("webshield-apply", "webshield-remove"):
        # privileged helper invoked through UAC / pkexec / osascript: no Sentinel instance, hosts file only
        try:
            return _webshield_privileged(argv)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    args = build_parser().parse_args(argv)
    setup_logging(args.verbose)
    if args.command == "quarantine" and args.action != "list" and not args.id:
        print("quarantine restore/delete needs an ID (see `quarantine list`)", file=sys.stderr)
        return 2
    if args.command == "rollback" and args.action != "list" and not args.target:
        print("rollback versions/restore/since needs a target (see --help)", file=sys.stderr)
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
            "checkup": cmd_checkup,
            "memscan": cmd_memscan,
            "rollback": cmd_rollback,
            "webshield": cmd_webshield,
            "password-check": cmd_password_check,
            "shred": cmd_shred,
        }[args.command]
        return handler(sv, args)
    except KeyboardInterrupt:
        return 2
    except Exception as exc:
        print(_c(RED, f"error: {exc}"), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
