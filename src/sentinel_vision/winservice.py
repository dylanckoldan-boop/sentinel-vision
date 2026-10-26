"""The "Sentinel Vision Protection" Windows service (runs as LocalSystem).

* Keeps every user's rollback vault, quarantine and protection settings in ``%ProgramData%\\SentinelVision\\Service``,
  a folder only Windows itself and administrators can open (see :mod:`sentinel_vision.servicecore`).
* Answers the app over a local named pipe; each request is tied to the calling account.
* Starts the app when a user signs in and restarts it if it is closed or stops responding, unless the user stopped
  protection with administrator approval. If something keeps closing it, the user is told.
* Applies machine-wide blocking (hosts file, Windows Firewall) from lists it downloads itself.

Command line (the installer uses these; all need administrator rights):
    sentinel-vision-service.exe                 run (started by the Service Control Manager)
    sentinel-vision-service.exe wipe-data       delete every user's protected data (uninstall, after the user agreed)
    sentinel-vision-service.exe remove-system   remove hosts-file and firewall blocking (uninstall)
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import threading
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

from sentinel_vision import servicecore, systemblock
from sentinel_vision.service_client import PIPE_NAME, SERVICE_NAME, decode, encode, error_reply

log = logging.getLogger("sentinel_vision.service")

DISPLAY_NAME = "Sentinel Vision Protection"
DESCRIPTION = (
    "Protects Sentinel Vision's rollback vault, quarantine and settings from other programs, keeps the app running, "
    "and applies system-wide website and network blocking."
)
# only Windows itself (SYSTEM) and administrators; inherited by everything inside; owner SYSTEM
DATA_SDDL = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
# signed-in users may connect; never over the network; nobody may create a second server instance
PIPE_SDDL = "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)"
WATCH_INTERVAL = 15
HEARTBEAT_STALE = 300
RESTART_LIMIT = 3
RESTART_WINDOW = 600
REFRESH_HOURS = 6
APP_EXE = "SentinelVision.exe"


def data_root() -> Path:
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "SentinelVision" / "Service"


def install_dir() -> Path:
    return Path(sys.executable).resolve().parent


# ---------------------------------------------------------------------------------------------- folder safety
def _is_reparse(path: Path) -> bool:
    try:
        return bool(os.lstat(path).st_file_attributes & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
    except OSError:
        return False


def secure_dir(path: Path) -> None:
    """Create ``path`` (and its parent) owned by SYSTEM with a protected SYSTEM+Administrators-only ACL.

    A folder created beforehand by an ordinary user (or a junction pointing elsewhere) is moved aside first, so the
    service can never be tricked into writing through somebody else's link or keeping their permissions."""
    import win32file
    import win32security

    sd = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(DATA_SDDL, win32security.SDDL_REVISION_1)
    for p in (path.parent, path):
        if p.exists() and (_is_reparse(p) or not _owned_by_system_or_admins(p)):
            aside = p.with_name(f"{p.name}.untrusted-{int(time.time())}")
            log.warning("moving untrusted %s aside to %s", p, aside)
            os.rename(p, aside)
        if not p.exists():
            sa = win32security.SECURITY_ATTRIBUTES()
            sa.SECURITY_DESCRIPTOR = sd
            win32file.CreateDirectory(str(p), sa)
        win32security.SetNamedSecurityInfo(
            str(p),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION
            | win32security.DACL_SECURITY_INFORMATION
            | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            sd.GetSecurityDescriptorOwner(),
            None,
            sd.GetSecurityDescriptorDacl(),
            None,
        )


def _owned_by_system_or_admins(p: Path) -> bool:
    import win32security

    try:
        owner = win32security.GetNamedSecurityInfo(
            str(p), win32security.SE_FILE_OBJECT, win32security.OWNER_SECURITY_INFORMATION
        ).GetSecurityDescriptorOwner()
        name = win32security.ConvertSidToStringSid(owner)
    except Exception:
        return False
    return name in ("S-1-5-18", "S-1-5-32-544")


# ---------------------------------------------------------------------------------------------- system blocking
class WindowsApplier(servicecore.SystemApplier):
    def __init__(self, root: Path, core_ref) -> None:
        self.root = root
        self.core_ref = core_ref
        self._lock = threading.Lock()

    def _state(self) -> dict:
        try:
            return json.loads((self.root / "system.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_state(self, st: dict) -> None:
        (self.root / "system.json").write_text(json.dumps(st), encoding="utf-8")

    def _excluded_feeds(self) -> set[str]:
        """A source any user turned off (for example licence reasons in a business) is not used machine-wide."""
        from sentinel_vision.config import DEFAULT_FEEDS

        excluded: set[str] = set()
        core = self.core_ref()
        users = self.root / "users"
        for d in users.iterdir() if users.is_dir() else []:
            pol = core.policy(d.name) if core else {}
            if "enabled_feeds" in pol:
                excluded |= {f.name for f in DEFAULT_FEEDS} - set(pol["enabled_feeds"])
        return excluded

    def refresh(self) -> dict:
        return systemblock.refresh_lists(self.root, self._excluded_feeds())

    def apply_hosts(self) -> str:
        from sentinel_vision import webshield

        with self._lock:
            domains = systemblock.load_list(self.root, "domains.txt")
            if not domains:
                self.refresh()
                domains = systemblock.load_list(self.root, "domains.txt")
            n = webshield.apply_hosts(domains[: webshield.MAX_HOSTS_ENTRIES])
            webshield.flush_dns()
        return f"{n:,} sites blocked"

    def remove_hosts(self) -> str:
        from sentinel_vision import webshield

        with self._lock:
            webshield.remove_hosts()
            webshield.flush_dns()
        return "removed"

    def apply_firewall(self) -> str:
        with self._lock:
            nets = systemblock.load_list(self.root, "networks.txt")
            if not nets:
                self.refresh()
                nets = systemblock.load_list(self.root, "networks.txt")
            st = self._state()
            cmds, rules = systemblock.firewall_commands(nets, int(st.get("firewall_rules", 0)))
            failed = sum(1 for cmd in cmds if _run(cmd) != 0 and "add" in cmd)
            st["firewall_rules"] = rules
            self._save_state(st)
        if failed:
            raise RuntimeError(f"Windows Firewall refused {failed} of {rules * 2} rule(s)")
        return f"{len(systemblock.safe_networks(nets)):,} networks blocked in {rules} rule(s)"

    def remove_firewall(self) -> str:
        with self._lock:
            st = self._state()
            cmds, _ = systemblock.firewall_commands([], max(int(st.get("firewall_rules", 0)), 30))
            for cmd in cmds:
                _run(cmd)
            st["firewall_rules"] = 0
            self._save_state(st)
        return "removed"

    def status(self) -> dict:
        from sentinel_vision import webshield

        try:
            feeds = json.loads((self.root / "feeds" / "state.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            feeds = {}
        return {
            "hosts_entries": webshield.hosts_status(),
            "firewall_rules": int(self._state().get("firewall_rules", 0)),
            "lists": feeds,
        }


def _command_line(cmd: list[str]) -> str | list[str]:
    from sentinel_vision.network.firewall import command_line

    return command_line(cmd)


def _run(cmd: list[str]) -> int:
    try:
        r = subprocess.run(  # noqa: S603 - fixed system tools, no shell
            _command_line(cmd), capture_output=True, timeout=120, creationflags=0x08000000
        )
        if r.returncode != 0:
            out = (r.stdout or b"").decode("utf-8", "replace") + (r.stderr or b"").decode("utf-8", "replace")
            first = " ".join(out.strip().splitlines()[:2])
            log.warning("%s exited with %s: %s", " ".join(cmd[:6]), r.returncode, first[:300])
        return r.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("%s failed: %s", cmd[:5], exc)
        return -1


# ---------------------------------------------------------------------------------------------- pipe server
class PipeServer:
    def __init__(self, core: servicecore.ServiceCore, stop: threading.Event) -> None:
        self.core = core
        self.stop = stop
        import win32security

        self._sa = win32security.SECURITY_ATTRIBUTES()
        self._sa.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            PIPE_SDDL, win32security.SDDL_REVISION_1
        )
        self._first = True

    def _new_instance(self):
        import win32pipe

        open_mode = win32pipe.PIPE_ACCESS_DUPLEX | (0x00080000 if self._first else 0)  # FILE_FLAG_FIRST_PIPE_INSTANCE
        self._first = False
        return win32pipe.CreateNamedPipe(
            PIPE_NAME,
            open_mode,
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT | 0x00000008,  # REJECT_REMOTE
            win32pipe.PIPE_UNLIMITED_INSTANCES,
            1024 * 1024,
            1024 * 1024,
            0,
            self._sa,
        )

    def serve(self) -> None:
        import pywintypes
        import win32pipe

        while not self.stop.is_set():
            try:
                h = self._new_instance()
            except pywintypes.error as exc:
                log.error("cannot create the pipe (is another program holding the name?): %s", exc)
                self.core._event("*", "system", "The protection service could not open its private channel")
                self.stop.wait(10)
                continue
            try:
                win32pipe.ConnectNamedPipe(h, None)
            except pywintypes.error as exc:
                if exc.winerror != 535:  # ERROR_PIPE_CONNECTED
                    _close(h)
                    continue
            if self.stop.is_set():
                _close(h)
                break
            threading.Thread(target=self._client, args=(h,), name="sv-pipe-client", daemon=True).start()

    def _identify(self, h) -> servicecore.Caller:
        import win32api
        import win32pipe
        import win32security

        # Windows allows this only after the first message was read from the pipe
        win32security.ImpersonateNamedPipeClient(h)
        try:
            tok = win32security.OpenThreadToken(win32api.GetCurrentThread(), win32security.TOKEN_QUERY, True)
            sid = win32security.ConvertSidToStringSid(
                win32security.GetTokenInformation(tok, win32security.TokenUser)[0]
            )
            elevated = bool(win32security.GetTokenInformation(tok, win32security.TokenElevation))
            session = int(win32security.GetTokenInformation(tok, win32security.TokenSessionId))
        finally:
            win32security.RevertToSelf()
        try:
            pid = int(win32pipe.GetNamedPipeClientProcessId(h))
        except Exception:
            pid = 0
        return servicecore.Caller(sid=sid, elevated=elevated, pid=pid, session=session)

    def _client(self, h) -> None:
        import pywintypes
        import win32file

        caller = None

        def read_exact(n: int) -> bytes:
            buf = bytearray()
            while len(buf) < n:
                _, chunk = win32file.ReadFile(h, min(n - len(buf), 1024 * 1024))
                if not chunk:
                    raise EOFError
                buf += chunk
            return bytes(buf)

        try:
            while not self.stop.is_set():
                try:
                    req, payload = decode(read_exact)
                except (EOFError, pywintypes.error):
                    break
                if caller is None:
                    try:
                        caller = self._identify(h)
                    except Exception as exc:
                        log.warning("could not identify a client: %s", exc)
                        break
                try:
                    result, data = self.core.handle(caller, str(req.get("op", "")), req.get("args") or {}, payload)
                    reply = {"ok": True, "result": result}
                except Exception as exc:
                    if not isinstance(exc, servicecore.ServiceError):
                        log.exception("request %s failed", req.get("op"))
                    reply, data = error_reply(exc), b""
                win32file.WriteFile(h, encode(reply, data))
        except Exception as exc:
            log.info("client connection ended: %s", exc)
        finally:
            _close(h)

    def wake(self) -> None:
        """Unblock ConnectNamedPipe so the serving loop notices the stop flag."""
        import win32file

        try:
            hh = win32file.CreateFile(PIPE_NAME, win32file.GENERIC_READ, 0, None, win32file.OPEN_EXISTING, 0, None)
            win32file.CloseHandle(hh)
        except Exception:
            pass


def _close(h) -> None:
    import win32file
    import win32pipe

    try:
        win32pipe.DisconnectNamedPipe(h)
    except Exception:
        pass
    try:
        win32file.CloseHandle(h)
    except Exception:
        pass


# ---------------------------------------------------------------------------------------------- watchdog
class Watchdog:
    """Starts the app at sign-in and restarts it if it is closed or hangs (per signed-in user)."""

    def __init__(self, core: servicecore.ServiceCore, stop: threading.Event) -> None:
        self.core = core
        self.stop = stop
        self.app = install_dir() / APP_EXE
        self.restarts: dict[tuple[str, int], list[float]] = {}
        self.cooldown: dict[tuple[str, int], float] = {}
        self.seen_session: set[tuple[str, int]] = set()
        self._skipped: set[int] = set()
        self._last_state: dict[tuple[str, int], str] = {}

    def run(self) -> None:
        while not self.stop.wait(WATCH_INTERVAL):
            try:
                self.tick()
            except Exception:
                log.exception("watchdog tick failed")

    def _sessions(self) -> list[tuple[int, str]]:
        import win32security
        import win32ts

        out = []
        for s in win32ts.WTSEnumerateSessions(win32ts.WTS_CURRENT_SERVER_HANDLE):
            if s["State"] != win32ts.WTSActive or s["SessionId"] == 0:
                continue
            try:
                tok = win32ts.WTSQueryUserToken(s["SessionId"])
                sid = win32security.ConvertSidToStringSid(
                    win32security.GetTokenInformation(tok, win32security.TokenUser)[0]
                )
                out.append((s["SessionId"], sid))
            except Exception as exc:  # a session without a usable user token (e.g. still signing in)
                if s["SessionId"] not in self._skipped:
                    self._skipped.add(s["SessionId"])
                    log.info("watchdog: session %s has no usable user token: %s", s.get("SessionId"), exc)
        return out

    def _app_pids(self, session: int) -> list[int]:
        import psutil
        import win32ts

        pids = []
        target = os.path.normcase(str(self.app))
        for p in psutil.process_iter(["pid", "exe"]):
            try:
                if p.info["exe"] and os.path.normcase(p.info["exe"]) == target:
                    if win32ts.ProcessIdToSessionId(p.info["pid"]) == session:
                        pids.append(p.info["pid"])
            except Exception as exc:  # process ended while we looked
                log.debug("process check skipped: %s", exc)
        return pids

    def _state(self, key: tuple[str, int], state: str) -> None:
        """Log what the watchdog decided for a session whenever that changes (for diagnosing it)."""
        if self._last_state.get(key) != state:
            self._last_state[key] = state
            log.info("watchdog: session %s: %s", key[1], state)

    def tick(self) -> None:
        now = time.time()
        for session, sid in self._sessions():
            key = (sid, session)
            pol = self.core.policy(sid)
            if not pol:
                self._state(key, "account has not used Sentinel Vision")
                continue
            if not pol.get("keep_running", True):
                self._state(key, "start-at-sign-in is off")
                continue
            if key in self.core.paused:
                self._state(key, "protection stopped by the user until sign-out")
                continue
            if self.cooldown.get(key, 0) > now:
                self._state(key, "restarts paused")
                continue
            pids = self._app_pids(session)
            self._state(key, f"app running (process {', '.join(map(str, pids))})" if pids else "app not running")
            first = key not in self.seen_session
            self.seen_session.add(key)
            if pids:
                hb = self.core.heartbeats.get(key)
                if hb and now - hb[0] > HEARTBEAT_STALE:
                    self.core._event(sid, "watchdog", "Sentinel Vision stopped responding and was restarted")
                    self._message(session, "Sentinel Vision stopped responding and has been restarted.")
                    for pid in pids:
                        _kill(pid)
                    self.core.heartbeats.pop(key, None)
                    self._launch(session, key, now)
                continue
            if first:
                log.info("watchdog: session %s signed in without the app running; starting it", session)
                self._launch(session, key, now)  # start at sign-in
                continue
            # it was running in this session and is gone without the user stopping protection
            hist = [t for t in self.restarts.get(key, []) if now - t < RESTART_WINDOW]
            if len(hist) >= RESTART_LIMIT:
                self.cooldown[key] = now + 1800
                self.core._event(
                    sid, "watchdog", "Something keeps closing Sentinel Vision; restarts paused for 30 minutes"
                )
                self._message(
                    session,
                    "Something on this computer keeps closing Sentinel Vision. Run a full scan, and check "
                    "Microsoft Defender. Sentinel Vision will try again in 30 minutes.",
                )
                continue
            self.core._event(sid, "watchdog", "Sentinel Vision was closed without your approval and was restarted")
            log.info("watchdog: the app was closed in session %s; restarting it", session)
            self._launch(session, key, now)

    def _launch(self, session: int, key: tuple[str, int], now: float) -> None:
        import win32con
        import win32process
        import win32profile
        import win32ts

        if not self.app.exists():
            log.warning("watchdog: %s is missing", self.app)
            return
        tok = win32ts.WTSQueryUserToken(session)
        env = win32profile.CreateEnvironmentBlock(tok, False)
        si = win32process.STARTUPINFO()
        si.lpDesktop = "winsta0\\default"
        info = win32process.CreateProcessAsUser(
            tok,
            str(self.app),
            f'"{self.app}" --minimized',
            None,
            None,
            False,
            win32con.CREATE_UNICODE_ENVIRONMENT | win32con.CREATE_NEW_PROCESS_GROUP,
            env,
            str(self.app.parent),
            si,
        )
        self.restarts.setdefault(key, []).append(now)
        log.info("watchdog: started the app in session %s (process %s)", session, info[2])

    @staticmethod
    def _message(session: int, text: str) -> None:
        try:
            import win32ts

            win32ts.WTSSendMessage(win32ts.WTS_CURRENT_SERVER_HANDLE, session, DISPLAY_NAME, text, 0x40, 60, False)
        except Exception as exc:
            log.info("could not show a message: %s", exc)


def _kill(pid: int) -> None:
    try:
        import psutil

        psutil.Process(pid).kill()
    except Exception:
        pass


# ---------------------------------------------------------------------------------------------- the service
def _setup_logging(root: Path) -> None:
    h = RotatingFileHandler(root / "service.log", maxBytes=2_000_000, backupCount=2, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.getLogger().addHandler(h)
    logging.getLogger().setLevel(logging.INFO)


def run_service(stop: threading.Event) -> None:
    root = data_root()
    secure_dir(root)
    _setup_logging(root)
    core_holder: list[servicecore.ServiceCore] = []
    applier = WindowsApplier(root, lambda: core_holder[0] if core_holder else None)
    core = servicecore.ServiceCore(root, applier)
    core_holder.append(core)
    log.info("Sentinel Vision Protection service started")
    server = PipeServer(core, stop)
    threads = [
        threading.Thread(target=server.serve, name="sv-pipe", daemon=True),
        threading.Thread(target=Watchdog(core, stop).run, name="sv-watchdog", daemon=True),
        threading.Thread(target=_refresher, args=(core, applier, stop), name="sv-lists", daemon=True),
    ]
    for t in threads:
        t.start()
    stop.wait()
    server.wake()
    core.close()
    log.info("Sentinel Vision Protection service stopped")


def _refresher(core: servicecore.ServiceCore, applier: WindowsApplier, stop: threading.Event) -> None:
    if stop.wait(60):  # let the computer finish starting up
        return
    while True:
        g = core.global_policy()
        if g.get("webshield_block_hosts") or g.get("firewall_block"):
            try:
                state = applier.refresh()
                log.info("lists refreshed: %s", state)
                core.handle(servicecore.Caller("S-1-5-18", elevated=True), "system.refresh", {})
            except Exception:
                log.exception("refreshing blocking lists failed")
        if stop.wait(REFRESH_HOURS * 3600):
            return


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - Windows only
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "wipe-data":
        import shutil

        shutil.rmtree(data_root().parent, ignore_errors=True)
        return 0
    if argv and argv[0] == "remove-system":
        root = data_root()
        applier = WindowsApplier(root, lambda: None)
        for fn in (applier.remove_hosts, applier.remove_firewall):
            try:
                fn()
            except Exception as exc:
                print(f"{fn.__name__}: {exc}")
        return 0
    if argv and argv[0] == "debug":  # run in the console (testing)
        stop = threading.Event()
        try:
            run_service(stop)
        except KeyboardInterrupt:
            stop.set()
        return 0
    import servicemanager
    import win32service
    import win32serviceutil

    class Svc(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = DISPLAY_NAME
        _svc_description_ = DESCRIPTION

        def __init__(self, args) -> None:
            super().__init__(args)
            self.stop = threading.Event()

        def SvcStop(self) -> None:  # noqa: N802 - pywin32 API
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop.set()

        def SvcDoRun(self) -> None:  # noqa: N802 - pywin32 API
            try:
                run_service(self.stop)
            except Exception:
                log.exception("service crashed")
                raise

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(Svc)
    servicemanager.StartServiceCtrlDispatcher()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
