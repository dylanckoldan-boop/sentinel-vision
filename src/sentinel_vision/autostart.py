"""Start Sentinel Vision automatically when the user signs in.

* Windows: ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`` value ``SentinelVision``
  (the installer writes the same value — in HKLM for all-users installs — so both agree).
* macOS:   ``~/Library/LaunchAgents/io.github.dylanckoldan-boop.sentinel-vision.plist`` (RunAtLoad)
* Linux:   ``~/.config/autostart/sentinel-vision.desktop`` (XDG autostart, honoured by every major desktop)

The operating system's own entry is the single source of truth; nothing is cached in settings, so the
installer, the app and the user (e.g. Task Manager → Startup apps) can never disagree.
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "SentinelVision"
MAC_LABEL = "io.github.dylanckoldan-boop.sentinel-vision"
DESKTOP_NAME = "sentinel-vision.desktop"
MINIMIZED_FLAG = "--minimized"


class AutostartError(RuntimeError):
    pass


@dataclass
class AutostartStatus:
    enabled: bool
    scope: str  # "user", "all users", ""
    command: str
    can_change: bool  # False when only an all-users entry exists and we are not elevated


# ----------------------------------------------------------------------------- command


def launch_command() -> list[str]:
    """The command that starts the GUI hidden in the tray, for frozen and pip installs alike."""
    if getattr(sys, "frozen", False):
        # Always register the GUI executable, even when called from the bundled command-line tool.
        gui = Path(sys.executable).with_name("SentinelVision.exe" if sys.platform == "win32" else "SentinelVision")
        return [str(gui if gui.exists() else Path(sys.executable)), MINIMIZED_FLAG]
    exe = Path(sys.executable)
    if sys.platform == "win32":
        pythonw = exe.with_name("pythonw.exe")  # no console window at sign-in
        if pythonw.exists():
            exe = pythonw
    return [str(exe), "-m", "sentinel_vision", MINIMIZED_FLAG]


def is_installed_build() -> bool:
    """True when running from the Windows installer's install directory."""
    return getattr(sys, "frozen", False) and (Path(sys.executable).parent / "unins000.exe").exists()


def _desktop_quote(arg: str) -> str:
    # Desktop Entry spec: quote args containing reserved chars; escape " ` $ \ inside quotes.
    if arg and not any(c in arg for c in " \t\n\"'\\><~|&;$*?#()`"):
        return arg
    escaped = arg.replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$")
    return f'"{escaped}"'


# ----------------------------------------------------------------------------- platform backends


def _mac_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{MAC_LABEL}.plist"


def _linux_desktop_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "autostart" / DESKTOP_NAME


def _win_read(hive) -> str | None:
    import winreg

    try:
        with winreg.OpenKey(hive, RUN_KEY, 0, winreg.KEY_READ) as k:
            value, _type = winreg.QueryValueEx(k, VALUE_NAME)
            return str(value)
    except OSError:
        return None


def status() -> AutostartStatus:
    if sys.platform == "win32":
        import winreg

        user = _win_read(winreg.HKEY_CURRENT_USER)
        if user:
            return AutostartStatus(True, "user", user, True)
        machine = _win_read(winreg.HKEY_LOCAL_MACHINE)
        if machine:
            return AutostartStatus(True, "all users", machine, False)
        return AutostartStatus(False, "", "", True)
    if sys.platform == "darwin":
        p = _mac_plist_path()
        if p.exists():
            try:
                with open(p, "rb") as fh:
                    data = plistlib.load(fh)
                cmd = subprocess.list2cmdline(data.get("ProgramArguments", []))
            except (OSError, plistlib.InvalidFileException, ValueError):
                cmd = ""
            return AutostartStatus(True, "user", cmd, True)
        return AutostartStatus(False, "", "", True)
    p = _linux_desktop_path()
    if p.exists():
        cmd = ""
        hidden = False
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                if line.startswith("Exec="):
                    cmd = line[5:]
                elif line.strip().lower() in ("hidden=true", "x-gnome-autostart-enabled=false"):
                    hidden = True
        except OSError:
            pass
        return AutostartStatus(not hidden, "user", cmd, True)
    return AutostartStatus(False, "", "", True)


def is_enabled() -> bool:
    return status().enabled


def enable(command: list[str] | None = None) -> None:
    cmd = command or launch_command()
    try:
        if sys.platform == "win32":
            import winreg

            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, VALUE_NAME, 0, winreg.REG_SZ, subprocess.list2cmdline(cmd))
        elif sys.platform == "darwin":
            p = _mac_plist_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            plist = {
                "Label": MAC_LABEL,
                "ProgramArguments": cmd,
                "RunAtLoad": True,
                "KeepAlive": False,
                "ProcessType": "Interactive",
                "LimitLoadToSessionType": "Aqua",
            }
            tmp = p.with_suffix(".tmp")
            with open(tmp, "wb") as fh:
                plistlib.dump(plist, fh)
            os.replace(tmp, p)
        else:
            p = _linux_desktop_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            content = (
                "[Desktop Entry]\n"
                "Type=Application\n"
                "Name=Sentinel Vision\n"
                "Comment=Open-source antimalware protection\n"
                f"Exec={' '.join(_desktop_quote(a) for a in cmd)}\n"
                "Terminal=false\n"
                "X-GNOME-Autostart-enabled=true\n"
                "X-GNOME-Autostart-Delay=5\n"
            )
            tmp = p.with_suffix(".tmp")
            tmp.write_text(content, encoding="utf-8")
            os.replace(tmp, p)
    except OSError as exc:
        raise AutostartError(f"could not enable start at sign-in: {exc}") from exc


def disable() -> None:
    try:
        if sys.platform == "win32":
            import winreg

            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
                    winreg.DeleteValue(k, VALUE_NAME)
            except FileNotFoundError:
                pass
            if _win_read(winreg.HKEY_LOCAL_MACHINE):
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
                        winreg.DeleteValue(k, VALUE_NAME)
                except PermissionError as exc:
                    raise AutostartError(
                        "Sentinel Vision was installed for all users, so turning off start at sign-in needs "
                        "administrator rights. Re-run the installer and untick the option, or run the app as "
                        "administrator once."
                    ) from exc
                except FileNotFoundError:
                    pass
        elif sys.platform == "darwin":
            _mac_plist_path().unlink(missing_ok=True)
        else:
            _linux_desktop_path().unlink(missing_ok=True)
    except OSError as exc:
        raise AutostartError(f"could not disable start at sign-in: {exc}") from exc


def set_enabled(on: bool) -> None:
    enable() if on else disable()


def repair() -> bool:
    """If start-at-sign-in is on but points at an executable that no longer exists (moved venv, deleted
    portable copy), re-point it at the running copy. Returns True when something was fixed."""
    st = status()
    if not st.enabled or st.scope != "user" or not st.command:
        return False
    target = _first_arg(st.command)
    if target and not Path(target).exists():
        enable()
        return True
    return False


def _first_arg(cmd: str) -> str:
    cmd = cmd.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    return cmd.split(" ", 1)[0]
