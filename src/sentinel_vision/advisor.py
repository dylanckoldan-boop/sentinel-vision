"""Security checkup: read-only checks of the computer's security settings, with a score and how to fix each.

Every check is defensive: it only reads settings, never changes them, needs no administrator rights, and
reports "unknown" rather than guessing when the operating system doesn't say.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import psutil

PASS, WARN, FAIL, UNKNOWN, INFO = "pass", "warn", "fail", "unknown", "info"
WEIGHTS = {"critical": 3, "important": 2, "recommended": 1}


@dataclass
class Check:
    id: str
    title: str
    status: str  # pass | warn | fail | unknown | info
    detail: str
    fix: str = ""
    importance: str = "important"  # critical | important | recommended


def _run(cmd: list[str], timeout: float = 20) -> str:
    """Run a read-only system command; returns stdout ('' on any failure)."""
    if not shutil.which(cmd[0]) and not os.path.isabs(cmd[0]):
        return ""
    kwargs: dict = {"capture_output": True, "timeout": timeout}
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    try:
        proc = subprocess.run(cmd, **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    for enc in ("utf-8", "mbcs" if sys.platform == "win32" else "latin-1"):
        try:
            return proc.stdout.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return proc.stdout.decode("latin-1", "replace")


def _ps(script: str, timeout: float = 30) -> str:
    return _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout
    )


def _reg(hive: str, path: str, name: str):
    import winreg

    root = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[hive]
    for view in (winreg.KEY_WOW64_64KEY, 0):
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as k:
                return winreg.QueryValueEx(k, name)[0]
        except OSError:
            continue
    return None


# ----------------------------------------------------------------------------- parsers (unit-tested)


def parse_netsh_firewall(text: str) -> dict[str, bool]:
    """'netsh advfirewall show allprofiles state' -> {profile: on?}"""
    out: dict[str, bool] = {}
    profile = ""
    for line in text.splitlines():
        m = re.match(r"^(\w+) Profile Settings", line.strip())
        if m:
            profile = m.group(1)
        m = re.match(r"^State\s+(ON|OFF)", line.strip(), re.I)
        if m and profile:
            out[profile] = m.group(1).upper() == "ON"
    return out


def parse_lsblk_encrypted(text: str) -> bool | None:
    """True if the root file system sits on a dm-crypt (LUKS) device, from `lsblk -J -o NAME,TYPE,MOUNTPOINTS`."""
    try:
        data = json.loads(text)
    except ValueError:
        return None

    def walk(node, crypt_above: bool) -> bool | None:
        crypt = crypt_above or node.get("type") == "crypt"
        mps = node.get("mountpoints") or [node.get("mountpoint")]
        if "/" in (mps or []):
            return crypt
        for child in node.get("children", []) or []:
            found = walk(child, crypt)
            if found is not None:
                return found
        return None

    for dev in data.get("blockdevices", []) or []:
        found = walk(dev, False)
        if found is not None:
            return found
    return None


def parse_winget_upgrades(text: str) -> int | None:
    m = re.search(r"(\d+)\s+upgrades?\s+available", text, re.I)
    if m:
        return int(m.group(1))
    if re.search(r"no (available upgrade|installed package)", text, re.I):
        return 0
    return None


def parse_dns_servers(text: str) -> list[str]:
    """DNS servers from resolv.conf, `scutil --dns` or `ipconfig /all`."""
    out: list[str] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        s = line.strip()
        m = re.match(r"^nameserver(?:\[\d+\])?\s*:?\s*(\d{1,3}(?:\.\d{1,3}){3})", s)
        if not m and re.match(r"^DNS Servers[ .]*:", s):
            m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", s)
            if m:
                out.append(m.group(1))
                for nxt in lines[i + 1 : i + 4]:  # continuation lines hold further servers
                    m2 = re.fullmatch(r"\s+(\d{1,3}(?:\.\d{1,3}){3})\s*", nxt)
                    if not m2:
                        break
                    out.append(m2.group(1))
                continue
        if m:
            out.append(m.group(1))
    return list(dict.fromkeys(out))


def parse_arp_table(text: str) -> dict[str, str]:
    """IP -> MAC from `arp -a` (Windows, macOS, Linux) or `ip neigh` output."""
    out: dict[str, str] = {}
    mac_re = r"([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}"
    for line in text.lower().splitlines():
        ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        mac = re.search(mac_re, line)
        if not ip or not mac:
            continue
        m = mac.group(0).replace("-", ":")
        m = ":".join(part.zfill(2) for part in m.split(":"))
        if m in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or m.startswith("01:00:5e"):
            continue
        out[ip.group(1)] = m
    return out


def parse_default_gateway(text: str) -> str:
    """Default gateway IPv4 from `route print -4` (Windows), `netstat -rn` (macOS) or `ip route` (Linux)."""
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^default via (\d{1,3}(?:\.\d{1,3}){3})", s)  # ip route
        if m:
            return m.group(1)
        m = re.match(r"^default\s+(\d{1,3}(?:\.\d{1,3}){3})\s", s)  # netstat -rn (macOS)
        if m:
            return m.group(1)
        m = re.match(r"^0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s", s)  # route print
        if m:
            return m.group(1)
    return ""


def parse_wifi_security(text: str) -> tuple[str, str] | None:
    """(SSID, authentication) of the connected Wi-Fi from `netsh wlan show interfaces` or `nmcli -t` output."""
    ssid = auth = ""
    for line in text.splitlines():
        s = line.strip()
        m = re.match(r"^SSID\s*:\s*(.*)$", s)
        if m:
            ssid = m.group(1)
        m = re.match(r"^Authentication\s*:\s*(.*)$", s)
        if m:
            auth = m.group(1)
        if s.startswith("yes:"):  # nmcli -t -f ACTIVE,SSID,SECURITY dev wifi
            parts = s.split(":")
            if len(parts) >= 3:
                return parts[1], parts[2] or "Open"
    return (ssid, auth) if ssid and auth else None


def wifi_is_weak(auth: str) -> bool:
    a = auth.lower().replace(" ", "")
    return a in ("", "open", "none", "--") or "wep" in a


KNOWN_RESOLVERS = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "76.76.2.0",
    "76.76.10.0",
    "185.228.168.9",
    "185.228.169.9",
}


# ----------------------------------------------------------------------------- checks


def _app_checks(sentinel) -> list[Check]:
    from sentinel_vision import autostart

    out = []
    rt = sentinel.realtime.running
    out.append(
        Check(
            "sv-realtime",
            "Real-time file protection",
            PASS if rt else FAIL,
            "On" if rt else "Off: new files are not checked",
            "Turn it on in Protection.",
            "critical",
        )
    )
    beh = sentinel.behavior.running
    out.append(
        Check(
            "sv-behavior",
            "Behavior monitoring",
            PASS if beh else WARN,
            "On" if beh else "Off",
            "Turn it on in Protection.",
            "important",
        )
    )
    rw = sentinel.ransomware.running
    out.append(
        Check(
            "sv-ransomware",
            "Ransomware shield & rollback vault",
            PASS if rw else WARN,
            f"Protecting {len(sentinel.ransomware.folders)} folder(s)" if rw else "Off",
            "Turn it on in Protection.",
            "important",
        )
    )
    auto = autostart.is_enabled()
    out.append(
        Check(
            "sv-autostart",
            "Protection starts at sign-in",
            PASS if auto else FAIL,
            "Yes" if auto else "No: after a restart nothing is protected until you open the app",
            "Turn on “Start at sign-in” in Protection.",
            "critical",
        )
    )
    age = time.time() - sentinel.updater.last_update
    out.append(
        Check(
            "sv-defs",
            "Threat definitions up to date",
            PASS if age < 3 * 86400 else WARN if age < 14 * 86400 else FAIL,
            "Updated recently" if age < 3 * 86400 else "Out of date",
            "Settings & updates → Update now.",
            "important",
        )
    )
    clam = any(e.name == "clamav" and e.available() for e in sentinel.scanner.engines)
    out.append(
        Check(
            "sv-clamav",
            "ClamAV engine installed",
            PASS if clam else WARN,
            "Available" if clam else "Not installed: millions of extra signatures are missing",
            "See the installation guide → Add ClamAV.",
            "recommended",
        )
    )
    return out


def _exposed_services() -> Check:
    risky = {
        21: "FTP",
        23: "Telnet",
        445: "Windows file sharing (SMB)",
        3389: "Remote Desktop",
        5900: "VNC",
        5985: "WinRM",
        2375: "Docker API (unauthenticated)",
        6379: "Redis",
        27017: "MongoDB",
        9200: "Elasticsearch",
    }
    found = set()
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.status == "LISTEN" and c.laddr and c.laddr.port in risky and c.laddr.ip in ("0.0.0.0", "::"):  # noqa: S104
                found.add(c.laddr.port)
    except (psutil.AccessDenied, OSError):
        return Check(
            "os-exposed", "Network services open to other computers", UNKNOWN, "Not visible without admin rights"
        )
    if not found:
        return Check(
            "os-exposed",
            "Network services open to other computers",
            PASS,
            "No risky services listening",
            importance="important",
        )
    names = ", ".join(f"{risky[p]} ({p})" for p in sorted(found))
    return Check(
        "os-exposed",
        "Network services open to other computers",
        WARN,
        f"Listening on all networks: {names}",
        "Turn off services you don't use, or allow them only on trusted networks in your firewall.",
        "important",
    )


def _windows_checks() -> list[Check]:
    out: list[Check] = []
    fw = parse_netsh_firewall(_run(["netsh", "advfirewall", "show", "allprofiles", "state"]))
    if fw:
        off = [p for p, on in fw.items() if not on]
        out.append(
            Check(
                "os-firewall",
                "Windows Firewall",
                FAIL if off else PASS,
                f"Off for: {', '.join(off)}" if off else "On for all network profiles",
                "Windows Security → Firewall & network protection → turn on.",
                "critical",
            )
        )
    else:
        out.append(
            Check(
                "os-firewall", "Windows Firewall", UNKNOWN, "Could not read the firewall state", importance="critical"
            )
        )
    mp = _ps(
        "Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,AntivirusSignatureAge "
        "| ConvertTo-Json"
    )
    try:
        d = json.loads(mp) if mp.strip() else None
    except ValueError:
        d = None
    if isinstance(d, dict):
        on = bool(d.get("RealTimeProtectionEnabled"))
        out.append(
            Check(
                "os-defender",
                "Microsoft Defender real-time protection",
                PASS if on else WARN,
                "On (recommended alongside Sentinel Vision)" if on else "Off",
                "Keep Microsoft Defender on unless another full antivirus replaces it.",
                "important",
            )
        )
    else:
        out.append(
            Check(
                "os-defender",
                "Microsoft Defender real-time protection",
                UNKNOWN,
                "Not reported (another antivirus may be registered)",
                importance="recommended",
            )
        )
    bl = _ps(
        "(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive + '\\')"
        ".Self.ExtendedProperty('System.Volume.BitLockerProtection')"
    ).strip()
    state = {"1": (PASS, "On"), "3": (PASS, "Encrypting"), "2": (FAIL, "Off"), "5": (WARN, "Suspended")}.get(bl)
    if state:
        out.append(
            Check(
                "os-diskcrypt",
                "Drive encryption (BitLocker / Device Encryption)",
                state[0],
                state[1],
                "Settings → Privacy & security → Device encryption (or BitLocker) → turn on.",
                "important",
            )
        )
    else:
        out.append(
            Check(
                "os-diskcrypt",
                "Drive encryption (BitLocker / Device Encryption)",
                UNKNOWN,
                "Not reported on this edition of Windows",
                importance="important",
            )
        )
    uac = _reg("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    prompt = _reg("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
    if uac == 0:
        out.append(
            Check(
                "os-uac",
                "User Account Control",
                FAIL,
                "Disabled: every program runs with full rights",
                "Control Panel → User Accounts → Change User Account Control settings.",
                "critical",
            )
        )
    elif prompt == 0:
        out.append(
            Check(
                "os-uac",
                "User Account Control",
                WARN,
                "Elevates without asking",
                "Set User Account Control to “Notify me…”.",
                "important",
            )
        )
    else:
        out.append(Check("os-uac", "User Account Control", PASS, "On", importance="critical"))
    auto = _reg("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
    out.append(
        Check(
            "os-autologin",
            "Sign-in requires a password",
            FAIL if str(auto) == "1" else PASS,
            "Automatic sign-in is enabled" if str(auto) == "1" else "Yes",
            "Run netplwiz and require users to enter a password.",
            "important",
        )
    )
    rdp = _reg("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    out.append(
        Check(
            "os-rdp",
            "Remote Desktop",
            WARN if rdp == 0 else PASS,
            "Enabled: a common target for attackers" if rdp == 0 else "Off",
            "Settings → System → Remote Desktop → off (unless you need it).",
            "recommended",
        )
    )
    smb1 = _reg("HKLM", r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
    out.append(
        Check(
            "os-smb1",
            "Outdated SMBv1 file sharing",
            FAIL if smb1 is not None and smb1 != 4 else PASS,
            "Enabled (used by WannaCry)" if smb1 is not None and smb1 != 4 else "Off",
            "Turn Windows features on or off → untick “SMB 1.0/CIFS File Sharing Support”.",
            "important",
        )
    )
    sb = _reg("HKLM", r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    out.append(
        Check(
            "os-secureboot",
            "Secure Boot",
            PASS if sb == 1 else WARN if sb == 0 else UNKNOWN,
            {1: "On", 0: "Off: boot-level malware is not blocked"}.get(sb, "Not reported"),
            "Enable Secure Boot in your PC's UEFI/BIOS settings.",
            "recommended",
        )
    )
    hf = _ps(
        "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn.ToString('yyyy-MM-dd')"
    ).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", hf):
        days = (time.time() - time.mktime(time.strptime(hf, "%Y-%m-%d"))) / 86400
        out.append(
            Check(
                "os-updates",
                "Windows updates",
                PASS if days < 45 else WARN if days < 90 else FAIL,
                f"Last update installed {int(days)} days ago",
                "Settings → Windows Update → Check for updates.",
                "critical",
            )
        )
    else:
        out.append(
            Check("os-updates", "Windows updates", UNKNOWN, "Could not read update history", importance="critical")
        )
    if shutil.which("winget"):
        text = _run(
            ["winget", "upgrade", "--include-unknown", "--accept-source-agreements", "--disable-interactivity"], 90
        )
        n = parse_winget_upgrades(text)
        if n is not None:
            out.append(
                Check(
                    "os-apps",
                    "Apps with available updates",
                    PASS if n == 0 else WARN,
                    "All apps up to date" if n == 0 else f"{n} app(s) have updates (outdated apps are a top way in)",
                    "Run “winget upgrade --all” or update them from the Store / their own updater.",
                    "important",
                )
            )
    return out


def _mac_checks() -> list[Check]:
    out: list[Check] = []
    fw = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    on = "enabled" in fw.lower() or "state = 1" in fw.lower() or "state = 2" in fw.lower()
    out.append(
        Check(
            "os-firewall",
            "macOS firewall",
            PASS if on else WARN if fw else UNKNOWN,
            "On" if on else "Off" if fw else "Not reported",
            "System Settings → Network → Firewall → on.",
            "important",
        )
    )
    fv = _run(["fdesetup", "status"])
    out.append(
        Check(
            "os-diskcrypt",
            "FileVault disk encryption",
            PASS if "On" in fv else FAIL if "Off" in fv else UNKNOWN,
            fv.strip().splitlines()[0] if fv.strip() else "Not reported",
            "System Settings → Privacy & Security → FileVault → turn on.",
            "important",
        )
    )
    gk = _run(["spctl", "--status"])
    out.append(
        Check(
            "os-gatekeeper",
            "Gatekeeper (app verification)",
            PASS if "enabled" in gk else FAIL if gk else UNKNOWN,
            gk.strip() or "Not reported",
            "Run “sudo spctl --master-enable”.",
            "critical",
        )
    )
    sip = _run(["csrutil", "status"])
    out.append(
        Check(
            "os-sip",
            "System Integrity Protection",
            PASS if "enabled" in sip else FAIL if sip else UNKNOWN,
            sip.strip() or "Not reported",
            "Re-enable it from Recovery mode: csrutil enable.",
            "critical",
        )
    )
    au = _run(
        ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"]
    ).strip()
    out.append(
        Check(
            "os-updates",
            "Automatic macOS updates",
            PASS if au == "1" else WARN if au == "0" else UNKNOWN,
            {"1": "On", "0": "Off"}.get(au, "Not reported"),
            "System Settings → General → Software Update → Automatic updates.",
            "important",
        )
    )
    return out


def _linux_checks() -> list[Check]:
    out: list[Check] = []
    active = []
    for svc in ("ufw", "firewalld", "nftables"):
        if _run(["systemctl", "is-active", svc]).strip() == "active":
            active.append(svc)
    if shutil.which("systemctl"):
        out.append(
            Check(
                "os-firewall",
                "Firewall",
                PASS if active else WARN,
                ", ".join(active) + " active" if active else "No firewall service active",
                "Install and enable ufw: sudo ufw enable",
                "important",
            )
        )
    enc = parse_lsblk_encrypted(_run(["lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINTS"]))
    out.append(
        Check(
            "os-diskcrypt",
            "Disk encryption (LUKS)",
            PASS if enc else WARN if enc is False else UNKNOWN,
            "System disk is encrypted" if enc else "System disk is not encrypted" if enc is False else "Not reported",
            "Enable encryption when (re)installing your distribution.",
            "important",
        )
    )
    if shutil.which("apt"):
        text = _run(["apt", "list", "--upgradable"], 60)
        n = sum(1 for ln in text.splitlines() if "/" in ln and "[upgradable" in ln)
        sec = sum(1 for ln in text.splitlines() if "-security" in ln)
        out.append(
            Check(
                "os-updates",
                "System updates",
                PASS if n == 0 else FAIL if sec else WARN,
                "Up to date" if n == 0 else f"{n} update(s) available, {sec} security",
                "sudo apt update && sudo apt upgrade",
                "critical",
            )
        )
        ua = os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades") or os.path.exists(
            "/etc/apt/apt.conf.d/50unattended-upgrades"
        )
        out.append(
            Check(
                "os-autoupdate",
                "Automatic security updates",
                PASS if ua else WARN,
                "Configured" if ua else "Not configured",
                "sudo apt install unattended-upgrades && sudo dpkg-reconfigure unattended-upgrades",
                "important",
            )
        )
    try:
        cfg = open("/etc/ssh/sshd_config", encoding="utf-8", errors="replace").read()
        root = re.search(r"^\s*PermitRootLogin\s+yes\b", cfg, re.M | re.I)
        pw = re.search(r"^\s*PasswordAuthentication\s+yes\b", cfg, re.M | re.I)
        if root or pw:
            out.append(
                Check(
                    "os-ssh",
                    "SSH server hardening",
                    WARN,
                    "Allows " + " and ".join(x for x, y in (("root login", root), ("password logins", pw)) if y),
                    "Set PermitRootLogin no and use SSH keys (PasswordAuthentication no).",
                    "important",
                )
            )
    except OSError:
        pass
    sb = _run(["mokutil", "--sb-state"])
    if sb:
        out.append(
            Check(
                "os-secureboot",
                "Secure Boot",
                PASS if "enabled" in sb.lower() else WARN,
                sb.strip(),
                "Enable Secure Boot in your UEFI settings.",
                "recommended",
            )
        )
    return out


def network_checks(sentinel=None) -> list[Check]:
    out: list[Check] = []
    if sys.platform == "win32":
        wifi = parse_wifi_security(_run(["netsh", "wlan", "show", "interfaces"]))
    elif sys.platform.startswith("linux") and shutil.which("nmcli"):
        wifi = parse_wifi_security(_run(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi"]))
    else:
        wifi = None
    if wifi:
        ssid, auth = wifi
        weak = wifi_is_weak(auth)
        out.append(
            Check(
                "net-wifi",
                "Wi-Fi encryption",
                FAIL if weak else PASS,
                f"“{ssid}”: {auth}",
                "Avoid entering passwords on open/WEP Wi-Fi; use WPA2/WPA3 networks or a VPN.",
                "important",
            )
        )
    guard = getattr(sentinel, "netguard", None) if sentinel else None
    if guard is not None:
        out.append(guard.check())
    return out


# ---------------------------------------------------------------------------------------------- browser DNS
def _browser_profiles() -> dict[str, list[Path]]:
    """Files that record each browser's own "secure DNS" (DNS over HTTPS) choice."""
    home = Path.home()
    out: dict[str, list[Path]] = {"Chrome": [], "Edge": [], "Brave": [], "Firefox": []}
    if sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local"))
        roaming = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
        out["Chrome"].append(local / "Google/Chrome/User Data/Local State")
        out["Edge"].append(local / "Microsoft/Edge/User Data/Local State")
        out["Brave"].append(local / "BraveSoftware/Brave-Browser/User Data/Local State")
        ff = roaming / "Mozilla/Firefox/Profiles"
    elif sys.platform == "darwin":
        sup = home / "Library/Application Support"
        out["Chrome"].append(sup / "Google/Chrome/Local State")
        out["Edge"].append(sup / "Microsoft Edge/Local State")
        out["Brave"].append(sup / "BraveSoftware/Brave-Browser/Local State")
        ff = sup / "Firefox/Profiles"
    else:
        cfg = home / ".config"
        out["Chrome"].append(cfg / "google-chrome/Local State")
        out["Edge"].append(cfg / "microsoft-edge/Local State")
        out["Brave"].append(cfg / "BraveSoftware/Brave-Browser/Local State")
        ff = home / ".mozilla/firefox"
    if ff.is_dir():
        out["Firefox"] = sorted(ff.glob("*/prefs.js"))
    return out


def chromium_secure_dns_mode(local_state: str) -> str:
    """ "secure" means the browser resolves names itself over HTTPS only."""
    try:
        data = json.loads(local_state)
    except ValueError:
        return ""
    return str((data.get("dns_over_https") or {}).get("mode", ""))


def firefox_trr_mode(prefs_js: str) -> int:
    m = re.search(r'user_pref\("network\.trr\.mode",\s*(\d+)\);', prefs_js)
    return int(m.group(1)) if m else 0


def _windows_doh_policies() -> dict[str, str]:
    if sys.platform != "win32":
        return {}
    import winreg

    found = {}
    for browser, key in (("Chrome", r"SOFTWARE\Policies\Google\Chrome"), ("Edge", r"SOFTWARE\Policies\Microsoft\Edge")):
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, key) as k:
                    found[browser] = str(winreg.QueryValueEx(k, "DnsOverHttpsMode")[0])
            except OSError:
                continue
    return found


def browser_dns_check(sentinel) -> Check:
    """Browsers set to "secure DNS only" resolve websites themselves and may skip the hosts file that Web Shield's
    system-wide blocking uses."""
    bypass: list[str] = []
    for browser, files in _browser_profiles().items():
        for f in files:
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if browser == "Firefox" and firefox_trr_mode(text) == 3:
                bypass.append("Firefox (DNS over HTTPS: Max Protection)")
                break
            if browser != "Firefox" and chromium_secure_dns_mode(text) == "secure":
                bypass.append(f"{browser} (Use secure DNS with a custom provider)")
                break
    for browser, mode in _windows_doh_policies().items():
        if mode.lower() == "secure":
            bypass.append(f"{browser} (set by policy)")
    blocking = bool(getattr(sentinel.settings, "webshield_block_hosts", False))
    if not bypass:
        return Check(
            "browser-dns",
            "Website blocking reaches every browser",
            PASS if blocking else INFO,
            "No browser is set to bypass the system's name lookups"
            + ("" if blocking else " (system-wide blocking is off)"),
            "",
            "recommended",
        )
    return Check(
        "browser-dns",
        "Website blocking reaches every browser",
        WARN if blocking else INFO,
        "May skip system-wide blocking: " + ", ".join(sorted(set(bypass))),
        "These browsers look websites up themselves. To keep Web Shield's blocking in them, set their secure DNS "
        "option to the automatic/default setting (Chrome/Edge: Settings → Privacy → Use secure DNS → With your "
        "current service provider; Firefox: Settings → Privacy → DNS over HTTPS → Default Protection).",
        "recommended",
    )


def run_checkup(sentinel, progress: Callable[[str], None] | None = None) -> list[Check]:
    say = progress or (lambda _m: None)
    checks: list[Check] = []
    say("Checking Sentinel Vision protection…")
    checks += _app_checks(sentinel)
    try:
        checks.append(browser_dns_check(sentinel))
    except Exception as exc:
        checks.append(
            Check("browser-dns", "Website blocking reaches every browser", UNKNOWN, f"Could not check: {exc}")
        )
    say("Checking operating-system security…")
    try:
        if sys.platform == "win32":
            checks += _windows_checks()
        elif sys.platform == "darwin":
            checks += _mac_checks()
        else:
            checks += _linux_checks()
    except Exception as exc:  # a broken check must never break the checkup
        checks.append(Check("os-error", "Operating-system checks", UNKNOWN, f"Could not complete: {exc}"))
    say("Checking network services and Wi-Fi…")
    checks.append(_exposed_services())
    checks += network_checks(sentinel)
    return checks


def score(checks: list[Check]) -> int:
    total = got = 0.0
    for c in checks:
        if c.status in (UNKNOWN, INFO):
            continue
        w = WEIGHTS.get(c.importance, 1)
        total += w
        got += w * {PASS: 1.0, WARN: 0.5, FAIL: 0.0}[c.status]
    return round(100 * got / total) if total else 0


# ----------------------------------------------------------------------------- network guard


def _gateway() -> str:
    if sys.platform == "win32":
        return parse_default_gateway(_run(["route", "print", "-4"]))
    if sys.platform == "darwin":
        return parse_default_gateway(_run(["netstat", "-rn", "-f", "inet"]))
    return parse_default_gateway(_run(["ip", "-4", "route"]))


def _arp() -> dict[str, str]:
    if sys.platform.startswith("linux") and shutil.which("ip"):
        return parse_arp_table(_run(["ip", "neigh"]))
    return parse_arp_table(_run(["arp", "-a"]))


def _dns_servers() -> list[str]:
    if sys.platform == "win32":
        return parse_dns_servers(_run(["ipconfig", "/all"]))
    if sys.platform == "darwin":
        return parse_dns_servers(_run(["scutil", "--dns"]))
    servers = []
    try:
        servers = parse_dns_servers(open("/etc/resolv.conf", encoding="utf-8", errors="replace").read())
    except OSError:
        pass
    if servers == ["127.0.0.53"] and shutil.which("resolvectl"):
        servers = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", _run(["resolvectl", "dns"])) or servers
    return list(dict.fromkeys(servers))


def _is_private(ip: str) -> bool:
    import ipaddress

    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local


class NetGuard:
    """Watches for local-network attacks: ARP spoofing of the router (man-in-the-middle) and DNS hijacking.

    The router's hardware address is remembered per router IP; a change, or a second device answering with
    the router's address, is reported. DNS servers are checked against threat intelligence."""

    def __init__(self, db, intel, on_alert: Callable[[str, str], None] | None = None, sources=None) -> None:
        self.db = db
        self.intel = intel
        self.on_alert = on_alert
        self.gateway_fn, self.arp_fn, self.dns_fn = sources or (_gateway, _arp, _dns_servers)
        self.last: Check = Check(
            "net-lan", "Local network (router spoofing, DNS hijacking)", UNKNOWN, "Not checked yet"
        )
        self._alerted: set[str] = set()
        self._stop = None
        self._thread = None

    def check(self) -> Check:
        try:
            self.last = self._check()
        except Exception as exc:
            self.last = Check(
                "net-lan", "Local network (router spoofing, DNS hijacking)", UNKNOWN, f"Check failed: {exc}"
            )
        return self.last

    def _alert(self, key: str, text: str, level: str) -> None:
        if key in self._alerted:
            return
        self._alerted.add(key)
        self.db.log_event("network", text, level)
        if self.on_alert:
            self.on_alert(text, level)

    def _check(self) -> Check:
        title = "Local network (router spoofing, DNS hijacking)"
        problems: list[str] = []
        status = PASS
        gw = self.gateway_fn()
        arp = self.arp_fn() if gw else {}
        mac = arp.get(gw, "")
        if gw and mac:
            key = f"gwmac:{gw}"
            known = self.db.get_meta(key)
            if known is None:
                self.db.set_meta(key, mac)
            elif known != mac:
                status = FAIL
                msg = f"The router ({gw}) changed its hardware address from {known} to {mac}: possible ARP spoofing"
                problems.append(msg)
                self._alert(f"gwchange:{gw}:{mac}", msg + " (expected only if you replaced your router).", "critical")
            twins = [ip for ip, m in arp.items() if m == mac and ip != gw and _is_private(ip)]
            if twins:
                status = FAIL if status == FAIL else WARN
                msg = f"Another device ({', '.join(twins[:3])}) answers with the router's hardware address"
                problems.append(msg)
                self._alert(f"gwtwin:{gw}:{','.join(sorted(twins))}", msg + ": possible man-in-the-middle.", "warning")
        bad_dns = []
        unusual = []
        for d in self.dns_fn():
            src = self.intel.lookup(d) if self.intel is not None else None
            if src:
                bad_dns.append(f"{d} ({src})")
            elif not _is_private(d) and d not in KNOWN_RESOLVERS:
                unusual.append(d)
        if bad_dns:
            status = FAIL
            msg = f"Your DNS server is on a threat list: {', '.join(bad_dns)} (DNS hijacking)"
            problems.append(msg)
            self._alert("dnsbad:" + ",".join(bad_dns), msg, "critical")
        if not problems:
            detail = "No signs of router spoofing or DNS hijacking"
            if not gw:
                detail = "No router found (not connected?)"
            if unusual:
                detail += f"; DNS servers: {', '.join(unusual)} (from your provider or network admin)"
            return Check("net-lan", title, PASS if gw else UNKNOWN, detail, importance="important")
        return Check(
            "net-lan", title, status, "; ".join(problems),
            "Disconnect from this network, restart your router, and change its admin password. "
            "Check the router's DNS settings.",
            "important",
        )  # fmt: skip

    def start(self, interval: float = 60.0) -> None:
        import threading

        if self._thread and self._thread.is_alive():
            return
        self._stop = threading.Event()

        def run() -> None:
            while not self._stop.is_set():
                self.check()
                self._stop.wait(interval)

        self._thread = threading.Thread(target=run, name="netguard", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._stop:
            self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())
