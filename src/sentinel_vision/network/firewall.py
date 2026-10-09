"""Block a remote IP with the operating system's own firewall.

Only ever invoked by an explicit user action in the GUI or CLI. Arguments are passed as a list
(never through a shell) and the address is validated first, so no input can inject commands.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import sys

RULE_PREFIX = "SentinelVision block"


class FirewallError(RuntimeError):
    pass


def _validate(ip: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        addr = ipaddress.ip_address(ip.strip().strip("[]"))
    except ValueError as exc:
        raise FirewallError(f"not an IP address: {ip!r}") from exc
    if addr.is_loopback or addr.is_unspecified or addr.is_private:
        raise FirewallError("refusing to block a loopback, unspecified or private address")
    return addr


def block_commands(ip: str) -> list[list[str]]:
    addr = _validate(ip)
    a = str(addr)
    if sys.platform == "win32":
        name = f"{RULE_PREFIX} {a}"
        return [
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={name}",
                "dir=out",
                "action=block",
                f"remoteip={a}",
            ],
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={name}",
                "dir=in",
                "action=block",
                f"remoteip={a}",
            ],
        ]
    if sys.platform.startswith("linux"):
        tool = "iptables" if addr.version == 4 else "ip6tables"
        if shutil.which(tool):
            return [
                [tool, "-I", "OUTPUT", "-d", a, "-j", "DROP", "-m", "comment", "--comment", RULE_PREFIX],
                [tool, "-I", "INPUT", "-s", a, "-j", "DROP", "-m", "comment", "--comment", RULE_PREFIX],
            ]
        if shutil.which("nft"):
            fam = "ip" if addr.version == 4 else "ip6"
            return [
                ["nft", "add", "table", "inet", "sentinelvision"],
                ["nft", "add", "chain", "inet", "sentinelvision", "out", "{ type filter hook output priority 0 ; }"],
                ["nft", "add", "rule", "inet", "sentinelvision", "out", fam, "daddr", a, "drop"],
            ]
        raise FirewallError("neither iptables nor nft is installed")
    raise FirewallError(
        "automatic blocking is not supported on this OS yet; use the system firewall (e.g. LuLu or pf on macOS)"
    )


def is_admin() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:
            return False
    return os.geteuid() == 0


def block_ip(ip: str) -> str:
    cmds = block_commands(ip)
    if not is_admin():
        raise FirewallError(
            "administrator rights are required. Run these commands in an elevated terminal:\n"
            + "\n".join(subprocess.list2cmdline(c) for c in cmds)
        )
    for cmd in cmds:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0 and "exists" not in (proc.stderr or "").lower():
            raise FirewallError(proc.stderr.strip() or f"{cmd[0]} failed with exit code {proc.returncode}")
    return f"Blocked {ip} in the system firewall."
