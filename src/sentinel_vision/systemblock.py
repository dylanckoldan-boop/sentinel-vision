"""Machine-wide blocking applied by the protection service: websites through the hosts file, criminal networks
through Windows Firewall.

The service downloads these lists itself, straight from the publishers, into its protected folder. It never accepts
a list from a program running as the user, so malware can't use the service to block arbitrary sites or addresses
(for example security-update servers).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from pathlib import Path

log = logging.getLogger(__name__)

RULE_PREFIX = "Sentinel Vision - malicious networks"
RULE_BATCH = 800
MAX_NETWORKS = 20000
DOMAIN_KINDS = ("domains_malware", "domains_phishing")
FIREWALL_FEEDS = ("Spamhaus DROP", "Feodo Tracker botnet C2", "Emerging Threats compromised hosts")


def refresh_lists(root: Path, excluded_feeds: set[str] | None = None) -> dict:
    """Download the key-free website and network lists. Returns counts; keeps the previous lists on failure."""
    from sentinel_vision.config import DEFAULT_FEEDS
    from sentinel_vision.network.threatintel import IP_PARSERS
    from sentinel_vision.updater import _maybe_unzip_text, download
    from sentinel_vision.webshield import blockable, parse_domain_list

    excluded = excluded_feeds or set()
    feeds_dir = Path(root) / "feeds"
    feeds_dir.mkdir(parents=True, exist_ok=True)
    malware: set[str] = set()
    phishing: set[str] = set()
    networks: set[str] = set()
    errors: list[str] = []
    for feed in DEFAULT_FEEDS:
        if feed.requires_key or not feed.enabled or feed.name in excluded:
            continue
        if feed.kind not in DOMAIN_KINDS and feed.name not in FIREWALL_FEEDS:
            continue
        try:
            text = _maybe_unzip_text(download(feed.url))
            if feed.kind in DOMAIN_KINDS:
                target = malware if feed.kind == "domains_malware" else phishing
                target.update(h for h in parse_domain_list(text) if blockable(h))
            elif feed.kind in IP_PARSERS:
                networks.update(IP_PARSERS[feed.kind](text))
        except Exception as exc:  # one publisher being down never empties the lists
            errors.append(f"{feed.name}: {exc}")
    state = {"time": time.time(), "errors": errors}
    # malware sites first: the hosts file is capped (see webshield.MAX_HOSTS_ENTRIES), so they are never left out
    domains = sorted(malware) + sorted(phishing - malware)
    if domains:
        (feeds_dir / "domains.txt").write_text("\n".join(domains), encoding="utf-8")
    if networks:
        (feeds_dir / "networks.txt").write_text("\n".join(sorted(networks)), encoding="utf-8")
    state["domains"] = len(load_list(root, "domains.txt"))
    state["networks"] = len(load_list(root, "networks.txt"))
    (feeds_dir / "state.json").write_text(json.dumps(state), encoding="utf-8")
    return state


def load_list(root: Path, name: str) -> list[str]:
    try:
        return [x for x in (Path(root) / "feeds" / name).read_text(encoding="utf-8").splitlines() if x]
    except OSError:
        return []


def safe_networks(networks: list[str]) -> list[str]:
    """Only public, routable networks; never anything that could cut off the local network or the whole
    internet (private ranges, loopback, link-local, multicast, very large blocks)."""
    out = []
    for n in networks:
        try:
            net = ipaddress.ip_network(n.strip(), strict=False)
        except ValueError:
            continue
        if not net.is_global or net.is_multicast:
            continue
        if (net.version == 4 and net.prefixlen < 8) or (net.version == 6 and net.prefixlen < 24):
            continue
        out.append(str(net))
    return sorted(set(out))[:MAX_NETWORKS]


def firewall_batches(networks: list[str]) -> list[str]:
    nets = safe_networks(networks)
    return [",".join(nets[i : i + RULE_BATCH]) for i in range(0, len(nets), RULE_BATCH)]


def firewall_commands(networks: list[str], previous_rules: int) -> tuple[list[list[str]], int]:
    """netsh commands that replace the previous rules with blocking rules (outbound and inbound)."""
    cmds: list[list[str]] = []
    for i in range(1, max(previous_rules, 0) + 1):
        for direction in ("out", "in"):
            cmds.append(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX} {direction} {i}"])
    batches = firewall_batches(networks)
    for i, batch in enumerate(batches, 1):
        for direction in ("out", "in"):
            cmds.append(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule", f"name={RULE_PREFIX} {direction} {i}",
                    f"dir={direction}", "action=block", "enable=yes", "profile=any", f"remoteip={batch}",
                ]
            )  # fmt: skip
    return cmds, len(batches)
