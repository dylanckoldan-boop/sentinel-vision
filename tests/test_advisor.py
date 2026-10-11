import json

from sentinel_vision import advisor
from sentinel_vision.advisor import Check, NetGuard

NETSH = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 OFF
Ok.
"""


def test_netsh_firewall_parser():
    assert advisor.parse_netsh_firewall(NETSH) == {"Domain": True, "Private": True, "Public": False}


def test_lsblk_parser():
    enc = {
        "blockdevices": [
            {"name": "nvme0n1", "type": "disk", "mountpoints": [None], "children": [
                {"name": "p1", "type": "part", "mountpoints": ["/boot/efi"]},
                {"name": "p2", "type": "part", "mountpoints": [None], "children": [
                    {"name": "luks", "type": "crypt", "mountpoints": [None], "children": [
                        {"name": "vg-root", "type": "lvm", "mountpoints": ["/"]}]}]}]}
        ]
    }  # fmt: skip
    plain = {
        "blockdevices": [
            {"name": "sda", "type": "disk", "children": [{"name": "sda1", "type": "part", "mountpoints": ["/"]}]}
        ]
    }
    assert advisor.parse_lsblk_encrypted(json.dumps(enc)) is True
    assert advisor.parse_lsblk_encrypted(json.dumps(plain)) is False
    assert advisor.parse_lsblk_encrypted("garbage") is None


def test_route_arp_dns_wifi_winget_parsers():
    assert advisor.parse_default_gateway("default via 192.168.1.1 dev wlan0 proto dhcp\n") == "192.168.1.1"
    assert advisor.parse_default_gateway("Destination Gateway\ndefault 10.0.0.1 UGScg en0\n") == "10.0.0.1"
    assert (
        advisor.parse_default_gateway("          0.0.0.0          0.0.0.0      192.168.0.1    192.168.0.23     25\n")
        == "192.168.0.1"
    )
    win_arp = (
        "  192.168.1.1           a4-2b-b0-11-22-33     dynamic\n  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
    )
    mac_arp = "? (10.0.0.1) at 0:1b:63:a:b:c on en0 ifscope [ethernet]\n"
    linux = "192.168.1.1 dev wlan0 lladdr a4:2b:b0:11:22:33 REACHABLE\n"
    assert advisor.parse_arp_table(win_arp) == {"192.168.1.1": "a4:2b:b0:11:22:33"}
    assert advisor.parse_arp_table(mac_arp) == {"10.0.0.1": "00:1b:63:0a:0b:0c"}
    assert advisor.parse_arp_table(linux) == {"192.168.1.1": "a4:2b:b0:11:22:33"}
    ipconfig = (
        "   DNS Servers . . . . . . . . . . . : 192.168.1.1\n"
        "                                       8.8.8.8\n"
        "   NetBIOS : Enabled\n"
    )
    assert advisor.parse_dns_servers(ipconfig) == ["192.168.1.1", "8.8.8.8"]
    assert advisor.parse_dns_servers("nameserver 127.0.0.53\noptions edns0\n") == ["127.0.0.53"]
    assert advisor.parse_dns_servers("resolver #1\n  nameserver[0] : 1.1.1.1\n") == ["1.1.1.1"]
    wlan = "    SSID                   : CoffeeShop\n    BSSID   : aa\n    Authentication         : Open\n"
    assert advisor.parse_wifi_security(wlan) == ("CoffeeShop", "Open") and advisor.wifi_is_weak("Open")
    assert advisor.parse_wifi_security("no:Other:WPA2\nyes:Home:WPA2 WPA3\n") == ("Home", "WPA2 WPA3")
    assert not advisor.wifi_is_weak("WPA2-Personal") and advisor.wifi_is_weak("WEP")
    assert advisor.parse_winget_upgrades("...\n3 upgrades available.\n") == 3
    assert advisor.parse_winget_upgrades("No available upgrade found.") == 0
    assert advisor.parse_winget_upgrades("") is None


def test_score_weights():
    checks = [
        Check("a", "a", "pass", "", importance="critical"),
        Check("b", "b", "fail", "", importance="recommended"),
        Check("c", "c", "unknown", ""),
    ]
    assert advisor.score(checks) == 75


def test_netguard_detects_router_spoofing_and_bad_dns(sentinel):
    state = {"gw": "192.168.1.1", "arp": {"192.168.1.1": "aa:aa:aa:aa:aa:01"}, "dns": ["192.168.1.1"]}
    alerts = []
    g = NetGuard(
        sentinel.db,
        sentinel.intel,
        lambda text, level: alerts.append(level),
        sources=(lambda: state["gw"], lambda: state["arp"], lambda: state["dns"]),
    )
    assert g.check().status == "pass"  # first sight: remembered
    state["arp"] = {"192.168.1.1": "bb:bb:bb:bb:bb:02"}
    c = g.check()
    assert c.status == "fail" and "ARP spoofing" in c.detail and alerts == ["critical"]
    g.check()
    assert alerts == ["critical"]  # alerted once
    state["arp"] = {"192.168.1.1": "aa:aa:aa:aa:aa:01", "192.168.1.66": "aa:aa:aa:aa:aa:01"}
    sentinel.db.set_meta("gwmac:192.168.1.1", "aa:aa:aa:aa:aa:01")
    assert g.check().status == "warn"
    sentinel.intel.add_runtime("203.0.113.53/32", "unit-test")
    state["arp"] = {"192.168.1.1": "aa:aa:aa:aa:aa:01"}
    state["dns"] = ["203.0.113.53"]
    c = g.check()
    assert c.status == "fail" and "DNS" in c.detail


def test_full_checkup_runs_on_this_machine(sentinel):
    checks = advisor.run_checkup(sentinel)
    ids = {c.id for c in checks}
    assert {"sv-realtime", "sv-autostart", "os-exposed"} <= ids
    assert all(c.status in ("pass", "warn", "fail", "unknown", "info") for c in checks)
    assert 0 <= advisor.score(checks) <= 100
