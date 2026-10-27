"""Which settings protect the user, their allowed types and ranges, and strict validation.

Shared by the protection service (every policy request, audit finding SV-F01/SV-A03) and by ``Settings.load``
(SV-F06), so the two can never disagree. Values are checked by exact type: ``True`` is not an integer here, ``0``
is not a boolean, and NaN or infinity is never a number.
"""

from __future__ import annotations

import math

# Which direction counts as "weaker" is defined in servicecore; the fields themselves live here.
BOOL_ON = (
    "realtime_enabled", "behavior_enabled", "behavior_kill_malicious", "behavior_block_ransomware",
    "ransomware_enabled", "ransomware_auto_suspend", "network_enabled", "webshield_enabled", "auto_quarantine",
    "hash_enabled", "yara_enabled", "clamav_enabled", "heuristics_enabled", "usb_autoscan", "privacy_monitor",
    "netsec_enabled", "scan_archives", "check_app_updates", "schedule_quick_daily", "schedule_full_weekly",
    "schedule_memory_scan", "keep_running",
)  # fmt: skip
GLOBAL_BOOL_ON = ("webshield_block_hosts", "firewall_block")  # machine-wide
LIST_KEEP = ("ransomware_folders", "watch_paths", "enabled_feeds")  # removing an entry weakens
LIST_GROW = ("exclusions", "approved_plugins")  # adding an entry weakens
NUM_LOWER_IS_STRONGER = ("heuristic_threshold",)
NUM_HIGHER_IS_STRONGER = ("max_file_size_mb", "vault_max_mb", "vault_keep_versions")
INT_RANGES = {
    "heuristic_threshold": (1, 100),
    "max_file_size_mb": (1, 4096),
    "vault_max_mb": (100, 102_400),
    "vault_keep_versions": (1, 100),
    "auto_update_hours": (0, 168),
}
LIST_FIELDS = LIST_KEEP + LIST_GROW
MAX_LIST_ITEMS = 500
MAX_ITEM_CHARS = 1024


class SchemaError(ValueError):
    pass


def check(name: str, value) -> None:
    """Raise SchemaError unless ``value`` is allowed for the protected field ``name``."""
    if name in BOOL_ON or name in GLOBAL_BOOL_ON:
        if type(value) is not bool:
            raise SchemaError(f"{name} must be true or false")
    elif name in INT_RANGES:
        lo, hi = INT_RANGES[name]
        if type(value) is not int or not lo <= value <= hi:
            raise SchemaError(f"{name} must be a whole number from {lo} to {hi}")
    elif name in LIST_FIELDS:
        if type(value) is not list or len(value) > MAX_LIST_ITEMS:
            raise SchemaError(f"{name} must be a list of at most {MAX_LIST_ITEMS} entries")
        for item in value:
            if type(item) is not str or not 0 < len(item) <= MAX_ITEM_CHARS or "\0" in item:
                raise SchemaError(f"{name} entries must be text of 1 to {MAX_ITEM_CHARS} characters")
    else:
        raise SchemaError(f"unknown setting {name!r}")


def valid(name: str, value) -> bool:
    try:
        check(name, value)
        return True
    except SchemaError:
        return False


def finite_number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)
