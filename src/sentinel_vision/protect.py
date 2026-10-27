"""Administrator approval for changes the protection service guards (Windows).

The app runs as the user. When a change would weaken protection, it asks Windows to start
``sentinel-vision-cli.exe protect-apply`` with administrator rights (the program lives in Program Files, which
programs running as the user can't modify). That elevated helper shows the user exactly what will change, and only
on "Yes" passes it to the service with its administrator token. The service accepts nothing weaker otherwise.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

from sentinel_vision.servicecore import GLOBAL_BOOL_ON, LIST_GROW, LIST_KEEP, label, policy_from_settings, weakened

APPLIED, DECLINED, FAILED = 0, 3, 2


def describe(old: dict, new: dict, old_global: dict, new_global: dict) -> list[str]:
    """Plain-language list of what the change weakens."""
    lines = []
    for k in weakened(old, new) + weakened({g: old_global.get(g, False) for g in new_global}, new_global):
        if k in LIST_GROW:
            added = sorted(set(map(str, new.get(k, []))) - set(map(str, old.get(k, []))))
            lines += [f"Add to {label(k)}: {a}" for a in added]
        elif k in LIST_KEEP:
            removed = sorted(set(map(str, old.get(k, []))) - set(map(str, new.get(k, []))))
            lines += [f"Remove from {label(k)}: {r}" for r in removed]
        elif k in GLOBAL_BOOL_ON or isinstance(new.get(k), bool):
            lines.append(f"Turn off {label(k)}")
        else:
            lines.append(f"Change {label(k)}: {old.get(k)} → {new.get(k)}")
    return lines


def request_change(sentinel) -> bool:
    """Ask for administrator approval to apply the (weaker) settings currently held in ``sentinel.settings``.
    Returns True when the user approved and the service accepted it."""
    if sentinel.service is None:
        return False
    sid = sentinel.service.call("ping")[0]["sid"]
    body = {"sid": sid, "policy": policy_from_settings(sentinel.settings), "global": sentinel._global_from_settings()}
    fd, path = tempfile.mkstemp(prefix="sv-change-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(body, fh)
        code = _run_elevated(["protect-apply", path])
    finally:
        Path(path).unlink(missing_ok=True)
    if code == APPLIED:
        sentinel.settings.save()
        return True
    return False


def request_pause(sentinel) -> bool:
    """Stop protection until the next sign-in (the watchdog then leaves the app closed)."""
    if sentinel.service is None:
        return True
    sid = sentinel.service.call("ping")[0]["sid"]
    return _run_elevated(["protect-pause", "--sid", sid, "--session", str(current_session())]) == APPLIED


def request_release(sentinel, item_id: str) -> bool:
    """Ask for administrator approval to restore one quarantined item (it may then be opened once, by this
    account, within two minutes). The elevated helper only approves; the app writes the file as the user."""
    if sentinel.service is None:
        return False
    sid = sentinel.service.call("ping")[0]["sid"]
    return _run_elevated(["protect-release", "--sid", sid, "--id", str(item_id)]) == APPLIED


def current_session() -> int:
    if sys.platform != "win32":
        return -1
    import ctypes

    sess = ctypes.c_ulong(0)
    k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    k32.ProcessIdToSessionId(k32.GetCurrentProcessId(), ctypes.byref(sess))
    return int(sess.value)


def _run_elevated(args: list[str]) -> int:
    from sentinel_vision.webshield import run_elevated

    try:
        return int(run_elevated(args))
    except OSError:
        return DECLINED  # the administrator prompt was cancelled


# ---------------------------------------------------------------------------------------------- elevated side
def confirm(title: str, text: str) -> bool:  # pragma: no cover - interactive
    if sys.platform == "win32":
        import ctypes

        flags = 0x4 | 0x30 | 0x100 | 0x40000  # YESNO | ICONWARNING | DEFBUTTON2 | TOPMOST
        return ctypes.windll.user32.MessageBoxW(None, text, title, flags) == 6  # type: ignore[attr-defined]
    return input(f"{text}\nContinue? [y/N] ").strip().lower() == "y"


def privileged_main(argv: list[str], confirm_fn=confirm, transport=None) -> int:
    """Entry point for ``protect-apply FILE``, ``protect-pause --sid S --session N`` and
    ``protect-release --sid S --id ITEM`` (run elevated)."""
    from sentinel_vision import service_client
    from sentinel_vision.servicecore import ServiceError

    t = transport or service_client.connect(timeout=10)
    if t is None:
        print("the protection service is not running", file=sys.stderr)
        return FAILED
    try:
        if not t.call("ping")[0].get("elevated"):
            print("administrator approval is required", file=sys.stderr)
            return FAILED
        if argv[0] == "protect-release":
            sid = argv[argv.index("--sid") + 1]
            item_id = argv[argv.index("--id") + 1]
            # the item belongs to the account that asked (the approving administrator may be another account)
            item = t.call("quarantine.get", {"id": item_id, "sid": sid})[0]["item"]
            where, threat = item["original_path"], f"\nDetected as: {item['threat']}"
            if not confirm_fn(
                "Restore a file from quarantine?",
                f"Sentinel Vision quarantined this file because it looked dangerous:\n\n{where}{threat}\n\n"
                "Only continue if you are sure it is safe and you asked to restore it yourself.",
            ):
                return DECLINED
            t.call("quarantine.release", {"sid": sid, "id": item_id})
            return APPLIED
        if argv[0] == "protect-pause":
            sid = argv[argv.index("--sid") + 1]
            session = int(argv[argv.index("--session") + 1])
            if not confirm_fn(
                "Stop Sentinel Vision?",
                "Sentinel Vision will stop protecting this computer until you next sign in.\n\n"
                "Only continue if you chose to quit Sentinel Vision yourself.",
            ):
                return DECLINED
            t.call("pause", {"sid": sid, "session": session})
            return APPLIED
        body = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        sid = str(body["sid"])
        current = t.call("policy.get", {"sid": sid})[0]
        lines = describe(
            current.get("policy") or {}, body.get("policy") or {}, current.get("global") or {}, body.get("global") or {}
        )
        if lines and not confirm_fn(
            "Reduce Sentinel Vision protection?",
            "These changes reduce your protection:\n\n• "
            + "\n• ".join(lines[:15])
            + ("\n• …" if len(lines) > 15 else "")
            + "\n\nOnly continue if you made these changes yourself.",
        ):
            return DECLINED
        t.call("policy.set", {"sid": sid, "policy": body.get("policy") or {}, "global": body.get("global") or {}})
        return APPLIED
    except (ServiceError, OSError, ValueError, KeyError, IndexError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return FAILED
    finally:
        if transport is None:
            t.close()
