"""Protect small secrets (such as an abuse.ch Auth-Key) in the settings file.

On Windows the value is encrypted with DPAPI (``CryptProtectData``) for the current user: a copied settings file is
useless on another account or computer. Elsewhere the settings file is only readable by its owner (mode 0600), which
is the platform convention for per-user API keys.

This does not stop malware already running as the same user, which can ask Windows to decrypt it just as the app
does; nothing in user space can.
"""

from __future__ import annotations

import base64
import sys

PREFIX_DPAPI = "dpapi:"


def protect(value: str) -> str:
    if not value:
        return ""
    if sys.platform == "win32":
        try:
            return PREFIX_DPAPI + base64.b64encode(_dpapi(value.encode("utf-8"), encrypt=True)).decode()
        except OSError:
            pass
    return value


def unprotect(value: str) -> str:
    if not value or not value.startswith(PREFIX_DPAPI):
        return value  # plain value (older settings, or a non-Windows system)
    if sys.platform != "win32":
        return ""
    try:
        return _dpapi(base64.b64decode(value[len(PREFIX_DPAPI) :]), encrypt=False).decode("utf-8")
    except (OSError, ValueError):
        return ""  # protected on another account/computer: the user enters the key again


def _dpapi(data: bytes, encrypt: bool) -> bytes:  # pragma: no cover - Windows only
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    buf = ctypes.create_string_buffer(data, len(data))
    src = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    out = Blob()
    flags = 0x1  # CRYPTPROTECT_UI_FORBIDDEN
    entropy_raw = b"SentinelVision/settings/v1"
    ebuf = ctypes.create_string_buffer(entropy_raw, len(entropy_raw))
    entropy = Blob(len(entropy_raw), ctypes.cast(ebuf, ctypes.POINTER(ctypes.c_char)))
    fn = crypt32.CryptProtectData if encrypt else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(src), None, ctypes.byref(entropy), None, None, flags, ctypes.byref(out))
    if not ok:
        raise OSError(ctypes.get_last_error() or "DPAPI failed")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)
