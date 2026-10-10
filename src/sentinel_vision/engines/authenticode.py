"""Windows Authenticode verification (WinVerifyTrust) — used to cut heuristic false positives.

A file whose embedded signature chains to a trusted root and whose hash still matches the signature
was published by an identifiable, certificate-holding vendor and has not been modified since. That is
strong evidence against heuristic suspicions such as "packed" or "few imports". A *broken* signature
(file modified after signing) is the opposite: strong evidence of tampering.

Revocation checks are disabled and no network retrieval is performed, so verification never blocks a
scan on the internet. On non-Windows platforms every call returns ``Signature.UNAVAILABLE``.
"""

from __future__ import annotations

import sys
from enum import Enum


class Signature(str, Enum):
    VALID = "valid"  # signed, trusted chain, digest matches
    UNSIGNED = "unsigned"  # no embedded signature (may still be catalog-signed by Windows)
    TAMPERED = "tampered"  # digest mismatch: modified after signing
    UNTRUSTED = "untrusted"  # signed, but chain not trusted / explicitly distrusted / expired etc.
    UNAVAILABLE = "unavailable"  # not on Windows, or the API failed


TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
TRUST_E_BAD_DIGEST = 0x80096010
CRYPT_E_FILE_ERROR = 0x80092003


def _classify(code: int) -> Signature:
    code &= 0xFFFFFFFF
    if code == 0:
        return Signature.VALID
    if code in (TRUST_E_NOSIGNATURE, TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_PROVIDER_UNKNOWN):
        return Signature.UNSIGNED
    if code == TRUST_E_BAD_DIGEST:
        return Signature.TAMPERED
    if code == CRYPT_E_FILE_ERROR:
        return Signature.UNAVAILABLE
    return Signature.UNTRUSTED


if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [
            ("Data1", wintypes.DWORD),
            ("Data2", wintypes.WORD),
            ("Data3", wintypes.WORD),
            ("Data4", ctypes.c_ubyte * 8),
        ]

    class WINTRUST_FILE_INFO(ctypes.Structure):  # noqa: N801
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pcwszFilePath", wintypes.LPCWSTR),
            ("hFile", wintypes.HANDLE),
            ("pgKnownSubject", ctypes.POINTER(GUID)),
        ]

    class WINTRUST_DATA(ctypes.Structure):  # noqa: N801
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
            ("dwStateAction", wintypes.DWORD),
            ("hWVTStateData", wintypes.HANDLE),
            ("pwszURLReference", wintypes.LPWSTR),
            ("dwProvFlags", wintypes.DWORD),
            ("dwUIContext", wintypes.DWORD),
            ("pSignatureSettings", ctypes.c_void_p),
        ]

    WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
        0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
    )
    WTD_UI_NONE = 2
    WTD_REVOKE_NONE = 0
    WTD_CHOICE_FILE = 1
    WTD_STATEACTION_VERIFY = 1
    WTD_STATEACTION_CLOSE = 2
    WTD_REVOCATION_CHECK_NONE = 0x10
    WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
    WTD_DISABLE_MD2_MD4 = 0x2000

    _wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    _WinVerifyTrust = _wintrust.WinVerifyTrust
    _WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    _WinVerifyTrust.restype = wintypes.LONG

    def verify(path: str) -> Signature:
        file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = WTD_CHOICE_FILE
        data.pFile = ctypes.pointer(file_info)
        data.dwStateAction = WTD_STATEACTION_VERIFY
        data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4
        guid = GUID.from_buffer_copy(WINTRUST_ACTION_GENERIC_VERIFY_V2)
        try:
            code = _WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))
        except OSError:
            return Signature.UNAVAILABLE
        finally:
            data.dwStateAction = WTD_STATEACTION_CLOSE
            try:
                _WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))
            except OSError:
                pass
        return _classify(int(code))

else:

    def verify(path: str) -> Signature:  # noqa: ARG001
        return Signature.UNAVAILABLE
