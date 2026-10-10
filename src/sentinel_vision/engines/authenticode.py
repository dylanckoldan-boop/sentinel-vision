"""Windows Authenticode verification (WinVerifyTrust) — used to cut heuristic false positives.

A file whose embedded signature (or, for most Windows system files, its entry in a signed catalog) chains to a
trusted root and whose hash still matches the signature
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

    class WINTRUST_CATALOG_INFO(ctypes.Structure):  # noqa: N801
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("dwCatalogVersion", wintypes.DWORD),
            ("pcwszCatalogFilePath", wintypes.LPCWSTR),
            ("pcwszMemberTag", wintypes.LPCWSTR),
            ("pcwszMemberFilePath", wintypes.LPCWSTR),
            ("hMemberFile", wintypes.HANDLE),
            ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
            ("cbCalculatedFileHash", wintypes.DWORD),
            ("pcCatalogContext", ctypes.c_void_p),
            ("hCatAdmin", wintypes.HANDLE),
        ]

    class CATALOG_INFO(ctypes.Structure):  # noqa: N801
        _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]

    class WINTRUST_DATA(ctypes.Structure):  # noqa: N801
        _fields_ = [
            ("cbStruct", wintypes.DWORD),
            ("pPolicyCallbackData", ctypes.c_void_p),
            ("pSIPClientData", ctypes.c_void_p),
            ("dwUIChoice", wintypes.DWORD),
            ("fdwRevocationChecks", wintypes.DWORD),
            ("dwUnionChoice", wintypes.DWORD),
            ("pInfo", ctypes.c_void_p),  # WINTRUST_FILE_INFO* or WINTRUST_CATALOG_INFO*
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
    WTD_CHOICE_CATALOG = 2
    WTD_STATEACTION_VERIFY = 1
    WTD_STATEACTION_CLOSE = 2
    WTD_REVOCATION_CHECK_NONE = 0x10
    WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
    WTD_DISABLE_MD2_MD4 = 0x2000

    _wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    _WinVerifyTrust = _wintrust.WinVerifyTrust
    _WinVerifyTrust.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.c_void_p]
    _WinVerifyTrust.restype = wintypes.LONG

    _AcquireContext2 = _wintrust.CryptCATAdminAcquireContext2
    _AcquireContext2.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    _AcquireContext2.restype = wintypes.BOOL
    _CalcHash2 = _wintrust.CryptCATAdminCalcHashFromFileHandle2
    _CalcHash2.argtypes = [
        wintypes.HANDLE,
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
    ]
    _CalcHash2.restype = wintypes.BOOL
    _EnumCatalog = _wintrust.CryptCATAdminEnumCatalogFromHash
    _EnumCatalog.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ctypes.c_ubyte),
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    _EnumCatalog.restype = wintypes.HANDLE
    _CatalogInfo = _wintrust.CryptCATCatalogInfoFromContext
    _CatalogInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD]
    _CatalogInfo.restype = wintypes.BOOL
    _ReleaseCatalog = _wintrust.CryptCATAdminReleaseCatalogContext
    _ReleaseCatalog.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD]
    _ReleaseCatalog.restype = wintypes.BOOL
    _ReleaseContext = _wintrust.CryptCATAdminReleaseContext
    _ReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _ReleaseContext.restype = wintypes.BOOL

    def _trust(choice: int, info_ptr: int) -> int:
        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = choice
        data.pInfo = info_ptr
        data.dwStateAction = WTD_STATEACTION_VERIFY
        data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4
        guid = GUID.from_buffer_copy(WINTRUST_ACTION_GENERIC_VERIFY_V2)
        try:
            return int(_WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data)))
        finally:
            data.dwStateAction = WTD_STATEACTION_CLOSE
            _WinVerifyTrust(None, ctypes.byref(guid), ctypes.byref(data))

    def _verify_embedded(path: str) -> Signature:
        file_info = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path, None, None)
        return _classify(_trust(WTD_CHOICE_FILE, ctypes.addressof(file_info)))

    def _verify_catalog(path: str) -> Signature:
        """Most Windows system files carry no embedded signature: their hash is listed in a signed catalog."""
        import msvcrt

        with open(path, "rb") as fh:
            hfile = msvcrt.get_osfhandle(fh.fileno())
            for algorithm in ("SHA256", None):  # modern catalogs use SHA-256, older ones SHA-1
                admin = wintypes.HANDLE()
                if not _AcquireContext2(ctypes.byref(admin), None, algorithm, None, 0):
                    continue
                try:
                    size = wintypes.DWORD(100)
                    buf = (ctypes.c_ubyte * 100)()
                    if not _CalcHash2(admin, hfile, ctypes.byref(size), buf, 0):
                        continue
                    catalog = _EnumCatalog(admin, buf, size, 0, None)
                    if not catalog:
                        continue
                    try:
                        cinfo = CATALOG_INFO()
                        cinfo.cbStruct = ctypes.sizeof(CATALOG_INFO)
                        if not _CatalogInfo(catalog, ctypes.byref(cinfo), 0):
                            continue
                        tag = "".join(f"{b:02X}" for b in bytes(buf)[: size.value])
                        info = WINTRUST_CATALOG_INFO()
                        info.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
                        info.pcwszCatalogFilePath = cinfo.wszCatalogFile
                        info.pcwszMemberTag = tag
                        info.pcwszMemberFilePath = path
                        info.hMemberFile = hfile
                        info.pbCalculatedFileHash = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
                        info.cbCalculatedFileHash = size.value
                        info.hCatAdmin = admin
                        result = _classify(_trust(WTD_CHOICE_CATALOG, ctypes.addressof(info)))
                        if result is Signature.VALID:
                            return result
                    finally:
                        _ReleaseCatalog(admin, catalog, 0)
                finally:
                    _ReleaseContext(admin, 0)
        return Signature.UNSIGNED

    def verify(path: str) -> Signature:
        try:
            result = _verify_embedded(path)
            if result is Signature.UNSIGNED:
                result = _verify_catalog(path)
            return result
        except OSError:
            return Signature.UNAVAILABLE

else:

    def verify(path: str) -> Signature:  # noqa: ARG001
        return Signature.UNAVAILABLE
