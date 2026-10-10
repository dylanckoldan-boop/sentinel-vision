"""Static heuristics: catches suspicious files that no signature knows about yet.

Each indicator adds weight to a 0-100 score. Only scores at or above the configured threshold are
reported, and heuristic detections are never auto-quarantined unless the user opts in, because
heuristics trade certainty for coverage.
"""

from __future__ import annotations

import io
import math
import re
import time
import zipfile
from collections import Counter
from dataclasses import dataclass

from sentinel_vision.engines import authenticode
from sentinel_vision.engines.authenticode import Signature
from sentinel_vision.engines.base import Detection, Engine, ScanObject, Severity

try:
    import pefile  # type: ignore

    HAVE_PEFILE = True
except Exception:  # pragma: no cover
    pefile = None
    HAVE_PEFILE = False

EXEC_EXT = {
    "exe",
    "dll",
    "scr",
    "com",
    "pif",
    "cpl",
    "sys",
    "msi",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "lnk",
    "jar",
    "elf",
    "so",
    "dylib",
    "app",
    "sh",
    "apk",
}
# what a victim can double-click (libraries such as "Windows.Data.Pdf.dll" are not)
LAUNCHABLE_EXT = {
    "exe", "scr", "com", "pif", "cpl", "msi", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "lnk", "jar", "sh", "app", "apk",
}  # fmt: skip
DECOY_EXT = {
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "txt",
    "rtf",
    "jpg",
    "jpeg",
    "png",
    "gif",
    "bmp",
    "mp3",
    "mp4",
    "avi",
    "mov",
    "zip",
    "rar",
    "csv",
    "odt",
    "html",
    "htm",
}
SCRIPT_EXT = {
    "ps1",
    "psm1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "hta",
    "bat",
    "cmd",
    "sh",
    "bash",
    "py",
    "pl",
    "rb",
    "php",
    "applescript",
}
PACKER_SECTIONS = {
    b"upx0": ("UPX", 10),
    b"upx1": ("UPX", 10),
    b".aspack": ("ASPack", 25),
    b".adata": ("ASPack", 15),
    b".mpress1": ("MPRESS", 25),
    b".mpress2": ("MPRESS", 25),
    b".petite": ("Petite", 25),
    b".themida": ("Themida", 30),
    b".winlice": ("WinLicense", 30),
    b".vmp0": ("VMProtect", 25),
    b".vmp1": ("VMProtect", 25),
    b".enigma1": ("Enigma", 25),
    b".nsp0": ("NsPack", 25),
    b"pec2": ("PECompact", 25),
    b".packed": ("Generic packer", 25),
    b".rlpack": ("RLPack", 25),
    b".yp": ("Y0da", 25),
    b"mew": ("MEW", 25),
}


@dataclass
class Indicator:
    weight: int
    category: str
    text: str


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _has(text: str, *needles: str) -> bool:
    return all(n in text for n in needles)


def _any(text: str, *needles: str) -> bool:
    return any(n in text for n in needles)


class HeuristicEngine(Engine):
    name = "heuristics"
    label = "Heuristics"

    def __init__(self, threshold: int = 60) -> None:
        self.threshold = threshold

    def available(self) -> bool:
        return True

    def status(self) -> str:
        return f"threshold {self.threshold}" + ("" if HAVE_PEFILE else " (pefile missing: PE checks off)")

    # ------------------------------------------------------------------ entry
    def analyze(self, obj: ScanObject) -> list[Indicator]:
        head = obj.head
        name = obj.name
        lname = name.lower()
        ext = lname.rsplit(".", 1)[-1] if "." in lname else ""
        ind: list[Indicator] = []

        ind += self._filename(name, lname, ext, head)
        if head[:2] == b"MZ":
            ind += self._pe(obj)
        if ext in SCRIPT_EXT or head[:2] == b"#!":
            ind += self._script(head)
        if head[:4] == b"PK\x03\x04" and ext in {"docm", "xlsm", "pptm", "docx", "xlsx", "pptx", "dotm", "xlam"}:
            ind += self._ooxml(obj)
        if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            ind += self._ole(head)
        if head[:8] == b"L\x00\x00\x00\x01\x14\x02\x00":
            ind += self._lnk(head)
        ind += self._strings(head)
        return ind

    def scan(self, obj: ScanObject) -> list[Detection]:
        ind = self.analyze(obj)
        score = min(100, sum(i.weight for i in ind))
        if score < self.threshold or not ind:
            return []
        top = max(ind, key=lambda i: i.weight)
        sev = Severity.HIGH if score >= 85 else Severity.MEDIUM
        return [
            Detection(
                engine=self.name,
                name=f"Heuristic.{top.category}",
                severity=sev,
                description=f"Suspicion score {score}/100: " + "; ".join(i.text for i in ind[:6]),
                details={"score": score, "indicators": [f"[{i.weight}] {i.text}" for i in ind]},
            )
        ]

    # ------------------------------------------------------------------ checks
    def _filename(self, name: str, lname: str, ext: str, head: bytes) -> list[Indicator]:
        out: list[Indicator] = []
        if "‮" in name:
            out.append(Indicator(70, "Masquerade", "Right-to-left override character hides the real extension"))
        is_exe = head[:2] == b"MZ" or head[:4] == b"\x7fELF"
        parts = lname.split(".")
        if len(parts) >= 3 and parts[-1] in LAUNCHABLE_EXT and parts[-2] in DECOY_EXT:
            # A document-looking name that is really a program is a classic phishing trick.
            weight = (
                60 if (is_exe or parts[-1] in SCRIPT_EXT or parts[-1] in {"scr", "pif", "com", "lnk", "hta"}) else 40
            )
            out.append(Indicator(weight, "Masquerade", f"Double extension '.{parts[-2]}.{parts[-1]}'"))
        if re.search(r"\s{5,}\.\w+$", name):
            out.append(Indicator(30, "Masquerade", "Long whitespace padding before extension"))
        if is_exe and ext in DECOY_EXT:
            out.append(Indicator(45, "Masquerade", f"Executable code disguised with '.{ext}' extension"))
        return out

    def _pe(self, obj: ScanObject) -> list[Indicator]:
        out: list[Indicator] = []
        if not HAVE_PEFILE:
            return out
        try:
            if obj.fs_path is not None:
                pe = pefile.PE(str(obj.fs_path), fast_load=True)
            else:
                pe = pefile.PE(data=obj.data, fast_load=True)
        except Exception:
            if b"PE\x00\x00" in obj.head[:4096]:
                out.append(Indicator(20, "Malformed", "Malformed PE structure"))
            return out
        has_signature = False
        try:
            out += self._pe_body(pe, obj)
            sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4] if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > 4 else None
            has_signature = sec is not None and sec.Size > 0
        except Exception:
            out.append(Indicator(15, "Malformed", "PE structure could not be fully analysed"))
        finally:
            pe.close()  # release the file mapping (on Windows an open mapping locks the file)
        if has_signature and obj.fs_path is not None:
            sig = authenticode.verify(str(obj.fs_path))
            if sig is Signature.TAMPERED:
                out.append(
                    Indicator(40, "Tampered", "Authenticode signature is broken: file was modified after signing")
                )
            elif sig is Signature.VALID and sum(i.weight for i in out) > 0:
                out.append(Indicator(-60, "Signed", "Valid Authenticode signature from a trusted publisher"))
            elif sig is Signature.UNAVAILABLE and out:
                out.append(Indicator(-10, "Signed", "Carries an Authenticode signature (verified only on Windows)"))
        return out

    def _pe_body(self, pe, obj: ScanObject) -> list[Indicator]:
        out: list[Indicator] = []
        try:
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                ]
            )
        except Exception:
            out.append(Indicator(15, "Malformed", "Corrupt PE data directories"))

        imports: set[str] = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                if imp.name:
                    imports.add(imp.name.decode(errors="ignore"))

        def imp(*names: str) -> bool:
            return any(n in imports or n + "A" in imports or n + "W" in imports for n in names)

        # packers & entropy
        packer_hits = set()
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section = None
        for i, s in enumerate(pe.sections):
            sname = s.Name.rstrip(b"\x00").lower()
            if sname in PACKER_SECTIONS and PACKER_SECTIONS[sname][0] not in packer_hits:
                pk, w = PACKER_SECTIONS[sname]
                packer_hits.add(pk)
                out.append(Indicator(w, "Packed", f"Packed with {pk}"))
            chars = s.Characteristics
            executable = bool(chars & 0x20000000)
            writable = bool(chars & 0x80000000)
            if executable and writable:
                out.append(
                    Indicator(15, "Packed", f"Section {sname.decode(errors='replace')!r} is writable and executable")
                )
            if executable and s.SizeOfRawData > 1024 and s.get_entropy() > 7.2:
                out.append(
                    Indicator(25, "Packed", f"Encrypted/compressed code section {sname.decode(errors='replace')!r}")
                )
            if s.contains_rva(ep):
                ep_section = i
        if pe.sections and ep and ep_section is None:
            out.append(Indicator(25, "Malformed", "Entry point lies outside every section"))
        elif ep_section is not None and len(pe.sections) > 2 and ep_section == len(pe.sections) - 1:
            out.append(Indicator(15, "Packed", "Entry point in last section (common for packers/infectors)"))

        if not imports and not pe.is_driver():
            out.append(Indicator(20, "Packed", "No import table (imports resolved at runtime)"))
        elif len(imports) < 10 and shannon_entropy(obj.head) > 7.3:
            out.append(Indicator(20, "Packed", "Very few imports with high overall entropy"))

        # behaviour suggested by imports
        if (
            imp("VirtualAllocEx")
            and imp("WriteProcessMemory")
            and imp("CreateRemoteThread", "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext", "RtlCreateUserThread")
        ):
            out.append(Indicator(40, "Injection", "Imports for code injection into other processes"))
        if imp("NtUnmapViewOfSection", "ZwUnmapViewOfSection") and imp("SetThreadContext", "Wow64SetThreadContext"):
            out.append(Indicator(40, "Injection", "Imports for process hollowing"))
        if imp("SetWindowsHookEx") and imp("GetAsyncKeyState", "GetKeyState", "GetKeyboardState"):
            out.append(Indicator(30, "Keylogger", "Global keyboard hook with key-state polling"))
        elif imp("GetAsyncKeyState") and imp("GetForegroundWindow"):
            out.append(Indicator(15, "Keylogger", "Polls keystrokes and the active window"))
        if imp("URLDownloadToFile", "URLDownloadToCacheFile"):
            out.append(Indicator(20, "Downloader", "Downloads files from the internet"))
        if imp("InternetOpenUrl", "WinHttpOpenRequest") and imp("WinExec", "ShellExecute", "CreateProcess"):
            out.append(Indicator(10, "Downloader", "Network access combined with process execution"))
        if (
            imp("CryptEncrypt", "BCryptEncrypt")
            and imp("FindFirstFile", "FindFirstFileEx")
            and imp("DeleteFile", "MoveFileEx", "SetFileAttributes")
        ):
            out.append(Indicator(25, "Ransomware", "Enumerates, encrypts and deletes/renames files"))
        if imp("IsDebuggerPresent") and imp("CheckRemoteDebuggerPresent", "NtQueryInformationProcess"):
            out.append(Indicator(10, "Evasion", "Multiple anti-debugging checks"))
        if imp("CryptUnprotectData") and imp("CredEnumerate", "LsaRetrievePrivateData"):
            out.append(Indicator(20, "Stealer", "Accesses protected credentials"))
        if imp("AdjustTokenPrivileges") and imp("OpenProcess") and imp("MiniDumpWriteDump"):
            out.append(Indicator(35, "Stealer", "Dumps process memory with elevated privileges (LSASS dumping)"))

        ts = pe.FILE_HEADER.TimeDateStamp
        if ts > time.time() + 86400 * 30:
            out.append(Indicator(10, "Malformed", "Compile timestamp is in the future"))

        return out

    def _decode(self, head: bytes) -> str:
        if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
            return head.decode("utf-16", errors="ignore")
        return head.decode("utf-8", errors="ignore")

    def _script(self, head: bytes) -> list[Indicator]:
        t = self._decode(head[: 4 * 1024 * 1024]).lower()
        t_ns = re.sub(r"[\s`^\"'+]", "", t)  # defeat trivial string splitting / caret / backtick obfuscation
        out: list[Indicator] = []
        # PowerShell
        if re.search(r"-(e|en|enc|enco|encodedcommand)\s+[a-z0-9+/=]{80,}", t):
            out.append(Indicator(40, "Obfuscation", "PowerShell encoded command"))
        if _any(t_ns, "iex(", "invoke-expression") and _any(
            t_ns, "downloadstring", "net.webclient", "invoke-webrequest", "iwr", "downloaddata", "start-bitstransfer"
        ):
            out.append(Indicator(45, "Downloader", "Downloads and executes code in memory"))
        if _has(t_ns, "frombase64string") and _any(t_ns, "iex", "invoke-expression", "reflection.assembly"):
            out.append(Indicator(30, "Obfuscation", "Decodes and executes base64 payload"))
        if re.search(r"-(w|win|window|windowstyle)\s+(h|hidden)\b", t):
            out.append(Indicator(15, "Evasion", "Runs with a hidden window"))
        if _any(t_ns, "set-mppreference-disable", "disablerealtimemonitoring$true", "add-mppreference-exclusionpath"):
            out.append(Indicator(50, "Evasion", "Tampers with Microsoft Defender"))
        if _any(t_ns, "amsiutils", "amsiinitfailed", "amsiscanbuffer"):
            out.append(Indicator(60, "Evasion", "AMSI bypass attempt"))
        if _any(t_ns, "invoke-mimikatz", "sekurlsa::", "lsadump::"):
            out.append(Indicator(70, "Stealer", "Mimikatz credential theft"))
        # WSH / JScript / HTA
        if _has(t_ns, "wscript.shell") and _any(t_ns, ".run(", ".exec(") and "http" in t:
            out.append(Indicator(35, "Downloader", "Windows Script Host runs commands fetched from the web"))
        if _any(t_ns, "msxml2.xmlhttp", "winhttp.winhttprequest", "microsoft.xmlhttp") and _has(t_ns, "adodb.stream"):
            out.append(Indicator(45, "Downloader", "Downloads a file and writes it to disk"))
        if re.search(r"eval\s*\(\s*(unescape|atob|string\.fromcharcode|function\s*\(p,a,c,k,e)", t):
            out.append(Indicator(25, "Obfuscation", "Evaluates obfuscated code"))
        # Unix shells
        if re.search(r"(curl|wget)[^\n|;]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b", t):
            out.append(Indicator(35, "Downloader", "Pipes a downloaded script straight into a shell"))
        if "/dev/tcp/" in t or re.search(r"\b(nc|ncat|netcat)\b[^\n]{0,80}\s-e\s", t):
            out.append(Indicator(60, "Backdoor", "Reverse shell"))
        if re.search(r"base64\s+(-d|--decode)[^\n]{0,40}\|\s*(ba)?sh", t):
            out.append(Indicator(40, "Obfuscation", "Decodes base64 into a shell"))
        if re.search(r"chmod\s+\+?[0-7x]+\s+/(tmp|dev/shm|var/tmp)/", t) and _any(t, "curl", "wget"):
            out.append(Indicator(25, "Dropper", "Downloads and marks a temp file executable"))
        if "crontab" in t and _any(t, "curl", "wget") and re.search(r"(\*\s+){4}\*", t):
            out.append(Indicator(25, "Persistence", "Installs a cron job that downloads code"))
        if re.search(r"[a-z0-9+/]{2000,}={0,2}", t):
            out.append(Indicator(15, "Obfuscation", "Large embedded base64 blob"))
        return out

    def _ooxml(self, obj: ScanObject) -> list[Indicator]:
        out: list[Indicator] = []
        try:
            with zipfile.ZipFile(io.BytesIO(obj.read_all(64 * 1024 * 1024))) as z:
                vba = [n for n in z.namelist() if n.lower().endswith("vbaproject.bin")]
                if vba:
                    out.append(Indicator(25, "Macro", "Document contains VBA macros"))
                    info = z.getinfo(vba[0])
                    if info.file_size < 32 * 1024 * 1024:
                        out += self._vba(z.read(vba[0]))
        except (zipfile.BadZipFile, OSError, RuntimeError, ValueError):
            pass
        return out

    def _ole(self, head: bytes) -> list[Indicator]:
        if b"VBA" not in head and b"_VBA_PROJECT" not in head:
            return []
        return [Indicator(20, "Macro", "Legacy Office document with VBA macros"), *self._vba(head)]

    def _vba(self, blob: bytes) -> list[Indicator]:
        t = blob.lower()
        out: list[Indicator] = []
        auto = any(k in t for k in (b"autoopen", b"document_open", b"workbook_open", b"auto_open", b"autoexec"))
        exec_ = any(k in t for k in (b"shell", b"wscript.shell", b"createobject", b"powershell", b"urldownloadtofile"))
        if auto and exec_:
            out.append(Indicator(45, "Macro", "Auto-executing macro that launches commands"))
        elif auto:
            out.append(Indicator(10, "Macro", "Auto-executing macro"))
        return out

    def _lnk(self, head: bytes) -> list[Indicator]:
        t = (head.decode("latin-1") + head.decode("utf-16-le", errors="ignore")).lower()
        if _any(t, "powershell", "cmd.exe", "mshta", "rundll32", "wscript", "certutil", "bitsadmin"):
            weight = 50 if _any(t, "http", "-enc", "frombase64") else 30
            return [Indicator(weight, "Dropper", "Shortcut launches a script host / LOLBin")]
        return []

    def _strings(self, head: bytes) -> list[Indicator]:
        low = head.lower()
        wide = low.replace(b"\x00", b"")
        blob = low + b"\n" + wide if b"\x00" in low[:4096] else low
        out: list[Indicator] = []
        ransom = [
            b"vssadmin delete shadows",
            b"vssadmin.exe delete shadows",
            b"wmic shadowcopy delete",
            b"wbadmin delete catalog",
            b"bcdedit /set {default} recoveryenabled no",
            b"bcdedit /set {default} bootstatuspolicy ignoreallfailures",
        ]
        hits = [r for r in ransom if r in blob]
        families = {h.split()[0].split(b".")[0] for h in hits}  # vssadmin / wmic / wbadmin / bcdedit
        if len(families) >= 2:
            out.append(Indicator(70, "Ransomware", "Deletes backups with several different tools"))
        elif hits and head[:2] != b"MZ":
            # a single tool's command inside a script; the Windows tools' own help text contains it too
            out.append(Indicator(50, "Ransomware", "Deletes backups / shadow copies"))
        if b"stratum+tcp://" in blob or b"stratum+ssl://" in blob or b"xmrig" in blob:
            out.append(Indicator(55, "CoinMiner", "Cryptocurrency mining pool / miner"))
        if b"your files have been encrypted" in blob or b"files are encrypted" in blob and b"bitcoin" in blob:
            out.append(Indicator(45, "Ransomware", "Ransom note text"))
        return out
