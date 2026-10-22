# PyInstaller spec — build with:  pyinstaller --noconfirm packaging/sentinel_vision.spec
# -*- mode: python ; coding: utf-8 -*-
#
# Produces one folder ("dist/SentinelVision", or "dist/SentinelVision.app" on macOS) containing:
#   SentinelVision(.exe)          the desktop app (no console window)
#   sentinel-vision-cli(.exe)     the command-line tool (console)
#   sentinel-vision-service.exe   Windows only: the protection service (runs as LocalSystem)
# All executables share one set of libraries.
import os
import re
import sys

SPEC_DIR = os.path.abspath(SPECPATH)  # noqa: F821 (SPECPATH is injected by PyInstaller)
SRC = os.path.abspath(os.path.join(SPEC_DIR, "..", "src"))
ASSETS = os.path.join(SPEC_DIR, "assets")
sys.path.insert(0, SRC)  # works from a source checkout as well as after `pip install .`

from PyInstaller.utils.hooks import collect_data_files, collect_submodules  # noqa: E402

with open(os.path.join(SRC, "sentinel_vision", "__init__.py"), encoding="utf-8") as fh:
    VERSION = re.search(r'__version__ = "([^"]+)"', fh.read()).group(1)
NUMERIC = tuple(int(x) for x in re.findall(r"\d+", VERSION)[:3]) + (0,)

datas = collect_data_files("sentinel_vision", includes=["rules/*.yar", "rules/*.yara"])
hidden = collect_submodules("sentinel_vision") + collect_submodules("watchdog.observers")
# pywin32 modules are imported inside functions (Windows only), so PyInstaller can't see them on its own
WIN_CLIENT = ["win32file", "win32pipe", "win32api", "win32security", "pywintypes"] if sys.platform == "win32" else []
WIN_SERVICE = WIN_CLIENT + ["win32ts", "win32profile", "win32process", "win32con", "win32service",
                            "win32serviceutil", "servicemanager", "win32timezone", "win32event"]  # fmt: skip
excludes = ["tkinter", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.Qt3DCore", "PySide6.QtQuick3D"]

version_file = None
if sys.platform == "win32":
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

    version_file = VSVersionInfo(
        ffi=FixedFileInfo(filevers=NUMERIC, prodvers=NUMERIC, mask=0x3F, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0),
        kids=[
            StringFileInfo(
                [
                    StringTable(
                        "040904B0",
                        [
                            StringStruct("CompanyName", "Sentinel Vision contributors"),
                            StringStruct("FileDescription", "Sentinel Vision antimalware"),
                            StringStruct("FileVersion", VERSION),
                            StringStruct("InternalName", "SentinelVision"),
                            StringStruct("LegalCopyright", "MIT License"),
                            StringStruct("OriginalFilename", "SentinelVision.exe"),
                            StringStruct("ProductName", "Sentinel Vision"),
                            StringStruct("ProductVersion", VERSION),
                        ],
                    )
                ]
            ),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )

icon = os.path.join(ASSETS, "icon.icns" if sys.platform == "darwin" else "icon.ico")

a = Analysis(
    [os.path.join(SPEC_DIR, "launcher.py")],
    pathex=[SRC],
    datas=datas,
    hiddenimports=hidden + WIN_CLIENT,
    excludes=excludes,
    noarchive=False,
)
cli = Analysis(
    [os.path.join(SPEC_DIR, "launcher_cli.py")],
    pathex=[SRC],
    datas=datas,
    hiddenimports=[m for m in hidden if not m.startswith("sentinel_vision.gui")] + WIN_CLIENT,
    excludes=excludes + ["PySide6"],
    noarchive=False,
)
svc = None
if sys.platform == "win32":
    svc = Analysis(
        [os.path.join(SPEC_DIR, "launcher_service.py")],
        pathex=[SRC],
        datas=datas,
        hiddenimports=[m for m in hidden if not m.startswith("sentinel_vision.gui")] + WIN_SERVICE,
        excludes=excludes + ["PySide6"],
        noarchive=False,
    )

pyz = PYZ(a.pure)
gui_exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SentinelVision",
    console=False,
    icon=icon,
    version=version_file,
    upx=False,
)
cli_pyz = PYZ(cli.pure)
cli_exe = EXE(
    cli_pyz,
    cli.scripts,
    [],
    exclude_binaries=True,
    name="sentinel-vision-cli",
    console=True,
    icon=icon,
    version=version_file,
    upx=False,
)
extra = []
if svc is not None:
    svc_exe = EXE(
        PYZ(svc.pure),
        svc.scripts,
        [],
        exclude_binaries=True,
        name="sentinel-vision-service",
        console=True,
        icon=icon,
        version=version_file,
        upx=False,
    )
    extra = [svc_exe, svc.binaries, svc.datas]
coll = COLLECT(
    gui_exe,
    a.binaries,
    a.datas,
    cli_exe,
    cli.binaries,
    cli.datas,
    *extra,
    name="SentinelVision",
    upx=False,
)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="SentinelVision.app",
        icon=icon,
        bundle_identifier="io.github.dylanckoldan-boop.sentinel-vision",
        version=VERSION,
        info_plist={
            "CFBundleName": "Sentinel Vision",
            "CFBundleDisplayName": "Sentinel Vision",
            "CFBundleShortVersionString": VERSION,
            "CFBundleVersion": VERSION,
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "14.0",
        },
    )
