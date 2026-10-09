# PyInstaller spec — build with:  pyinstaller --noconfirm packaging/sentinel_vision.spec
# -*- mode: python ; coding: utf-8 -*-
import os
import sys

SRC = os.path.abspath(os.path.join(SPECPATH, "..", "src"))  # noqa: F821 (SPECPATH is injected by PyInstaller)
sys.path.insert(0, SRC)  # works from a source checkout as well as after `pip install .`

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

datas = collect_data_files("sentinel_vision", includes=["rules/*.yar", "rules/*.yara"])
hidden = collect_submodules("sentinel_vision") + collect_submodules("watchdog.observers")

a = Analysis(
    ["launcher.py"],
    pathex=[SRC],
    datas=datas,
    hiddenimports=hidden,
    excludes=["tkinter", "PySide6.QtWebEngineCore", "PySide6.Qt3DCore", "PySide6.QtQuick3D"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SentinelVision",
    console=False,
    upx=False,
)
coll = COLLECT(exe, a.binaries, a.datas, name="SentinelVision", upx=False)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="SentinelVision.app",
        bundle_identifier="io.github.dylanckoldan-boop.sentinel-vision",
        info_plist={"NSHighResolutionCapable": True, "LSUIElement": False},
    )
