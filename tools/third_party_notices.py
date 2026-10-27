"""Write THIRD_PARTY_NOTICES.txt for a build: every package the app bundles, with its licence text.

    python tools/third_party_notices.py OUTPUT [--check]

The list is the app's runtime dependency tree (Requires-Dist of the installed ``sentinel-vision`` package, followed
transitively, for this platform), so it is exactly what PyInstaller bundles. Exits with 1 if any of those packages
has no licence text and no vendored text in packaging/licenses (audit finding SV-E01). Run it in the build
environment, after ``pip install .``.
"""

from __future__ import annotations

import re
import sys
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDORED = ROOT / "packaging" / "licenses"
LICENSE_FILE = re.compile(r"(^|/)(LICEN[CS]E|COPYING|NOTICE|AUTHORS)[^/]*$", re.I)
# packages whose wheels carry no licence text: the vendored texts that apply
NO_TEXT_IN_WHEEL = {
    "pyside6": ["LGPL-3.0.txt", "GPL-3.0.txt"],
    "pyside6-essentials": ["LGPL-3.0.txt", "GPL-3.0.txt"],
    "pyside6-addons": ["LGPL-3.0.txt", "GPL-3.0.txt"],
    "pyside6-webengine": ["LGPL-3.0.txt", "GPL-3.0.txt"],
    "pyside6-pdf": ["LGPL-3.0.txt", "GPL-3.0.txt"],
    "shiboken6": ["LGPL-3.0.txt", "GPL-3.0.txt"],
}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def runtime_distributions(root: str = "sentinel-vision") -> list[metadata.Distribution]:
    from packaging.markers import default_environment
    from packaging.requirements import Requirement

    env = default_environment()
    seen: dict[str, metadata.Distribution] = {}
    todo = [root]
    while todo:
        name = _norm(todo.pop())
        if name in seen:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        seen[name] = dist
        for raw in dist.requires or []:
            req = Requirement(raw)
            if req.marker is None or req.marker.evaluate({**env, "extra": ""}):
                todo.append(req.name)
    seen.pop(_norm(root), None)
    return sorted(seen.values(), key=lambda d: _norm(d.metadata["Name"]))


def licence_of(dist: metadata.Distribution) -> str:
    md = dist.metadata
    expr = md.get("License-Expression")
    if expr:
        return expr
    classifiers = [c.split("::")[-1].strip() for c in md.get_all("Classifier") or [] if c.startswith("License ::")]
    lic = (md.get("License") or "").strip()
    return "; ".join(classifiers) or (lic.splitlines()[0][:120] if lic else "")


# packages that keep their licence inside the package instead of the .dist-info folder
IN_PACKAGE = {"pywin32": ("win32/license.txt", "win32com/License.txt", "pythonwin/license.txt")}


def licence_texts(dist: metadata.Distribution) -> list[tuple[str, str]]:
    out = []
    extra = IN_PACKAGE.get(_norm(dist.metadata["Name"]), ())
    for f in dist.files or []:
        if (LICENSE_FILE.search(str(f)) and ".dist-info" in str(f)) or str(f).replace("\\", "/") in extra:
            try:
                out.append((Path(str(f)).name, Path(dist.locate_file(f)).read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
    return out


def build(check_only: bool = False) -> tuple[str, list[str]]:
    from sentinel_vision import __version__

    dists = runtime_distributions()
    missing: list[str] = []
    parts = [
        f"Sentinel Vision {__version__}: third-party software notices",
        "",
        "Sentinel Vision itself is MIT-licensed (see LICENSE). This build also contains the software below, each",
        "under its own licence. Licence texts follow the list.",
        "",
    ]
    body: list[str] = []
    pyside_version = ""
    for d in dists:
        name, version = d.metadata["Name"], d.version
        lic = licence_of(d)
        url = d.metadata.get("Home-page") or next(
            (u.split(",", 1)[1].strip() for u in d.metadata.get_all("Project-URL") or [] if "," in u), ""
        )
        parts.append(f"  {name} {version}  ({lic or 'licence not stated'})  {url}".rstrip())
        texts = licence_texts(d)
        vendored = NO_TEXT_IN_WHEEL.get(_norm(name), [])
        if _norm(name) == "pyside6":
            pyside_version = version
        if not texts and not vendored:
            missing.append(f"{name} {version}")
        body.append("=" * 100)
        body.append(f"{name} {version}: {lic}")
        body.append("=" * 100)
        for fname, text in texts:
            body += [f"--- {fname}", text.rstrip(), ""]
        if vendored:
            body.append(f"Licensed under {lic}; the full licence texts are at the end of this file.")
            body.append("")
    parts += [
        f"  Python {sys.version.split()[0]}  (PSF-2.0)  https://www.python.org",
        "  YARA (the library inside yara-python)  (BSD-3-Clause)  https://github.com/VirusTotal/yara",
        "  OpenSSL (inside cryptography)  (Apache-2.0)  https://www.openssl.org",
        "",
        "Qt and Qt for Python (PySide6, Shiboken6) are used under the GNU Lesser General Public License version 3.",
        "You may replace the Qt and PySide6 libraries in this build with your own modified versions (they are the",
        "separate Qt6*.dll / libQt6* files and the PySide6 and shiboken6 folders). Their source code for exactly the",
        "version in this build is available at:",
        f"  https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-{pyside_version}-src/",
        f"  https://code.qt.io/cgit/pyside/pyside-setup.git/tag/?h=v{pyside_version}",
        "  https://download.qt.io/official_releases/qt/ (Qt itself, same version)",
        "Qt also contains third-party components under their own licences: https://doc.qt.io/qt-6/licenses-used-in-qt.html",
        "",
    ]
    tail = []
    for fname, title in (
        ("Python-PSF.txt", "Python"),
        ("YARA-BSD-3-Clause.txt", "YARA"),
        ("LGPL-3.0.txt", "GNU Lesser General Public License version 3"),
        ("GPL-3.0.txt", "GNU General Public License version 3 (which the LGPL builds on)"),
    ):
        tail += ["=" * 100, title, "=" * 100, (VENDORED / fname).read_text(encoding="utf-8").rstrip(), ""]
    return "\n".join(parts + body + tail) + "\n", missing


def main(argv: list[str]) -> int:
    text, missing = build()
    if missing:
        print("no licence text found for: " + ", ".join(missing), file=sys.stderr)
        return 1
    if argv and argv[0] != "--check":
        out = Path(argv[0])
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"wrote {out} ({len(text):,} characters)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
