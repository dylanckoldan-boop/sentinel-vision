"""Check that the built app carries every module of the packages it shares with plugins (INT-N04).

A plugin runs inside the app, and a package the app has already loaded (cryptography, for one) is always taken from
the app, so a copy installed into the plugin's folder is never used. PyInstaller bundles only the modules the app
itself imports, which left out cryptography's ``serialization`` package that Foldward needs for its keys: Foldward
was allowed but its pages never appeared. The spec now bundles the whole package, and the release runs this check
on the built app:

    python packaging/check_bundle.py dist/SentinelVision/SentinelVision.exe

It reads the app's module archive with PyInstaller's own reader and compares it with the pure-Python modules of
each shared package in the build environment. Exit code 0 when nothing is missing, 1 otherwise.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SHARED_WITH_PLUGINS = ("cryptography",)  # keep in step with packaging/sentinel_vision.spec


def shared_modules(packages=SHARED_WITH_PLUGINS) -> set[str]:
    """The pure-Python modules of ``packages`` as installed in this environment, found on disk without importing
    them (compiled modules sit next to the app as files and aren't in its archive)."""
    out: set[str] = set()
    for name in packages:
        spec = importlib.util.find_spec(name)
        if spec is None or not spec.submodule_search_locations:
            raise SystemExit(f"{name} is not an installed package here")
        for location in spec.submodule_search_locations:
            base = Path(location)
            for f in base.rglob("*.py"):
                rel = f.relative_to(base).with_suffix("")
                if "__pycache__" in rel.parts or not all(
                    (base.joinpath(*rel.parts[:i]) / "__init__.py").is_file() for i in range(len(rel.parts))
                ):
                    continue  # not part of the package (a folder without __init__.py)
                parts = [name, *rel.parts]
                out.add(".".join(parts[:-1] if parts[-1] == "__init__" else parts))
    return out


def bundled_modules(executable: str) -> set[str]:
    """Names of the modules in the archive PyInstaller embedded in ``executable``."""
    from PyInstaller.archive.readers import CArchiveReader

    archive = CArchiveReader(executable)
    pyz = next(name for name in archive.toc if name.endswith(".pyz"))
    return set(archive.open_embedded_archive(pyz).toc)


def missing(bundled: set[str], needed: set[str]) -> list[str]:
    return sorted(needed - bundled)


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        print("usage: check_bundle.py PATH-TO-THE-APP-EXECUTABLE", file=sys.stderr)
        return 2
    gaps = missing(bundled_modules(argv[0]), shared_modules())
    if gaps:
        print(f"{len(gaps)} module(s) that plugins share with the app are not in {argv[0]}:", file=sys.stderr)
        for name in gaps:
            print(f"  {name}", file=sys.stderr)
        return 1
    print(f"OK: {argv[0]} carries every module of {', '.join(SHARED_WITH_PLUGINS)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
