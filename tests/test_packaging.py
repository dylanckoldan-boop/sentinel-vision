"""The built app carries the packages plugins share with it (INT-N04), and the release checks that it does."""

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _check_bundle():
    spec = importlib.util.spec_from_file_location("check_bundle", ROOT / "packaging" / "check_bundle.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_spec_bundles_the_shared_packages_whole():
    spec = (ROOT / "packaging" / "sentinel_vision.spec").read_text(encoding="utf-8")
    listed = re.search(r"SHARED_WITH_PLUGINS = \[([^\]]*)\]", spec)
    assert listed, "the spec names the packages it shares with plugins"
    names = tuple(re.findall(r'"([^"]+)"', listed.group(1)))
    assert "cryptography" in names
    assert "hidden += [m for pkg in SHARED_WITH_PLUGINS for m in collect_submodules(pkg)]" in spec
    assert names == _check_bundle().SHARED_WITH_PLUGINS  # the check looks for what the spec bundles


def test_the_check_finds_what_foldward_needs_and_what_is_missing():
    cb = _check_bundle()
    needed = cb.shared_modules()
    # Foldward keeps its keys with serialization, which the app itself never imports
    assert {"cryptography", "cryptography.hazmat.primitives.serialization", "cryptography.x509"} <= needed
    assert not any(".__init__" in m or "__pycache__" in m for m in needed)
    assert cb.missing(needed, needed) == []
    assert cb.missing(needed - {"cryptography.hazmat.primitives.serialization"}, needed) == [
        "cryptography.hazmat.primitives.serialization"
    ]


def test_the_windows_release_runs_the_check_before_packaging():
    wf = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    build = wf.index("pyinstaller --noconfirm packaging/sentinel_vision.spec")
    check = wf.index(r"python packaging/check_bundle.py dist\SentinelVision\SentinelVision.exe")
    assert build < check < wf.index("Build installer (Inno Setup)")
