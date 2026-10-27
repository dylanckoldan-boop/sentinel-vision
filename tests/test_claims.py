"""docs/CLAIMS.md stays true to the code: every test it names exists, every file it names exists, and every
feature the website lists has a row (audit finding SV-E02)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAIMS = ROOT / "docs" / "CLAIMS.md"
SRC = ROOT / "src" / "sentinel_vision"


def _test_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def test_every_test_named_in_the_claims_register_exists():
    text = CLAIMS.read_text(encoding="utf-8")
    refs = re.findall(r"`(tests/[\w/]+\.py)::(\w+)`", text)
    assert len(refs) > 50
    missing = []
    cache: dict[str, set[str]] = {}
    for file, name in refs:
        path = ROOT / file
        if not path.is_file():
            missing.append(f"{file} (file)")
            continue
        names = cache.setdefault(file, _test_names(path))
        if name not in names:
            missing.append(f"{file}::{name}")
    assert not missing, "docs/CLAIMS.md names tests that don't exist: " + ", ".join(sorted(set(missing)))


def test_every_file_named_in_the_claims_register_exists():
    text = CLAIMS.read_text(encoding="utf-8")
    missing = []
    for ref in re.findall(r"`((?:packaging|tools|site)/[\w./-]+)`", text):
        if not (ROOT / ref).exists():
            missing.append(ref)
    for ref in re.findall(r"`([\w/]+\.py)`", text):
        if ref.startswith(("tests/", "tools/", "site/")):
            continue
        if not (SRC / ref).exists():
            missing.append(ref)
    for ref in re.findall(r"`(\w+/)`", text):
        if not (SRC / ref).is_dir():
            missing.append(ref)
    assert not missing, "docs/CLAIMS.md names files that don't exist: " + ", ".join(sorted(set(missing)))


def _website_features() -> list[str]:
    build = (ROOT / "site" / "build.py").read_text(encoding="utf-8")
    block = build[build.index("    also = [") : build.index("also_html =")]
    titles = re.findall(r'\(\s*"([^"]+)",', block)
    section = build[build.index('id="features"') : build.index('id="data"')]
    titles += re.findall(r"<article class=\"feature\">\s*<div>\s*<h3>([^<]+)</h3>", section)
    return titles


def test_every_website_feature_has_a_claims_row():
    titles = _website_features()
    assert len(titles) >= 15, titles
    rows = [line.lower() for line in CLAIMS.read_text(encoding="utf-8").splitlines() if line.startswith("| ")]
    missing = [t for t in titles if not any(row.startswith("| " + t.lower()) for row in rows)]
    assert not missing, "website features with no row in docs/CLAIMS.md: " + ", ".join(missing)


def test_no_shell_or_exec_of_scanned_content():
    """The source never runs a shell or evaluates text: no shell=True, os.system, os.popen, os.startfile,
    or the exec/eval built-ins."""
    found = []
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            where = f"{path.relative_to(ROOT)}:{node.lineno}"
            if isinstance(f, ast.Name) and f.id in ("exec", "eval"):
                found.append(where)
            if (
                isinstance(f, ast.Attribute)
                and isinstance(f.value, ast.Name)
                and f.value.id == "os"
                and f.attr in ("system", "popen", "startfile")
            ):
                found.append(where)
            for kw in node.keywords:
                if kw.arg == "shell" and not (isinstance(kw.value, ast.Constant) and kw.value.value is False):
                    found.append(where)
    assert not found, found
