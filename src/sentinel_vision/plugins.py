"""Finding plugins (no GUI code here; the window mounts them, see gui/app.py).

Where plugins come from:

* **Installed app (Windows):** only from the ``plugins`` folder inside the program folder, e.g.
  ``C:\\Program Files\\Sentinel Vision\\plugins\\<name>\\``, which only an administrator can change. Each plugin is a
  folder made with ``pip install --target <that folder> <package>``; its ``*.dist-info`` declares the entry point.
  Every folder and file in it is checked: if anyone other than SYSTEM, Administrators or TrustedInstaller could
  change them, the plugin is refused, because a program running with the user's rights could otherwise put code
  inside the antivirus.
* **Run from Python (pip / source installs, all platforms):** packages installed in the same Python environment
  that declare an entry point in the ``sentinel_vision.plugins`` group.
* **Installed macOS / Linux bundles and the portable Windows build:** no plugins (no folder that only an
  administrator can change).

A plugin found this way is shown only after the user allowed it once. The approval is tied to a fingerprint of the
plugin's files, so a changed plugin is asked about again. On Windows with the protection service, allowing a plugin
counts as reducing protection, so it needs administrator approval and other programs can't approve one silently.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sys
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

log = logging.getLogger(__name__)

GROUP = "sentinel_vision.plugins"
MAX_PLUGIN_BYTES = 300 * 1024 * 1024
TRUSTED_SIDS = {
    "S-1-5-18",  # SYSTEM
    "S-1-5-32-544",  # Administrators
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller
}
CREATOR_OWNER = "S-1-3-0"
WRITE_MASK = (
    0x0002 | 0x0004 | 0x0010 | 0x0040 | 0x0100  # write data, append, write EA, delete child, write attributes
    | 0x00010000 | 0x00040000 | 0x00080000  # DELETE, WRITE_DAC, WRITE_OWNER
    | 0x10000000 | 0x40000000  # GENERIC_ALL, GENERIC_WRITE
)  # fmt: skip


@dataclass
class FoundPlugin:
    name: str
    version: str
    source: str  # "folder" (Program Files) or "python" (entry point in this Python environment)
    location: str
    fingerprint: str
    entry_points: list = field(default_factory=list, repr=False)
    problem: str = ""  # set when the plugin was found but must not be loaded

    @property
    def loadable(self) -> bool:
        return not self.problem and bool(self.entry_points)


# ---------------------------------------------------------------------------------------------- where to look
def plugins_root() -> Path | None:
    """The protected plugins folder of an installed Windows app, or None when plugins come from Python itself."""
    if not getattr(sys, "frozen", False) or sys.platform != "win32":
        return None
    from sentinel_vision.policy import _norm, program_dirs

    app = Path(sys.executable).resolve().parent
    if not any(_norm(str(app)).startswith(d.rstrip(os.sep) + os.sep) for d in program_dirs()):
        return None  # portable build or an unusual install location: no plugins
    return app / "plugins"


def admin_only_problem(path: Path) -> str:
    """'' when only SYSTEM, Administrators or TrustedInstaller can change ``path``; otherwise why not."""
    if sys.platform != "win32":
        return ""
    try:
        import win32security

        if os.path.islink(path) or (os.lstat(path).st_file_attributes & 0x400):
            return f"{path} is a link"
        sd = win32security.GetNamedSecurityInfo(
            str(path),
            win32security.SE_FILE_OBJECT,
            win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION,
        )
        owner = win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
        if owner not in TRUSTED_SIDS:
            return f"{path} is owned by {owner}"
        dacl = sd.GetSecurityDescriptorDacl()
        if dacl is None:
            return f"{path} has no access list (anyone can change it)"
        for i in range(dacl.GetAceCount()):
            (ace_type, ace_flags), mask, sid = dacl.GetAce(i)[:3]
            if ace_type != 0 or ace_flags & 0x08:  # only "allow" entries that apply to this object
                continue
            who = win32security.ConvertSidToStringSid(sid)
            if mask & WRITE_MASK and who not in TRUSTED_SIDS and who != CREATOR_OWNER:
                return f"{path} can be changed by {who}"
    except Exception as exc:  # can't tell: don't load
        return f"could not check permissions of {path}: {exc}"
    return ""


def _tree_problem(root: Path) -> str:
    for p in [root, *sorted(root.rglob("*"))]:
        problem = admin_only_problem(p)
        if problem:
            return problem
    return ""


def _folder_fingerprint(folder: Path) -> str:
    h, total = hashlib.sha256(), 0
    for p in sorted(folder.rglob("*")):
        if p.is_file() and "__pycache__" not in p.parts:
            data = p.read_bytes()
            total += len(data)
            if total > MAX_PLUGIN_BYTES:
                raise ValueError("plugin folder is too large")
            h.update(p.relative_to(folder).as_posix().encode() + b"\0" + hashlib.sha256(data).digest())
    return h.hexdigest()


def _dist_fingerprint(dist) -> str:
    h = hashlib.sha256(f"{dist.metadata['Name']}\0{dist.version}\0".encode())
    h.update((dist.read_text("RECORD") or "").encode())
    return h.hexdigest()


# ---------------------------------------------------------------------------------------------- discovery
def discover() -> list[FoundPlugin]:
    root = plugins_root()
    return _refuse_superseded(_discover_folder(root) if root is not None else _discover_python())


# Agent Guard was renamed Foldward (0.5.1). The old package carries code with known security problems (fixed in
# Foldward 0.2.0), keeps its old approval and registers the same `ag_*` pages, so it is never loaded (INT-07).
SUPERSEDED = {"agent-guard": "Foldward"}


def _canon(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _refuse_superseded(found: list[FoundPlugin]) -> list[FoundPlugin]:
    for f in found:
        newer = SUPERSEDED.get(_canon(f.name))
        if newer and not f.problem:
            f.problem = (
                f"{f.name} was renamed {newer}, and this old copy has known security problems; install {newer} "
                "(docs/PLUGINS.md) and remove this folder"
            )
            log.warning("plugin %s refused: %s", f.name, f.problem)
    return found


def _discover_python() -> list[FoundPlugin]:
    by_dist: dict[str, FoundPlugin] = {}
    try:
        eps = metadata.entry_points(group=GROUP)
    except Exception as exc:
        log.warning("could not list plugins: %s", exc)
        return []
    for ep in eps:
        dist = getattr(ep, "dist", None)
        name = dist.metadata["Name"] if dist else ep.name
        if name not in by_dist:
            by_dist[name] = FoundPlugin(
                name=name,
                version=dist.version if dist else "?",
                source="python",
                location=str(getattr(dist, "_path", "") or ""),
                fingerprint=(f"{name}@{dist.version}#{_dist_fingerprint(dist)[:24]}" if dist else name).lower(),
            )
        by_dist[name].entry_points.append(ep)
    return list(by_dist.values())


def _discover_folder(root: Path) -> list[FoundPlugin]:
    if not root.is_dir():
        return []
    out: list[FoundPlugin] = []
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        found = FoundPlugin(name=folder.name, version="?", source="folder", location=str(folder), fingerprint="")
        out.append(found)
        found.problem = admin_only_problem(root) or _tree_problem(folder)
        if found.problem:
            log.warning("plugin %s refused: %s", folder.name, found.problem)
            continue
        try:
            dists = list(metadata.distributions(path=[str(folder)]))
            fp = _folder_fingerprint(folder)
        except Exception as exc:
            found.problem = f"could not read the plugin: {exc}"
            continue
        for dist in dists:
            eps = [ep for ep in dist.entry_points if ep.group == GROUP]
            if eps:
                found.name, found.version = dist.metadata["Name"], dist.version
                found.entry_points += eps
        found.fingerprint = f"{found.name}@{found.version}#{fp[:24]}".lower()
        if not found.entry_points:
            found.problem = "no sentinel_vision.plugins entry point in this folder"
    return out


def load_pages(found: FoundPlugin) -> list:
    """Run the plugin's ``register()`` functions and return the page descriptors. Raises on any problem."""
    if not found.loadable:
        raise RuntimeError(found.problem or "nothing to load")
    if found.source == "folder" and found.location not in sys.path:
        sys.path.insert(0, found.location)
    pages = []
    for ep in found.entry_points:
        for p in ep.load()() or []:
            key, label, factory = getattr(p, "key", None), getattr(p, "label", None), getattr(p, "factory", None)
            if not (isinstance(key, str) and key and isinstance(label, str) and label and callable(factory)):
                raise TypeError(f"{ep.name}: a page needs a text key, a text label and a factory")
            pages.append(p)
    return pages
