"""Stable surface for Sentinel Vision plugins (API version 1).

A plugin is a Python package that declares an entry point in the ``sentinel_vision.plugins`` group::

    [project.entry-points."sentinel_vision.plugins"]
    my_plugin = "my_plugin.gui:register"

``register()`` returns a list of page descriptors, each with ``key`` (unique id), ``label`` (sidebar text) and
``factory`` (a callable taking the host context and returning a QWidget). :class:`PluginPage` is a ready-made
descriptor. The host context is the app's :class:`AppContext`; plugins should only rely on ``notify(title, text,
level)`` and ``navigate(key)``.

Where plugins are loaded from, the approval step and the command-line tools for plugins (``quarantine add``,
``plugin-log``, ``net block``) are described in docs/PLUGINS.md. Sentinel Vision never imports a plugin by name.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sentinel_vision.pluginlog import PluginLogError, check_name, verify_chain

if TYPE_CHECKING:  # imported lazily at run time (they need PySide6), see __getattr__
    from sentinel_vision.gui.pages.base import AppContext, Page

API_VERSION = 1
ENTRY_POINT_GROUP = "sentinel_vision.plugins"

__all__ = [
    "API_VERSION",
    "ENTRY_POINT_GROUP",
    "AppContext",
    "Page",
    "PluginLog",
    "PluginLogError",
    "PluginPage",
    "plugin_log",
    "verify_chain",
]


@dataclass(frozen=True)
class PluginPage:
    key: str
    label: str
    factory: Callable[[Any], Any]


def __getattr__(name: str):
    # the GUI classes need PySide6; import them only when a GUI plugin asks for them
    if name in ("AppContext", "Page"):
        from sentinel_vision.gui.pages import base

        return getattr(base, name)
    raise AttributeError(name)


class PluginLog:
    """Append-only records for one plugin. ``protected`` tells whether the protection service keeps them."""

    def __init__(self, name: str, transport=None) -> None:
        self.name = check_name(name)
        self._t = transport
        self._local = None
        if transport is None:
            from sentinel_vision.config import sub_dir
            from sentinel_vision.pluginlog import AppendOnlyLog

            self._local = AppendOnlyLog(sub_dir("plugins") / self.name / "log.jsonl")

    @property
    def protected(self) -> bool:
        return self._t is not None

    def append(self, record: dict) -> int:
        """Add a record; returns its sequence number."""
        if self._t is not None:
            from sentinel_vision.servicecore import ServiceError

            try:
                return int(self._t.call("plugin.append", {"name": self.name, "record": record})[0]["seq"])
            except ServiceError as exc:
                raise PluginLogError(str(exc)) from exc
        return int(self._local.append(record)["seq"])

    def read(self, since: int = 0, limit: int = 1000) -> list[dict]:
        """Entries after sequence number ``since`` (each with seq, ts, record, prev and hash)."""
        if self._t is not None:
            from sentinel_vision.servicecore import ServiceError

            try:
                return self._t.call("plugin.read", {"name": self.name, "since": since, "limit": limit})[0]["entries"]
            except ServiceError as exc:
                raise PluginLogError(str(exc)) from exc
        return self._local.read(since, limit)

    def verify(self) -> tuple[bool, int]:
        """(chain intact, number of entries)."""
        if self._t is not None:
            r = self._t.call("plugin.read", {"name": self.name, "since": 0, "limit": 1, "verify": True})[0]
            return bool(r["intact"]), int(r["count"])
        return self._local.verify()


def plugin_log(name: str) -> PluginLog:
    """The log for plugin ``name``. Uses the protection service when it is installed; if it is installed but not
    reachable this raises instead of quietly writing an unprotected log."""
    from sentinel_vision import service_client

    t = service_client.connect()
    if t is None and service_client.service_installed():
        raise PluginLogError("the protection service is installed but not reachable; nothing was written")
    return PluginLog(name, t)
