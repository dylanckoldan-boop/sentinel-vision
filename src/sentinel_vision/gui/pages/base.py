from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QLabel, QTableView, QVBoxLayout, QWidget

from sentinel_vision.gui import theme
from sentinel_vision.gui.workers import Bridge

if TYPE_CHECKING:
    from sentinel_vision.core import Sentinel


@dataclass
class AppContext:
    sentinel: Sentinel
    bridge: Bridge
    notify: object  # callable(title, text, level)
    navigate: object  # callable(page_name)


class Page(QWidget):
    title = ""
    subtitle = ""
    refresh_ms = 3000

    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.setObjectName("page")
        self.root = QVBoxLayout(self)
        self.root.setContentsMargins(28, 24, 28, 24)
        self.root.setSpacing(16)
        h1 = QLabel(self.title)
        h1.setObjectName("h1")
        self.root.addWidget(h1)
        if self.subtitle:
            sub = QLabel(self.subtitle)
            sub.setObjectName("muted")
            sub.setWordWrap(True)
            self.root.addWidget(sub)

    @property
    def s(self) -> Sentinel:
        return self.ctx.sentinel

    def refresh(self) -> None:
        """Called when the page becomes visible and periodically while visible."""


def make_table(model, stretch_col: int | None = None) -> QTableView:
    t = QTableView()
    t.setModel(model)
    t.setAlternatingRowColors(True)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.ExtendedSelection)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(30)
    t.setShowGrid(False)
    t.setWordWrap(False)
    t.setTextElideMode(Qt.ElideMiddle)
    hh = t.horizontalHeader()
    hh.setHighlightSections(False)
    hh.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    hh.setSectionResizeMode(QHeaderView.Interactive)
    hh.setStretchLastSection(stretch_col is None)
    if stretch_col is not None:
        hh.setSectionResizeMode(stretch_col, QHeaderView.Stretch)
    t.setSortingEnabled(False)
    return t


def fmt_ts(ts: float) -> str:
    if not ts:
        return "never"
    d = dt.datetime.fromtimestamp(ts)
    today = dt.date.today()
    if d.date() == today:
        return d.strftime("Today %H:%M:%S")
    if d.date() == today - dt.timedelta(days=1):
        return d.strftime("Yesterday %H:%M")
    return d.strftime("%Y-%m-%d %H:%M")


def ago(ts: float) -> str:
    if not ts:
        return "never"
    secs = max(0, dt.datetime.now().timestamp() - ts)
    if secs < 90:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)} min ago"
    if secs < 86400 * 2:
        return f"{int(secs // 3600)} h ago"
    return f"{int(secs // 86400)} days ago"


def severity_color(sev: int) -> str:
    return theme.SEVERITY_COLORS.get(int(sev), theme.TEXT)
