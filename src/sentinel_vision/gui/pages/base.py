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

    def commit_settings(self, apply: bool = True) -> bool:
        """Save (and apply) the settings. On Windows with the protection service, a change that reduces protection
        needs administrator approval; if the user doesn't give it, the change is undone. Returns True if saved."""
        return commit_settings(self, self.s, apply)


def commit_settings(parent: QWidget, sentinel: Sentinel, apply: bool = True) -> bool:
    import threading

    from PySide6.QtCore import QEventLoop, QTimer
    from PySide6.QtWidgets import QMessageBox

    from sentinel_vision.core import ProtectionChangeNeedsAdmin
    from sentinel_vision.protect import request_change
    from sentinel_vision.servicecore import label

    try:
        if apply:
            sentinel.apply_settings()
        else:
            sentinel.save_settings()
        return True
    except ProtectionChangeNeedsAdmin as exc:
        names = ", ".join(label(f) for f in exc.fields)
        if getattr(sentinel, "degraded", False):
            QMessageBox.warning(
                parent,
                "Protection can't be reduced right now",
                f"This change reduces your protection ({names}), and Sentinel Vision can't reach its protection "
                "service to ask for administrator approval. The change was undone.",
            )
            sentinel.reload_protected_settings()
            if apply:
                sentinel.apply_runtime()
            return False
        answer = QMessageBox.question(
            parent,
            "Administrator approval needed",
            f"This change reduces your protection ({names}).\n\nTo stop other programs from switching protection "
            "off, Windows will ask for administrator permission, and Sentinel Vision will then show exactly what "
            "will change.",
            QMessageBox.Ok | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        ok = False
        if answer == QMessageBox.Ok:
            result: list[bool] = []
            worker = threading.Thread(target=lambda: result.append(request_change(sentinel)), daemon=True)
            worker.start()
            loop = QEventLoop()
            timer = QTimer()
            timer.timeout.connect(lambda: loop.quit() if not worker.is_alive() else None)
            timer.start(100)
            loop.exec()
            timer.stop()
            ok = bool(result and result[0])
        if not ok:
            sentinel.reload_protected_settings()
        if apply:
            sentinel.apply_runtime()
        return ok


def wait_for(fn):
    """Run a blocking call (such as waiting for the Windows administrator prompt) without freezing the window."""
    import threading

    from PySide6.QtCore import QEventLoop, QTimer

    result: list = []
    worker = threading.Thread(target=lambda: result.append(fn()), daemon=True)
    worker.start()
    loop = QEventLoop()
    timer = QTimer()
    timer.timeout.connect(lambda: loop.quit() if not worker.is_alive() else None)
    timer.start(100)
    loop.exec()
    timer.stop()
    return result[0] if result else None


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
