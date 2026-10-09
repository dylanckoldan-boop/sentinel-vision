"""Main window, system tray, notifications and application entry point."""

from __future__ import annotations

import getpass
import os
import sys

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from sentinel_vision import APP_NAME, __version__
from sentinel_vision.core import Sentinel, setup_logging
from sentinel_vision.gui import theme
from sentinel_vision.gui.pages import (
    DashboardPage,
    HistoryPage,
    NetworkPage,
    ProtectionPage,
    QuarantinePage,
    ScanPage,
    SettingsPage,
)
from sentinel_vision.gui.pages.base import AppContext
from sentinel_vision.gui.widgets import app_icon
from sentinel_vision.gui.workers import Bridge, Task, start

NAV = [
    ("overview", "◉  Overview", DashboardPage),
    ("scan", "⌕  Scan", ScanPage),
    ("protection", "⛨  Protection", ProtectionPage),
    ("network", "⇅  Live traffic", NetworkPage),
    ("quarantine", "⊘  Quarantine", QuarantinePage),
    ("history", "☰  History", HistoryPage),
    ("settings", "⚙  Settings", SettingsPage),
]


class MainWindow(QMainWindow):
    def __init__(self, sentinel: Sentinel) -> None:
        super().__init__()
        self.sentinel = sentinel
        self.bridge = Bridge()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(app_icon())
        self.resize(1320, 860)
        self.setMinimumSize(1040, 680)
        self._quitting = False

        root = QWidget()
        root.setObjectName("root")
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        self.setCentralWidget(root)

        side = QWidget()
        side.setObjectName("sidebar")
        side.setFixedWidth(220)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(14, 20, 14, 16)
        sl.setSpacing(4)
        brand_row = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(app_icon().pixmap(34, 34))
        brand_row.addWidget(logo)
        bt = QVBoxLayout()
        bt.setSpacing(0)
        b1 = QLabel("SENTINEL VISION")
        b1.setObjectName("brand")
        b2 = QLabel("open-source antimalware")
        b2.setObjectName("brandSub")
        bt.addWidget(b1)
        bt.addWidget(b2)
        brand_row.addLayout(bt)
        brand_row.addStretch(1)
        sl.addLayout(brand_row)
        sl.addSpacing(20)

        self.stack = QStackedWidget()
        self.ctx = AppContext(sentinel, self.bridge, self.notify, self.navigate)
        self.pages: dict[str, QWidget] = {}
        self.buttons: dict[str, QPushButton] = {}
        group = QButtonGroup(self)
        group.setExclusive(True)
        for key, text, cls in NAV:
            page = cls(self.ctx)
            self.pages[key] = page
            self.stack.addWidget(page)
            btn = QPushButton(text)
            btn.setObjectName("nav")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.clicked.connect(lambda _c=False, k=key: self.navigate(k))
            group.addButton(btn)
            self.buttons[key] = btn
            sl.addWidget(btn)
        sl.addStretch(1)
        self.status_pill = QLabel()
        self.status_pill.setWordWrap(True)
        sl.addWidget(self.status_pill)
        ver = QLabel(f"v{__version__} · MIT licensed")
        ver.setObjectName("brandSub")
        sl.addWidget(ver)
        h.addWidget(side)
        h.addWidget(self.stack, 1)

        # tray
        self.tray = QSystemTrayIcon(app_icon(), self)
        menu = QMenu()
        menu.addAction(QAction("Open Sentinel Vision", self, triggered=self.show_normal))
        menu.addAction(
            QAction("Quick scan", self, triggered=lambda: (self.show_normal(), self.navigate("scan", "quick")))
        )
        menu.addAction(QAction("Update definitions", self, triggered=lambda: self.navigate("settings", "update")))
        menu.addSeparator()
        menu.addAction(QAction("Quit", self, triggered=self.quit))
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda reason: (
                self.show_normal() if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None
            )
        )
        self.tray.setToolTip(APP_NAME)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

        # engine callbacks → UI thread
        sentinel.realtime.on_result = self.bridge.realtime_result.emit
        sentinel.network.add_listener(self.bridge.network_alert.emit)
        self.bridge.realtime_result.connect(self._on_realtime)
        self.bridge.network_alert.connect(self._on_network_alert)
        self.bridge.status_changed.connect(self._update_status)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(500)
        self._ticks = 0
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._auto_update)
        self.update_timer.start(30 * 60 * 1000)
        QTimer.singleShot(4000, self._auto_update)

        self.navigate("overview")
        self._update_status()

    # ------------------------------------------------------------------ navigation
    def navigate(self, key: str, action: str | None = None) -> None:
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        self.buttons[key].setChecked(True)
        page.refresh()
        if action and hasattr(page, "action"):
            page.action(action)

    def _tick(self) -> None:
        self._ticks += 1
        page = self.stack.currentWidget()
        if self.isVisible() and not self.isMinimized() and self._ticks * 500 % max(500, page.refresh_ms) == 0:
            page.refresh()
        if self._ticks % 10 == 0:
            self._update_status()

    def _update_status(self) -> None:
        s = self.sentinel
        on = s.realtime.running
        net = s.network.running
        color = theme.OK if on else theme.DANGER
        self.status_pill.setText(
            f"<span style='color:{color}'>●</span> Files: {'protected' if on else 'unprotected'}<br>"
            f"<span style='color:{theme.OK if net else theme.MUTED}'>●</span> Network: {'monitored' if net else 'off'}"
        )
        self.tray.setIcon(app_icon(theme.ACCENT if on else theme.DANGER))

    # ------------------------------------------------------------------ alerts
    def notify(self, title: str, text: str, level: str = "info") -> None:
        icon = {"danger": QSystemTrayIcon.Critical, "info": QSystemTrayIcon.Information}.get(
            level, QSystemTrayIcon.Warning
        )
        if self.tray.isVisible():
            self.tray.showMessage(title, text, icon, 8000)

    def _on_realtime(self, res) -> None:
        top = res.top
        self.notify(
            "Threat blocked" if res.action == "quarantined" else "Threat detected",
            f"{top.name if top else 'Malware'}\n{res.path}\n→ {res.action}",
            "danger",
        )
        self._update_status()

    def _on_network_alert(self, conn) -> None:
        self.notify(
            "Suspicious connection",
            f"{conn.process or 'Unknown'} (PID {conn.pid}) → {conn.remote}\n{conn.threat}",
            "danger" if conn.severity >= 3 else "warning",
        )

    def _auto_update(self) -> None:
        up = self.sentinel.updater
        if not up.due():
            return
        task = Task(lambda t: up.run())
        task.signals.finished.connect(lambda _r: (self.sentinel.after_update(), self._update_status()))
        start(task)

    # ------------------------------------------------------------------ window lifecycle
    def show_normal(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def closeEvent(self, e: QCloseEvent) -> None:  # noqa: N802
        if not self._quitting and self.sentinel.settings.minimize_to_tray and self.tray.isVisible():
            e.ignore()
            self.hide()
            self.notify(APP_NAME, "Still protecting you in the background. Right-click the tray icon to quit.")
            return
        self._quitting = True
        self.sentinel.shutdown()
        e.accept()
        QApplication.quit()

    def quit(self) -> None:
        self._quitting = True
        self.close()


def _single_instance(app: QApplication) -> QLocalServer | None:
    name = f"SentinelVision-{getpass.getuser()}"
    sock = QLocalSocket()
    sock.connectToServer(name)
    if sock.waitForConnected(300):
        sock.write(b"show")
        sock.flush()
        sock.waitForBytesWritten(300)
        return None
    QLocalServer.removeServer(name)
    server = QLocalServer(app)
    server.listen(name)
    return server


def main() -> int:
    setup_logging()
    if hasattr(Qt, "HighDpiScaleFactorRoundingPolicy"):
        QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setWindowIcon(app_icon())
    app.setStyle("Fusion")
    app.setStyleSheet(theme.STYLESHEET)
    app.setQuitOnLastWindowClosed(False)

    server = _single_instance(app)
    if server is None and not os.environ.get("SENTINEL_VISION_MULTI"):
        print("Sentinel Vision is already running; bringing it to the front.")
        return 0

    try:
        sentinel = Sentinel()
    except Exception as exc:
        QMessageBox.critical(None, APP_NAME, f"Could not start the protection engine:\n\n{exc}")
        return 1
    win = MainWindow(sentinel)
    if server is not None:
        server.newConnection.connect(lambda: (server.nextPendingConnection(), win.show_normal()))

    # start background protection
    if sentinel.settings.realtime_enabled:
        sentinel.realtime.start(sentinel.settings.watch_paths)
    if sentinel.settings.network_enabled:
        sentinel.network.start()
    win._update_status()

    if "--minimized" not in sys.argv:
        win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
