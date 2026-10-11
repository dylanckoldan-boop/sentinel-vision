"""Main window, system tray, notifications, self-update and application entry point."""

from __future__ import annotations

import getpass
import logging
import os
import sys

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QCloseEvent, QDesktopServices
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QFrame,
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

from sentinel_vision import APP_NAME, __version__, app_update, autostart
from sentinel_vision.core import Sentinel, setup_logging
from sentinel_vision.gui import theme
from sentinel_vision.gui.pages import (
    CheckupPage,
    DashboardPage,
    HistoryPage,
    NetworkPage,
    ProtectionPage,
    QuarantinePage,
    RansomwarePage,
    ScanPage,
    SettingsPage,
    ToolsPage,
    WebShieldPage,
)
from sentinel_vision.gui.pages.base import AppContext
from sentinel_vision.gui.widgets import app_icon
from sentinel_vision.gui.workers import Bridge, Task, start

log = logging.getLogger(__name__)

NAV = [
    ("overview", "◉  Overview", DashboardPage),
    ("scan", "⌕  Scan", ScanPage),
    ("protection", "⛨  Protection", ProtectionPage),
    ("ransomware", "⟲  Ransomware", RansomwarePage),
    ("webshield", "◎  Web Shield", WebShieldPage),
    ("network", "⇅  Live traffic", NetworkPage),
    ("checkup", "✓  Checkup", CheckupPage),
    ("tools", "⚿  Privacy && tools", ToolsPage),
    ("quarantine", "⊘  Quarantine", QuarantinePage),
    ("history", "☰  History", HistoryPage),
    ("settings", "⚙  Settings", SettingsPage),
]
WINDOWS_MUTEX = "SentinelVisionAppMutex"  # lets installers and admin tools detect a running instance
APP_UPDATE_INTERVAL_MS = 6 * 60 * 60 * 1000


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
        self.available_update: app_update.ReleaseInfo | None = None
        self._update_task: Task | None = None

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
        self.status_pill.setTextFormat(Qt.RichText)
        self.status_pill.setWordWrap(True)
        sl.addWidget(self.status_pill)
        ver = QLabel(f"v{__version__} · MIT licensed")
        ver.setObjectName("brandSub")
        sl.addWidget(ver)
        h.addWidget(side)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(0)
        self.banner = self._build_banner()
        rl.addWidget(self.banner)
        rl.addWidget(self.stack, 1)
        h.addWidget(right, 1)

        # tray (the menu is kept on self: Qt does not take ownership of it)
        self.tray = QSystemTrayIcon(app_icon(), self)
        self.tray_menu = QMenu()
        self.tray_menu.addAction(QAction("Open Sentinel Vision", self, triggered=self.show_normal))
        self.tray_menu.addAction(
            QAction("Quick scan", self, triggered=lambda: (self.show_normal(), self.navigate("scan", "quick")))
        )
        self.tray_menu.addAction(
            QAction(
                "Update definitions", self, triggered=lambda: (self.show_normal(), self.navigate("settings", "update"))
            )
        )
        self.autostart_action = QAction("Start at sign-in", self, checkable=True)
        self.autostart_action.toggled.connect(self._tray_autostart)
        self.tray_menu.addAction(self.autostart_action)
        self.tray_menu.addSeparator()
        self.tray_menu.addAction(QAction("Quit Sentinel Vision", self, triggered=self.quit))
        self.tray_menu.aboutToShow.connect(self._sync_tray_menu)
        self.tray.setContextMenu(self.tray_menu)
        self.tray.activated.connect(
            lambda reason: (
                self.show_normal() if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick) else None
            )
        )
        self.tray.setToolTip(APP_NAME)
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray.show()

        # engine callbacks (any thread) → UI thread
        sentinel.realtime.on_result = self.bridge.realtime_result.emit
        sentinel.network.add_listener(self.bridge.network_alert.emit)
        sentinel.behavior.add_listener(self.bridge.behavior_alert.emit)
        sentinel.ransomware.add_listener(self.bridge.ransomware_alert.emit)
        sentinel.alert_listeners.append(lambda title, text, level: self.bridge.generic_alert.emit(title, text, level))
        self.bridge.ransomware_alert.connect(self._on_ransomware)
        self.bridge.generic_alert.connect(self.notify)
        self.bridge.realtime_result.connect(self._on_realtime)
        self.bridge.network_alert.connect(self._on_network_alert)
        self.bridge.behavior_alert.connect(self._on_behavior_alert)
        self.bridge.status_changed.connect(self.refresh_now)
        self.bridge.app_update_requested.connect(lambda: self.check_app_update(manual=True))

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(500)
        self._ticks = 0
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self._auto_update)
        self.update_timer.start(30 * 60 * 1000)
        self._first_defs_check = self._one_shot(4000, self._auto_update)
        self.schedule_timer = QTimer(self)
        self.schedule_timer.timeout.connect(self._scheduled)
        self.schedule_timer.start(60_000)
        self.app_update_timer = QTimer(self)
        self.app_update_timer.timeout.connect(self.check_app_update)
        self.app_update_timer.start(APP_UPDATE_INTERVAL_MS)
        self._first_app_check = self._one_shot(60_000, self.check_app_update)

        self.navigate("overview")
        self._update_status()

    def _one_shot(self, ms: int, fn) -> QTimer:
        """A single-shot timer owned by the window, so it can be stopped on shutdown (QTimer.singleShot can't)."""
        t = QTimer(self)
        t.setSingleShot(True)
        t.timeout.connect(fn)
        t.start(ms)
        return t

    def stop_timers(self) -> None:
        for t in self.findChildren(QTimer):
            t.stop()

    # ------------------------------------------------------------------ update banner
    def _build_banner(self) -> QFrame:
        f = QFrame()
        f.setObjectName("banner")
        f.setStyleSheet(
            f"QFrame#banner {{ background: #10302b; border-bottom: 1px solid {theme.ACCENT_DIM}; }}"
            f"QLabel {{ color: {theme.TEXT}; }}"
        )
        lay = QHBoxLayout(f)
        lay.setContentsMargins(28, 10, 28, 10)
        self.banner_text = QLabel()
        lay.addWidget(self.banner_text, 1)
        self.banner_go = QPushButton("Update now")
        self.banner_go.setObjectName("primary")
        self.banner_go.clicked.connect(self._banner_action)
        later = QPushButton("Later")
        later.clicked.connect(lambda: f.setVisible(False))
        lay.addWidget(self.banner_go)
        lay.addWidget(later)
        f.setVisible(False)
        return f

    def check_app_update(self, manual: bool = False) -> None:
        if self._quitting or (not manual and not self.sentinel.settings.check_app_updates):
            return
        task = Task(lambda _t: app_update.check_latest())
        task.signals.finished.connect(lambda info: self._on_update_checked(info, manual))
        task.signals.failed.connect(
            lambda err: (
                QMessageBox.warning(self, "Check for updates", f"Could not check for updates:\n{err}")
                if manual
                else log.info("app update check failed: %s", err)
            )
        )
        start(task)

    def _on_update_checked(self, info, manual: bool) -> None:
        if info is None:
            if manual:
                QMessageBox.information(self, "Check for updates", f"You have the latest version ({__version__}).")
            return
        self.available_update = info
        auto = app_update.can_self_install(info)
        self.banner_text.setText(
            f"<b>Sentinel Vision {info.version}</b> is available (you have {__version__})."
            + ("" if auto else " Download it from the release page.")
        )
        self.banner_go.setText("Update now" if auto else "View release")
        self.banner.setVisible(True)
        if not manual:
            self.notify("Update available", f"Sentinel Vision {info.version} is ready to install.", "info")
        elif auto:
            self._banner_action()

    def _banner_action(self) -> None:
        info = self.available_update
        if info is None:
            return
        if not app_update.can_self_install(info):
            QDesktopServices.openUrl(QUrl(info.page_url))
            return
        if self._update_task is not None:
            return
        if (
            QMessageBox.question(
                self,
                "Install update",
                f"Download and install Sentinel Vision {info.version}?\n\n"
                "The installer is verified against the release's SHA-256 checksums, closes Sentinel Vision, "
                "upgrades it and starts it again. Your settings, quarantine and history are kept.",
            )
            != QMessageBox.Yes
        ):
            return
        self.banner_go.setEnabled(False)
        self.banner_go.setText("Downloading…")
        task = Task(lambda _t: app_update.download_installer(info))
        task.signals.finished.connect(self._run_installer)
        task.signals.failed.connect(self._update_failed)
        self._update_task = start(task)

    def _run_installer(self, path) -> None:
        self._update_task = None
        try:
            app_update.run_installer(path)
        except Exception as exc:
            self._update_failed(str(exc))
            return
        self.quit()

    def _update_failed(self, err: str) -> None:
        self._update_task = None
        self.banner_go.setEnabled(True)
        self.banner_go.setText("Update now")
        QMessageBox.critical(self, "Update failed", f"The update could not be installed:\n\n{err}")

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

    def refresh_now(self) -> None:
        """Re-evaluate status everywhere immediately (e.g. right after protection started)."""
        dash = self.pages.get("overview")
        if dash is not None and hasattr(dash, "_last_slow"):
            dash._last_slow = 0.0
        self._update_status()
        current = self.stack.currentWidget()
        if current is not None:
            current.refresh()

    def _update_status(self) -> None:
        s = self.sentinel
        on = s.realtime.running
        net = s.network.running
        beh = s.behavior.running

        def dot(ok: bool, off_color: str = theme.MUTED) -> str:
            return f"<span style='color:{theme.OK if ok else off_color}'>●</span>"

        self.status_pill.setText(
            f"{dot(on, theme.DANGER)} Files: {'protected' if on else 'unprotected'}<br>"
            f"{dot(beh)} Behavior: {'watched' if beh else 'off'}<br>"
            f"{dot(net)} Network: {'monitored' if net else 'off'}"
        )
        self.tray.setIcon(app_icon(theme.ACCENT if on else theme.DANGER))

    # ------------------------------------------------------------------ autostart
    def _sync_tray_menu(self) -> None:
        self.autostart_action.blockSignals(True)
        self.autostart_action.setChecked(autostart.is_enabled())
        self.autostart_action.blockSignals(False)

    def _tray_autostart(self, on: bool) -> None:
        try:
            autostart.set_enabled(on)
        except autostart.AutostartError as exc:
            QMessageBox.warning(self, "Start at sign-in", str(exc))
        self._sync_tray_menu()
        self.bridge.status_changed.emit()

    def maybe_offer_autostart(self) -> None:
        """First run of a non-installer copy: offer to start at sign-in (the installer asks itself)."""
        db = self.sentinel.db
        if db.get_meta("autostart_offered") or autostart.is_installed_build():
            return
        db.set_meta("autostart_offered", "1")
        if autostart.is_enabled():
            return
        answer = QMessageBox.question(
            self,
            "Start automatically?",
            "Protection only runs while Sentinel Vision is running.\n\n"
            "Start it automatically (hidden in the system tray) every time you sign in?\n"
            "You can change this any time in Protection or from the tray icon.",
        )
        if answer == QMessageBox.Yes:
            self._tray_autostart(True)

    # ------------------------------------------------------------------ alerts
    def notify(self, title: str, text: str, level: str = "info") -> None:
        if self.sentinel.settings.quiet_mode and level != "danger":
            return
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

    def _scheduled(self) -> None:
        if not self._quitting:
            started = self.sentinel.run_due_scans()
            if started:
                self.notify("Scheduled scan", f"A scheduled {started[0]} scan started in the background.", "info")

    def _on_ransomware(self, inc) -> None:
        frozen = [f"{s.name} (PID {s.pid})" for s in inc.suspects if s.state == "suspended"]
        self.notify("RANSOMWARE BLOCKED" if frozen else "Ransomware alert", inc.detail, "danger")
        self.show_normal()
        self.navigate("ransomware")
        page = self.pages["ransomware"]
        page.refresh()
        if page.inc_model.rowCount():
            page.inc_table.selectRow(0)
        QMessageBox.critical(
            self,
            "Ransomware activity detected",
            f"{inc.detail}\n\n"
            + (
                f"Frozen: {', '.join(frozen)}.\n\nChoose “End & quarantine” to remove it, or “Resume” if you are "
                "sure it is safe. Then restore your files from the rollback vault."
                if frozen
                else "No program could be identified automatically. Disconnect from the network, then check the "
                "Ransomware page and restore your files from the rollback vault."
            ),
        )

    def _on_behavior_alert(self, ev) -> None:
        who = f"{ev.process} (PID {ev.pid})" if ev.pid else ev.path
        self.notify(
            "Malicious behavior stopped" if ev.action.startswith("terminated") else "Suspicious behavior",
            f"{ev.name}\n{who}\n{ev.description}\n→ {ev.action}",
            "danger" if ev.severity >= 3 else "warning",
        )

    def _auto_update(self) -> None:
        if self._quitting:
            return
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
        self.stop_timers()
        self.tray.hide()
        self.sentinel.shutdown()
        e.accept()
        QApplication.quit()

    def quit(self) -> None:
        self._quitting = True
        self.close()


def _single_instance(app: QApplication, show_existing: bool) -> QLocalServer | None:
    name = f"SentinelVision-{getpass.getuser()}"
    sock = QLocalSocket()
    sock.connectToServer(name)
    if sock.waitForConnected(300):
        if show_existing:
            sock.write(b"show")
            sock.flush()
            sock.waitForBytesWritten(300)
        return None
    QLocalServer.removeServer(name)
    server = QLocalServer(app)
    server.listen(name)
    return server


_MUTEX_HANDLE = None


def _windows_mutex() -> None:
    """Named mutex so installers / management tools can detect that the app is running."""
    global _MUTEX_HANDLE
    if sys.platform != "win32":
        return
    try:
        import ctypes

        _MUTEX_HANDLE = ctypes.windll.kernel32.CreateMutexW(None, False, WINDOWS_MUTEX)  # type: ignore[attr-defined]
    except Exception:
        _MUTEX_HANDLE = None


def main() -> int:
    setup_logging()
    minimized = "--minimized" in sys.argv
    if hasattr(Qt, "HighDpiScaleFactorRoundingPolicy"):
        QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    app.setWindowIcon(app_icon())
    app.setStyle("Fusion")
    app.setStyleSheet(theme.STYLESHEET)
    app.setQuitOnLastWindowClosed(False)

    server = _single_instance(app, show_existing=not minimized)
    if server is None and not os.environ.get("SENTINEL_VISION_MULTI"):
        return 0  # already running (it was brought to the front unless this was a sign-in launch)
    _windows_mutex()

    try:
        sentinel = Sentinel()
    except Exception as exc:
        QMessageBox.critical(None, APP_NAME, f"Could not start the protection engine:\n\n{exc}")
        return 1
    try:
        autostart.repair()
    except Exception as exc:
        log.warning("could not repair start-at-sign-in entry: %s", exc)

    win = MainWindow(sentinel)
    if server is not None:
        server.newConnection.connect(lambda: (server.nextPendingConnection(), win.show_normal()))

    sentinel.start_protection()
    win.refresh_now()

    if minimized and QSystemTrayIcon.isSystemTrayAvailable():
        pass  # started at sign-in: stay in the tray
    elif minimized:
        win.showMinimized()  # no tray on this desktop: keep a taskbar entry so the app stays reachable
    else:
        win.show()
        win._one_shot(800, win.maybe_offer_autostart)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
