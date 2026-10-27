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
        self._nav_group = group
        self._sidebar_layout = sl
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
        self._plugin_insert_at = sl.count()  # plugin buttons go after the built-in pages (loaded at the end)
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
        self.degraded_banner = self._build_degraded_banner()
        rl.addWidget(self.degraded_banner)
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
        self._service_task: Task | None = None
        if self.sentinel.service is not None:
            self.service_timer = QTimer(self)
            self.service_timer.timeout.connect(self._service_tick)
            self.service_timer.start(60_000)
            self._one_shot(3000, self._service_tick)

        self._reconnect_task: Task | None = None
        if self.sentinel.degraded:
            self._show_degraded_state()
            self.reconnect_timer = QTimer(self)
            self.reconnect_timer.timeout.connect(self._try_reconnect)
            self.reconnect_timer.start(15_000)
            self._one_shot(
                1500,
                lambda: self.notify(
                    "Tamper protection is off",
                    "Sentinel Vision can't reach its protection service. Protection stays at full strength.",
                    "danger",
                ),
            )

        self._load_plugins()  # last: plugins get a fully built window (tray, notifications, navigation)
        self.navigate("overview")
        self._update_status()

    def _one_shot(self, ms: int, fn) -> QTimer:
        """A single-shot timer owned by the window, so it can be stopped on shutdown (QTimer.singleShot can't)."""
        t = QTimer(self)
        t.setSingleShot(True)
        t.timeout.connect(fn)
        t.start(ms)
        return t

    def _service_tick(self) -> None:
        """Heartbeat to the protection service (it restarts the app if this stops) and show what it reported."""
        if self._quitting or self._service_task is not None:
            return
        sv = self.sentinel
        task = Task(lambda _t: sv.service_tick())
        task.signals.finished.connect(self._service_events)
        task.signals.failed.connect(lambda _e: setattr(self, "_service_task", None))
        self._service_task = start(task)

    def _service_events(self, events) -> None:
        self._service_task = None
        for ev in events or []:
            if ev.get("kind") == "refused":
                self.sentinel.alert("Protection change blocked", ev.get("detail", ""), "danger")
            elif ev.get("kind") == "watchdog":
                self.sentinel.alert("Sentinel Vision was restarted", ev.get("detail", ""), "warning")

    def stop_timers(self) -> None:
        for t in self.findChildren(QTimer):
            t.stop()

    # ------------------------------------------------------------------ update banner
    def _build_degraded_banner(self) -> QFrame:
        """Shown for as long as the installed protection service can't be reached (audit finding SV-A01)."""
        f = QFrame()
        f.setObjectName("degradedBanner")
        f.setStyleSheet(
            f"QFrame#degradedBanner {{ background: #3a1216; border-bottom: 1px solid {theme.DANGER}; }}"
            f"QLabel {{ color: {theme.TEXT}; }}"
        )
        lay = QHBoxLayout(f)
        lay.setContentsMargins(28, 10, 28, 10)
        self.degraded_text = QLabel()
        self.degraded_text.setWordWrap(True)
        self.degraded_text.setTextFormat(Qt.RichText)
        lay.addWidget(self.degraded_text, 1)
        f.setVisible(False)  # no "Later" button: it stays until the service is back
        return f

    def _show_degraded_state(self) -> None:
        sv = self.sentinel
        if not sv.degraded:
            self.degraded_banner.setVisible(False)
            return
        if sv.degraded_reason == "impostor":
            why = "Another program is answering in its place, which may be an attack. Run a full scan."
        else:
            why = "It isn't running or can't be reached. Sentinel Vision keeps trying every 15 seconds."
        self.degraded_text.setText(
            f"<b style='color:{theme.DANGER}'>Protection service unreachable — tamper protection is off.</b> {why} "
            "Protection stays at full strength, nothing is quarantined or kept in the rollback vault until it's back, "
            "and protection can't be reduced."
        )
        self.degraded_banner.setVisible(True)

    def _try_reconnect(self) -> None:
        """Degraded mode: try to reach the service again (off the window's thread)."""
        if self._quitting or not self.sentinel.degraded or self._reconnect_task is not None:
            return
        sv = self.sentinel
        task = Task(lambda _t: sv.try_reconnect())
        task.signals.finished.connect(self._reconnected)
        task.signals.failed.connect(lambda _e: setattr(self, "_reconnect_task", None))
        self._reconnect_task = start(task)

    def _reconnected(self, ok) -> None:
        self._reconnect_task = None
        if ok:
            self._show_degraded_state()
            self.reload_protected_pages()
            if not hasattr(self, "service_timer"):
                self.service_timer = QTimer(self)
                self.service_timer.timeout.connect(self._service_tick)
                self.service_timer.start(60_000)

    def reload_protected_pages(self) -> None:
        for page in self.pages.values():
            if hasattr(page, "load"):
                try:
                    page.load()
                except Exception as exc:
                    log.warning("reloading a page failed: %s", exc)

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
        # installed by the protection service only (never from a folder other programs can write to)
        auto = app_update.can_self_install(info) and self.sentinel.service is not None
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
        if not app_update.can_self_install(info) or self.sentinel.service is None:
            QDesktopServices.openUrl(QUrl(info.page_url))
            return
        if self._update_task is not None:
            return
        if (
            QMessageBox.question(
                self,
                "Install update",
                f"Install Sentinel Vision {info.version}?\n\n"
                "The protection service downloads it, checks its post-quantum signature and SHA-256, and installs "
                "it. Sentinel Vision closes and starts again on its own. Your settings, quarantine and history "
                "are kept.",
            )
            != QMessageBox.Yes
        ):
            return
        self.banner_go.setEnabled(False)
        self.banner_go.setText("Installing…")
        service = self.sentinel.service
        task = Task(lambda _t: service.call("update.install", {"version": info.version})[0])
        task.signals.finished.connect(self._update_started)
        task.signals.failed.connect(self._update_failed)
        self._update_task = start(task)

    def _update_started(self, result) -> None:
        self._update_task = None
        version = (result or {}).get("version", "")
        self.banner_text.setText(
            f"<b>Installing Sentinel Vision {version}.</b> It closes in a moment and starts again on its own."
        )
        self.banner_go.setVisible(False)

    def _update_failed(self, err: str) -> None:
        self._update_task = None
        self.banner_go.setEnabled(True)
        self.banner_go.setText("Update now")
        QMessageBox.critical(self, "Update failed", f"The update could not be installed:\n\n{err}")

    # ------------------------------------------------------------------ plugins
    def _load_plugins(self) -> None:
        """Mount pages contributed by plugins the user allowed, and ask once about new ones. Never fails the app:
        a broken plugin is logged and skipped. See plugins.py for where plugins may come from."""
        try:
            from sentinel_vision import plugins

            found = plugins.discover()
        except Exception as exc:
            log.warning("could not look for plugins: %s", exc)
            return
        st = self.sentinel.settings
        allowed = {x.lower() for x in st.approved_plugins}
        declined = {x.lower() for x in st.declined_plugins}
        new = []
        for f in found:
            if f.problem:
                log.warning("plugin %s not loaded: %s", f.name, f.problem)
            elif f.fingerprint in allowed:
                self._mount_plugin(f)
            elif f.fingerprint not in declined:
                new.append(f)
        if new:
            self._one_shot(4000, lambda: self._ask_about_plugins(new))  # owned by the window: stops on shutdown

    def _mount_plugin(self, found) -> None:
        from sentinel_vision import plugins

        try:
            pages = plugins.load_pages(found)
        except Exception as exc:
            log.warning("plugin %s failed to load: %s", found.name, exc)
            return
        for p in pages:
            if p.key in self.pages:
                log.warning("plugin %s: page key %r is already used", found.name, p.key)
                continue
            try:
                widget = p.factory(self.ctx)
                host = PluginHost(widget)
            except Exception as exc:
                log.warning("plugin %s page %s failed: %s", found.name, p.key, exc)
                continue
            self.pages[p.key] = host
            self.stack.addWidget(host)
            btn = QPushButton(p.label)
            btn.setObjectName("nav")
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setToolTip(f"Plugin: {found.name} {found.version}")
            btn.clicked.connect(lambda _c=False, k=p.key: self.navigate(k))
            self._nav_group.addButton(btn)
            self.buttons[p.key] = btn
            self._sidebar_layout.insertWidget(self._plugin_insert_at, btn)
            self._plugin_insert_at += 1
            log.info("plugin page %s (%s %s) added", p.key, found.name, found.version)

    def _ask_about_plugins(self, new: list) -> None:
        from sentinel_vision.gui.pages.base import commit_settings

        st = self.sentinel.settings
        for f in new:
            if getattr(self, "_quitting", False):
                return
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Warning)
            box.setWindowTitle("Allow a plugin?")
            box.setText(f"Sentinel Vision found a plugin: <b>{f.name} {f.version}</b>")
            box.setInformativeText(
                f"Location: {f.location}\n\nA plugin runs inside Sentinel Vision with the same rights, so it is "
                "trusted as much as Sentinel Vision itself. Only allow plugins you installed yourself."
            )
            allow = box.addButton("Allow", QMessageBox.AcceptRole)
            box.addButton("Don't allow", QMessageBox.RejectRole)
            box.exec()
            if box.clickedButton() is allow:
                st.approved_plugins = [*st.approved_plugins, f.fingerprint]
                if commit_settings(self, self.sentinel, apply=False):  # administrator approval with the service
                    self._mount_plugin(f)
            else:
                st.declined_plugins = [*st.declined_plugins, f.fingerprint]
                try:
                    self.sentinel.save_settings()
                except Exception as exc:
                    log.warning("could not save the plugin choice: %s", exc)

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
        if self.sentinel.service is not None and self.sentinel.settings.keep_running:
            # the protection service restarts the app unless protection is stopped with administrator approval
            from sentinel_vision.protect import request_pause

            if (
                QMessageBox.question(
                    self,
                    "Quit Sentinel Vision",
                    "Quitting stops Sentinel Vision's protection until you next sign in.\n\nWindows will ask for "
                    "administrator permission, so other programs can't do this without you.",
                    QMessageBox.Ok | QMessageBox.Cancel,
                    QMessageBox.Cancel,
                )
                != QMessageBox.Ok
            ):
                return
            if not request_pause(self.sentinel):
                QMessageBox.information(self, "Quit Sentinel Vision", "Sentinel Vision keeps running.")
                return
        self._quitting = True
        self.close()


class PluginHost(QWidget):
    """Holds a plugin's page: gives it the refresh interface the window expects and contains its errors."""

    refresh_ms = 3000

    def __init__(self, widget: QWidget) -> None:
        super().__init__()
        self.widget = widget
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(widget)
        self._failed = False

    def refresh(self) -> None:
        fn = getattr(self.widget, "refresh", None)
        if callable(fn) and not self._failed:
            try:
                fn()
            except Exception as exc:
                self._failed = True  # log once, then stop calling it
                log.warning("plugin page refresh failed: %s", exc)


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
    multi = bool(os.environ.get("SENTINEL_VISION_MULTI")) and not getattr(sys, "frozen", False)  # developers only
    if server is None and not multi:
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
