from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import QCheckBox, QFileDialog, QHBoxLayout, QListWidget, QMessageBox, QPushButton, QVBoxLayout

from sentinel_vision import autostart
from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page, fmt_ts, make_table, severity_color
from sentinel_vision.gui.widgets import RowTableModel, StatCard, card, label

BIG = "font-size: 14px; font-weight: 600;"
MAC_FDA_URL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"


class ProtectionPage(Page):
    title = "Protection"
    subtitle = (
        "Files are scanned the moment they are created, downloaded, changed or moved into a protected folder; "
        "new programs and auto-start entries are checked as they appear. Known malware is quarantined."
    )

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        top = QHBoxLayout()
        top.setSpacing(12)

        sw_card, sl = card()
        cols = QHBoxLayout()
        left, right = QVBoxLayout(), QVBoxLayout()
        left.setSpacing(6)
        right.setSpacing(6)
        self.toggle = QCheckBox("Real-time file protection")
        self.behavior_toggle = QCheckBox("Behavior monitoring")
        self.net_toggle = QCheckBox("Live network monitoring")
        self.login_toggle = QCheckBox("Start at sign-in")
        for w in (self.toggle, self.behavior_toggle, self.net_toggle, self.login_toggle):
            w.setStyleSheet(BIG)
        self.state = label("", "muted")
        self.state.setTextFormat(Qt.RichText)
        self.login_state = label("", "muted")
        self.login_state.setWordWrap(True)
        left.addWidget(self.toggle)
        left.addWidget(self.state)
        left.addWidget(self.behavior_toggle)
        self.rw_toggle = QCheckBox("Ransomware shield && rollback vault")
        self.rw_toggle.setStyleSheet(BIG)
        left.addWidget(self.rw_toggle)
        left.addWidget(self.net_toggle)
        self.usb_toggle = QCheckBox("Scan USB drives when connected")
        self.privacy_toggle = QCheckBox("Alert when an app uses the camera or microphone")
        self.netsec_toggle = QCheckBox("Watch for router spoofing and DNS hijacking")
        self.fw_toggle = QCheckBox("Block known criminal networks in Windows Firewall")
        self.fw_toggle.setToolTip(
            "Applied by the protection service from Spamhaus DROP, Feodo Tracker and Emerging Threats lists. "
            "Local and private networks are never blocked."
        )
        for w in (self.usb_toggle, self.privacy_toggle, self.netsec_toggle, self.fw_toggle):
            left.addWidget(w)
        self.fw_toggle.setVisible(self.s.service is not None)
        left.addStretch(1)
        self.auto_q = QCheckBox("Quarantine signature detections automatically")
        self.kill_mal = QCheckBox("End programs confirmed as malware")
        self.kill_ransom = QCheckBox("Stop ransomware from deleting backups")
        right.addWidget(self.login_toggle)
        right.addWidget(self.login_state)
        right.addWidget(self.auto_q)
        right.addWidget(self.kill_mal)
        right.addWidget(self.kill_ransom)
        right.addStretch(1)
        cols.addLayout(left, 1)
        cols.addLayout(right, 1)
        sl.addLayout(cols)
        top.addWidget(sw_card, 1)
        self.root.addLayout(top)

        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.c_scanned = StatCard("Files checked")
        self.c_blocked = StatCard("Threats stopped")
        self.c_procs = StatCard("Programs checked")
        for c in (self.c_scanned, self.c_blocked, self.c_procs):
            stats.addWidget(c)
        self.root.addLayout(stats)

        if sys.platform == "darwin":
            mac, ml = card()
            ml.addWidget(label("macOS needs your permission", "h2"))
            ml.addWidget(
                label(
                    "To scan Downloads, Desktop, Documents, Mail and other protected folders, add Sentinel Vision in "
                    "System Settings → Privacy & Security → Full Disk Access, then restart the app.",
                    "muted",
                    wrap=True,
                )
            )
            b = QPushButton("Open Full Disk Access settings")
            b.clicked.connect(lambda: QDesktopServices.openUrl(QUrl(MAC_FDA_URL)))
            ml.addWidget(b, 0, Qt.AlignLeft)
            self.root.addWidget(mac)

        f_card, fl = card()
        fl.addWidget(label("Protected folders", "h2"))
        self.folders = QListWidget()
        self.folders.setMaximumHeight(96)
        fl.addWidget(self.folders)
        row = QHBoxLayout()
        self.b_add = QPushButton("Add folder…")
        self.b_rm = QPushButton("Remove")
        row.addWidget(self.b_add)
        row.addWidget(self.b_rm)
        row.addStretch(1)
        self.errors = label("", None, wrap=True)
        self.errors.setStyleSheet(f"color: {theme.WARN};")
        fl.addLayout(row)
        fl.addWidget(self.errors)
        self.root.addWidget(f_card)

        self.root.addWidget(label("Recent real-time and behavior detections", "h2"))
        self.model = RowTableModel(
            ["When", "Threat", "Source", "File / program", "Action"], color_for=lambda d: severity_color(d.severity)
        )
        self.table = make_table(self.model, stretch_col=3)
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 260)
        self.table.setColumnWidth(2, 110)
        self.root.addWidget(self.table, 1)

        self.toggle.toggled.connect(lambda on: self._set("realtime_enabled", on, apply=True))
        self.behavior_toggle.toggled.connect(lambda on: self._set("behavior_enabled", on, apply=True))
        self.net_toggle.toggled.connect(lambda on: self._set("network_enabled", on, apply=True))
        self.auto_q.toggled.connect(lambda on: self._set("auto_quarantine", on))
        self.kill_mal.toggled.connect(lambda on: self._set("behavior_kill_malicious", on))
        self.kill_ransom.toggled.connect(lambda on: self._set("behavior_block_ransomware", on))
        self.login_toggle.toggled.connect(self._toggle_login)
        self.rw_toggle.toggled.connect(lambda on: self._set("ransomware_enabled", on, apply=True))
        self.usb_toggle.toggled.connect(lambda on: self._set("usb_autoscan", on, apply=True))
        self.privacy_toggle.toggled.connect(lambda on: self._set("privacy_monitor", on, apply=True))
        self.netsec_toggle.toggled.connect(lambda on: self._set("netsec_enabled", on, apply=True))
        self.fw_toggle.toggled.connect(lambda on: self._set("firewall_block", on))
        self.b_add.clicked.connect(self._add)
        self.b_rm.clicked.connect(self._remove)
        self._sync()

    # ------------------------------------------------------------------ state
    def _sync(self) -> None:
        st = self.s.settings
        pairs = (
            (self.toggle, st.realtime_enabled),
            (self.behavior_toggle, st.behavior_enabled),
            (self.net_toggle, st.network_enabled),
            (self.auto_q, st.auto_quarantine),
            (self.kill_mal, st.behavior_kill_malicious),
            (self.kill_ransom, st.behavior_block_ransomware),
            (self.rw_toggle, st.ransomware_enabled),
            (self.usb_toggle, st.usb_autoscan),
            (self.privacy_toggle, st.privacy_monitor),
            (self.netsec_toggle, st.netsec_enabled),
            (self.fw_toggle, st.firewall_block),
        )
        for w, v in pairs:
            w.blockSignals(True)
            w.setChecked(v)
            w.blockSignals(False)
        self._sync_login()
        self.folders.clear()
        self.folders.addItems(st.watch_paths)

    def _sync_login(self) -> None:
        stt = autostart.status()
        self.login_toggle.blockSignals(True)
        self.login_toggle.setChecked(stt.enabled)
        self.login_toggle.blockSignals(False)
        if stt.enabled:
            scope = " for all users" if stt.scope == "all users" else ""
            self.login_state.setText(f"Starts hidden in the tray when you sign in{scope}.")
        else:
            self.login_state.setText("Off — protection stops whenever the app is not running.")

    def _set(self, key: str, value: bool, apply: bool = False) -> None:
        setattr(self.s.settings, key, value)
        self.commit_settings(apply)
        if apply:
            self.ctx.bridge.status_changed.emit()
        self.refresh()

    def _toggle_login(self, on: bool) -> None:
        if self.s.service is not None:
            # with the protection service, "start at sign-in" also means "restart if closed" and is guarded
            self.s.settings.keep_running = on
            if not self.commit_settings(apply=False):
                self._sync_login()
                return
        try:
            autostart.set_enabled(on)
        except autostart.AutostartError as exc:
            QMessageBox.warning(self, "Start at sign-in", str(exc))
        self._sync_login()

    def _add(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Protect folder")
        if d and d not in self.s.settings.watch_paths:
            self.s.settings.watch_paths.append(d)
            self._sync()
            self.commit_settings()
            self.refresh()

    def _remove(self) -> None:
        for item in self.folders.selectedItems():
            if item.text() in self.s.settings.watch_paths:
                self.s.settings.watch_paths.remove(item.text())
        self._sync()
        self.commit_settings()
        self.refresh()

    def refresh(self) -> None:
        rt = self.s.realtime
        on = rt.running
        self.state.setText(
            f"<span style='color:{theme.OK if on else theme.DANGER}'>●</span> "
            + (
                f"Active — watching {len(rt.watching)} folder(s)"
                if on
                else "Off — files are not checked when they arrive"
            )
        )
        self.c_scanned.set(f"{rt.files_scanned:,}", "this session")
        dets = self.s.db.recent_detections(400)
        rows = [d for d in dets if d.origin in ("realtime", "behavior", "ransomware", "usb", "memory")][:150]
        stopped = rt.threats_blocked + sum(1 for e in self.s.behavior.events if e.action.startswith("terminated"))
        self.c_blocked.set(str(stopped), "this session", theme.DANGER if stopped else theme.OK)
        self.c_procs.set(f"{self.s.behavior.processes_checked:,}", "this session")
        self.errors.setText("\n".join(rt.errors))
        self.model.set_rows([(fmt_ts(d.ts), d.name, d.origin, d.path, d.action) for d in rows], rows)
        self._sync_login()
