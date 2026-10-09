from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QFileDialog, QHBoxLayout, QListWidget, QPushButton

from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page, fmt_ts, make_table, severity_color
from sentinel_vision.gui.widgets import RowTableModel, StatCard, card, label


class ProtectionPage(Page):
    title = "Real-time protection"
    subtitle = (
        "Files are scanned as soon as they are created, downloaded, modified or moved into a protected folder. "
        "Known malware is quarantined before you can open it."
    )

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        top = QHBoxLayout()
        sw_card, sl = card()
        self.toggle = QCheckBox("Real-time file protection")
        self.toggle.setStyleSheet("font-size: 15px; font-weight: 600;")
        self.state = label("", "muted")
        self.state.setTextFormat(Qt.RichText)
        sl.addWidget(self.toggle)
        sl.addWidget(self.state)
        self.net_toggle = QCheckBox("Live network monitoring")
        self.net_toggle.setStyleSheet("font-size: 15px; font-weight: 600;")
        sl.addWidget(self.net_toggle)
        self.auto_q = QCheckBox("Quarantine signature detections automatically")
        sl.addWidget(self.auto_q)
        top.addWidget(sw_card, 2)
        self.c_scanned = StatCard("Files checked")
        self.c_blocked = StatCard("Threats stopped")
        top.addWidget(self.c_scanned, 1)
        top.addWidget(self.c_blocked, 1)
        self.root.addLayout(top)

        f_card, fl = card()
        fl.addWidget(label("Protected folders", "h2"))
        self.folders = QListWidget()
        self.folders.setMaximumHeight(170)
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

        self.root.addWidget(label("Recent real-time detections", "h2"))
        self.model = RowTableModel(
            ["When", "Threat", "Engine", "File", "Action"], color_for=lambda d: severity_color(d.severity)
        )
        self.table = make_table(self.model, stretch_col=3)
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 240)
        self.root.addWidget(self.table, 1)

        self.toggle.toggled.connect(self._toggle_rt)
        self.net_toggle.toggled.connect(self._toggle_net)
        self.auto_q.toggled.connect(self._toggle_aq)
        self.b_add.clicked.connect(self._add)
        self.b_rm.clicked.connect(self._remove)
        self._sync()

    def _sync(self) -> None:
        st = self.s.settings
        for w, v in (
            (self.toggle, st.realtime_enabled),
            (self.net_toggle, st.network_enabled),
            (self.auto_q, st.auto_quarantine),
        ):
            w.blockSignals(True)
            w.setChecked(v)
            w.blockSignals(False)
        self.folders.clear()
        self.folders.addItems(st.watch_paths)

    def _apply(self) -> None:
        self.s.apply_settings()
        self.ctx.bridge.status_changed.emit()
        self.refresh()

    def _toggle_rt(self, on: bool) -> None:
        self.s.settings.realtime_enabled = on
        self._apply()

    def _toggle_net(self, on: bool) -> None:
        self.s.settings.network_enabled = on
        self._apply()

    def _toggle_aq(self, on: bool) -> None:
        self.s.settings.auto_quarantine = on
        self.s.settings.save()

    def _add(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Protect folder")
        if d and d not in self.s.settings.watch_paths:
            self.s.settings.watch_paths.append(d)
            self._sync()
            self._apply()

    def _remove(self) -> None:
        for item in self.folders.selectedItems():
            if item.text() in self.s.settings.watch_paths:
                self.s.settings.watch_paths.remove(item.text())
        self._sync()
        self._apply()

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
        self.c_blocked.set(str(rt.threats_blocked), "this session", theme.DANGER if rt.threats_blocked else theme.OK)
        self.errors.setText("\n".join(rt.errors))
        rows = [d for d in self.s.db.recent_detections(300) if d.origin == "realtime"][:100]
        self.model.set_rows([(fmt_ts(d.ts), d.name, d.engine, d.path, d.action) for d in rows], rows)
