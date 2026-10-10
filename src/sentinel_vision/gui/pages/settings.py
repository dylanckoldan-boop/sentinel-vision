from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from sentinel_vision import __version__
from sentinel_vision.gui.pages.base import Page, ago
from sentinel_vision.gui.widgets import label
from sentinel_vision.gui.workers import Task, start


class SettingsPage(Page):
    title = "Settings & updates"
    refresh_ms = 10000

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        st = self.s.settings
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        body = QWidget()
        body.setObjectName("page")
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 12, 0)
        lay.setSpacing(14)
        scroll.setWidget(body)
        self.root.addWidget(scroll, 1)

        # ---- updates
        up = QGroupBox("Threat definitions")
        ul = QVBoxLayout(up)
        row = QHBoxLayout()
        self.last_update = label("", "muted")
        row.addWidget(self.last_update, 1)
        self.b_update = QPushButton("Update now")
        self.b_update.setObjectName("primary")
        row.addWidget(self.b_update)
        ul.addLayout(row)
        self.update_log = QPlainTextEdit()
        self.update_log.setReadOnly(True)
        self.update_log.setMaximumHeight(140)
        self.update_log.setPlaceholderText("Update results appear here.")
        ul.addWidget(self.update_log)
        form = QFormLayout()
        self.key = QLineEdit(st.abusech_auth_key)
        self.key.setEchoMode(QLineEdit.Password)
        self.key.setPlaceholderText("Free key from auth.abuse.ch — enables MalwareBazaar hash feed")
        form.addRow("abuse.ch Auth-Key", self.key)
        self.auto_hours = QSpinBox()
        self.auto_hours.setRange(0, 168)
        self.auto_hours.setSuffix(" h  (0 = off)")
        self.auto_hours.setValue(st.auto_update_hours)
        form.addRow("Update automatically every", self.auto_hours)
        self.freshclam = QCheckBox("Also run freshclam (ClamAV database)")
        self.freshclam.setChecked(st.run_freshclam)
        form.addRow("", self.freshclam)
        ul.addLayout(form)
        ul.addWidget(label("Sources", "muted"))
        self.feeds = QListWidget()
        self.feeds.setMaximumHeight(200)
        for f in st.feeds:
            it = QListWidgetItem(f"{f.name}  —  {f.description}")
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Checked if f.enabled else Qt.Unchecked)
            it.setToolTip(f.url.replace("{abusech_key}", "<key>"))
            self.feeds.addItem(it)
        ul.addWidget(self.feeds)
        lay.addWidget(up)

        # ---- engines
        eng = QGroupBox("Detection engines")
        ef = QFormLayout(eng)
        self.e_hash = QCheckBox("Hash blocklists (exact matches, zero false positives)")
        self.e_yara = QCheckBox("YARA rules (bundled + YARA Forge + your own)")
        self.e_clam = QCheckBox("ClamAV (requires ClamAV installed; clamd recommended)")
        self.e_heur = QCheckBox("Heuristics (unknown threats; report-only by default)")
        for w, v in (
            (self.e_hash, st.hash_enabled),
            (self.e_yara, st.yara_enabled),
            (self.e_clam, st.clamav_enabled),
            (self.e_heur, st.heuristics_enabled),
        ):
            w.setChecked(v)
            ef.addRow(w)
        self.threshold = QSpinBox()
        self.threshold.setRange(20, 100)
        self.threshold.setValue(st.heuristic_threshold)
        self.threshold.setToolTip("Lower = more sensitive, more false positives")
        ef.addRow("Heuristic threshold (score)", self.threshold)
        self.clamd = QLineEdit(st.clamd_address)
        self.clamd.setPlaceholderText("auto-detect  (or /run/clamav/clamd.ctl, or 127.0.0.1:3310)")
        ef.addRow("clamd address", self.clamd)
        self.heur_q = QCheckBox("Also auto-quarantine high-score heuristic detections")
        self.heur_q.setChecked(st.auto_quarantine_heuristics)
        ef.addRow(self.heur_q)
        lay.addWidget(eng)

        # ---- scanning
        sc = QGroupBox("Scanning")
        sf = QFormLayout(sc)
        self.max_size = QSpinBox()
        self.max_size.setRange(1, 4096)
        self.max_size.setSuffix(" MB")
        self.max_size.setValue(st.max_file_size_mb)
        sf.addRow("Skip files larger than", self.max_size)
        self.archives = QCheckBox("Look inside archives (zip, tar, gz) with zip-bomb protection")
        self.archives.setChecked(st.scan_archives)
        sf.addRow(self.archives)
        self.threads = QSpinBox()
        self.threads.setRange(1, 32)
        self.threads.setValue(st.scan_threads)
        sf.addRow("Scan threads", self.threads)
        self.exclusions = QPlainTextEdit("\n".join(st.exclusions))
        self.exclusions.setPlaceholderText("One file or folder per line")
        self.exclusions.setMaximumHeight(110)
        sf.addRow("Exclusions", self.exclusions)
        lay.addWidget(sc)

        # ---- network
        net = QGroupBox("Network monitor")
        nf = QFormLayout(net)
        self.poll = QDoubleSpinBox()
        self.poll.setRange(0.5, 30)
        self.poll.setSingleStep(0.5)
        self.poll.setSuffix(" s")
        self.poll.setValue(st.network_poll_seconds)
        nf.addRow("Refresh interval", self.poll)
        self.ports = QLineEdit(", ".join(str(p) for p in st.suspicious_ports))
        nf.addRow("Suspicious ports", self.ports)
        lay.addWidget(net)

        ui = QGroupBox("Application")
        uf = QFormLayout(ui)
        self.tray = QCheckBox("Keep protecting in the system tray when the window is closed")
        self.tray.setChecked(st.minimize_to_tray)
        uf.addRow(self.tray)
        self.app_updates = QCheckBox("Check for new versions of Sentinel Vision automatically")
        self.app_updates.setChecked(st.check_app_updates)
        uf.addRow(self.app_updates)
        check_row = QHBoxLayout()
        self.b_check_app = QPushButton("Check for app updates now")
        self.b_check_app.clicked.connect(self.ctx.bridge.app_update_requested.emit)
        check_row.addWidget(self.b_check_app)
        check_row.addWidget(label(f"Installed version: {__version__}", "muted"))
        check_row.addStretch(1)
        uf.addRow(check_row)
        lay.addWidget(ui)
        lay.addStretch(1)

        for spin in body.findChildren(QSpinBox) + body.findChildren(QDoubleSpinBox):
            spin.setButtonSymbols(QSpinBox.NoButtons)
            spin.setMaximumWidth(220)
        for edit in (self.key, self.clamd, self.ports):
            edit.setMaximumWidth(560)

        bottom = QHBoxLayout()
        bottom.addStretch(1)
        self.b_save = QPushButton("Save settings")
        self.b_save.setObjectName("primary")
        bottom.addWidget(self.b_save)
        self.root.addLayout(bottom)

        self.b_save.clicked.connect(self.save)
        self.b_update.clicked.connect(self.run_update)
        self.task: Task | None = None

    def action(self, name: str) -> None:
        if name == "update":
            self.run_update()

    def refresh(self) -> None:
        last = self.s.updater.last_update
        self.last_update.setText(
            f"Last update: {ago(last)} · {self.s.db.hash_count():,} hashes · {self.s.intel.count:,} malicious networks"
        )

    def _collect(self) -> None:
        st = self.s.settings
        st.abusech_auth_key = self.key.text().strip()
        st.auto_update_hours = self.auto_hours.value()
        st.run_freshclam = self.freshclam.isChecked()
        for i, f in enumerate(st.feeds):
            f.enabled = self.feeds.item(i).checkState() == Qt.Checked
        st.hash_enabled = self.e_hash.isChecked()
        st.yara_enabled = self.e_yara.isChecked()
        st.clamav_enabled = self.e_clam.isChecked()
        st.heuristics_enabled = self.e_heur.isChecked()
        st.heuristic_threshold = self.threshold.value()
        st.clamd_address = self.clamd.text().strip()
        st.auto_quarantine_heuristics = self.heur_q.isChecked()
        st.max_file_size_mb = self.max_size.value()
        st.scan_archives = self.archives.isChecked()
        st.scan_threads = self.threads.value()
        st.exclusions = [ln.strip() for ln in self.exclusions.toPlainText().splitlines() if ln.strip()]
        st.network_poll_seconds = self.poll.value()
        ports = []
        for tok in self.ports.text().replace(";", ",").split(","):
            tok = tok.strip()
            if tok.isdigit() and 0 < int(tok) < 65536:
                ports.append(int(tok))
        st.suspicious_ports = ports
        st.minimize_to_tray = self.tray.isChecked()
        st.check_app_updates = self.app_updates.isChecked()

    def save(self) -> None:
        self._collect()
        self.s.apply_settings()
        self.ctx.bridge.status_changed.emit()
        self.ctx.notify("Settings saved", "Your changes are active.", "info")

    def run_update(self) -> None:
        if self.task is not None:
            return
        self._collect()
        self.s.settings.save()
        self.b_update.setEnabled(False)
        self.b_update.setText("Updating…")
        self.update_log.setPlainText("")
        up = self.s.updater

        def work(t: Task):
            return up.run(t.message)

        task = Task(work)
        task.signals.message.connect(lambda m: self.update_log.appendPlainText(m))
        task.signals.finished.connect(self._update_done)
        task.signals.failed.connect(self._update_failed)
        self.task = start(task)

    def _update_done(self, results) -> None:
        self.task = None
        self.s.after_update()
        self.b_update.setEnabled(True)
        self.b_update.setText("Update now")
        lines = [f"{'✓' if r.ok else '✗'} {r.feed}: {r.message}" for r in results]
        self.update_log.setPlainText("\n".join(lines))
        self.refresh()
        ok = sum(r.ok for r in results)
        self.ctx.notify("Definitions updated", f"{ok}/{len(results)} sources updated", "info" if ok else "danger")
        self.ctx.bridge.status_changed.emit()

    def _update_failed(self, err: str) -> None:
        self.task = None
        self.b_update.setEnabled(True)
        self.b_update.setText("Update now")
        QMessageBox.critical(self, "Update failed", err)
