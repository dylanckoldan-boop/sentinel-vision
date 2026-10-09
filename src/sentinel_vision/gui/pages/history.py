from __future__ import annotations

import csv

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QMessageBox, QPushButton, QTabWidget, QVBoxLayout, QWidget

from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page, fmt_ts, make_table, severity_color
from sentinel_vision.gui.widgets import RowTableModel

LEVEL_COLORS = {"critical": theme.DANGER, "warning": theme.WARN, "info": theme.MUTED}


class HistoryPage(Page):
    title = "History"
    refresh_ms = 5000

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        tabs = QTabWidget()
        self.det_model = RowTableModel(
            ["When", "Threat", "Severity", "Engine", "Source", "Path", "Action"],
            color_for=lambda d: severity_color(d.severity),
        )
        self.det_table = make_table(self.det_model, stretch_col=5)
        for c, w in enumerate((150, 240, 80, 90, 80)):
            self.det_table.setColumnWidth(c, w)
        self.ev_model = RowTableModel(["When", "Level", "Kind", "Message"], color_for=lambda e: LEVEL_COLORS.get(e[1]))
        self.ev_table = make_table(self.ev_model, stretch_col=3)
        for c, w in enumerate((150, 80, 100)):
            self.ev_table.setColumnWidth(c, w)
        tabs.addTab(self._wrap(self.det_table), "Detections")
        tabs.addTab(self._wrap(self.ev_table), "Event log")
        self.root.addWidget(tabs, 1)
        row = QHBoxLayout()
        b_export = QPushButton("Export CSV…")
        b_clear = QPushButton("Clear detection history")
        b_clear.setObjectName("danger")
        row.addWidget(b_export)
        row.addStretch(1)
        row.addWidget(b_clear)
        self.root.addLayout(row)
        b_export.clicked.connect(self.export)
        b_clear.clicked.connect(self.clear)

    @staticmethod
    def _wrap(w) -> QWidget:
        box = QWidget()
        lay = QVBoxLayout(box)
        lay.setContentsMargins(0, 8, 0, 0)
        lay.addWidget(w)
        return box

    def refresh(self) -> None:
        dets = self.s.db.recent_detections(2000)
        self.det_model.set_rows(
            [
                (fmt_ts(d.ts), d.name, theme.SEVERITY_NAMES.get(d.severity, "?"), d.engine, d.origin, d.path, d.action)
                for d in dets
            ],
            dets,
        )
        evs = self.s.db.recent_events(2000)
        self.ev_model.set_rows([(fmt_ts(ts), lvl, kind, msg) for ts, lvl, kind, msg in evs], evs)

    def export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export detections", "sentinel-detections.csv", "CSV (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["timestamp", "threat", "severity", "engine", "origin", "path", "sha256", "action"])
            for d in self.s.db.recent_detections(1_000_000):
                w.writerow([d.ts, d.name, d.severity, d.engine, d.origin, d.path, d.sha256 or "", d.action])

    def clear(self) -> None:
        if (
            QMessageBox.question(self, "Clear history", "Delete all detection records? Quarantined files are kept.")
            == QMessageBox.Yes
        ):
            self.s.db.clear_detections()
            self.refresh()
