from __future__ import annotations

import os
import subprocess
import sys
import time

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
)

from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page, make_table, severity_color
from sentinel_vision.gui.widgets import RowTableModel, card, label
from sentinel_vision.gui.workers import Task, start
from sentinel_vision.scanner import ScanResult, ScanSummary, bytes_human, kill_process


class ScanPage(Page):
    title = "Scan"
    subtitle = "Every file is checked by all enabled engines: hash blocklists, YARA rules, ClamAV and heuristics."

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.task: Task | None = None
        self.results: list[ScanResult] = []

        # scan types
        row = QHBoxLayout()
        row.setSpacing(10)
        self.b_quick = QPushButton("Quick scan")
        self.b_quick.setObjectName("primary")
        self.b_quick.setToolTip("Downloads, Desktop, temp and startup folders, plus every running program")
        self.b_full = QPushButton("Full scan")
        self.b_full.setToolTip("Every file on every local drive")
        self.b_folder = QPushButton("Scan folder…")
        self.b_file = QPushButton("Scan file…")
        self.b_proc = QPushButton("Running processes")
        self.b_mem = QPushButton("Memory scan")
        self.b_mem.setToolTip("Scan the memory of running programs for fileless malware (report-only)")
        for b in (self.b_quick, self.b_full, self.b_folder, self.b_file, self.b_proc, self.b_mem):
            row.addWidget(b)
        row.addStretch(1)
        self.chk_rescan = QCheckBox("Re-check unchanged files")
        self.chk_rescan.setToolTip("By default files that were clean under the current definitions are skipped")
        row.addWidget(self.chk_rescan)
        self.root.addLayout(row)

        # progress
        prog_card, pl = card()
        top = QHBoxLayout()
        self.status = label("Ready to scan.", "h2")
        top.addWidget(self.status, 1)
        self.b_cancel = QPushButton("Cancel")
        self.b_cancel.setObjectName("danger")
        self.b_cancel.setVisible(False)
        top.addWidget(self.b_cancel)
        pl.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1)
        self.bar.setValue(0)
        self.bar.setFixedHeight(8)
        pl.addWidget(self.bar)
        self.current = QLabel("")
        self.current.setObjectName("mono")
        self.current.setMinimumWidth(10)
        pl.addWidget(self.current)
        self.counters = QLabel("")
        self.counters.setObjectName("muted")
        pl.addWidget(self.counters)
        self.root.addWidget(prog_card)

        # results
        self.model = RowTableModel(
            ["Threat", "Severity", "Engine", "File", "Action"],
            color_for=lambda r: severity_color(r.top.severity) if r.top else theme.WARN,
            tooltip_for=self._tooltip,
        )
        self.table = make_table(self.model, stretch_col=3)
        self.table.setColumnWidth(0, 260)
        self.table.setColumnWidth(1, 80)
        self.table.setColumnWidth(2, 90)
        self.table.doubleClicked.connect(lambda _i: self.show_details())
        self.root.addWidget(self.table, 1)

        acts = QHBoxLayout()
        self.b_q = QPushButton("Quarantine selected")
        self.b_kill = QPushButton("End process")
        self.b_open = QPushButton("Show in folder")
        self.b_details = QPushButton("Details")
        for b in (self.b_q, self.b_kill, self.b_open, self.b_details):
            acts.addWidget(b)
        acts.addStretch(1)
        self.root.addLayout(acts)

        self.b_quick.clicked.connect(self.quick_scan)
        self.b_full.clicked.connect(self.full_scan)
        self.b_folder.clicked.connect(self.folder_scan)
        self.b_file.clicked.connect(self.file_scan)
        self.b_proc.clicked.connect(self.process_scan)
        self.b_mem.clicked.connect(self.memory_scan)
        self.b_cancel.clicked.connect(self.cancel)
        self.b_q.clicked.connect(self.quarantine_selected)
        self.b_kill.clicked.connect(self.kill_selected)
        self.b_open.clicked.connect(self.open_folder)
        self.b_details.clicked.connect(self.show_details)

        self._t0 = 0.0
        self._n = 0
        self._last_path = ""
        self._ui_timer = QTimer(self)
        self._ui_timer.timeout.connect(self._tick)

    # ------------------------------------------------------------------ actions
    def action(self, name: str) -> None:
        if name == "quick":
            self.quick_scan()

    def _busy(self, busy: bool) -> None:
        for b in (self.b_quick, self.b_full, self.b_folder, self.b_file, self.b_proc, self.b_mem):
            b.setEnabled(not busy)
        self.b_cancel.setVisible(busy)
        self.bar.setRange(0, 0 if busy else 1)
        self.bar.setValue(0 if busy else 1)
        if busy:
            self._ui_timer.start(150)
        else:
            self._ui_timer.stop()

    def _start(self, label_text: str, fn) -> None:
        if self.task is not None:
            return
        self.results = []
        self.model.set_rows([])
        self.status.setText(label_text)
        self._t0, self._n, self._last_path = time.time(), 0, ""
        self._busy(True)
        task = Task(fn)
        task.signals.progress.connect(self._on_progress)
        task.signals.item.connect(self._on_item)
        task.signals.finished.connect(self._on_done)
        task.signals.failed.connect(self._on_failed)
        self.task = start(task)

    def _scan_roots(self, title: str, roots: list[str], with_processes: bool = False) -> None:
        use_cache = not self.chk_rescan.isChecked()
        sc = self.s.scanner

        def work(t: Task):
            summary = ScanSummary()
            if with_processes:
                ps = sc.scan_processes(progress=t.progress, on_result=t.item, cancel=t.cancel)
                summary.scanned += ps.scanned
                summary.infected += ps.infected
            fs = sc.scan_paths(roots, progress=t.progress, on_result=t.item, cancel=t.cancel, use_cache=use_cache)
            fs.scanned += summary.scanned
            fs.infected += summary.infected
            fs.started = summary.started
            return fs

        self._start(title, work)

    def quick_scan(self) -> None:
        self._scan_roots("Quick scan running…", self.s.scanner.quick_scan_roots(), with_processes=True)

    def full_scan(self) -> None:
        self._scan_roots("Full scan running…", self.s.scanner.full_scan_roots(), with_processes=True)

    def folder_scan(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose a folder to scan")
        if d:
            self._scan_roots(f"Scanning {d}…", [d])

    def file_scan(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Choose files to scan")
        if files:
            self.chk_rescan.setChecked(True)
            self._scan_roots(f"Scanning {len(files)} file(s)…", files)

    def memory_scan(self) -> None:
        from sentinel_vision import memscan
        from sentinel_vision.engines.base import Detection, Severity

        sc = self.s.scanner

        def work(t: Task) -> ScanSummary:
            ms = memscan.scan_processes(sc, progress=t.progress, cancel=t.cancel)
            out = ScanSummary(scanned=ms.scanned, infected=len(ms.hits), skipped=ms.skipped + ms.denied)
            out.cancelled = ms.cancelled
            for h in ms.hits:
                dets = [
                    Detection(
                        "memory",
                        rule,
                        Severity(sev),
                        f"Found in the memory of {h.name} (PID {h.pid})",
                        {"processes": [(h.pid, h.name)]},
                    )
                    for rule, sev in h.rules
                ]
                r = ScanResult(path=h.exe or h.name, detections=dets, action="reported", origin="memory")
                out.results.append(r)
                t.item(r)
            out.finished = time.time()
            return out

        self._start("Scanning program memory…", work)

    def process_scan(self) -> None:
        sc = self.s.scanner
        self._start("Scanning running processes…", lambda t: sc.scan_processes(t.progress, t.item, t.cancel))

    def cancel(self) -> None:
        if self.task:
            self.task.cancel.set()
            self.status.setText("Cancelling…")

    # ------------------------------------------------------------------ signals
    def _on_progress(self, n: int, path: str) -> None:
        self._n, self._last_path = n, path

    def _tick(self) -> None:
        el = max(0.001, time.time() - self._t0)
        self.counters.setText(
            f"{self._n:,} files · {self._n / el:,.0f} files/s · {len(self.results)} threat(s) · {el:,.0f}s"
        )
        fm = self.current.fontMetrics()
        self.current.setText(fm.elidedText(self._last_path, Qt.ElideMiddle, max(100, self.current.width() - 10)))

    def _on_item(self, r: ScanResult) -> None:
        if not r.infected:
            return
        self.results.append(r)
        self._render()
        top = r.top
        self.ctx.notify(
            "Threat detected", f"{top.name if top else '?'}\n{r.path}\n→ {r.action or 'reported'}", "danger"
        )

    def _render(self) -> None:
        rows = []
        for r in self.results:
            top = r.top
            engines = ", ".join(sorted({d.engine for d in r.detections}))
            rows.append((top.name if top else "", top.severity.label if top else "", engines, r.path, r.action))
        self.model.set_rows(rows, list(self.results))

    def _on_done(self, summary: ScanSummary) -> None:
        self.task = None
        self._busy(False)
        self._tick()
        verb = "cancelled" if summary.cancelled else "complete"
        if summary.threats:
            extra = f", {summary.review} item(s) to review" if summary.review else ""
            self.status.setText(f"Scan {verb}: {summary.threats} threat(s) found{extra}")
            self.status.setStyleSheet(f"color: {theme.DANGER};")
        elif summary.review:
            self.status.setText(
                f"Scan {verb}: no threats found · {summary.review} item(s) to review (hints, not confirmed threats)"
            )
            self.status.setStyleSheet(f"color: {theme.WARN};")
        else:
            self.status.setText(f"Scan {verb}: no threats found")
            self.status.setStyleSheet(f"color: {theme.OK};")
        self.counters.setText(
            f"{summary.scanned:,} files ({bytes_human(summary.bytes)}) in {summary.duration:,.1f}s · "
            f"{summary.skipped:,} skipped (unchanged / too large) · {summary.errors:,} unreadable"
        )
        self.current.setText("")

    def _on_failed(self, err: str) -> None:
        self.task = None
        self._busy(False)
        self.status.setText("Scan failed")
        QMessageBox.critical(self, "Scan failed", err)

    # ------------------------------------------------------------------ result actions
    def _selected(self) -> list[ScanResult]:
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()})
        return [self.model.objects[r] for r in rows]  # type: ignore[misc]

    @staticmethod
    def _tooltip(r: ScanResult, _col: int) -> str:
        return "\n".join(f"[{d.engine}] {d.name}: {d.description}" for d in r.detections)

    def quarantine_selected(self) -> None:
        sel = [r for r in self._selected() if r.action != "quarantined"]
        if not sel:
            return
        if (
            QMessageBox.question(self, "Quarantine", f"Move {len(sel)} file(s) into the encrypted quarantine?")
            != QMessageBox.Yes
        ):
            return
        errors = []
        for r in sel:
            try:
                self.s.scanner.quarantine_result(r)
            except Exception as exc:
                errors.append(f"{r.path}: {exc}")
        self._render()
        if errors:
            QMessageBox.warning(
                self,
                "Some files could not be quarantined",
                "\n".join(errors) + "\n\nIf a file belongs to a running program, end the process first.",
            )

    def kill_selected(self) -> None:
        procs = [
            (pid, name) for r in self._selected() for d in r.detections for pid, name in d.details.get("processes", [])
        ]
        procs = list(dict.fromkeys(procs))
        if not procs:
            QMessageBox.information(self, "End process", "Select a detection from a running-process scan.")
            return
        names = "\n".join(f"{n} (PID {p})" for p, n in procs)
        if QMessageBox.question(self, "End process", f"Terminate these processes?\n\n{names}") != QMessageBox.Yes:
            return
        errors = []
        for pid, _ in procs:
            try:
                kill_process(pid)
            except Exception as exc:
                errors.append(f"PID {pid}: {exc}")
        if errors:
            QMessageBox.warning(self, "End process", "\n".join(errors))
        else:
            self.ctx.notify("Process ended", names, "info")

    def open_folder(self) -> None:
        sel = self._selected()
        if not sel:
            return
        path = sel[0].path.split("!", 1)[0]
        folder = os.path.dirname(path)
        if sys.platform == "win32" and os.path.exists(path):
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(folder))

    def show_details(self) -> None:
        sel = self._selected()
        if not sel:
            return
        r = sel[0]
        lines = [f"File: {r.path}", f"SHA-256: {r.sha256}", f"Size: {bytes_human(r.size)}", f"Action: {r.action}", ""]
        for d in r.detections:
            lines.append(f"[{d.engine}] {d.name} — {d.severity.label}")
            lines.append(f"    {d.description}")
            for ind in d.details.get("indicators", []):
                lines.append(f"      • {ind}")
        box = QMessageBox(self)
        box.setWindowTitle("Detection details")
        box.setText(r.top.name if r.top else "Details")
        box.setDetailedText("\n".join(lines))
        box.setInformativeText("\n".join(lines[:4]))
        box.exec()
