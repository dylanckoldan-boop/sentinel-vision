from __future__ import annotations

import datetime as dt

from PySide6.QtCore import QDateTime, Qt
from PySide6.QtWidgets import (
    QDateTimeEdit,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page, fmt_ts, make_table
from sentinel_vision.gui.widgets import RowTableModel, StatCard, card, label
from sentinel_vision.gui.workers import Task, start
from sentinel_vision.scanner import bytes_human


class RansomwarePage(Page):
    title = "Ransomware & rollback"
    subtitle = (
        "Decoy files and encryption-burst detection catch ransomware in the act and freeze the program doing it. "
        "Every good version of your documents is kept encrypted in the rollback vault, so files can be restored."
    )
    refresh_ms = 4000

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.c_state = StatCard("Shield")
        self.c_files = StatCard("Files in vault")
        self.c_size = StatCard("Vault size")
        self.c_incidents = StatCard("Incidents")
        for c in (self.c_state, self.c_files, self.c_size, self.c_incidents):
            stats.addWidget(c)
        self.root.addLayout(stats)

        tabs = QTabWidget()
        # ---- incidents
        inc = QWidget()
        il = QVBoxLayout(inc)
        il.setContentsMargins(0, 8, 0, 0)
        self.inc_model = RowTableModel(
            ["When", "Trigger", "What happened", "Frozen programs"], color_for=lambda _i: theme.DANGER
        )
        self.inc_table = make_table(self.inc_model, stretch_col=2)
        self.inc_table.setColumnWidth(0, 150)
        self.inc_table.setColumnWidth(1, 130)
        il.addWidget(self.inc_table, 1)
        self.sus_model = RowTableModel(["Program", "PID", "State", "Why it's suspected"])
        self.sus_table = make_table(self.sus_model, stretch_col=3)
        self.sus_table.setColumnWidth(0, 200)
        self.sus_table.setMaximumHeight(170)
        il.addWidget(label("Programs suspected in the selected incident", "h2"))
        il.addWidget(self.sus_table)
        row = QHBoxLayout()
        self.b_kill = QPushButton("End & quarantine")
        self.b_kill.setObjectName("danger")
        self.b_resume = QPushButton("Resume (it's safe)")
        self.b_restore_inc = QPushButton("Restore the affected files")
        self.b_restore_inc.setObjectName("primary")
        for b in (self.b_kill, self.b_resume, self.b_restore_inc):
            row.addWidget(b)
        row.addStretch(1)
        il.addLayout(row)
        tabs.addTab(inc, "Incidents")

        # ---- vault
        vault = QWidget()
        vl = QVBoxLayout(vault)
        vl.setContentsMargins(0, 8, 0, 0)
        rb_card, rbl = card()
        rbl.addWidget(label("Roll back to a point in time", "h2"))
        rbl.addWidget(
            label(
                "Every file changed after this moment is put back to its last good version from "
                "before it. The current contents are kept in the vault, so this can be undone.",
                "muted",
                wrap=True,
            )
        )
        r2 = QHBoxLayout()
        self.when = QDateTimeEdit(QDateTime.currentDateTime().addSecs(-3600))
        self.when.setCalendarPopup(True)
        self.when.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.b_rollback = QPushButton("Roll back…")
        self.b_rollback.setObjectName("primary")
        r2.addWidget(QLabel("Changed after"))
        r2.addWidget(self.when)
        r2.addWidget(self.b_rollback)
        r2.addStretch(1)
        rbl.addLayout(r2)
        vl.addWidget(rb_card)
        self.files_model = RowTableModel(["File", "Versions", "Last saved"])
        self.files_table = make_table(self.files_model, stretch_col=0)
        self.files_table.setColumnWidth(1, 80)
        self.files_table.setColumnWidth(2, 160)
        vl.addWidget(self.files_table, 2)
        self.ver_model = RowTableModel(
            ["Version", "Saved", "Size", "Note"], color_for=lambda v: theme.WARN if v.suspect else None
        )
        self.ver_table = make_table(self.ver_model, stretch_col=3)
        self.ver_table.setMaximumHeight(160)
        vl.addWidget(self.ver_table, 1)
        r3 = QHBoxLayout()
        self.b_restore = QPushButton("Restore selected version")
        self.b_restore_to = QPushButton("Restore to folder…")
        r3.addWidget(self.b_restore)
        r3.addWidget(self.b_restore_to)
        r3.addStretch(1)
        vl.addLayout(r3)
        tabs.addTab(vault, "Rollback vault")
        self.root.addWidget(tabs, 1)

        self.inc_table.selectionModel().selectionChanged.connect(lambda *_: self._show_suspects())
        self.files_table.selectionModel().selectionChanged.connect(lambda *_: self._show_versions())
        self.b_kill.clicked.connect(self._kill)
        self.b_resume.clicked.connect(self._resume)
        self.b_restore_inc.clicked.connect(self._restore_incident)
        self.b_rollback.clicked.connect(self._rollback)
        self.b_restore.clicked.connect(lambda: self._restore(False))
        self.b_restore_to.clicked.connect(lambda: self._restore(True))
        self._task: Task | None = None

    # ------------------------------------------------------------------ data
    def refresh(self) -> None:
        rw = self.s.ransomware
        on = rw.running
        self.c_state.set(
            "On" if on else "Off",
            f"{len(rw.folders)} folder(s) · {len(rw.canaries)} decoys",
            theme.OK if on else theme.DANGER,
        )
        files, versions, used = self.s.vault.stats()
        self.c_files.set(f"{files:,}", f"{versions:,} versions")
        self.c_size.set(bytes_human(used), f"limit {bytes_human(self.s.vault.max_total)}")
        n = len(rw.incidents)
        self.c_incidents.set(str(n), "this session", theme.DANGER if n else theme.OK)
        sel = self._selected_incident()
        incs = list(reversed(rw.incidents))
        self.inc_model.set_rows(
            [
                (
                    fmt_ts(i.ts),
                    i.trigger,
                    i.detail,
                    ", ".join(f"{s.name} ({s.pid})" for s in i.suspects if s.state == "suspended") or "none",
                )
                for i in incs
            ],
            incs,
        )
        if sel in incs:
            self.inc_table.selectRow(incs.index(sel))
        if not self.files_table.selectionModel().hasSelection():
            rows = self.s.vault.files(3000)
            self.files_model.set_rows([(p, n, fmt_ts(ts)) for p, n, ts in rows], rows)

    def _selected_incident(self):
        rows = self.inc_table.selectionModel().selectedRows() if self.inc_table.selectionModel() else []
        return self.inc_model.objects[rows[0].row()] if rows else None

    def _show_suspects(self) -> None:
        inc = self._selected_incident()
        sus = inc.suspects if inc else []
        self.sus_model.set_rows([(s.name, s.pid, s.state, "; ".join(s.reasons)) for s in sus], sus)

    def _selected_suspect(self):
        rows = self.sus_table.selectionModel().selectedRows()
        return self.sus_model.objects[rows[0].row()] if rows else None

    # ------------------------------------------------------------------ incident actions
    def _kill(self) -> None:
        s = self._selected_suspect()
        if s is None:
            return
        if (
            QMessageBox.question(self, "End program", f"End {s.name} (PID {s.pid}) and quarantine its program file?")
            != QMessageBox.Yes
        ):
            return
        try:
            result = self.s.ransomware.terminate_and_quarantine(s, self.s.quarantine)
            self.s.db.log_event("ransomware", f"{s.name} ({s.pid}): {result}", "warning")
        except Exception as exc:
            QMessageBox.warning(self, "End program", str(exc))
        self._show_suspects()

    def _resume(self) -> None:
        s = self._selected_suspect()
        if s is None:
            return
        try:
            self.s.ransomware.resume(s)
            self.s.db.log_event("ransomware", f"{s.name} ({s.pid}) resumed by the user")
        except Exception as exc:
            QMessageBox.warning(self, "Resume", str(exc))
        self._show_suspects()

    def _restore_incident(self) -> None:
        inc = self._selected_incident()
        if inc is None:
            return
        if any(s.state == "suspended" for s in inc.suspects):
            QMessageBox.information(
                self,
                "Restore",
                "End (or resume) the frozen programs first, so the attack can't encrypt the restored files again.",
            )
            return
        results = self.s.vault.rollback(inc.ts - 120)
        ok = sum(r == "restored" for _, r in results)
        QMessageBox.information(
            self,
            "Restore",
            f"{ok} file(s) restored from the vault.\n\n" + "\n".join(f"{r}: {p}" for p, r in results[:30]),
        )

    # ------------------------------------------------------------------ vault actions
    def _show_versions(self) -> None:
        rows = self.files_table.selectionModel().selectedRows()
        if not rows:
            self.ver_model.set_rows([])
            return
        path = self.files_model.objects[rows[0].row()][0]
        vs = self.s.vault.versions(path)
        self.ver_model.set_rows(
            [(v.id, fmt_ts(v.ts), bytes_human(v.size), "content looked encrypted" if v.suspect else "") for v in vs],
            vs,
        )

    def _restore(self, choose: bool) -> None:
        rows = self.ver_table.selectionModel().selectedRows()
        if not rows:
            return
        v = self.ver_model.objects[rows[0].row()]
        dest = None
        if choose:
            dest = QFileDialog.getExistingDirectory(self, "Restore to folder")
            if not dest:
                return
        try:
            out = self.s.vault.restore(v.id, dest)
            QMessageBox.information(self, "Restore", f"Restored to {out}")
        except Exception as exc:
            QMessageBox.warning(self, "Restore", str(exc))
        self._show_versions()

    def _rollback(self) -> None:
        since = self.when.dateTime().toSecsSinceEpoch()
        when = dt.datetime.fromtimestamp(since).strftime("%Y-%m-%d %H:%M")
        if (
            QMessageBox.question(
                self, "Roll back", f"Restore every protected file changed after {when} to its previous good version?"
            )
            != QMessageBox.Yes
        ):
            return
        vault = self.s.vault
        task = Task(lambda _t: vault.rollback(float(since)))
        task.signals.finished.connect(self._rollback_done)
        task.signals.failed.connect(lambda e: QMessageBox.critical(self, "Roll back", e))
        self._task = start(task)

    def _rollback_done(self, results) -> None:
        ok = sum(r == "restored" for _, r in results)
        other = [f"{r}: {p}" for p, r in results if r != "restored"][:20]
        QMessageBox.information(
            self, "Roll back", f"{ok} file(s) restored." + ("\n\n" + "\n".join(other) if other else "")
        )
        self.files_table.clearSelection()
        self.refresh()


_ = Qt
