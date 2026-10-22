from __future__ import annotations

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QMessageBox, QPushButton

from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page, fmt_ts, make_table
from sentinel_vision.gui.widgets import RowTableModel, label
from sentinel_vision.scanner import bytes_human


class QuarantinePage(Page):
    title = "Quarantine"
    subtitle = (
        "Quarantined files are encrypted with AES-256-GCM in a private vault: they cannot run or be opened. "
        "Restore only files you are certain are safe."
    )

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.model = RowTableModel(
            ["Threat", "Detected by", "Original location", "Size", "Quarantined"],
            color_for=lambda _i: theme.WARN,
            tooltip_for=lambda i, _c: f"{i.original_path}\nSHA-256: {i.sha256}",
        )
        self.table = make_table(self.model, stretch_col=2)
        self.table.setColumnWidth(0, 260)
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(3, 80)
        self.table.setColumnWidth(4, 160)
        self.root.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.b_restore = QPushButton("Restore")
        self.b_restore_to = QPushButton("Restore to…")
        self.b_delete = QPushButton("Delete permanently")
        self.b_delete.setObjectName("danger")
        for b in (self.b_restore, self.b_restore_to, self.b_delete):
            row.addWidget(b)
        row.addStretch(1)
        self.summary = label("", "muted")
        row.addWidget(self.summary)
        self.root.addLayout(row)
        self.b_restore.clicked.connect(lambda: self.restore(False))
        self.b_restore_to.clicked.connect(lambda: self.restore(True))
        self.b_delete.clicked.connect(self.delete)

    def refresh(self) -> None:
        items = self.s.quarantine.list()
        self.model.set_rows(
            [(i.threat, i.engine, i.original_path, bytes_human(i.size), fmt_ts(i.ts)) for i in items], items
        )
        self.summary.setText(f"{len(items)} item(s) · {bytes_human(sum(i.size for i in items))}")

    def _selected(self):
        rows = sorted({i.row() for i in self.table.selectionModel().selectedRows()})
        return [self.model.objects[r] for r in rows]

    def restore(self, choose: bool) -> None:
        sel = self._selected()
        if not sel:
            return
        if (
            QMessageBox.warning(
                self,
                "Restore",
                f"Restore {len(sel)} file(s)? They were detected as malicious and will be able to run again.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            != QMessageBox.Yes
        ):
            return
        dest = None
        if choose:
            dest = QFileDialog.getExistingDirectory(self, "Restore to folder")
            if not dest:
                return
        errors, done = [], []
        for item in sel:
            try:
                p = self.s.quarantine.restore(item.id, dest)
                done.append(str(p))
                self.s.settings.exclusions.append(str(p))  # don't immediately re-quarantine it
                self.s.db.log_event("quarantine", f"Restored {item.threat} to {p}", "warning")
            except Exception as exc:
                errors.append(f"{item.original_path}: {exc}")
        if done and not self.commit_settings(apply=False):
            errors.append("The restored files were not added to the exclusions (administrator approval was not given).")
        self.refresh()
        msg = ""
        if done:
            msg += "Restored (and added to exclusions):\n" + "\n".join(done)
        if errors:
            msg += "\n\nFailed:\n" + "\n".join(errors)
        QMessageBox.information(self, "Restore", msg.strip())

    def delete(self) -> None:
        sel = self._selected()
        if not sel:
            return
        if (
            QMessageBox.question(self, "Delete", f"Permanently delete {len(sel)} quarantined file(s)?")
            != QMessageBox.Yes
        ):
            return
        for item in sel:
            try:
                self.s.quarantine.delete(item.id)
            except Exception as exc:
                QMessageBox.warning(self, "Delete", str(exc))
        self.s.db.log_event("quarantine", f"Deleted {len(sel)} quarantined item(s)")
        self.refresh()
