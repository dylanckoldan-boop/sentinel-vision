from __future__ import annotations

from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton

from sentinel_vision import devices
from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page, fmt_ts, make_table
from sentinel_vision.gui.widgets import RowTableModel, card, label
from sentinel_vision.gui.workers import Task, start
from sentinel_vision.reputation import password_breach_count, password_strength


class ToolsPage(Page):
    title = "Privacy & tools"
    subtitle = "Camera and microphone use, password breach checks and secure file deletion."
    refresh_ms = 3000

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        # ---- camera / microphone
        cam, cl = card()
        cl.addWidget(label("Camera & microphone", "h2"))
        self.cam_note = label("", "muted", wrap=True)
        cl.addWidget(self.cam_note)
        self.cam_model = RowTableModel(
            ["Device", "App", "Status", "Last used"], color_for=lambda u: theme.WARN if u.active else None
        )
        self.cam_table = make_table(self.cam_model, stretch_col=1)
        self.cam_table.setColumnWidth(0, 110)
        self.cam_table.setColumnWidth(2, 100)
        self.cam_table.setMinimumHeight(150)
        cl.addWidget(self.cam_table)
        self.root.addWidget(cam, 1)

        # ---- password check
        pw, pl = card()
        pl.addWidget(label("Has my password been leaked?", "h2"))
        pl.addWidget(
            label(
                "Checked against hundreds of millions of breached passwords using k-anonymity: only the first 5 "
                "characters of a one-way hash leave this computer, never the password.",
                "muted",
                wrap=True,
            )
        )
        row = QHBoxLayout()
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.setPlaceholderText("Type a password")
        self.b_pw = QPushButton("Check")
        self.b_pw.setObjectName("primary")
        row.addWidget(self.pw, 1)
        row.addWidget(self.b_pw)
        pl.addLayout(row)
        self.pw_result = QLabel("")
        self.pw_result.setWordWrap(True)
        pl.addWidget(self.pw_result)
        self.root.addWidget(pw)

        # ---- shredder
        sh, sl = card()
        sl.addWidget(label("File shredder", "h2"))
        sl.addWidget(
            label(
                "Overwrites files with random data before deleting them so they can't be undeleted. "
                "On SSDs, the drive itself may keep old copies; full-disk encryption is the complete "
                "protection there.",
                "muted",
                wrap=True,
            )
        )
        r3 = QHBoxLayout()
        self.b_files = QPushButton("Shred files…")
        self.b_folder = QPushButton("Shred folder…")
        for b in (self.b_files, self.b_folder):
            b.setObjectName("danger")
            r3.addWidget(b)
        r3.addStretch(1)
        sl.addLayout(r3)
        self.root.addWidget(sh)

        self.b_pw.clicked.connect(self.check_password)
        self.pw.returnPressed.connect(self.check_password)
        self.b_files.clicked.connect(self.shred_files)
        self.b_folder.clicked.connect(self.shred_folder)
        self._task: Task | None = None

    def refresh(self) -> None:
        if not devices.privacy_supported():
            self.cam_note.setText(
                "macOS shows a camera/microphone indicator in the menu bar; it does not let other "
                "apps see which program is using them."
            )
            return
        mon = self.s.privacy
        uses = mon.current if mon.running else devices.device_use()
        uses = sorted(uses, key=lambda u: (not u.active, -u.last_used))
        on = sum(u.active for u in uses)
        self.cam_note.setText(
            ("You'll be notified whenever an app starts using them. " if mon.running else "Monitoring is off. ")
            + (f"{on} in use right now." if on else "Nothing is using them right now.")
        )
        self.cam_model.set_rows(
            [(u.kind, u.app, "IN USE" if u.active else "", fmt_ts(u.last_used) if u.last_used else "") for u in uses],
            uses,
        )

    def check_password(self) -> None:
        pw = self.pw.text()
        if not pw or self._task is not None:
            return
        _score, strength = password_strength(pw)
        self.pw_result.setText("Checking…")
        task = Task(lambda _t: password_breach_count(pw))
        task.signals.finished.connect(lambda n: self._pw_done(n, strength))
        task.signals.failed.connect(lambda e: self._pw_done(None, strength, e))
        self._task = start(task)
        self.pw.clear()

    def _pw_done(self, count, strength: str, err: str = "") -> None:
        self._task = None
        if err:
            self.pw_result.setStyleSheet(f"color: {theme.WARN};")
            self.pw_result.setText(f"Could not reach the breach service: {err}")
            return
        if count:
            self.pw_result.setStyleSheet(f"color: {theme.DANGER}; font-weight: 600;")
            self.pw_result.setText(
                f"Found in {count:,} data breaches. Stop using this password everywhere and "
                f"switch to a unique one. (Strength: {strength})"
            )
        else:
            self.pw_result.setStyleSheet(f"color: {theme.OK}; font-weight: 600;")
            self.pw_result.setText(f"Not found in known breaches. Estimated strength: {strength}.")

    def _confirm_and_shred(self, paths: list[str]) -> None:
        if not paths:
            return
        if (
            QMessageBox.warning(
                self,
                "Shred",
                f"Permanently destroy {len(paths)} item(s)? This cannot be undone.",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            != QMessageBox.Yes
        ):
            return
        results = devices.shred(paths)
        failed = [f"{r}: {p}" for p, r in results if r != "shredded"]
        done = sum(r == "shredded" for _, r in results)
        QMessageBox.information(
            self, "Shred", f"{done} file(s) shredded." + ("\n\n" + "\n".join(failed[:20]) if failed else "")
        )

    def shred_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Choose files to shred")
        self._confirm_and_shred(files)

    def shred_folder(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose a folder to shred")
        if d:
            self._confirm_and_shred([d])
