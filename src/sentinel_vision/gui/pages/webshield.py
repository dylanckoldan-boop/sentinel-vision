from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton

from sentinel_vision import webshield
from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page
from sentinel_vision.gui.widgets import StatCard, card, label
from sentinel_vision.gui.workers import Task, start

VERDICT_COLORS = {"dangerous": theme.CRIT, "suspicious": theme.DANGER, "caution": theme.WARN, "safe-looking": theme.OK}
VERDICT_TEXT = {
    "dangerous": "Dangerous — don't open it",
    "suspicious": "Suspicious — very likely a scam",
    "caution": "Be careful",
    "safe-looking": "No warning signs",
}


class WebShieldPage(Page):
    title = "Web Shield"
    subtitle = (
        "Blocks websites known for malware and phishing on the whole computer, and checks any link before you open "
        "it — including brand-new scam sites that imitate real brands."
    )
    refresh_ms = 5000

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        stats = QHBoxLayout()
        stats.setSpacing(12)
        self.c_known = StatCard("Known bad sites")
        self.c_block = StatCard("System-wide blocking")
        stats.addWidget(self.c_known)
        stats.addWidget(self.c_block)
        self.root.addLayout(stats)

        chk, cl = card()
        cl.addWidget(label("Check a link", "h2"))
        cl.addWidget(label("Paste a link from an email, text message or website. Nothing is sent anywhere.", "muted"))
        row = QHBoxLayout()
        self.url = QLineEdit()
        self.url.setPlaceholderText("https://…")
        self.url.setClearButtonEnabled(True)
        self.b_check = QPushButton("Check link")
        self.b_check.setObjectName("primary")
        row.addWidget(self.url, 1)
        row.addWidget(self.b_check)
        cl.addLayout(row)
        self.verdict = QLabel("")
        self.verdict.setStyleSheet("font-size: 17px; font-weight: 700;")
        self.reasons = QLabel("")
        self.reasons.setWordWrap(True)
        self.reasons.setTextInteractionFlags(Qt.TextSelectableByMouse)
        cl.addWidget(self.verdict)
        cl.addWidget(self.reasons)
        self.root.addWidget(chk)

        blk, bl = card()
        bl.addWidget(label("Block dangerous sites everywhere", "h2"))
        bl.addWidget(
            label(
                "Adds known malware and phishing sites to your computer's hosts file so no browser or app can "
                "reach them. Needs administrator permission each time it's turned on or refreshed. Large "
                "platforms (Google, Microsoft, GitHub…) are never blocked as a whole.",
                "muted",
                wrap=True,
            )
        )
        r2 = QHBoxLayout()
        self.b_enable = QPushButton("Turn on / refresh blocking")
        self.b_enable.setObjectName("primary")
        self.b_disable = QPushButton("Turn off blocking")
        r2.addWidget(self.b_enable)
        r2.addWidget(self.b_disable)
        r2.addStretch(1)
        bl.addLayout(r2)
        self.block_msg = label("", "muted", wrap=True)
        bl.addWidget(self.block_msg)
        self.root.addWidget(blk)
        self.root.addStretch(1)

        self.b_check.clicked.connect(self.check)
        self.url.returnPressed.connect(self.check)
        self.b_enable.clicked.connect(lambda: self._set_blocking(True))
        self.b_disable.clicked.connect(lambda: self._set_blocking(False))
        self._task: Task | None = None

    def refresh(self) -> None:
        n = self.s.domains.count()
        self.c_known.set(
            f"{n:,}",
            "malware & phishing domains" if n else "update definitions to download the lists",
            theme.TEXT if n else theme.WARN,
        )
        active = webshield.hosts_status()
        self.c_block.set(
            f"{active:,}" if active else "Off",
            "domains blocked on this computer" if active else "turn on below",
            theme.OK if active else theme.MUTED,
        )

    def check(self) -> None:
        text = self.url.text().strip()
        if not text:
            return
        v = webshield.check_url(text, self.s.domains)
        color = VERDICT_COLORS[v.verdict]
        self.verdict.setText(f"{VERDICT_TEXT[v.verdict]}  ({v.host or 'no website name'})")
        self.verdict.setStyleSheet(f"font-size: 17px; font-weight: 700; color: {color};")
        self.reasons.setText("\n".join(f"• {r}" for r in v.reasons))

    def _set_blocking(self, on: bool) -> None:
        if self._task is not None:
            return
        if on and self.s.domains.count() == 0:
            QMessageBox.information(self, "Web Shield", "Download the lists first: Settings & updates → Update now.")
            return
        self.s.settings.webshield_block_hosts = on
        self.s.settings.save()
        args = ["webshield-apply", "--db", str(self.s.domains.path)] if on else ["webshield-remove"]
        self.block_msg.setText("Waiting for administrator permission…")
        task = Task(lambda _t: webshield.run_elevated(args))
        task.signals.finished.connect(lambda code: self._done(on, code))
        task.signals.failed.connect(lambda err: self._done(on, err))
        self._task = start(task)

    def _done(self, on: bool, result) -> None:
        self._task = None
        if result == 0:
            self.block_msg.setText("Blocking is on." if on else "Blocking is off.")
            self.s.db.log_event("webshield", "System-wide blocking " + ("enabled" if on else "disabled"))
        else:
            self.block_msg.setText(
                f"Not changed: {result if isinstance(result, str) else 'permission was not granted'}"
            )
        self.refresh()
