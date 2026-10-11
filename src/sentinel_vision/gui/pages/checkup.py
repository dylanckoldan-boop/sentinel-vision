from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QPushButton

from sentinel_vision import advisor
from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page, make_table
from sentinel_vision.gui.widgets import RowTableModel, StatusHero, card
from sentinel_vision.gui.workers import Task, start

STATUS = {
    "pass": ("✓ OK", theme.OK),
    "warn": ("! Improve", theme.WARN),
    "fail": ("✗ At risk", theme.DANGER),
    "unknown": ("? Unknown", theme.MUTED),
    "info": ("i Info", theme.MUTED),
}


class CheckupPage(Page):
    title = "Security checkup"
    subtitle = (
        "Reads your computer's security settings — firewall, encryption, updates, remote access, Wi-Fi and router "
        "safety — and tells you exactly what to fix. Nothing is changed without you."
    )
    refresh_ms = 60000

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        hero_card, hl = card(padding=12)
        row = QHBoxLayout()
        self.hero = StatusHero()
        self.hero.set_state("warn", "Not checked yet", "Run a checkup to get your security score.")
        row.addWidget(self.hero, 1)
        self.b_run = QPushButton("Run checkup")
        self.b_run.setObjectName("primary")
        self.b_run.setMinimumWidth(180)
        row.addWidget(self.b_run)
        hl.addLayout(row)
        self.root.addWidget(hero_card)
        self.model = RowTableModel(
            ["Status", "Check", "Result", "How to fix"],
            color_for=lambda c: STATUS.get(c.status, ("", theme.TEXT))[1],
            tooltip_for=lambda c, _col: f"{c.title}\n{c.detail}\n\n{c.fix}",
        )
        self.table = make_table(self.model, stretch_col=3)
        for col, w in enumerate((100, 280, 330)):
            self.table.setColumnWidth(col, w)
        self.root.addWidget(self.table, 1)
        self.b_run.clicked.connect(self.run)
        self._task: Task | None = None
        self._ran = False

    def refresh(self) -> None:
        if not self._ran:
            self._ran = True
            self.run()

    def run(self) -> None:
        if self._task is not None:
            return
        self.b_run.setEnabled(False)
        self.b_run.setText("Checking…")
        sv = self.s
        task = Task(lambda t: advisor.run_checkup(sv, t.message))
        task.signals.message.connect(lambda m: self.hero.set_state("warn", "Checking…", m))
        task.signals.finished.connect(self._done)
        task.signals.failed.connect(self._failed)
        self._task = start(task)

    def _done(self, checks) -> None:
        self._task = None
        self.b_run.setEnabled(True)
        self.b_run.setText("Run again")
        order = {"fail": 0, "warn": 1, "unknown": 2, "info": 3, "pass": 4}
        checks = sorted(checks, key=lambda c: (order.get(c.status, 5), c.title))
        sc = advisor.score(checks)
        fails = sum(c.status == "fail" for c in checks)
        warns = sum(c.status == "warn" for c in checks)
        level = "ok" if sc >= 85 and not fails else "warn" if sc >= 60 else "danger"
        self.hero.set_state(
            level,
            f"Security score {sc}/100",
            f"{fails} at risk · {warns} to improve · {sum(c.status == 'pass' for c in checks)} OK",
        )
        self.model.set_rows(
            [
                (STATUS.get(c.status, ("?", ""))[0], c.title, c.detail, c.fix if c.status in ("warn", "fail") else "")
                for c in checks
            ],
            checks,
        )
        self.s.db.set_meta("last_checkup_score", str(sc))

    def _failed(self, err: str) -> None:
        self._task = None
        self.b_run.setEnabled(True)
        self.b_run.setText("Run checkup")
        self.hero.set_state("warn", "Checkup failed", err)
