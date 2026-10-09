from __future__ import annotations

import time

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QGuiApplication
from PySide6.QtWidgets import QCheckBox, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton

from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page, make_table, severity_color
from sentinel_vision.gui.widgets import RowTableModel, StatCard, ThroughputGraph, card, label
from sentinel_vision.network.firewall import FirewallError, block_ip
from sentinel_vision.network.monitor import Connection, _is_public
from sentinel_vision.scanner import bytes_human, kill_process


def _age(ts: float) -> str:
    s = int(time.time() - ts)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"


class NetworkPage(Page):
    title = "Live traffic"
    subtitle = (
        "Every connection on this machine, mapped to the program that owns it and checked against threat intelligence."
    )
    refresh_ms = 1500

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        grid = QGridLayout()
        grid.setSpacing(12)
        self.c_down = StatCard("Download", accent=theme.DOWN)
        self.c_up = StatCard("Upload", accent=theme.UP)
        self.c_est = StatCard("Established")
        self.c_listen = StatCard("Listening ports")
        self.c_threat = StatCard("Alerts")
        for i, c in enumerate((self.c_down, self.c_up, self.c_est, self.c_listen, self.c_threat)):
            grid.addWidget(c, 0, i)
        self.root.addLayout(grid)

        g_card, gl = card(padding=12)
        self.graph = ThroughputGraph(seconds=240)
        self.graph.setMinimumHeight(200)
        gl.addWidget(self.graph)
        self.root.addWidget(g_card)

        bar = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter by process, address, port or status…")
        self.filter.setClearButtonEnabled(True)
        bar.addWidget(self.filter, 1)
        self.chk_threats = QCheckBox("Alerts only")
        self.chk_remote = QCheckBox("Internet only")
        self.chk_remote.setToolTip("Hide loopback / LAN connections and listening sockets")
        self.chk_pause = QCheckBox("Pause")
        for w in (self.chk_threats, self.chk_remote, self.chk_pause):
            bar.addWidget(w)
        self.root.addLayout(bar)

        self.notice = QLabel("")
        self.notice.setStyleSheet(f"color: {theme.WARN};")
        self.notice.setVisible(False)
        self.root.addWidget(self.notice)

        self.model = RowTableModel(
            ["Process", "PID", "Proto", "Local", "Remote", "State", "Age", "Assessment"],
            color_for=lambda c: severity_color(c.severity) if c.severity >= 0 else None,
            tooltip_for=lambda c, _col: f"{c.exe or c.process}\n{c.threat or 'No known threat'}",
        )
        self.table = make_table(self.model, stretch_col=7)
        for col, w in enumerate((170, 64, 60, 190, 220, 110, 60)):
            self.table.setColumnWidth(col, w)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.root.addWidget(self.table, 1)

        acts = QHBoxLayout()
        self.b_kill = QPushButton("End process")
        self.b_block = QPushButton("Block remote IP")
        self.b_lookup = QPushButton("Look up IP")
        self.b_trust = QPushButton("Trust IP")
        for b in (self.b_kill, self.b_block, self.b_lookup, self.b_trust):
            acts.addWidget(b)
        acts.addStretch(1)
        self.intel_lbl = label("", "muted")
        acts.addWidget(self.intel_lbl)
        self.root.addLayout(acts)

        self.b_kill.clicked.connect(self.kill)
        self.b_block.clicked.connect(self.block)
        self.b_lookup.clicked.connect(self.lookup)
        self.b_trust.clicked.connect(self.trust)
        self.filter.textChanged.connect(lambda _t: self.refresh(force=True))
        self.chk_threats.toggled.connect(lambda _b: self.refresh(force=True))
        self.chk_remote.toggled.connect(lambda _b: self.refresh(force=True))

    # ------------------------------------------------------------------ data
    def refresh(self, force: bool = False) -> None:
        snap = self.s.network.snapshot()
        self.graph.set_history(snap.history)
        self.c_down.set(f"{bytes_human(snap.down_bps)}/s", f"{bytes_human(snap.total_recv)} since boot")
        self.c_up.set(f"{bytes_human(snap.up_bps)}/s", f"{bytes_human(snap.total_sent)} since boot")
        self.c_est.set(str(snap.established), f"{len(snap.connections)} sockets total")
        self.c_listen.set(str(snap.listening), "open to connections")
        self.c_threat.set(str(snap.threats), "risky right now", theme.DANGER if snap.threats else theme.OK)
        self.notice.setVisible(bool(snap.error))
        self.notice.setText("⚠ " + snap.error)
        running = self.s.network.running
        self.intel_lbl.setText(
            f"{self.s.intel.count:,} malicious networks loaded" + ("" if running else " · monitor stopped")
        )
        if self.chk_pause.isChecked() and not force:
            return

        q = self.filter.text().strip().lower()
        conns = snap.connections
        if self.chk_threats.isChecked():
            conns = [c for c in conns if c.severity >= 1]
        if self.chk_remote.isChecked():
            conns = [c for c in conns if c.rip and _is_public(c.rip)]
        if q:
            conns = [
                c
                for c in conns
                if q in c.process.lower()
                or q in c.local.lower()
                or q in c.remote.lower()
                or q in c.status.lower()
                or q in str(c.pid)
                or q in c.threat.lower()
            ]
        selected = {c.key for c in self._selected()}
        rows = [
            (
                c.process or "—",
                c.pid or "",
                c.proto,
                c.local,
                c.remote or "—",
                c.status,
                _age(c.first_seen),
                c.threat or ("ok" if c.rip else ""),
            )
            for c in conns
        ]
        self.model.set_rows(rows, conns)
        if selected:
            sm = self.table.selectionModel()
            for i, c in enumerate(conns):
                if c.key in selected:
                    sm.select(self.model.index(i, 0), sm.SelectionFlag.Select | sm.SelectionFlag.Rows)

    def _selected(self) -> list[Connection]:
        sm = self.table.selectionModel()
        if sm is None:
            return []
        rows = sorted({i.row() for i in sm.selectedRows()})
        return [self.model.objects[r] for r in rows if r < len(self.model.objects)]  # type: ignore[misc]

    # ------------------------------------------------------------------ actions
    def _menu(self, pos) -> None:
        if not self._selected():
            return
        m = QMenu(self)
        m.addAction("End process", self.kill)
        m.addAction("Block remote IP", self.block)
        m.addAction("Look up IP reputation", self.lookup)
        m.addAction("Trust this IP", self.trust)
        m.addSeparator()
        m.addAction("Copy remote address", self.copy)
        m.exec(self.table.viewport().mapToGlobal(pos))

    def copy(self) -> None:
        sel = self._selected()
        if sel:
            QGuiApplication.clipboard().setText("\n".join(c.rip for c in sel if c.rip))

    def kill(self) -> None:
        procs = {(c.pid, c.process) for c in self._selected() if c.pid}
        if not procs:
            return
        names = "\n".join(f"{n} (PID {p})" for p, n in sorted(procs))
        if QMessageBox.question(self, "End process", f"Terminate these processes?\n\n{names}") != QMessageBox.Yes:
            return
        errs = []
        for pid, _ in procs:
            try:
                kill_process(pid)
            except Exception as exc:
                errs.append(f"PID {pid}: {exc}")
        if errs:
            QMessageBox.warning(self, "End process", "\n".join(errs))

    def block(self) -> None:
        ips = sorted({c.rip for c in self._selected() if c.rip})
        if not ips:
            return
        if (
            QMessageBox.question(
                self, "Block IP", "Add firewall rules blocking all traffic to and from:\n\n" + "\n".join(ips)
            )
            != QMessageBox.Yes
        ):
            return
        for ip in ips:
            try:
                msg = block_ip(ip)
                self.s.db.log_event("firewall", msg, "warning")
                self.ctx.notify("Blocked", msg, "info")
            except FirewallError as exc:
                QMessageBox.warning(self, f"Could not block {ip}", str(exc))

    def lookup(self) -> None:
        for c in self._selected()[:3]:
            if c.rip:
                QDesktopServices.openUrl(QUrl(f"https://www.abuseipdb.com/check/{c.rip}"))

    def trust(self) -> None:
        for c in self._selected():
            if c.rip:
                self.s.network.whitelist.add(c.rip)
        self.refresh(force=True)
