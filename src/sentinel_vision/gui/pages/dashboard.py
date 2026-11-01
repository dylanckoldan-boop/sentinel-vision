from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from sentinel_vision import autostart
from sentinel_vision.gui import theme
from sentinel_vision.gui.pages.base import Page, ago, fmt_ts
from sentinel_vision.gui.widgets import StatCard, StatusHero, ThroughputGraph, card, label


class DashboardPage(Page):
    title = "Overview"
    refresh_ms = 1500

    def __init__(self, ctx) -> None:
        super().__init__(ctx)
        self.hero = StatusHero()
        hero_card, hl = card(padding=12)
        row = QHBoxLayout()
        row.addWidget(self.hero, 1)
        actions = QVBoxLayout()
        actions.setSpacing(8)
        self.btn_quick = QPushButton("Quick scan")
        self.btn_quick.setObjectName("primary")
        self.btn_update = QPushButton("Update definitions")
        self.btn_net = QPushButton("Live traffic")
        for b in (self.btn_quick, self.btn_update, self.btn_net):
            b.setMinimumWidth(180)
            actions.addWidget(b)
        actions.addStretch(1)
        row.addLayout(actions)
        hl.addLayout(row)
        self.root.addWidget(hero_card)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.c_threats = StatCard("Threats · 24 h")
        self.c_quarantine = StatCard("Quarantined")
        self.c_rt = StatCard("Real-time scans")
        self.c_conns = StatCard("Live connections")
        self.c_netthreats = StatCard("Network alerts")
        self.c_sigs = StatCard("Definitions")
        for i, c in enumerate(
            (self.c_threats, self.c_quarantine, self.c_rt, self.c_conns, self.c_netthreats, self.c_sigs)
        ):
            grid.addWidget(c, i // 3, i % 3)
        self.root.addLayout(grid)

        bottom = QHBoxLayout()
        bottom.setSpacing(12)
        eng_card, el = card()
        el.addWidget(label("Detection engines", "h2"))
        self.engines_box = QVBoxLayout()
        self.engines_box.setSpacing(6)
        el.addLayout(self.engines_box)
        el.addStretch(1)
        bottom.addWidget(eng_card, 2)

        g_card, gl = card()
        gl.addWidget(label("Network throughput", "h2"))
        self.graph = ThroughputGraph(seconds=180)
        gl.addWidget(self.graph)
        bottom.addWidget(g_card, 3)
        self.root.addLayout(bottom, 1)

        ev_card, evl = card()
        evl.addWidget(label("Recent activity", "h2"))
        self.events_box = QVBoxLayout()
        self.events_box.setSpacing(4)
        evl.addLayout(self.events_box)
        self.root.addWidget(ev_card)

        self.btn_quick.clicked.connect(lambda: ctx.navigate("scan", "quick"))
        self.btn_update.clicked.connect(lambda: ctx.navigate("settings", "update"))
        self.btn_net.clicked.connect(lambda: ctx.navigate("network"))
        self._engine_labels: list[QLabel] = []
        self._event_labels: list[QLabel] = []
        self._last_slow = 0.0

    def _state(self) -> tuple[str, str, str]:
        s = self.s
        threats_24h = s.db.detection_count(time.time() - 86400)
        last = s.updater.last_update
        net = s.network.snapshot()
        recent = [i for i in s.ransomware.incidents if time.time() - i.ts < 86400]
        if recent:
            return (
                "danger",
                "Ransomware activity was stopped",
                "Open the Ransomware page to remove the program and restore your files.",
            )
        if not s.settings.realtime_enabled or not s.realtime.running:
            return (
                "danger",
                "Real-time protection is off",
                "New and downloaded files are not being checked. Turn it on in Protection.",
            )
        if net.threats:
            return (
                "danger",
                "Suspicious network activity",
                f"{net.threats} connection(s) match threat intelligence or risky patterns.",
            )
        if threats_24h:
            return (
                "warn",
                f"{threats_24h} threat(s) found today",
                "Review them in History. Signature hits were quarantined automatically.",
            )
        full = s.vault.full_since() if s.settings.ransomware_enabled else None
        if full:  # a lasting warning while the rollback vault refuses versions (SV-N01)
            return (
                "warn",
                "The rollback vault is full",
                f"Some new versions of your documents weren't kept (the first was refused {ago(full)}). This "
                "stays until there is room again: review it under Ransomware → Rollback vault, or raise its size "
                "limit in Settings.",
            )
        if time.time() - last > 7 * 86400:
            return "warn", "Definitions are out of date", f"Last update: {ago(last)}. Click “Update definitions”."
        rw_off = not s.settings.ransomware_enabled or (s.settings.ransomware_folders and not s.ransomware.running)
        if rw_off:
            return (
                "warn",
                "Ransomware shield is off",
                "Your documents have no decoys or rollback vault. Turn it on in Protection.",
            )
        if not s.settings.behavior_enabled or not s.behavior.running:
            return "warn", "Behavior monitoring is off", "New programs and auto-start changes are not being checked."
        if not autostart.is_enabled():
            return (
                "warn",
                "Protection won't start after a restart",
                "Turn on “Start at sign-in” in Protection (or from the tray icon).",
            )
        return "ok", "You're protected", f"Real-time and behavior protection on · definitions updated {ago(last)}"

    def refresh(self) -> None:
        s = self.s
        net = s.network.snapshot()
        self.graph.set_history(net.history)
        self.c_conns.set(f"{len(net.connections):,}", f"{net.established} established · {net.listening} listening")
        self.c_netthreats.set(
            str(net.threats), "risky connections right now", theme.DANGER if net.threats else theme.OK
        )
        self.c_rt.set(f"{s.realtime.files_scanned:,}", f"{s.realtime.threats_blocked} blocked this session")
        now = time.time()
        if now - self._last_slow < 4:
            return
        self._last_slow = now
        level, title, sub = self._state()
        self.hero.set_state(level, title, sub)
        t24 = s.db.detection_count(now - 86400)
        self.c_threats.set(str(t24), f"{s.db.detection_count():,} all time", theme.DANGER if t24 else theme.OK)
        q = s.quarantine.list()
        self.c_quarantine.set(str(len(q)), "encrypted & neutralised")
        yara_rules = next((e.status() for e in s.scanner.engines if e.name == "yara"), "off")
        self.c_sigs.set(f"{s.db.hash_count():,}", f"hashes · {yara_rules} · {s.intel.count:,} bad IPs")

        status = s.scanner.engine_status()
        while len(self._engine_labels) < len(status):
            lbl = QLabel()
            lbl.setTextFormat(Qt.RichText)
            self._engine_labels.append(lbl)
            self.engines_box.addWidget(lbl)
        for lbl, (name, ok, text) in zip(self._engine_labels, status):
            color = theme.OK if ok else theme.WARN
            lbl.setText(
                f"<span style='color:{color}'>●</span>&nbsp; <b>{name}</b> "
                f"<span style='color:{theme.MUTED}'>— {text}</span>"
            )
        for lbl in self._engine_labels[len(status) :]:
            lbl.setText("")

        events = s.db.recent_events(8)
        while len(self._event_labels) < 8:
            lbl = QLabel()
            lbl.setTextFormat(Qt.RichText)
            lbl.setWordWrap(False)
            lbl.setMinimumHeight(20)
            self._event_labels.append(lbl)
            self.events_box.addWidget(lbl)
        colors = {"critical": theme.DANGER, "warning": theme.WARN, "info": theme.MUTED}
        for i, lbl in enumerate(self._event_labels):
            if i < len(events):
                ts, lvl, kind, msg = events[i]
                lbl.setText(
                    f"<span style='color:{theme.MUTED};font-family:monospace'>{fmt_ts(ts)}</span>&nbsp;&nbsp;"
                    f"<span style='color:{colors.get(lvl, theme.MUTED)}'>{kind.upper()}</span>&nbsp;&nbsp;{_esc(msg)}"
                )
            else:
                lbl.setText(
                    "" if events else f"<span style='color:{theme.MUTED}'>No activity yet.</span>" if i == 0 else ""
                )


def _esc(t: str) -> str:
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
