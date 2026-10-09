"""Reusable widgets: cards, the shield status hero, the live throughput graph, a fast table model."""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPointF, QRectF, QSize, Qt
from PySide6.QtGui import (
    QBrush,
    QColor,
    QFont,
    QIcon,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
    QRadialGradient,
)
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget

from sentinel_vision.gui import theme
from sentinel_vision.scanner import bytes_human

# ----------------------------------------------------------------------------- icon


def shield_path(rect: QRectF) -> QPainterPath:
    x, y, w, h = rect.x(), rect.y(), rect.width(), rect.height()
    p = QPainterPath()
    p.moveTo(x + w / 2, y)
    p.cubicTo(x + w * 0.72, y + h * 0.10, x + w * 0.88, y + h * 0.12, x + w, y + h * 0.14)
    p.cubicTo(x + w, y + h * 0.55, x + w * 0.85, y + h * 0.82, x + w / 2, y + h)
    p.cubicTo(x + w * 0.15, y + h * 0.82, x, y + h * 0.55, x, y + h * 0.14)
    p.cubicTo(x + w * 0.12, y + h * 0.12, x + w * 0.28, y + h * 0.10, x + w / 2, y)
    p.closeSubpath()
    return p


def paint_shield(painter: QPainter, rect: QRectF, color: QColor, glyph: str = "eye") -> None:
    painter.setRenderHint(QPainter.Antialiasing)
    grad = QLinearGradient(rect.topLeft(), rect.bottomRight())
    c1, c2 = QColor(color), QColor(color)
    c1.setAlpha(255)
    c2 = c2.darker(220)
    grad.setColorAt(0, c1)
    grad.setColorAt(1, c2)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QBrush(grad))
    painter.drawPath(shield_path(rect))
    inner = QColor(theme.BG)
    cx, cy = rect.center().x(), rect.y() + rect.height() * 0.47
    s = rect.width()
    pen = QPen(inner, max(1.5, s * 0.07), Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    if glyph == "eye":
        eye = QPainterPath()
        eye.moveTo(cx - s * 0.30, cy)
        eye.quadTo(cx, cy - s * 0.26, cx + s * 0.30, cy)
        eye.quadTo(cx, cy + s * 0.26, cx - s * 0.30, cy)
        painter.drawPath(eye)
        painter.setBrush(inner)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(cx, cy), s * 0.075, s * 0.075)
    elif glyph == "check":
        path = QPainterPath()
        path.moveTo(cx - s * 0.20, cy)
        path.lineTo(cx - s * 0.05, cy + s * 0.15)
        path.lineTo(cx + s * 0.22, cy - s * 0.14)
        painter.drawPath(path)
    elif glyph == "alert":
        painter.drawLine(QPointF(cx, cy - s * 0.20), QPointF(cx, cy + s * 0.05))
        painter.setBrush(inner)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(QPointF(cx, cy + s * 0.17), s * 0.045, s * 0.045)


def app_icon(color: str = theme.ACCENT) -> QIcon:
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        pm = QPixmap(size, size)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        m = size * 0.06
        paint_shield(p, QRectF(m, m, size - 2 * m, size - 2 * m), QColor(color), "eye")
        p.end()
        icon.addPixmap(pm)
    return icon


# ----------------------------------------------------------------------------- layout helpers


def card(*, padding: int = 16) -> tuple[QFrame, QVBoxLayout]:
    f = QFrame()
    f.setObjectName("card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(padding, padding, padding, padding)
    lay.setSpacing(8)
    return f, lay


def label(text: str = "", obj: str | None = None, wrap: bool = False) -> QLabel:
    lbl = QLabel(text)
    if obj:
        lbl.setObjectName(obj)
    lbl.setWordWrap(wrap)
    lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return lbl


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "—", accent: str = theme.TEXT) -> None:
        super().__init__()
        self.setObjectName("card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(2)
        self.title = QLabel(title.upper())
        self.title.setObjectName("statLabel")
        self.value = QLabel(value)
        self.value.setObjectName("statValue")
        self.sub = QLabel("")
        self.sub.setObjectName("muted")
        lay.addWidget(self.title)
        lay.addWidget(self.value)
        lay.addWidget(self.sub)
        self.set_accent(accent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set(self, value: str, sub: str = "", accent: str | None = None) -> None:
        self.value.setText(value)
        self.sub.setText(sub)
        if accent:
            self.set_accent(accent)

    def set_accent(self, color: str) -> None:
        self.value.setStyleSheet(f"color: {color};")


class StatusHero(QWidget):
    """Large shield with a status headline."""

    def __init__(self) -> None:
        super().__init__()
        self.color = QColor(theme.OK)
        self.glyph = "check"
        self.title = "Protected"
        self.subtitle = ""
        self.setMinimumHeight(150)

    def set_state(self, level: str, title: str, subtitle: str) -> None:
        self.color = QColor({"ok": theme.OK, "warn": theme.WARN, "danger": theme.DANGER}[level])
        self.glyph = {"ok": "check", "warn": "alert", "danger": "alert"}[level]
        self.title, self.subtitle = title, subtitle
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        h = self.height()
        size = min(h - 20, 128)
        center = QPointF(20 + size / 2, h / 2)
        radius = min(h / 2, size * 0.75)
        rg = QRadialGradient(center, radius)
        rg.setColorAt(0, theme.qcolor(self.color.name(), 70))
        rg.setColorAt(1, theme.qcolor(self.color.name(), 0))
        p.setPen(Qt.NoPen)
        p.setBrush(rg)
        p.drawEllipse(center, radius, radius)
        paint_shield(p, QRectF(20, (h - size) / 2, size, size), self.color, self.glyph)
        x = 20 + size + 32
        f = QFont(self.font())
        f.setPointSizeF(24)
        f.setBold(True)
        p.setFont(f)
        p.setPen(QColor(theme.TEXT))
        p.drawText(QRectF(x, h / 2 - 44, self.width() - x, 40), Qt.AlignLeft | Qt.AlignBottom, self.title)
        f.setPointSizeF(11)
        f.setBold(False)
        p.setFont(f)
        p.setPen(QColor(theme.MUTED))
        p.drawText(
            QRectF(x, h / 2 + 2, self.width() - x - 10, 60), Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap, self.subtitle
        )


# ----------------------------------------------------------------------------- throughput graph


def _nice_ceiling(v: float) -> float:
    if v <= 0:
        return 1024.0
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if m * exp >= v:
            return m * exp
    return 10 * exp


class ThroughputGraph(QWidget):
    def __init__(self, seconds: int = 240) -> None:
        super().__init__()
        self.history: list[tuple[float, float, float]] = []
        self.seconds = seconds
        self.setMinimumHeight(180)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(600, 220)

    def set_history(self, history: Sequence[tuple[float, float, float]]) -> None:
        self.history = list(history)
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        left, right, top, bottom = 70, 12, 26, 24
        plot = QRectF(left, top, w - left - right, h - top - bottom)
        mono = QFont(self.font())
        mono.setFamilies(["JetBrains Mono", "Cascadia Mono", "SF Mono", "Menlo", "Consolas", "monospace"])
        mono.setPointSizeF(8.5)
        p.setFont(mono)

        if not self.history:
            p.setPen(QColor(theme.MUTED))
            p.drawText(plot, Qt.AlignCenter, "Collecting traffic samples…")
            return
        now = self.history[-1][0]
        t0 = now - self.seconds
        pts = [(t, u, d) for t, u, d in self.history if t >= t0]
        peak = max([max(u, d) for _, u, d in pts] + [1.0])
        ymax = _nice_ceiling(peak * 1.15)

        # grid
        p.setPen(QPen(QColor(theme.BORDER), 1, Qt.DashLine))
        for i in range(5):
            y = plot.bottom() - plot.height() * i / 4
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            p.setPen(QColor(theme.MUTED))
            p.drawText(
                QRectF(0, y - 8, left - 8, 16), Qt.AlignRight | Qt.AlignVCenter, bytes_human(ymax * i / 4) + "/s"
            )
            p.setPen(QPen(QColor(theme.BORDER), 1, Qt.DashLine))
        p.setPen(QColor(theme.MUTED))
        p.drawText(QRectF(plot.left(), plot.bottom() + 4, 120, 16), Qt.AlignLeft, f"-{self.seconds // 60} min")
        p.drawText(QRectF(plot.right() - 60, plot.bottom() + 4, 60, 16), Qt.AlignRight, "now")

        def xy(t: float, v: float) -> QPointF:
            return QPointF(
                plot.left() + plot.width() * (t - t0) / self.seconds, plot.bottom() - plot.height() * v / ymax
            )

        for idx, color in ((2, theme.DOWN), (1, theme.UP)):
            line = QPainterPath()
            for i, sample in enumerate(pts):
                pt = xy(sample[0], sample[idx])
                line.moveTo(pt) if i == 0 else line.lineTo(pt)
            area = QPainterPath(line)
            area.lineTo(xy(pts[-1][0], 0))
            area.lineTo(xy(pts[0][0], 0))
            area.closeSubpath()
            grad = QLinearGradient(0, plot.top(), 0, plot.bottom())
            grad.setColorAt(0, theme.qcolor(color, 90))
            grad.setColorAt(1, theme.qcolor(color, 0))
            p.setPen(Qt.NoPen)
            p.setBrush(grad)
            p.drawPath(area)
            p.setPen(QPen(QColor(color), 2))
            p.setBrush(Qt.NoBrush)
            p.drawPath(line)

        # legend
        _, up, down = pts[-1]
        x = plot.left()
        for name, color, val in (("▼ Download", theme.DOWN, down), ("▲ Upload", theme.UP, up)):
            p.setPen(QColor(color))
            txt = f"{name}  {bytes_human(val)}/s"
            p.drawText(QRectF(x, 2, 220, 18), Qt.AlignLeft | Qt.AlignVCenter, txt)
            x += 200


# ----------------------------------------------------------------------------- table model


class RowTableModel(QAbstractTableModel):
    """Lightweight model: rows are tuples; optional per-row colour and tooltip callbacks."""

    def __init__(
        self,
        headers: Sequence[str],
        color_for: Callable[[object], str | None] | None = None,
        tooltip_for: Callable[[object, int], str | None] | None = None,
    ) -> None:
        super().__init__()
        self.headers = list(headers)
        self.rows: list[tuple] = []
        self.objects: list[object] = []
        self.color_for = color_for
        self.tooltip_for = tooltip_for

    def set_rows(self, rows: list[tuple], objects: list[object] | None = None) -> None:
        self.beginResetModel()
        self.rows = rows
        self.objects = objects if objects is not None else rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self.headers)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        r, c = index.row(), index.column()
        if role == Qt.DisplayRole:
            v = self.rows[r][c]
            return "" if v is None else str(v)
        if role == Qt.ForegroundRole and self.color_for:
            col = self.color_for(self.objects[r])
            if col:
                return QColor(col)
        if role == Qt.ToolTipRole:
            if self.tooltip_for:
                return self.tooltip_for(self.objects[r], c)
            return str(self.rows[r][c])
        if role == Qt.UserRole:
            return self.objects[r]
        return None

    def headerData(self, section: int, orientation, role: int = Qt.DisplayRole):  # noqa: N802
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None


def hbox(*widgets, spacing: int = 10, stretch_last: bool = False) -> QHBoxLayout:
    lay = QHBoxLayout()
    lay.setSpacing(spacing)
    for w in widgets:
        if w is None:
            lay.addStretch(1)
        elif isinstance(w, QWidget):
            lay.addWidget(w)
        else:
            lay.addLayout(w)
    if stretch_last:
        lay.addStretch(1)
    return lay
