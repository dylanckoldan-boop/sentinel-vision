"""Visual identity: a deep-ink control-room palette with a single luminous teal accent."""

from __future__ import annotations

from PySide6.QtGui import QColor

BG = "#0b1016"
SURFACE = "#111821"
SURFACE_2 = "#16202b"
BORDER = "#223041"
TEXT = "#e6edf3"
MUTED = "#8b9bb0"
ACCENT = "#2ee6c5"
ACCENT_DIM = "#1a8f7c"
DOWN = "#4aa8ff"  # download series
UP = "#2ee6c5"  # upload series
OK = "#3ddc84"
WARN = "#ffb547"
DANGER = "#ff5c6c"
CRIT = "#ff2d55"

SEVERITY_COLORS = {0: MUTED, 1: "#7fb3ff", 2: WARN, 3: DANGER, 4: CRIT}
SEVERITY_NAMES = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

MONO = "'JetBrains Mono', 'Cascadia Mono', 'SF Mono', Menlo, Consolas, monospace"
SANS = "'Inter', 'Segoe UI Variable', 'Segoe UI', 'SF Pro Text', 'Helvetica Neue', Arial, sans-serif"


def qcolor(hex_: str, alpha: int = 255) -> QColor:
    c = QColor(hex_)
    c.setAlpha(alpha)
    return c


STYLESHEET = f"""
* {{ font-family: {SANS}; font-size: 13px; color: {TEXT}; }}
QMainWindow, QWidget#root {{ background: {BG}; }}
QWidget#page {{ background: {BG}; }}
QToolTip {{ background: {SURFACE_2}; color: {TEXT}; border: 1px solid {BORDER}; padding: 6px; }}

/* sidebar */
QWidget#sidebar {{ background: {SURFACE}; border-right: 1px solid {BORDER}; }}
QLabel#brand {{ font-size: 15px; font-weight: 700; letter-spacing: 0.5px; }}
QLabel#brandSub {{ color: {MUTED}; font-size: 11px; }}
QPushButton#nav {{
    text-align: left; padding: 10px 14px; border: none; border-radius: 8px;
    color: {MUTED}; background: transparent; font-size: 13px;
}}
QPushButton#nav:hover {{ background: {SURFACE_2}; color: {TEXT}; }}
QPushButton#nav:checked {{ background: {SURFACE_2}; color: {ACCENT}; font-weight: 600; border-left: 3px solid {ACCENT}; }}

/* headings */
QLabel#h1 {{ font-size: 22px; font-weight: 700; }}
QLabel#h2 {{ font-size: 15px; font-weight: 600; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#mono {{ font-family: {MONO}; color: {MUTED}; font-size: 12px; }}

/* cards */
QFrame#card {{ background: {SURFACE}; border: 1px solid {BORDER}; border-radius: 12px; }}
QLabel#statValue {{ font-size: 24px; font-weight: 700; font-family: {MONO}; }}
QLabel#statLabel {{ color: {MUTED}; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }}

/* buttons */
QPushButton {{
    background: {SURFACE_2}; border: 1px solid {BORDER}; border-radius: 8px; padding: 8px 16px; font-weight: 600;
}}
QPushButton:hover {{ border-color: {ACCENT_DIM}; }}
QPushButton:pressed {{ background: {BORDER}; }}
QPushButton:disabled {{ color: {MUTED}; border-color: {SURFACE_2}; }}
QPushButton#primary {{ background: {ACCENT}; color: #04211c; border: none; }}
QPushButton#primary:hover {{ background: #5cf0d6; }}
QPushButton#primary:disabled {{ background: {ACCENT_DIM}; color: #0b3a33; }}
QPushButton#danger {{ background: transparent; color: {DANGER}; border: 1px solid {DANGER}; }}
QPushButton#danger:hover {{ background: rgba(255,92,108,0.12); }}

/* inputs */
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox, QPlainTextEdit, QTextEdit {{
    background: {SURFACE_2}; border: 1px solid {BORDER}; border-radius: 8px; padding: 6px 8px;
    selection-background-color: {ACCENT_DIM};
}}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus {{ border-color: {ACCENT}; }}
QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px; border: 1px solid {BORDER}; background: {SURFACE_2}; }}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

/* tables */
QTableView, QTreeView, QListWidget {{
    background: {SURFACE}; alternate-background-color: #131c26; border: 1px solid {BORDER}; border-radius: 10px;
    gridline-color: transparent; selection-background-color: #1d3340; selection-color: {TEXT};
}}
QHeaderView::section {{
    background: {SURFACE}; color: {MUTED}; border: none; border-bottom: 1px solid {BORDER};
    padding: 8px 6px; font-size: 11px; font-weight: 600; text-transform: uppercase;
}}
QTableView::item {{ padding: 4px 6px; border: none; }}
QListWidget::item {{ padding: 5px 6px; }}
QAbstractSpinBox {{ padding-right: 8px; }}

QProgressBar {{ background: {SURFACE_2}; border: none; border-radius: 4px; height: 8px; text-align: center; color: transparent; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 4px; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 4px; min-height: 30px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {BORDER}; border-radius: 4px; min-width: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}

QTabWidget::pane {{ border: none; }}
QTabBar::tab {{ background: transparent; color: {MUTED}; padding: 8px 14px; border-bottom: 2px solid transparent; }}
QTabBar::tab:selected {{ color: {ACCENT}; border-bottom: 2px solid {ACCENT}; }}
QGroupBox {{ border: 1px solid {BORDER}; border-radius: 10px; margin-top: 14px; padding: 14px 12px 10px 12px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 4px; color: {MUTED}; font-weight: 600; }}
QMenu {{ background: {SURFACE}; border: 1px solid {BORDER}; padding: 4px; }}
QMenu::item {{ padding: 6px 18px; border-radius: 4px; }}
QMenu::item:selected {{ background: {SURFACE_2}; }}
QScrollArea {{ border: none; background: transparent; }}
"""
