"""Regenerate packaging/assets/icon.{png,ico,icns} from the in-app shield artwork.

pip install pillow && python tools/make_icons.py
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def render(size: int) -> bytes:
    from PySide6.QtCore import QBuffer, QIODevice, QRectF, Qt
    from PySide6.QtGui import QColor, QImage, QPainter

    from sentinel_vision.gui import theme
    from sentinel_vision.gui.widgets import paint_shield

    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    m = size * 0.06
    paint_shield(p, QRectF(m, m, size - 2 * m, size - 2 * m), QColor(theme.ACCENT), "eye")
    p.end()
    buf = QBuffer()
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    return bytes(buf.data())


def main() -> None:
    from PIL import Image
    from PySide6.QtGui import QGuiApplication

    _app = QGuiApplication([])
    out = ROOT / "packaging" / "assets"
    out.mkdir(parents=True, exist_ok=True)
    big = Image.open(io.BytesIO(render(1024))).convert("RGBA")
    big.save(out / "icon.png")
    ico_sizes = [(s, s) for s in (16, 20, 24, 32, 40, 48, 64, 128, 256)]
    big.save(out / "icon.ico", sizes=ico_sizes)
    big.save(out / "icon.icns")
    print("wrote", ", ".join(str(p.relative_to(ROOT)) for p in sorted(out.iterdir())))


if __name__ == "__main__":
    main()
