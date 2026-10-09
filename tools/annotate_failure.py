"""Turn the interesting tail of a log into a GitHub Actions error annotation (readable through the API)."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def main() -> int:
    path, title = Path(sys.argv[1]), sys.argv[2] if len(sys.argv) > 2 else "Failure"
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = [f"(no log at {path})"]
    start = next(
        (i for i, ln in enumerate(lines) if re.match(r"^=+ (FAILURES|ERRORS) =+$", ln)), max(0, len(lines) - 120)
    )
    text = "\n".join(lines[start:])[-60000:]
    enc = text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")
    print(f"::error title={title}::{enc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
