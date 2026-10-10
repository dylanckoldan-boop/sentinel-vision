"""Turn a pytest log into GitHub Actions annotations, which are readable through the API.

python tools/annotate_failure.py pytest.log "Title"            # failure details as an error annotation
python tools/annotate_failure.py pytest.log "Title" --summary  # result line + skip reasons as a notice
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


def _enc(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def main() -> int:
    path = Path(sys.argv[1])
    title = sys.argv[2] if len(sys.argv) > 2 else "pytest"
    summary_mode = "--summary" in sys.argv[3:]
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = [f"(no log at {path})"]
    if summary_mode:
        keep = [ln for ln in lines if ln.startswith("SKIPPED") or re.match(r"^=* ?\d+ (passed|failed).*", ln)]
        print(f"::notice title={title}::{_enc(chr(10).join(keep[-20:]) or 'no summary found')}")
        return 0
    start = next(
        (i for i, ln in enumerate(lines) if re.match(r"^=+ (FAILURES|ERRORS) =+$", ln)), max(0, len(lines) - 120)
    )
    print(f"::error title={title}::{_enc(chr(10).join(lines[start:])[-60000:])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
