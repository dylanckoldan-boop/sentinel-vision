"""Entry point for frozen (PyInstaller) builds."""

import sys

from sentinel_vision.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
