"""Entry point for the frozen command-line tool (sentinel-vision-cli)."""

import sys

from sentinel_vision.cli import main

if __name__ == "__main__":
    sys.exit(main())
