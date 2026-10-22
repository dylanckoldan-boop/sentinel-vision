"""Entry point for the frozen Windows protection service (sentinel-vision-service.exe)."""

import sys

from sentinel_vision.winservice import main

if __name__ == "__main__":
    sys.exit(main())
