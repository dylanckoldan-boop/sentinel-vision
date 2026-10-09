"""`python -m sentinel_vision` launches the GUI; `python -m sentinel_vision <command>` runs the CLI."""

import sys


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] != "--minimized":
        from sentinel_vision.cli import main as cli_main

        return cli_main()
    from sentinel_vision.gui.app import main as gui_main

    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
