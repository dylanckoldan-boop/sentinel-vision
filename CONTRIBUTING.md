# Contributing to Sentinel Vision

Thanks for helping make open-source security better!

## Getting started

```bash
git clone https://github.com/dylanckoldan-boop/sentinel-vision
cd sentinel-vision
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
ruff check src tests && ruff format --check src tests
```

Set `SENTINEL_VISION_HOME=/some/tmp/dir` while developing so you don't touch your real settings, quarantine or database.

## Ground rules

1. **Never commit live malware.** Use the EICAR test string (assembled at runtime as in `tests/conftest.py`), synthetic samples, or hashes. PRs containing real malicious binaries will be closed.
2. **Treat every input as hostile.** Anything that parses files, archives or feeds must enforce size limits, avoid recursion without depth limits, and never execute or write untrusted content outside the quarantine.
3. **No `shell=True`, no `eval`, no pickle** on untrusted data.
4. **Every engine call must be crash-isolated** — one bad file must not stop a scan.
5. Add tests for new behaviour. CI runs on Windows, macOS and Linux.

## Good first contributions

* **YARA rules** — add high-signal, low-false-positive rules to `src/sentinel_vision/rules/`. Include `meta: description`, `severity` (`low`/`medium`/`high`/`critical`) and `author`. Explain in the PR what the rule targets and how you checked it for false positives (e.g. scanned a clean Windows/macOS install).
* **Heuristics** — new indicators in `engines/heuristics.py`, each with a weight and a test.
* **Threat feeds** — add a `Feed` to `config.DEFAULT_FEEDS` with a parser in `network/threatintel.py`. Feeds must be HTTPS and free to use.
* **Translations / accessibility** for the GUI.

## Bigger projects we'd love help with

* On-access blocking via OS APIs: Linux `fanotify` (permission events), macOS Endpoint Security, Windows minifilter/AMSI provider
* Behavioural monitoring (process creation trees, persistence changes, suspicious child processes)
* Authenticode / notarization signature verification to reduce false positives
* Per-process bandwidth (ETW on Windows, eBPF on Linux, nettop on macOS)
* Signed release builds and auto-update of the application itself

## Pull requests

* Keep PRs focused; describe *what* and *why*.
* Run `ruff format` and `pytest` before pushing.
* By contributing you agree your work is released under the MIT license.
