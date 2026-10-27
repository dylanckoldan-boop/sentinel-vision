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

## Bigger projects

See [ROADMAP.md](ROADMAP.md) and the issues labelled
[`roadmap`](https://github.com/dylanckoldan-boop/sentinel-vision/issues?q=is%3Aissue+label%3Aroadmap) — for example
Linux fanotify on-access blocking, per-process bandwidth, macOS signature checks, translations and Linux packages.

## Building the apps and the Windows installer

```bash
pip install . pyinstaller
pyinstaller --noconfirm packaging/sentinel_vision.spec      # -> dist/SentinelVision (+ .app on macOS)
# Windows only, with Inno Setup 6.3+ installed:
iscc /DAppVersion=0.2.0 packaging\windows\SentinelVision.iss  # -> dist/installer/SentinelVision-0.2.0-Setup.exe
```

`python tools/fp_audit.py --update <folders>` scans known-clean software and lists anything that would be detected —
run it before proposing new rules or heuristics. `python tools/make_icons.py` regenerates the app icons.

## Releasing (maintainers)

1. Update `__version__` in `src/sentinel_vision/__init__.py` and add a section to `CHANGELOG.md`.
2. Commit to `main`, then either push a tag (`git tag v<version> && git push origin v<version>`) or open
   *Actions → Release → Run workflow* on `main` with **publish** ticked (the workflow creates the tag).
3. The *Release* workflow builds all platforms, installs/upgrades/uninstalls the Windows installer on a clean machine,
   smoke-tests macOS and Linux, and only then publishes the GitHub Release with `SHA256SUMS.txt`.
   Run it without a tag (*Actions → Release → Run workflow*) to test a build without publishing.

## AI-assisted contributions

AI tools are welcome; much of Sentinel Vision itself was written with them (see *How this was built* in the README).

* Say so in the pull request (the template has a checkbox), and describe what the tool did.
* You are responsible for every line you submit, exactly as if you had typed it: understand it, test it, and make sure
  you have the right to contribute it.
* Never paste secrets (keys, tokens), private data or live malware into an AI tool.
* The same rules apply as for any change: tests are required, and CI must pass on Windows, macOS and Linux.
* A change to anything the website or README promises must keep [docs/CLAIMS.md](docs/CLAIMS.md) true.

## Pull requests

* Keep PRs focused; describe *what* and *why*.
* Run `ruff format` and `pytest` before pushing.
* By contributing you agree your work is released under the MIT license.
