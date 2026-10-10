<p align="center">
  <img src="docs/screenshots/overview.png" alt="Sentinel Vision overview" width="900">
</p>

<h1 align="center">Sentinel Vision</h1>

<p align="center">
  <b>Open-source, multi-engine antimalware with real-time protection, behavior monitoring and live network monitoring.</b><br>
  Windows · macOS · Linux — MIT licensed — no telemetry, no account, no cloud upload of your files.
</p>

<p align="center">
  <a href="https://github.com/dylanckoldan-boop/sentinel-vision/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/dylanckoldan-boop/sentinel-vision?color=2ee6c5"></a>
  <a href="https://github.com/dylanckoldan-boop/sentinel-vision/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/dylanckoldan-boop/sentinel-vision/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-2ee6c5">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-4aa8ff">
</p>

<p align="center">
  <a href="https://github.com/dylanckoldan-boop/sentinel-vision/releases/latest"><b>⬇ Download</b></a> ·
  <a href="docs/INSTALL.md">Installation guide</a> ·
  <a href="ROADMAP.md">Roadmap</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

## Install

### Windows (recommended: the installer)

1. Download **`SentinelVision-<version>-Setup.exe`** from the [latest release](https://github.com/dylanckoldan-boop/sentinel-vision/releases/latest).
2. Run it. If Windows shows *"Windows protected your PC"*, click **More info → Run anyway** (the app isn't code-signed yet — [why](docs/CODE_SIGNING.md)).
3. Keep **"Start Sentinel Vision automatically when I sign in"** ticked and click **Install**. No administrator rights needed.
4. In the app, open **Settings & updates → Update now** to download the latest threat definitions.

That's it — Sentinel Vision now starts hidden in the system tray every time you sign in, and updates itself.

### macOS, Linux, portable and from source

See the **[installation guide](docs/INSTALL.md)** for step-by-step instructions for every platform, ClamAV setup,
updating, uninstalling and troubleshooting.

## What it does

| | |
|---|---|
| **4 detection engines** | Hash blocklists (MD5/SHA-1/SHA-256) · YARA (bundled rules + [YARA Forge](https://yarahq.github.io/) + your own) · ClamAV (via `clamd` or `clamscan`) · static heuristics for unknown threats, with Windows Authenticode and catalog-signature checks to avoid false alarms on signed software |
| **Real-time protection** | Watches Downloads, Desktop, Documents, temp and autostart folders; new or changed files are scanned the moment they finish writing and known malware is quarantined automatically |
| **Behavior monitoring** | Every new program is checked for attack techniques (malicious-document shells, download-and-run PowerShell, ransomware deleting backups, LOLBin abuse, reverse shells, miners) and its executable is scanned; confirmed malware is ended and quarantined. Auto-start locations are watched for new persistence. |
| **Live traffic monitor** | Every TCP/UDP connection mapped to its process, checked against botnet-C2 and criminal-netblock feeds, with a live throughput graph, alerts, *End process*, *Block IP* (OS firewall) and reputation lookup |
| **Starts at sign-in** | Runs quietly in the tray from the moment you log in (Windows, macOS and Linux) |
| **Self-updating** | Threat definitions every 6 hours; the app itself via verified installer updates on Windows |
| **Process & archive scanning** | Scans the executable behind every running process; looks inside zip / tar / gz / bz2 / xz (nested) with decompression-bomb protection |
| **Encrypted quarantine** | AES-256-GCM vault with chunk-level integrity; restores are hash-verified |
| **GUI + CLI + daemon** | Desktop app with tray icon & notifications; scriptable CLI with JSON output and exit codes; headless daemon for servers |

<p align="center">
  <img src="docs/screenshots/protection.png" alt="Protection page" width="49%">
  <img src="docs/screenshots/network.png" alt="Live traffic monitor" width="49%">
</p>

## Command line

Included with every install (`sentinel-vision-cli`; on Windows tick *Add to PATH* in the installer or run it from the install folder):

```bash
sentinel-vision-cli status                      # engines, definitions, start-at-sign-in
sentinel-vision-cli update                      # download the latest definitions
sentinel-vision-cli scan ~/Downloads /mnt/usb   # scan paths (auto-quarantines signature hits)
sentinel-vision-cli scan . --no-quarantine --json > report.json
sentinel-vision-cli quick                       # quick scan + running processes
sentinel-vision-cli processes                   # scan running programs only
sentinel-vision-cli net --watch                 # live connection table in the terminal
sentinel-vision-cli quarantine list
sentinel-vision-cli quarantine restore <ID> --to ~/restored
sentinel-vision-cli autostart on|off|status     # start the app at sign-in
sentinel-vision-cli check-update                # is a newer version available?
sentinel-vision-cli daemon                      # headless real-time + behavior + network protection
```

Exit codes: `0` clean · `1` threats found · `2` error — handy for CI pipelines and cron jobs.

## How detection works

```
file ─┬─► SHA-256 / SHA-1 / MD5 ──► hash blocklist ─────────┐  signature hits
      ├─► YARA (thread-local compiled rule set) ────────────┤  → auto-quarantine
      ├─► ClamAV (clamd INSTREAM, or clamscan) ─────────────┘
      ├─► heuristics: PE structure, packers, section entropy, injection/keylogger/ransomware
      │   import combos, script cradles, AMSI/Defender tampering, macro auto-exec, LNK
      │   launchers, double extensions, RTLO tricks, miner and ransom-note strings;
      │   valid Authenticode signatures lower the score, broken ones raise it
      │   → score 0-100, reported at ≥ threshold (report-only unless you opt in)
      └─► archives are unpacked in memory (count / size / bomb limits) and every
          member goes through the same pipeline

new process ─► technique rules (parent, command line, location) ─► report / end ransomware tools
            └► executable scanned by all engines ─► confirmed malware ended + quarantined
auto-start entry added ─► reported, target scanned
```

Clean results are cached by path + size + mtime and invalidated whenever definitions change, so repeat scans only
touch new or modified files. A weekly [false-positive audit](.github/workflows/fp-audit.yml) scans 20,000 clean system and
application files on each of Windows, macOS and Linux with every engine and fails if anything would be removed.

## Security design

Security software is a high-value target, so Sentinel Vision is built defensively:

* **Never executes what it scans.** Files are only read; `pefile`, `zipfile` and `tarfile` parse in memory and archive members are never written to disk.
* **Hardened parsing.** Size caps, member-count caps, decompression-bomb checks, YARA match timeouts, and every engine runs inside its own error boundary so a malformed file can't stop a scan.
* **Safe updates.** HTTPS only (TLS 1.2+, certificate verification always on, HTTPS-only redirects), download size limits, YARA archives are extracted file-by-file with flattened names (no path traversal), and new rules are compile-checked then swapped in atomically — a bad update never removes working protection. App updates are verified against the release's SHA-256 checksums before they run.
* **Encrypted quarantine.** AES-256-GCM with a per-install key stored owner-only; per-chunk nonces and authenticated position/final-chunk flags detect tampering, reordering and truncation; restores are verified against the original SHA-256 and never overwrite existing files.
* **Careful automatic actions.** Only signature-confirmed malware and the actual backup-deletion tools are ended automatically; heuristic and technique alerts are report-only by default. Pattern matches on validly signed programs, and anything short of an exact match on operating-system files, are reported rather than removed.
* **No shell, ever.** External tools (`netsh`, `iptables`, `clamscan`, `freshclam`, `taskkill`) are called with argument lists; IPs are validated before any firewall rule is built; private/loopback addresses can't be blocked.
* **Private by default.** No telemetry. Your files never leave your machine — only hash/IP feeds and update metadata are downloaded. Data lives in an owner-only directory.
* **Self-protection from false positives.** The app's own install and data directories are excluded so its signature files are never "detected".

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md).

## Honest limitations

Sentinel Vision is a strong second layer and a transparent, hackable security toolkit. It is **not** a drop-in
replacement for an OS-integrated antivirus — keep Microsoft Defender / XProtect enabled alongside it:

* Files are checked **when they are written** and programs **right after they start** (within about a second), not
  *before* they open. Blocking first requires OS-level hooks that need vendor approval (Windows minifilter drivers,
  macOS Endpoint Security) or root (Linux fanotify — on the [roadmap](ROADMAP.md)).
* Builds are not yet code-signed, so Windows and macOS show a warning on first launch ([how to fix that](docs/CODE_SIGNING.md)).
* Network throughput is system-wide; per-process bandwidth isn't available portably yet.
* On macOS, scanning protected folders needs Full Disk Access and seeing every process's connections needs admin rights.
* Detection quality depends on the feeds and rules you enable — keep definitions updated and add ClamAV.

## Data locations

| | |
|---|---|
| Windows | `%LOCALAPPDATA%\SentinelVision` |
| macOS | `~/Library/Application Support/SentinelVision` |
| Linux | `~/.local/share/SentinelVision` |

Inside: `settings.json`, `sentinel.db` (hashes, history, cache), `quarantine/`, `rules/downloaded/`, `rules/custom/`
(drop your own `.yar` files here), `feeds/`, `logs/`.

## Development

```bash
git clone https://github.com/dylanckoldan-boop/sentinel-vision && cd sentinel-vision
pip install -e ".[dev]"
pytest                 # engines, quarantine crypto, archives, intel, behavior, autostart, self-update, CLI, GUI
ruff check src tests tools
```

```
src/sentinel_vision/
  engines/      hash, YARA, ClamAV, heuristic engines + Authenticode verification
  network/      live connection monitor, threat-intel store, firewall integration
  gui/          PySide6 application (pages, widgets, theme)
  rules/        bundled YARA rules
  scanner.py    scan orchestration, archive handling, actions
  realtime.py   file-system watcher
  behavior.py   process and persistence monitoring
  quarantine.py encrypted vault
  updater.py    signature / feed updater
  app_update.py application self-update
  autostart.py  start at sign-in
  cli.py        command-line interface
packaging/      PyInstaller spec, icons, Windows installer (Inno Setup)
tools/          false-positive audit, icon generator
```

See [CONTRIBUTING.md](CONTRIBUTING.md) — rules, heuristics, feeds and the [roadmap](ROADMAP.md) items are especially welcome.

## Credits

Detection content comes from the security community: [YARA](https://virustotal.github.io/yara/), [YARA Forge](https://github.com/YARAHQ/yara-forge) and the rule authors it aggregates, [ClamAV](https://www.clamav.net/), [abuse.ch](https://abuse.ch/) (MalwareBazaar, Feodo Tracker, ThreatFox), [Spamhaus](https://www.spamhaus.org/drop/), [Proofpoint Emerging Threats](https://rules.emergingthreats.net/) and [CINS Army](https://cinsscore.com/). Downloaded rule sets and feeds remain under their own licenses and terms of use.

## License

[MIT](LICENSE) © 2026 Dylan Koldan
