# Changelog

All notable changes to Sentinel Vision are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.5.2] - 2026-10-31

Closes the Sentinel Vision findings of the 31 October 2026 audit (IDs in brackets) and publishes the command-line
contract companion programs rely on. Released together with Foldward 0.2.0, which needs this version: it is the first
Foldward that reads the new exit code 3 as final; older Foldward versions treat it as an error.

### Security
- **A flood of new files can't fill the rollback vault for good [SV-N01].** A fifth of the vault is kept for documents
  it already holds (whose first version is more than 24 hours old), so their edits are still kept while new files are
  refused. First versions of new files also count against an hourly byte budget (a quarter of the vault, and at least
  twice the per-file limit), not only a count.
- **A full vault is a lasting warning [SV-N01].** Once the vault refuses a version for lack of room, the dashboard and
  the Ransomware page say so until the largest version it refused would fit again, across restarts. A small file that
  still fits doesn't clear the warning. The service's `vault.stats` answer reports it as `full_since`.
- **`quarantine add` refuses on purpose with exit code 3 [INT-01, INT-04].** Links and other files that aren't regular
  files, operating-system files and Sentinel Vision's own files are refused with exit 3, so the companion program
  knows not to move the file some other way. Any other problem is still exit 2. Nothing changes in either case.
- **The old Agent Guard plugin is refused [INT-07].** A plugin named `agent-guard` is listed with the reason and never
  loaded: it carries code with security problems that Foldward 0.2.0 fixes, would keep its old approval, and registers
  the same pages. When `plugins\foldward` exists, the Windows installer also deletes `plugins\agent-guard`.

### Companion programs
- **`quarantine add --reason TEXT -- PATH` works on every supported Python [INT-01].** On Python 3.10, 3.11 and 3.12
  before 3.12.7, argparse rejected an option before the path, so the contract's form failed with exit 2 on source
  installs. Each `quarantine` action now has its own parser; `quarantine add PATH --reason TEXT` keeps working.
- New `docs/plugin-contract.json`: the command shapes, exit codes and example answers companion programs rely on.
  `tests/test_plugin_contract.py` runs the real tool against it on every change; Foldward keeps a copy and replays its
  examples [INT-01].
- `docs/PLUGINS.md`: `--` before every file name and address, the exit-code table, the `scan` command, and the
  Foldward install command pinned to a release tag (`v0.2.0`) instead of the moving `main` branch [INT-06].

### Documents
- New `docs/NAME_CLEARANCE.md`: the checks so far on the name "Sentinel Vision" and what is left for the owner,
  including why the name can't be registered on PyPI [SV-E05].
- README and the claims register describe the vault reserve and the contract.

## [0.5.1] - 2026-10-31

Released together with Foldward's switch to its new name. Older Foldward versions (still writing as `agent-guard`)
keep working with this release.

### Changed
- **Agent Guard is now Foldward.** `quarantine add` records `foldward` as the requesting program by default (items
  added before keep `agent-guard`), the docs install Foldward into `plugins\foldward`, and the Windows install test
  uses the new name. Plugins are still found by iterating the `sentinel_vision.plugins` entry-point group, never by
  name.
- Nothing Foldward relies on changed: command shapes and exit codes, the 32-character quarantine id, the
  entry-point group and `plugin_api.API_VERSION` (1).

### Kept
- The `agent-guard` plugin log is never removed or renamed and stays readable and verifiable next to the new
  `foldward` log (separate hash chains; see "Foldward, formerly Agent Guard" in `docs/PLUGINS.md`).

### Notes
- On the installed Windows app, remove the old `plugins\agent-guard` folder after installing Foldward, and allow
  Foldward once when asked: a renamed plugin needs administrator approval again.
- `THIRD_PARTY_NOTICES.txt` is now also published as a release file, covered by the signed checksums.

## [0.5.0] - 2026-10-27

This release closes the findings of the October 2026 readiness audit (IDs in brackets; the full list with the code
and test for each public claim is in `docs/CLAIMS.md`).

### Security
- **Fails safe when the protection service is down (Windows) [SV-A01, SV-F04].** If the service is installed but
  can't be reached, the app no longer falls back to storing protected data in your own folder. It shows a red
  warning, keeps protection settings at least at their defaults, refuses weakening changes, and reconnects by itself
  every 15 seconds. Developer switches (`SENTINEL_VISION_HOME`, `SENTINEL_VISION_NO_SERVICE`) are ignored by installed
  builds, and the Windows folder is read from Windows rather than from the environment.
- **The service's pipe [SV-A05]:** signed-in users can no longer create their own instance of it.
- **Strict requests [SV-F01, SV-A03, SV-F06]:** every request to the service is checked against a schema (unknown
  operations and arguments refused, NaN and infinity refused, exact types and ranges). Settings files with
  out-of-range values fall back to safe defaults.
- **Rollback vault [SV-A02, SV-F02]:** versions are kept by age (everything for 24 hours, hourly for a week, daily for
  30 days) and a flood of new versions can't push good ones out: a full vault refuses new versions instead. The vault
  only accepts files inside your protected folders, and restores never write through links or junctions.
- **Restoring from quarantine needs administrator approval on Windows [SV-A04]**, through a one-time release that
  expires after two minutes. The file is written back as you, not by the service.
- **Limits on the service [SV-F03]:** at most 50 changing requests a second per account (bursts of 100), 4 transfers
  and 4 GB in transit, 32 connections. Clients wait and retry automatically.
- **Updates through the service, without an administrator prompt [SV-A07].** The service downloads the installer into
  its own protected folder, verifies the post-quantum signature, SHA-256 and version, and runs it. Nothing is written
  to your Temp folder.
- **Administrator prompts only for protected programs [SV-A08]:** the app only asks to run itself with administrator
  rights when only administrators can change its program file (and never when run from source).
- **Machine-wide blocking floors [SV-A09]:** never blocks ranges wider than /16 (IPv4) or /32 (IPv6), DNS resolvers,
  or the publishers of the threat feeds. When Windows code signing is set up, the service program is now signed
  with the other programs (builds aren't code-signed yet).
- **Data folder scanned [SV-A06]:** programs or scripts in Sentinel Vision's own data folder are now reported.
- **Archive budget [SV-F05]:** listing compressed tar archives stops at a size and time budget
  (`Archive.LimitReached`).
- **Release-key rotation [SV-L03]:** `sentinel-vision-cli release-key new FOLDER` creates a new signing key on the
  owner's computer; see "Rotating the release key" in `docs/CODE_SIGNING.md`.

### Added
- **Third-party licences [SV-E01]:** every bundled component with its licence text, generated at build time (the
  build fails if one is missing), shipped next to the app and with each release, under Settings → Third-party
  licences, and on the website.
- **Claims register [SV-E02]** (`docs/CLAIMS.md`): each public promise with the code and test behind it, checked in CI.
- Website: the download section shows the installer's SHA-256 and the signing key, taken from the release only after
  its signature verifies [SV-C04]; after each deployment a job checks the live pages match the build [SV-C05];
  "How Sentinel Vision was built" page [SV-D01..D04]; the Norton/McAfee comparison re-checked with dated sources and
  reviewed every quarter [SV-C03, SV-E04]; CINS Army added to the list of everything that leaves your computer
  [SV-C02].
- Repository: CODEOWNERS, a `release` environment that holds the signing key, `docs/REPO_SETTINGS.md` [SV-B03]; the
  accessibility checker installed from a lockfile [SV-B02]; GitHub Pages hosting recorded as an accepted risk in
  SECURITY.md [SV-B01].

### Changed
- Public wording now matches what the code does: tamper protection protects against programs running with your
  rights; the limits of degraded mode, restore approval and the file shredder are listed under Honest limitations
  [SV-C01].

### Fixed
- Upgrading from 0.3.x could drop older rollback versions: the old vault was moved before the account's protected
  folders were registered, so the service refused every version. The account is now registered first, and any
  version the service refuses is kept (`vault-not-moved`) instead of deleted.
- A right-to-left override character in the source is now escaped [SV-F07].

### Notes for companion programs (Agent Guard)
- The `quarantine add` output and exit codes, `plugin-log` format, `net block`, and `scan --json` keys are unchanged.
- `plugin-log append` is rate-limited at 50 a second per account (at least 10 a second always works); the client
  retries by itself.
- `quarantine restore` now asks for administrator approval on Windows.

## [0.4.1] - 2026-10-26

### Security
- **Certificate trust (eMudhra / emSign compromise, October 2026).** Every download now trusts only the bundled,
  up-to-date certificate list (certifi 2026.10.23) and no longer the operating system's store. Python reads the
  trusted certificates from the Windows store but never Windows' list of blocked ones, so authorities Microsoft has
  distrusted were still trusted by the app. Without the bundled list, no download is made.
- `net block` and the firewall's one-click block accept only public internet addresses, and pass rule names to
  netsh in the form it expects.

### Added
- **Ways for companion programs to work with Sentinel Vision** (for example Agent Guard), all optional and described
  in `docs/PLUGINS.md`:
  - **Plugin pages** (entry point `sentinel_vision.plugins`). On the installed Windows app, plugins load only from the
    administrator-only `Program Files\Sentinel Vision\plugins` folder, after a check that no ordinary user can change
    them, and only after you allow each one. With the protection service, allowing a plugin needs administrator
    approval. A broken plugin can't stop the app.
  - `quarantine add PATH --reason TEXT`: moves a file into the (protected) quarantine and prints its id.
  - `plugin-log append|read|verify NAME`: append-only, hash-chained records kept by the protection service, which
    programs running as you can add to but not change or delete.
  - `net block IP` and `plugins` (lists plugins and why any was refused).
  - `sentinel_vision.plugin_api` for plugin authors.

### Fixed
- Alerts from the protection service (a refused change, system-wide blocking turned on) could be missed when two
  happened within one tick of the Windows clock (about 15 ms), for example right after the app started. Events now
  carry sequence numbers.
- The watchdog could fail to restart the app after it was ended, because a process that has exited stays listed by
  Windows while another program holds a handle to it. It now checks that the app is really still running.

## [0.4.0] - 2026-10-22

This release combines the planned 0.3.2 (fewer false alarms, pinned build tools) with 0.4.0 (tamper protection).

### Added
- **Tamper protection (Windows).** A new *Sentinel Vision Protection* service runs as LocalSystem and keeps the
  rollback vault, the quarantine and your protection settings in `%ProgramData%\SentinelVision\Service`, which
  ordinary programs can't read, change or delete. Each Windows account has its own vault and quarantine.
- **Administrator approval to weaken protection.** Turning a protection off, adding exclusions, removing protected
  folders, turning off system-wide blocking and quitting the app now need administrator approval, with a clear list
  of what will change. Turning protections *on* never asks. Refused attempts are shown as alerts.
- **Watchdog.** The service starts the app when you sign in and restarts it if something closes it (with limits so a
  crashing app can't loop). If the app stops responding it's restarted.
- **Firewall blocking.** The service blocks known-malicious networks (Spamhaus DROP, Feodo Tracker, Emerging Threats)
  in Windows Firewall for the whole computer, and keeps system-wide website blocking up to date, every 6 hours, from
  lists it downloads itself. Can be turned off (with approval).
- **Ransomware:** detects *intermittent* encryption (only parts of a file encrypted) and *slow* encryption
  (20 files in 10 minutes).
- **Scheduled memory scan** alongside the scheduled full scan.
- **Checkup:** warns when Chrome, Edge, Brave or Firefox use secure DNS that bypasses website blocking.
- `sentinel-vision-cli service` shows the service status; `--self-test` checks that weakening is refused without
  approval.

### Changed
- **Calmer, more honest scan results.** Results are split into *threats* and *items to review*. Pattern rules meant
  for memory are no longer used on files; automatically generated rules, dual-use tool rules and noisy rules only
  produce items to review; validly signed programs and files in Program Files / system folders are not quarantined
  on pattern matches; app caches, app data and package caches (update packages, extension bundles) are never
  quarantined on a pattern match alone, including findings inside archives. Exact matches
  (known-malware hashes) are still quarantined everywhere. Coin-miner detection now needs a real mining-pool address.
  Oversized archives are a review note, not a threat. The command line exits with 1 only for threats.
- **Installs into Program Files** (needs administrator permission once). Upgrading from 0.3.x moves everything
  automatically: see *Upgrading from 0.3.x* in `docs/INSTALL.md`.
- **abuse.ch feeds:** URLhaus and ThreatFox now require a free abuse.ch Auth-Key (abuse.ch retired the old
  key-free addresses). Enter it in Settings → Threat feeds; it's stored encrypted with Windows DPAPI.
- **Build pinning:** every GitHub Action is pinned to a commit, Python build/signing/website tools are installed from
  hash-locked lists, and Inno Setup is pinned to 6.7.1.
- The false-positive audit now installs everyday Windows apps and scans Windows, macOS and Linux systems in full.

### Fixed
- USB and scheduled-scan notifications could say "threats found" when there were only items to review.

## [0.3.1] - 2026-10-11

### Added
- Project website (`site/`), published with GitHub Pages: features, a complete list of everything the app sends over
  the internet, privacy policy, terms, cookie policy and accessibility statement. No JavaScript, no cookies and no
  third-party requests; every build is checked for broken links, missing alt text, colour contrast and accessibility.
- First release signed with the post-quantum release key (`SHA256SUMS.txt.sig`), so apps can update themselves.

### Fixed
- Ransomware decoys were rebuilt with a new timestamp inside the file, so the uninstaller didn't recognise older
  decoys and left them behind. Decoys are now byte-identical every time, and older ones are recognised too.
- A decoy could overwrite an existing file of yours that happened to have the same name. Such files are now left alone.

### Changed
- The Phishing Army and OpenPhish feeds now say in Settings that they're for personal, non-commercial use, and the
  README credits every data source with its licence.
- The Windows uninstaller's "delete data" question now mentions the rollback vault (encrypted earlier versions of
  your documents).
- Screenshots retaken with demonstration data; the web-blocking count in the docs is now stated without an
  unverified figure.

## [0.3.0] - 2026-10-11

### Added
- **Post-quantum signed updates.** Every release's checksum list is signed with a hybrid **ML-DSA-65 (FIPS 204) +
  Ed25519** signature, and the self-updater refuses any installer that isn't covered by a valid signature from the
  pinned release key, or that would be a downgrade. Rollback vault and quarantine use AES-256-GCM, which stays secure
  against quantum computers. See docs/COMPARISON.md → Post-quantum design.
- **Ransomware shield.** Hidden decoy files and encryption-burst detection (documents that stop being their file
  type, mass renames) catch ransomware in the act; the most likely culprits are frozen (reversible) so you can end
  and quarantine them or resume them.
- **Rollback vault.** Every good version of your documents is kept encrypted and deduplicated; restore single files,
  or roll back everything changed after a point in time. Content that looks encrypted is never recorded as "good".
- **Web Shield.** Four free malware/phishing domain feeds (URLhaus, Phishing.Database, Phishing Army, OpenPhish —
  over 500,000 domains), optional system-wide blocking through the hosts file (all browsers and apps; major platforms
  are never blocked as a whole), and a local **link checker** that spots look-alike brands, mixed-alphabet
  homographs, hidden destinations and other phishing tricks.
- **Security checkup** with a score: firewall, Defender, disk encryption, Windows/macOS/Linux updates, outdated apps
  (winget), UAC, auto-login, Remote Desktop, SMBv1, Secure Boot, Gatekeeper/SIP, SSH hardening, exposed services,
  Wi-Fi encryption.
- **Network attack detection:** router ARP spoofing (man-in-the-middle) and DNS servers on threat lists.
- **Memory scan** of running programs for fileless malware (report-only).
- **USB drives are scanned automatically** when connected; **scheduled scans** (daily quick, weekly full, catching
  up missed runs).
- **Camera & microphone alerts** when an app starts using them (Windows and Linux).
- **Password breach check** with k-anonymity (the password never leaves the device) and a **file shredder**.
- **Opt-in cloud hash reputation** (MalwareBazaar, CIRCL hashlookup): catches malware published minutes ago and clears
  heuristic alerts on catalogued software. Only SHA-256 fingerprints are sent, never files.
- **Quiet mode** for games and presentations (threat alerts still show).
- New pages: Ransomware, Web Shield, Checkup, Privacy & tools. New CLI commands: `checkup`, `memscan`, `rollback`,
  `webshield`, `password-check`, `shred`.
- Weekly **integration tests** against every live threat feed and service on Windows, macOS and Linux.
- docs/COMPARISON.md: source-backed comparison with Norton 360 and McAfee+.

### Changed
- The database tolerates background work that finishes after shutdown.
- Feeds added in new versions now appear for people upgrading with saved settings.

## [0.2.1] - 2026-10-09

### Fixed
- **False positives on Windows system files**, found by the new weekly audit of 20,000 clean files per platform:
  the bundled AMSI-bypass, Defender-tampering, backup-deletion and PowerShell-download rules matched legitimate
  Windows components (for example `amsi.dll`, Windows Security and Defender files, and `vssadmin` help text). The rules
  now match the attack technique itself — typically in scripts — and never the Windows tools that merely contain the
  same API or command names.
- Heuristics no longer flag library names such as `Windows.Data.Pdf.dll` as a "double extension", Windows tools'
  own help text as ransomware, or large PowerShell modules that merely use both web requests and
  `Invoke-Expression` somewhere as download-and-run code.

### Added
- **Catalog-signature verification**: most Windows system files are signed through Microsoft catalogs rather than an
  embedded signature; they are now recognised as validly signed too.
- Pattern (YARA) matches on programs with a valid publisher signature are reported but not quarantined
  automatically, and are ignored on validly signed operating-system components. Exact matches (hash / ClamAV) are
  unaffected.
- Heuristics take catalog signatures into account, so signed Windows components no longer raise heuristic alerts.
- Machine-generated Malpedia rules (`*_Auto`) are ignored on operating-system files, where they occasionally collide
  with ordinary graphics or system libraries; they still apply everywhere else.
- Operating-system files (`C:\Windows`, `/System`, `/usr/bin`, …) are only removed automatically on an exact
  hash or ClamAV match; other findings there are reported for review.

### Changed
- GitHub Actions updated to their Node 24 versions; the false-positive audit reports its results as annotations.

## [0.2.0] - 2026-10-09

### Added
- **Windows installer** (`SentinelVision-<version>-Setup.exe`): per-user install without administrator rights (or
  all-users), Start-menu shortcut, optional desktop icon, optional `sentinel-vision-cli` on PATH, clean upgrades that
  keep your settings, and a full uninstaller (asks before deleting your data). A portable zip is published too.
- **Start at sign-in** on Windows, macOS and Linux. The app starts hidden in the system tray. Turn it on or off in the
  installer, on the *Protection* page, from the tray menu, or with `sentinel-vision-cli autostart on|off`.
  A first-run prompt offers it when you did not use the installer.
- **Behavior monitoring**
  - Every new program is checked against attack-technique rules: Office documents launching shells, hidden or
    download-and-run PowerShell, shadow-copy/backup deletion (ransomware), certutil/mshta/regsvr32/rundll32 abuse,
    reverse shells, crypto-miners and payloads started from temp folders.
  - Every newly started program's executable is scanned. Programs confirmed as malware by a signature engine are
    ended and quarantined, and ransomware attempts to delete backups are stopped (both switchable).
  - Auto-start locations (Run keys, Startup folders, scheduled tasks, LaunchAgents/Daemons, XDG autostart, systemd,
    cron, shell profiles, SSH authorized_keys) are watched; new entries are reported and their targets scanned,
    including changes made while the app was closed.
- **App self-update**: the app checks GitHub Releases. On Windows it downloads the new installer, verifies its
  SHA-256 against the release's `SHA256SUMS.txt`, upgrades in place and restarts. Elsewhere it links to the release.
- **Authenticode verification** (Windows): validly signed programs no longer trip heuristic warnings, and programs
  whose signature was broken by modification are flagged.
- The installed app now includes the **command-line tool** (`sentinel-vision-cli.exe`).
- New CLI commands: `autostart`, `check-update`; `daemon` now includes behavior monitoring.
- macOS: in-app guidance for granting Full Disk Access.
- **False-positive audit** tool (`tools/fp_audit.py`) and a weekly workflow that scans thousands of clean system files on
  Windows, macOS and Linux with every engine.
- Release pipeline that installs, upgrades, relaunches and uninstalls the Windows installer on a clean machine, and
  smoke-tests the macOS and Linux builds, before anything is published.
- Optional Windows code signing in the release workflow (see `docs/CODE_SIGNING.md`).
- App icon, Windows version information, issue/PR templates, Dependabot, roadmap and installation guide.

### Changed
- Archives with many entries or lots of data (jar files, icon packs, datasets) are scanned up to the coverage limits
  instead of being reported as "Archive.Bomb". Only real decompression bombs (more than 1 GB packed at over 100:1)
  are flagged.
- Changing settings no longer recompiles every YARA rule unless an engine setting changed.

### Fixed
- PE files are always closed after analysis (an open file mapping could lock the file on Windows).
- The command-line tool can no longer crash when the console cannot display a character.
- Checking for updates before any release exists no longer reports an error.

## [0.1.0] - 2026-10-09

Source-only release (no downloadable builds).

### Added
- First release: hash, YARA, ClamAV and heuristic engines; real-time protection; encrypted quarantine; live traffic
  monitor with threat intelligence; threat-feed updater; PySide6 GUI; CLI and daemon; CI on Windows, macOS and Linux.

[0.4.1]: https://github.com/dylanckoldan-boop/sentinel-vision/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/dylanckoldan-boop/sentinel-vision/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/dylanckoldan-boop/sentinel-vision/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/dylanckoldan-boop/sentinel-vision/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/dylanckoldan-boop/sentinel-vision/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/dylanckoldan-boop/sentinel-vision/releases/tag/v0.2.0
[0.1.0]: https://github.com/dylanckoldan-boop/sentinel-vision/commit/d633c7e
