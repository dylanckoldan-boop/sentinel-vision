# Roadmap

What is done, what is next, and what needs outside help. Each open item has a GitHub issue with the
[`roadmap`](https://github.com/dylanckoldan-boop/sentinel-vision/issues?q=is%3Aissue+label%3Aroadmap) label —
comment there before starting so work isn't duplicated.

## Done

| Area | Since |
|---|---|
| Hash, YARA (bundled + YARA Forge), ClamAV and heuristic engines | 0.1.0 |
| Real-time file protection (on write), encrypted quarantine, archive scanning | 0.1.0 |
| Live traffic monitor with threat intelligence, firewall blocking | 0.1.0 |
| CLI, daemon, CI on Windows/macOS/Linux | 0.1.0 |
| Windows installer (per-user or all-users, upgrades, uninstaller, PATH option) | 0.2.0 |
| Start at sign-in on Windows, macOS and Linux | 0.2.0 |
| Behavior monitoring: process-technique rules, scanning of newly started programs, persistence watcher, ransomware backup-deletion blocking | 0.2.0 |
| App self-update with SHA-256-verified installer (Windows) and update notifications (all platforms) | 0.2.0 |
| Authenticode verification to cut false positives (Windows) | 0.2.0 |
| Command-line tool inside the installed app | 0.2.0 |
| macOS Full Disk Access guidance | 0.2.0 |
| False-positive audit tool + weekly cross-platform audit | 0.2.0 |
| Release pipeline that installs/upgrades/uninstalls the Windows installer before publishing | 0.2.0 |

## Next — can be built by contributors

| Item | Notes |
|---|---|
| **Linux on-access blocking with fanotify** | `FAN_OPEN_EXEC_PERM` permission events let the daemon block execution of a malicious file *before* it runs. Needs root (`CAP_SYS_ADMIN`); ship as an optional system service. |
| **Per-process bandwidth** | Windows: ETW `Microsoft-Windows-Kernel-Network` (admin); Linux: eBPF or `/proc/<pid>/net` + cgroups; macOS: `nettop` parsing. Today the graph is system-wide. |
| **macOS code-signature verification** | Use `codesign --verify` / `SecStaticCodeCheckValidity` like the Windows Authenticode check. |
| **Intel Mac and Windows-on-ARM builds** | Add an Intel macOS runner and a Windows ARM64 runner to the release matrix (PySide6 ships `win_arm64` wheels). |
| **Translations** | Wrap UI strings with Qt's `tr()` and add `.ts` files. |
| **Scheduled scans** | Run a quick scan daily / a full scan weekly from the app. |
| **Linux packages** | `.deb`, `.rpm` and Flatpak packaging. |
| **macOS `.dmg` installer** | Drag-to-Applications disk image instead of a zip. |

## Needs a sponsor or a platform vendor

| Item | Why it can't simply be coded |
|---|---|
| **Code-signed Windows builds** (no SmartScreen warning) | Requires a code-signing certificate. Free route for open source: [SignPath Foundation](https://signpath.org/). The release workflow already signs automatically once a certificate is added — see [docs/CODE_SIGNING.md](docs/CODE_SIGNING.md). |
| **Notarized macOS app** (no Gatekeeper warning) | Requires an Apple Developer account ($99/year) for signing and notarization. |
| **Windows on-access blocking (minifilter driver) / AMSI provider** | Kernel drivers must be signed by Microsoft through an EV certificate and the Windows Hardware Dev Center; AMSI providers need registration as a COM server and are best signed too. |
| **macOS Endpoint Security** | Requires the `com.apple.developer.endpoint-security.client` entitlement, granted by Apple on request. |
| **Registering with Windows Security Center** | Only available to vendors in Microsoft's Virus Initiative (MVI). |
