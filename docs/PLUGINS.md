# Plugins and companion programs

Sentinel Vision offers a few documented ways for companion programs (for example [Foldward](https://github.com/dylanckoldan-boop/Foldward), formerly
Agent Guard) to work with it. Sentinel Vision never imports a companion by name and has no dependency on one; the companion uses the entry point and the command-line tools below. Everything
here is optional: with no plugin installed, Sentinel Vision behaves exactly as before.

| What | How | Protected on Windows |
|---|---|---|
| A page inside the app | Python entry point `sentinel_vision.plugins` | Loaded only from an administrator-only folder, after the user allowed it |
| Hand a file to the quarantine | `sentinel-vision-cli quarantine add --reason TEXT -- PATH` | Stored by the protection service |
| Keep records nothing else can erase | `sentinel-vision-cli plugin-log append NAME --json RECORD` | Append-only, kept by the protection service |
| Block an address | `sentinel-vision-cli net block -- IP` | Needs administrator rights |
| Check a file | `sentinel-vision-cli scan --no-quarantine --json -- PATH` | Read-only |

Put `--` before any file name or address, so a name that starts with `-` can never be read as an option. (Before
0.5.2, `quarantine add --reason TEXT -- PATH` failed on Python 3.10, 3.11 and early 3.12 source installs; companion
programs should require 0.5.2.)

**The contract (since 0.5.2).** These command shapes, their exit codes and their output are also published as a
machine-readable file, [`docs/plugin-contract.json`](plugin-contract.json). `tests/test_plugin_contract.py` runs the
real tool against it on every change, and Foldward keeps a copy and replays its examples in its own tests, so a change
that would break a companion program fails a test on one side or the other. The file changes only together with
`plugin_api.API_VERSION` and a note here.

| Exit code | Meaning |
|---|---|
| 0 | Success: done, chain intact, or no threats found |
| 1 | An answer that isn't success: threats found (`scan`) or a broken chain (`plugin-log verify`) |
| 2 | Error: nothing changed. The caller may try again or use its own fallback |
| 3 | Refused on purpose (`quarantine add`, since 0.5.2): nothing changed, and the caller must not do it some other way |

## A page inside the app

Declare an entry point in your package:

```toml
[project.entry-points."sentinel_vision.plugins"]
my_plugin = "my_plugin.gui:register"
```

`register()` returns a list of pages. Each has a unique `key`, a sidebar `label` and a `factory(ctx)` that returns a
QWidget. `sentinel_vision.plugin_api.PluginPage` is a ready-made descriptor:

```python
from sentinel_vision.plugin_api import PluginPage


def register():
    return [PluginPage("my_plugin", "My plugin", lambda ctx: MyWidget(ctx))]
```

Use only `ctx.notify(title, text, level)` and `ctx.navigate(key)` from the context. If your widget has a `refresh()`
method, it is called when the page is shown and every few seconds while it is visible. A plugin that fails to load,
raises in `register()`, `factory()` or `refresh()`, or uses a key a built-in page already has, is logged and skipped;
it can't stop Sentinel Vision.

### Where plugins are loaded from

* **Installed app on Windows:** only `C:\Program Files\Sentinel Vision\plugins\<name>\`, which only an administrator
  can change. Install a plugin there from an administrator terminal, using a Python of the same version as the app
  (3.12):

  ```
  py -3.12 -m pip install --target "C:\Program Files\Sentinel Vision\plugins\my-plugin" my-plugin
  ```

  For Foldward, name a release tag, never the moving `main` branch, so what you install is what was reviewed and
  released (Foldward 0.2.0 and newer work with the 0.5.2 contract and refusals; 0.2.1 also fixes a canary flaw):

  ```
  py -3.12 -m pip install --target "C:\Program Files\Sentinel Vision\plugins\foldward" "foldward @ git+https://github.com/dylanckoldan-boop/Foldward@v0.2.1"
  ```

  To upgrade it later, run the same command with `--upgrade` and the newer tag, then allow Foldward again when asked.

  Before loading, Sentinel Vision checks every folder and file of the plugin. If anyone other than SYSTEM,
  Administrators or TrustedInstaller could change them, the plugin is refused, because otherwise a program running
  with your rights could put code inside the antivirus. The installed app contains only the parts of Python it uses
  itself, so a plugin's other dependencies must be installed into its folder too. Upgrading Sentinel Vision keeps
  plugins; uninstalling removes them.
* **Run from Python (pip or source installs, any platform):** packages installed in the same Python environment.
* **Installed macOS and Linux bundles, and the portable Windows build:** no plugins, because they have no folder
  that only an administrator can change.

`sentinel-vision-cli plugins` lists what was found and why anything was refused.

### Approval

A new plugin is never shown until you allow it. Sentinel Vision names the plugin and its folder and asks once. The
approval is tied to a fingerprint of the plugin's files, so a changed plugin is asked about again. On Windows with the
protection service, allowing a plugin counts as reducing protection (like adding an exclusion), so it needs
administrator approval and no other program can allow one silently.

A plugin runs inside Sentinel Vision with the same rights. Only allow plugins you installed yourself.

## Hand a file to the quarantine

```
sentinel-vision-cli quarantine add [--reason TEXT] [--source NAME] -- PATH
```

The file is **moved**: encrypted into the quarantine exactly like an automatic detection (AES-256-GCM, checked chunk
by chunk; on Windows into the protection service's storage) and the original deleted. On success the command prints
only the new item's id (32 hexadecimal characters) and exits with 0. The reason is shown as the threat name and the
source (default `foldward`; `agent-guard` before 0.5.1) as the engine, `external:<source>`. The item can be restored
or deleted like any other (`quarantine restore ID`, `quarantine delete ID`). On Windows with the protection service,
restoring needs administrator approval (since 0.5.0): `quarantine restore` shows the administrator prompt itself.

Refused on purpose, with exit code 3 (since 0.5.2; exit 2 before): links and anything else that isn't a regular file
(folders, pipes, devices), operating-system files, and Sentinel Vision's own program or data. A refused file must not
be moved some other way. Any other problem (the file doesn't exist, the protection service can't be reached) exits
with 2. In both cases nothing changes, and the reason is printed to standard error after `error:`.

From Python: `Sentinel().quarantine.add_external(path, reason, source)` returns the id.

## Records nothing else can erase

```
sentinel-vision-cli plugin-log append NAME [--json '{"event": "revoked", "agent": "x"}']   # or JSON on stdin
sentinel-vision-cli plugin-log read NAME [--since SEQ] [--limit N]                        # JSON lines
sentinel-vision-cli plugin-log verify NAME                                                # {"intact": true, ...}
```

On Windows the protection service keeps each account's log for a plugin in its protected folder
(`%ProgramData%\SentinelVision\Service\users\<account>\plugins\<name>\log.jsonl`). A program running as you can add
records and read them back, but it **can't change or delete them**: there is no request for that, and the folder is
open only to the service and administrators. Each entry records its sequence number, time, the process id that added
it and the SHA-256 of the previous entry, so `verify` shows whether the chain is complete. Records are JSON objects up
to 64 KB, with up to 50 MB per log; when a log is full, appends are refused rather than anything being dropped. If
the service is installed but not reachable, the command fails instead of writing an unprotected log.

On macOS, Linux and the portable build, the same format is kept in your own data folder. It is tamper-*evident*
(`verify` shows edits) but not tamper-proof.

### Limits (Windows protection service, since 0.5.0)

Requests that change something (appends, quarantine additions, vault versions) are limited to 50 per second per
account, with bursts of up to 100, so a companion program can append at least 10 records a second indefinitely. Over
the limit the service answers `too_many` with how long to wait; the client library waits (up to 2 seconds) and
retries by itself. At most 32 programs can be connected at once, and at most 4 file transfers (4 GB in total) can be
in progress per account; a transfer idle for 15 minutes is dropped. Unknown requests or arguments are refused.

From Python: `sentinel_vision.plugin_api.plugin_log(name)` returns an object with `append(record)`,
`read(since, limit)`, `verify()` and `protected`. `sentinel_vision.config.plugin_dir(name)` is a private working
folder for a plugin, in your own data folder; it is not protected from other programs running as you.

## Block an address

```
sentinel-vision-cli net block -- IP
```

Adds inbound and outbound block rules to the system firewall (Windows Firewall, iptables or nftables). Only public
internet addresses are accepted: private, local, link-local, multicast and documentation addresses are refused with
exit code 2. It needs administrator (root) rights; without them it prints the commands to run and exits with 2. It
exits with 0 when the rules were added.

## Check a file

```
sentinel-vision-cli scan --no-quarantine --json -- PATH
```

Scans without moving anything and prints a JSON summary (`scanned`, `infected`, `threats`, `review`, `errors`,
`duration`, `results`). It exits with 0 when no threats were found and 1 when at least one was; it exits with 2 only
when the command itself fails. A file that couldn't be read is counted in `errors`, not as a threat, so a caller
should check `errors` too, and check that `threats` agrees with the exit code.

## Foldward, formerly Agent Guard (0.5.1)

Agent Guard was renamed Foldward. What changed and what didn't:

| | Before | Now |
|---|---|---|
| Entry point in `sentinel_vision.plugins` | `agent_guard` | `foldward` (value `foldward.gui.plugin:register`) |
| Plugin folder (installed Windows app) | `plugins\agent-guard\` | `plugins\foldward\` |
| `quarantine add` default `--source` | `agent-guard` | `foldward` |
| Plugin log name used by Foldward | `agent-guard` | `foldward` |

Unchanged, and kept that way: the `sentinel_vision.plugins` group and `plugin_api.API_VERSION` (1); the command
shapes `quarantine add --reason TEXT -- PATH`, `plugin-log append NAME --json …`, `plugin-log verify NAME`,
`net block -- IP` and `scan --no-quarantine --json -- PATH`; their exit codes (0 success or intact, 1 broken chain or
threats found, 2 error, and since 0.5.2 3 for a file `quarantine add` refused on purpose); and the 32-character
hexadecimal quarantine id. Foldward's page keys stay `ag_*`.

**Existing records stay where they are.** The `agent-guard` log is never removed or renamed: `plugin-log read
agent-guard` and `plugin-log verify agent-guard` keep working, and Foldward reads it alongside its new `foldward`
log. The two are separate hash chains. Nothing is copied from one to the other, because copied entries would carry
new times and process ids and could no longer prove when and by whom the originals were written. Quarantined items
added before the rename keep `external:agent-guard` as their engine.

**After upgrading, on the installed Windows app:**

1. Install Foldward into `plugins\foldward` with the command above, from an administrator terminal.
2. Remove the old folder: `Remove-Item -Recurse "C:\Program Files\Sentinel Vision\plugins\agent-guard"`.
3. Open Sentinel Vision and allow Foldward when asked. A renamed plugin is a new plugin, so it needs your
   (administrator) approval once; the old approval no longer matches anything.

**The old Agent Guard plugin is refused (since 0.5.2).** A plugin named `agent-guard` (in a folder or in the Python
environment) is listed by `sentinel-vision-cli plugins` with the reason and never loaded: it carries code with
security problems that Foldward 0.2.0 fixes, it would keep its old approval, and it registers the same pages as
Foldward. When you upgrade the installed Windows app to 0.5.2 or later and `plugins\foldward` exists, the installer
also deletes `plugins\agent-guard`. If Foldward isn't installed yet, the old folder stays where it is, refused, until
you install Foldward and remove it as above.
