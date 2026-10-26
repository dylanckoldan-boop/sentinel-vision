# Plugins and companion programs

Sentinel Vision offers a few documented ways for companion programs (for example Agent Guard) to work with it. Sentinel Vision never imports a companion by
name and has no dependency on one; the companion uses the entry point and the command-line tools below. Everything
here is optional: with no plugin installed, Sentinel Vision behaves exactly as before.

| What | How | Protected on Windows |
|---|---|---|
| A page inside the app | Python entry point `sentinel_vision.plugins` | Loaded only from an administrator-only folder, after the user allowed it |
| Hand a file to the quarantine | `sentinel-vision-cli quarantine add PATH --reason TEXT` | Stored by the protection service |
| Keep records nothing else can erase | `sentinel-vision-cli plugin-log append NAME` | Append-only, kept by the protection service |
| Block an address | `sentinel-vision-cli net block IP` | Needs administrator rights |

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
sentinel-vision-cli quarantine add PATH [--reason TEXT] [--source NAME]
```

The file is **moved**: encrypted into the quarantine exactly like an automatic detection (AES-256-GCM, checked chunk
by chunk; on Windows into the protection service's storage) and the original deleted. On success the command prints
only the new item's id and exits with 0. On any problem it exits with 2 and nothing changes. The reason is shown as
the threat name and the source (default `agent-guard`) as the engine, `external:<source>`. The item can be restored
or deleted like any other (`quarantine restore ID`, `quarantine delete ID`).

Refused: anything that isn't an existing regular file (folders, links), operating-system files, and Sentinel Vision's
own program or data.

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

From Python: `sentinel_vision.plugin_api.plugin_log(name)` returns an object with `append(record)`,
`read(since, limit)`, `verify()` and `protected`. `sentinel_vision.config.plugin_dir(name)` is a private working
folder for a plugin, in your own data folder; it is not protected from other programs running as you.

## Block an address

```
sentinel-vision-cli net block IP
```

Adds inbound and outbound block rules to the system firewall (Windows Firewall, iptables or nftables). Only public
internet addresses are accepted: private, local, link-local, multicast and documentation addresses are refused.
It needs administrator (root) rights; without them it prints the commands to run and exits with 2. It exits with 0
when the rules were added.
