# Installing Sentinel Vision

- [Windows — installer (recommended)](#windows--installer-recommended)
- [Windows — portable zip](#windows--portable-zip)
- [macOS](#macos)
- [Linux](#linux)
- [Any OS — from source with Python](#any-os--from-source-with-python)
- [After installing: three steps for full protection](#after-installing-three-steps-for-full-protection)
- [Updating](#updating)
- [Uninstalling](#uninstalling)
- [Troubleshooting](#troubleshooting)

All downloads are on the [Releases page](https://github.com/dylanckoldan-boop/sentinel-vision/releases/latest).

---

## Windows — installer (recommended)

Requires Windows 10 or 11 (64-bit). No administrator rights needed.

1. Download **`SentinelVision-<version>-Setup.exe`** from the [latest release](https://github.com/dylanckoldan-boop/sentinel-vision/releases/latest).
2. Double-click it.
3. If Windows shows **"Windows protected your PC"**, click **More info → Run anyway**.
   This appears because the app is not code-signed yet (a certificate costs money); it is not a sign of malware.
   You can verify the file first — see [Verifying a download](#verifying-a-download).
4. Choose **Install for me only** (recommended, no admin rights) or **Install for all users**.
5. Accept the MIT license and keep the defaults. Make sure **"Start Sentinel Vision automatically when I sign in"** stays
   ticked — protection only runs while the app runs.
   Optional: *Create a desktop shortcut* and *Add the sentinel-vision-cli command-line tool to PATH*.
6. Click **Install**, then **Finish** with *Launch Sentinel Vision now* ticked.
7. Continue with [the three steps for full protection](#after-installing-three-steps-for-full-protection).

From now on Sentinel Vision starts by itself at sign-in and lives in the system tray (bottom-right, near the clock —
click the **^** arrow if it is hidden). Click the shield icon to open it; right-click for the menu.

**Silent / scripted install** (for IT admins):

```
SentinelVision-<version>-Setup.exe /VERYSILENT /CURRENTUSER /TASKS="autostart,addtopath"
```

`/ALLUSERS` installs for everyone (needs admin). Leave `autostart` out of `/TASKS` to not start at sign-in.

## Windows — portable zip

1. Download **`SentinelVision-<version>-windows-portable.zip`** and extract it anywhere (e.g. a USB stick).
2. Run **`SentinelVision.exe`** inside the extracted `SentinelVision` folder.
3. On first start it asks whether to start automatically at sign-in.

The portable build does not update itself; download new versions from the Releases page.

## macOS

Requires macOS 14 (Sonoma) or newer on an Apple Silicon Mac (M1 or later). Intel Macs: use the [from-source](#any-os--from-source-with-python) install.

1. Download **`SentinelVision-<version>-macos.zip`** and double-click it to unzip.
2. Drag **SentinelVision.app** into **Applications**.
3. **Right-click** the app → **Open** → **Open** (needed once because the app is not notarized by Apple yet).
   On macOS 15+, if there is no *Open* button: open **System Settings → Privacy & Security**, scroll down and click
   **Open Anyway** next to the Sentinel Vision message.
4. Grant **Full Disk Access** so it can scan Downloads, Desktop, Documents and Mail:
   **System Settings → Privacy & Security → Full Disk Access → +** → choose *SentinelVision* in Applications → turn it on,
   then quit and reopen the app. (The *Protection* page has a button that opens this settings pane.)
5. Accept the first-run prompt to start automatically at sign-in.

To see the connections of *every* process in Live traffic, macOS requires administrator rights; without them the
monitor shows your own processes.

## Linux

Requires a 64-bit x86 distribution with glibc 2.35+ (Ubuntu 22.04+, Debian 12+, Fedora 36+ or similar) and a desktop.

```bash
tar -xzf SentinelVision-<version>-linux-x86_64.tar.gz -C ~/.local/opt   # any folder works
~/.local/opt/SentinelVision/SentinelVision
```

Accept the first-run prompt to start automatically at sign-in (it adds `~/.config/autostart/sentinel-vision.desktop`).
The command-line tool is `~/.local/opt/SentinelVision/sentinel-vision-cli`.

## Any OS — from source with Python

Requires Python 3.10 or newer ([python.org](https://www.python.org/downloads/) — on Windows tick **"Add python.exe to
PATH"** in the installer).

1. Get the code: on GitHub click **Code → Download ZIP** and extract it, or `git clone https://github.com/dylanckoldan-boop/sentinel-vision`.
2. Open a terminal in that folder (Windows: click the File Explorer address bar, type `cmd`, press Enter).
3. Create a private Python environment and install:

   | Windows | macOS / Linux |
   |---|---|
   | `py -m venv .venv` | `python3 -m venv .venv` |
   | `.venv\Scripts\pip install .` | `.venv/bin/pip install .` |
   | `.venv\Scripts\sentinel-vision` | `.venv/bin/sentinel-vision` |

4. Accept the first-run prompt to start at sign-in. It remembers this exact environment, so keep the folder where it is.

## After installing: three steps for full protection

1. **Download the threat definitions**: open **Settings & updates → Update now**. (This also runs automatically every
   6 hours.) Without it only the built-in rules are active.
2. **Add ClamAV** (strongly recommended — millions of extra signatures). Sentinel Vision uses it automatically:
   - Windows: install from [clamav.net/downloads](https://www.clamav.net/downloads), then run `freshclam` once.
   - macOS: `brew install clamav`, copy `freshclam.conf.sample` to `freshclam.conf`, delete the `Example` line, run `freshclam`.
   - Ubuntu/Debian: `sudo apt install clamav clamav-daemon && sudo systemctl enable --now clamav-daemon`
   - Fedora: `sudo dnf install clamav clamd clamav-update && sudo freshclam`
3. **Optional — MalwareBazaar hashes**: get a free Auth-Key at [auth.abuse.ch](https://auth.abuse.ch/), paste it into
   **Settings → abuse.ch Auth-Key**, click **Save settings**, then **Update now**.

Keep Microsoft Defender / XProtect turned on as well: Sentinel Vision is designed to complement them.

## Updating

- **Windows installer**: the app checks for new versions every 6 hours and shows a banner — click **Update now**.
  The installer is downloaded, its SHA-256 checked, and the app upgraded and restarted. Settings, history and quarantine
  are kept. You can also run a newer Setup.exe over the existing install at any time.
- **Portable, macOS, Linux**: the banner links to the new release; download and replace the old copy.
- **From source**: `git pull` (or download the new ZIP) and run the `pip install .` step again.

## Uninstalling

- **Windows installer**: *Settings → Apps → Installed apps → Sentinel Vision → Uninstall* (or *Add or remove programs*).
  The uninstaller closes the app, removes start-at-sign-in and the PATH entry, and asks whether to delete your data.
- **Everything else**: turn off *Start at sign-in* on the Protection page (or `sentinel-vision-cli autostart off`),
  quit from the tray icon, then delete the app folder.
- Your data lives in `%LOCALAPPDATA%\SentinelVision` (Windows), `~/Library/Application Support/SentinelVision` (macOS)
  or `~/.local/share/SentinelVision` (Linux).

## Verifying a download

Every release has a `SHA256SUMS.txt`. Compare it with the file you downloaded:

- Windows (PowerShell): `Get-FileHash .\SentinelVision-<version>-Setup.exe -Algorithm SHA256`
- macOS: `shasum -a 256 SentinelVision-<version>-macos.zip`
- Linux: `sha256sum -c SHA256SUMS.txt --ignore-missing`

## Troubleshooting

| Problem | Fix |
|---|---|
| "Windows protected your PC" | **More info → Run anyway** (unsigned app — see above). |
| Can't find the window | It is in the system tray. Windows: click **^** near the clock. Launching it again also brings it to the front. |
| Protection page says *Off* after restart | Turn on **Start at sign-in** on the Protection page or the tray menu. |
| ClamAV shows "not installed" | Install ClamAV (above). On Linux start the daemon: `sudo systemctl start clamav-daemon`. |
| macOS: folders can't be scanned | Grant Full Disk Access (step 4 under macOS) and reopen the app. |
| Live traffic shows "Limited view" | Normal on macOS without admin rights; your own processes are still shown. |
| A file you trust was quarantined | Quarantine page → select it → **Restore**. It is added to the exclusions automatically. Please [report the false positive](https://github.com/dylanckoldan-boop/sentinel-vision/issues/new?template=false_positive.yml). |
| Anything else | Logs are in the data folder under `logs/`. [Open an issue](https://github.com/dylanckoldan-boop/sentinel-vision/issues/new/choose) and attach the last lines. |
