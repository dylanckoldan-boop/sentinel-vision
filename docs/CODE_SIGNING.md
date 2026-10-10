# Code signing

Unsigned Windows programs trigger SmartScreen's *"Windows protected your PC"* warning, and unsigned/un-notarized macOS
apps trigger Gatekeeper. Signing removes the warnings and lets users verify that a download really came from this
project. Sentinel Vision's release workflow is ready for signing — it only needs a certificate.

## Windows

### Option 1 — SignPath Foundation (free for open-source projects)

[SignPath Foundation](https://signpath.org/) signs releases of qualifying open-source projects for free, using a
certificate issued to the foundation. Apply on their site; they integrate with GitHub Actions. Once approved, replace
the two "Sign … (optional)" steps in `.github/workflows/release.yml` with their `signpath/github-action-submit-signing-request` step.

### Option 2 — your own certificate

1. Buy an OV or EV code-signing certificate from a CA (Certum, Sectigo, DigiCert, SSL.com…). Prices range from roughly
   $100 to $400 per year; Certum offers a lower-cost certificate for open-source developers.
   Note: since 2023 new certificates are issued on hardware tokens or cloud HSMs. Cloud-based offerings (e.g. SSL.com
   eSigner, Azure Trusted Signing) work in CI; hardware tokens do not. With a cloud HSM, follow the vendor's GitHub
   Actions instructions in place of the `signtool /f` step.
2. If you have an exportable `.pfx`:
   - Encode it: PowerShell `[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx")) | Set-Clipboard`
   - In GitHub: **Settings → Secrets and variables → Actions → New repository secret**
     - `WINDOWS_CERT_PFX_BASE64` = the base64 text
     - `WINDOWS_CERT_PASSWORD` = the PFX password
3. The next tagged release signs `SentinelVision.exe`, `sentinel-vision-cli.exe` and the Setup.exe automatically
   (SHA-256 digests, RFC 3161 timestamp from DigiCert).

SmartScreen reputation is built per certificate: EV certificates are trusted immediately, OV certificates after enough
users have downloaded signed builds.

## macOS

Requires an Apple Developer Program membership ($99/year):

1. Create a *Developer ID Application* certificate and an app-specific password for notarization.
2. Sign the bundle with the hardened runtime:
   `codesign --deep --force --options runtime --timestamp -s "Developer ID Application: NAME (TEAMID)" dist/SentinelVision.app`
3. Notarize and staple:
   `ditto -c -k --keepParent dist/SentinelVision.app app.zip && xcrun notarytool submit app.zip --apple-id … --team-id … --password … --wait && xcrun stapler staple dist/SentinelVision.app`

Add these as a step in the `unix` job of `release.yml` (guarded by secrets, like the Windows step).

## Verifying without signatures

Every release publishes `SHA256SUMS.txt`, and the app's built-in updater refuses any installer whose SHA-256 doesn't
match it. See [INSTALL.md → Verifying a download](INSTALL.md#verifying-a-download).
