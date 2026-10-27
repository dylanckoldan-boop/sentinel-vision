# Code signing

Sentinel Vision uses two independent kinds of signature:

1. **Post-quantum release signature (already built in, free).** The release workflow signs `SHA256SUMS.txt` with a
   hybrid **ML-DSA-65 + Ed25519** key; the app's self-updater verifies it against the public key pinned in
   `src/sentinel_vision/trust.py` before running any installer. This protects updates end-to-end, including against
   future quantum computers. It needs one repository secret — see below.
2. **Operating-system code signing (optional, costs money).** Removes the SmartScreen / Gatekeeper warning on first
   launch. Described in the rest of this page.

## Post-quantum release signing key (required for automatic updates)

The public half of the release key is pinned in `trust.py` (key id `0a5b8ebb9da90203`). The private half must be
stored as a GitHub Actions secret so the release workflow can sign:

1. Open the file `sentinel-vision-signing-key.txt` you were given (one line of base64). Keep it private; store a copy
   in a password manager.
2. On GitHub: **Settings → Environments → release → Add environment secret** (see [REPO_SETTINGS.md](REPO_SETTINGS.md))
   - Name: `SV_SIGNING_KEY`
   - Secret: paste the line from the file
3. Delete the file from your computer once it's stored safely.

Releases published while the secret is missing are still built and checksummed, but the app will not install them
automatically (it shows a link to the release page instead), and the workflow prints a warning.

### Rotating the release key

Do this when the private key may have been seen by anyone else, including when it was created somewhere other than
your own computer (audit finding SV-L03). Apps only trust keys pinned in `trust.py`, so the new key has to reach
users inside a release signed with the old one. Never switch the secret before step 4: a release signed with a key
the installed apps don't know yet can't be installed automatically.

1. **Create the new key on your own computer** (with Sentinel Vision 0.5.0 or later installed), in PowerShell:
   `sentinel-vision-cli release-key new "$env:USERPROFILE\sv-new-key"`. This writes the private key
   (`sentinel-vision-signing-key.txt`, secret) and the public key (`sentinel-vision-signing-key.pub.txt`, safe to
   share). From a source checkout, `python tools/pq_keygen.py FOLDER` does the same.
2. **Pin both keys.** Add the new public key to `RELEASE_KEYS_B64` in `trust.py`, after the current one, in a pull
   request. `sentinel-vision-cli release-key list` on a build from that branch shows both key IDs.
3. **Release once with the old key.** Publish that release as usual; the workflow still signs with the old key in
   `SV_SIGNING_KEY`. Installed apps update to it and from then on trust both keys.
4. **Switch the secret.** Settings → Environments → `release` → `SV_SIGNING_KEY` → paste the contents of the new
   `sentinel-vision-signing-key.txt`. Store a copy in your password manager, then delete the file with
   `sentinel-vision-cli shred "$env:USERPROFILE\sv-new-key\sentinel-vision-signing-key.txt"`.
5. **Release with the new key**, and confirm `sentinel-vision-cli verify-release` shows the new key ID.
6. **Remove the old key** from `trust.py` in a later release, once most installs have updated past step 3 (at
   least one month). Anyone still on an older build sees a "not signed by a trusted key" message and can update
   from the releases page by hand.

## Operating-system code signing (optional)

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

Every release publishes `SHA256SUMS.txt` (and its post-quantum signature `SHA256SUMS.txt.sig`); the app's built-in
updater refuses any installer whose signature or SHA-256 doesn't match. See [INSTALL.md → Verifying a download](INSTALL.md#verifying-a-download).
