# Security Policy

Sentinel Vision parses untrusted, potentially hostile files by design, so we treat security bugs in the scanner itself as the highest priority.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository
(direct link: <https://github.com/dylanckoldan-boop/sentinel-vision/security/advisories/new>). Include:

* affected version / commit
* operating system
* a description of the impact
* a minimal reproduction (for malicious-file bugs, describe or generate the sample rather than attaching live malware; the EICAR test string or a synthetic file is ideal)

You will get an acknowledgement within 72 hours. We aim to release a fix for confirmed high-severity issues within 14 days and will credit you in the release notes unless you prefer otherwise.

## In scope

* Code execution, crashes or hangs caused by a scanned file, archive or update feed
* Escaping the quarantine (decrypting/executing quarantined content without the user restoring it)
* Path traversal or arbitrary file write through updates, restores or archives
* Command injection through firewall, ClamAV or freshclam integration
* Tricking the self-updater into running a file other than the official installer (signature or checksum bypass,
  downgrade), or weaknesses in the post-quantum signature scheme or its implementation
* Tamper-protection bypasses on Windows: a program running with a user's normal rights reading, changing or deleting
  the protected vault, quarantine or settings, weakening protection without administrator approval, impersonating
  the protection service, reaching another account's data, or getting the service (LocalSystem) to act on its behalf
* Plugins: getting code loaded into Sentinel Vision without the user's (and, with the service, an administrator's)
  approval, loading a plugin from a folder ordinary users can change, or changing or deleting protected plugin-log
  records without administrator rights
* Ransomware-shield bypasses due to bugs (decoys not tripping, vault content altered without detection)
* Making the Web Shield block legitimate core services, or injecting entries into the hosts file
* Behavior monitoring terminating processes it should not (e.g. crafted command lines that kill system processes)
* Detection bypasses that come from a bug in our code (not simply "this sample isn't in any signature set")

## Out of scope

* Malware that no enabled rule set or feed knows about yet — please report the sample to [MalwareBazaar](https://bazaar.abuse.ch/) or submit a YARA rule via a pull request
* Attacks that require an attacker who already has administrator/root access to the machine (an administrator can
  always stop or remove any program that doesn't have a kernel driver)
* False positives (please open a normal issue)

## Hardening notes for users

* Keep definitions updated (automatic every 6 hours by default).
* Run `clamd` for ClamAV coverage.
* Keep your operating system's built-in protection (Microsoft Defender, XProtect) enabled — Sentinel Vision is designed to complement it.

## Accepted risks

### The website is hosted on GitHub Pages (audit finding SV-B01)

**Risk.** The website at `dylanckoldan-boop.github.io/sentinel-vision` is served by GitHub. Someone who took over the
owner's GitHub account, or GitHub itself, could change the download instructions or the fingerprint shown.

**Why it's accepted.** The site is static HTML with no scripts, cookies, forms or third-party requests, so there is
nothing on it to steal and no server of ours to break into. The downloads themselves are not on the site: they're
GitHub release files whose `SHA256SUMS.txt` is signed with the project's post-quantum key, and the app refuses any
update that doesn't verify against the keys built into it, whatever the website says. A separate host would add a
second account to protect without removing the dependency on GitHub, where the code and releases live.

**What limits it.** The site build only shows a fingerprint after verifying the release's signature
(`site/release_check.py`); after each deployment a job checks that every live page matches what was built
(`.github/workflows/pages.yml`); changes to `/site/` and `/.github/` need the owner's review (`.github/CODEOWNERS`);
the owner account uses two-factor authentication ([docs/REPO_SETTINGS.md](docs/REPO_SETTINGS.md)).

**Review.** Accepted 2026-10-27 by the project owner. Reviewed again by 2027-04-27, or sooner if the site gains
scripts, forms or downloads of its own.
