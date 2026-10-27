# Sentinel Vision compared with Norton 360 and McAfee+

This comparison uses **only public information**: the vendors' published feature lists, independent reviews and
independent lab results (sources at the end). No competitor software was decompiled or reverse-engineered, and no
competitor code is used; every Sentinel Vision feature is an independent, open-source implementation.

Last reviewed: 2026-10-27 (Sentinel Vision 0.5.0). Competitor cells were re-checked on that date against the
sources listed at the end; each cell names its source in brackets. Reviewed again every quarter (a scheduled workflow
opens a reminder issue), and before any change to this page is published, the project owner approves it.

## Protection features

✅ = available · **—** = not listed in the sources checked on the review date. A dash does **not** mean the product
lacks the feature, only that its public product page and the reviews below don't mention it.

| Feature | Sentinel Vision | Norton 360 Deluxe | McAfee+ Premium |
|---|---|---|---|
| Price | **Free, open source (MIT)** | Paid subscription | Paid subscription |
| Real-time file scanning | ✅ on write, plus programs checked right after they start | ✅ [PCW] | ✅ [MCA] |
| Signature engines | Hash lists, YARA (5,000+ community rules), ClamAV, your own rules | Proprietary | Proprietary |
| Cloud reputation | ✅ opt-in, hashes only (MalwareBazaar, CIRCL) | — | — |
| Behaviour monitoring | ✅ attack-technique rules, new-program scanning, persistence watch | ✅ "monitors apps for unusual activity" [PCW] | — |
| Ransomware: stopping encryption in progress | ✅ decoys + encryption-burst detection; freezes the culprit (reversible) | ✅ Data Protector: blocks untrusted programs from changing important files [NDP] | ✅ ransomware protection listed, method not described [MCA] |
| Ransomware: file rollback | ✅ **encrypted local versioned vault, point-in-time rollback** | Cloud backup, 50 GB, Windows only [N360] | — |
| Ransomware: slow and partial (intermittent) encryption detection | ✅ | — | — |
| Tamper protection | ✅ Windows: protected service; vault, quarantine and settings out of reach of programs running with your rights; turning protection off or restoring from quarantine needs administrator approval; app restarted if closed | ✅ Product Tamper Protection [NTP] | — |
| Memory scan for fileless malware | ✅ YARA on process memory | — | — |
| USB / removable drive scanning | ✅ automatic | ✅ "scanned by default" [PCW] | — |
| Scheduled scans | ✅ daily quick / weekly full, catches up missed runs | ✅ monthly full scan by default, adjustable [PCW] | Quick and full scans [TG] |
| Malicious & phishing website blocking | ✅ system-wide via hosts file (every browser and app), free feeds | ✅ Safe Web browser extension [PCW] | ✅ WebAdvisor [MCA] |
| Link / scam checking | ✅ local link checker with look-alike & homograph detection | ✅ Scam Protection for texts and deepfake videos [N360] | ✅ Scam Detector: messages and deepfake scams [MCA] |
| Firewall | ✅ Windows: blocks Spamhaus DROP, Feodo Tracker and Emerging Threats networks for the whole computer (uses Windows Firewall) | ✅ Smart Firewall [N360] | ✅ Advanced Firewall [MCA] |
| Live per-connection network monitor with threat intel | ✅ every connection → process, botnet/criminal-IP feeds, one-click block | — | — |
| Router spoofing (ARP) / DNS-hijack detection, Wi-Fi checks | ✅ | — | — |
| Security checkup with score | ✅ firewall, encryption, updates, UAC, RDP, SMBv1, Secure Boot, outdated apps… | — | — |
| Camera / microphone use alerts | ✅ Windows & Linux (alerts; doesn't block) | ✅ SafeCam, Windows only (blocks webcam access) [N360] | No [TG] |
| Password breach check | ✅ k-anonymity (password never leaves the device) | Dark Web Monitoring [N360] | Identity monitoring, dark web [MCA] |
| Password manager | No | ✅ [N360] | ✅ [MCA] |
| VPN | No | ✅ [N360] | ✅ [MCA] |
| File shredder | ✅ | — | ✅ [MCA] |
| **Post-quantum signed updates** | ✅ **ML-DSA-65 + Ed25519 hybrid**, downgrade protection | — | — |
| Open, auditable code & detection logic | ✅ | No | No |
| Account required | No | Yes | Yes |
| Platforms | Windows, macOS, Linux | Windows, macOS, Android, iOS [N360] | Windows, macOS, Android, iOS [MCA] |
| Independent lab results (AV-TEST, Windows 11, August 2026) | Not tested | Norton 360 26.6 & 26.7: protection 6, performance 6, usability 6 [AVT-N] | McAfee Total Protection 1.39: 6 / 6 / 6 (McAfee+ is not tested separately) [AVT-M] |

## What Norton and McAfee have that Sentinel Vision doesn't (and why)

| Missing | Why |
|---|---|
| **Blocking a file before it opens** (kernel driver / OS security APIs) | Windows minifilter drivers must be signed by Microsoft; macOS Endpoint Security needs an Apple-granted entitlement. Linux fanotify blocking is on the [roadmap](../ROADMAP.md). |
| **Large proprietary cloud and telemetry network** | Their detection draws on data collected across their customers' devices. Sentinel Vision relies on public, community threat intelligence and never collects user data. |
| **Independent lab certification** | AV-TEST and AV-Comparatives test commercial products by vendor application. In AV-TEST's August 2026 Windows 11 test, Norton 360 and McAfee Total Protection scored the maximum 6 for protection ([Norton](https://www.av-test.org/en/antivirus/home-windows/windows-11/august-2026/norton-norton-360-26.6--26.7-261415/), [McAfee](https://www.av-test.org/en/antivirus/home-windows/windows-11/august-2026/mcafee-total-protection-1.39-261413/)). Sentinel Vision has not been lab-tested, so its detection rate is unknown. |
| **VPN** | Needs paid server infrastructure; it is a privacy service, not malware protection. |
| **Identity theft insurance, data-broker removal, credit monitoring** | Commercial services, not software. |
| **Password manager, parental controls, cloud backup storage** | Separate products; excellent free open-source options exist (e.g. Bitwarden, KeePassXC). |
| **Registration with Windows Security Center** | Reserved for members of Microsoft's Virus Initiative. Keep Microsoft Defender on alongside Sentinel Vision. |

## Honest bottom line

Sentinel Vision covers many of the same **kinds** of protection as the commercial suites and leads on
**transparency, privacy and price**. It also has protections that the sources above don't list for these products:
**post-quantum signed updates, a local encrypted ransomware rollback vault, process-memory scanning, router-spoofing
and DNS-hijack detection, and system-wide (not browser-only) website blocking**. How well it **detects** malware has
not been measured by an independent lab, while both suites score the maximum in AV-TEST. The suites are also ahead on
pre-execution blocking and the scale of their cloud threat intelligence, and include a VPN and a password manager.
The recommended setup is therefore **Sentinel Vision together with Microsoft Defender (or XProtect)**.

## Post-quantum design

| Layer | Algorithm | Quantum-resistant? |
|---|---|---|
| Release & update signatures | **ML-DSA-65 (FIPS 204) + Ed25519 hybrid**; both must verify | ✅ Yes (ML-DSA) |
| Content integrity | SHA-256 / SHA3-512 | ✅ Yes (Grover's algorithm only halves the security level: 128-bit remains) |
| Quarantine & rollback vault encryption | AES-256-GCM | ✅ Yes (256-bit keys keep 128-bit security against quantum attacks) |
| Downloads of community feeds | TLS 1.2+ against the bundled certificate list only | Depends on the server; feed *content* is never trusted to run code |

There is no public-key encryption of user data anywhere in the design, so "harvest now, decrypt later" attacks
have nothing to target. The only public-key operation, update signing, uses a NIST-standardised post-quantum
algorithm in a hybrid that stays secure as long as either algorithm holds.

## Sources

All checked 2026-10-27.

- [N360] [Norton 360 Deluxe product page](https://ca.norton.com/products/norton-360-deluxe)
- [PCW] [PCWorld, Norton 360 Deluxe review (23 April 2026)](https://www.pcworld.com/article/3569151/norton-360-deluxe-antivirus-review.html)
- [NDP] [Norton Community, "Norton Data Protector is now available"](https://community.norton.com/t/norton-data-protector-is-now-available/213137)
- [NTP] [Norton Support, protecting Norton settings (Product Tamper Protection)](https://support.norton.com/sp/en/za/norton-360/current/solutions/v44151491)
- [MCA] [McAfee Total Protection / McAfee+ product page and feature comparison](https://www.mcafee.com/en-ie/antivirus/mcafee-total-protection.html)
- [TG] [Tom's Guide, McAfee+ Premium review (18 August 2026)](https://tomsguide.com/computing/antivirus/mcafee-plus-premium-review-2026)
- [AVT-N] [AV-TEST, Norton 360 26.6 & 26.7, Windows 11, August 2026](https://www.av-test.org/en/antivirus/home-windows/windows-11/august-2026/norton-norton-360-26.6--26.7-261415/)
- [AVT-M] [AV-TEST, McAfee Total Protection 1.39, Windows 11, August 2026](https://www.av-test.org/en/antivirus/home-windows/windows-11/august-2026/mcafee-total-protection-1.39-261413/)
- [NIST FIPS 204, ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
