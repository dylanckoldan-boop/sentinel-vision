# Sentinel Vision compared with Norton 360 and McAfee+

This comparison uses **only public information**: the vendors' published feature lists, independent reviews and
independent lab results (sources at the end). No competitor software was decompiled or reverse-engineered, and no
competitor code is used; every Sentinel Vision feature is an independent, open-source implementation.

Last reviewed: October 2026 (Sentinel Vision 0.3.1).

## Protection features

✅ = available · **n/d** = not described in the public sources reviewed (it may exist; we only list what is sourced)

| Feature | Sentinel Vision | Norton 360 Deluxe | McAfee+ Premium |
|---|---|---|---|
| Price | **Free, open source (MIT)** | Paid subscription | Paid subscription |
| Real-time file scanning | ✅ on write, plus programs checked right after they start | ✅ new/changed files | ✅ |
| Signature engines | Hash lists, YARA (5,000+ community rules), ClamAV, your own rules | Proprietary | Proprietary |
| Cloud reputation | ✅ opt-in, hashes only (MalwareBazaar, CIRCL) | n/d | n/d |
| Behaviour monitoring | ✅ attack-technique rules, new-program scanning, persistence watch | ✅ monitors apps for unusual activity | n/d |
| Ransomware: decoys + encryption-burst detection | ✅ freezes the culprit (reversible) | ✅ controlled folder access | ✅ |
| Ransomware: file rollback | ✅ **encrypted local versioned vault, point-in-time rollback** | Cloud backup (50 GB) | n/d |
| Ransomware: slow and partial (intermittent) encryption detection | ✅ | n/d | n/d |
| Tamper protection | ✅ Windows: protected service; vault, quarantine and settings out of reach of other programs; turning protection off needs administrator approval; app restarted if closed | ✅ Product Tamper Protection | n/d |
| Memory scan for fileless malware | ✅ YARA on process memory | n/d | n/d |
| USB / removable drive scanning | ✅ automatic | ✅ | n/d |
| Scheduled scans | ✅ daily quick / weekly full, catches up missed runs | ✅ | n/d |
| Malicious & phishing website blocking | ✅ system-wide via hosts file (every browser and app), 4 free feeds | ✅ Safe Web browser extension | n/d |
| Link / scam checking | ✅ local link checker with look-alike & homograph detection | ✅ Safe Search Plus link verification | ✅ email, text and video scam detection |
| Firewall blocking of known-malicious networks | ✅ Windows: Spamhaus DROP, Feodo Tracker, Emerging Threats lists, whole computer | ✅ Smart Firewall | ✅ Firewall |
| Live per-connection network monitor with threat intel | ✅ every connection → process, botnet/criminal-IP feeds, one-click block | Firewall | n/d |
| Router spoofing (ARP) / DNS-hijack detection, Wi-Fi checks | ✅ | Auto-VPN on unsecured Wi-Fi | n/d |
| Security checkup with score | ✅ firewall, encryption, updates, UAC, RDP, SMBv1, Secure Boot, outdated apps… | Outdated-software monitoring | n/d |
| Camera / microphone use alerts | ✅ Windows & Linux | ✅ SafeCam webcam protection | n/d |
| Password breach check | ✅ k-anonymity (password never leaves the device) | Dark-web monitoring | Data breach alerts |
| File shredder | ✅ | n/d | ✅ |
| **Post-quantum signed updates** | ✅ **ML-DSA-65 + Ed25519 hybrid**, downgrade protection | n/d | n/d |
| Open, auditable code & detection logic | ✅ | No | No |
| Account required | No | Yes | Yes |
| Platforms | Windows, macOS, Linux | Windows, macOS, mobile | Windows, macOS, mobile |

## What Norton and McAfee have that Sentinel Vision doesn't (and why)

| Missing | Why |
|---|---|
| **Blocking a file before it opens** (kernel driver / OS security APIs) | Windows minifilter drivers must be signed by Microsoft; macOS Endpoint Security needs an Apple-granted entitlement. Linux fanotify blocking is on the [roadmap](../ROADMAP.md). |
| **Large proprietary cloud and telemetry network** | Their detection draws on data collected across their customers' devices. Sentinel Vision relies on public, community threat intelligence and never collects user data. |
| **Independent lab certification** | AV-TEST and AV-Comparatives test commercial products by vendor application. Their August 2026 AV-TEST results gave Norton and McAfee 6/6 for protection. Sentinel Vision has not been lab-tested. |
| **VPN** | Needs paid server infrastructure; it is a privacy service, not malware protection. |
| **Identity theft insurance, data-broker removal, credit monitoring** | Commercial services, not software. |
| **Password manager, parental controls, cloud backup storage** | Separate products; excellent free open-source options exist (e.g. Bitwarden, KeePassXC). |
| **Registration with Windows Security Center** | Reserved for members of Microsoft's Virus Initiative. Keep Microsoft Defender on alongside Sentinel Vision. |

## Honest bottom line

Sentinel Vision matches the commercial suites on **breadth of protection features** and leads on **transparency,
privacy and price**. It also offers protections that the public descriptions of these products don't mention:
**post-quantum signed updates, a local encrypted ransomware rollback vault, process-memory scanning, router-spoofing
and DNS-hijack detection, and system-wide (not browser-only) website blocking**. The commercial suites remain ahead
on **pre-execution blocking and the scale of their cloud threat intelligence**, and they are independently
lab-certified. The recommended setup is therefore **Sentinel Vision together with Microsoft Defender (or XProtect)**.

## Post-quantum design

| Layer | Algorithm | Quantum-resistant? |
|---|---|---|
| Release & update signatures | **ML-DSA-65 (FIPS 204) + Ed25519 hybrid**; both must verify | ✅ Yes (ML-DSA) |
| Content integrity | SHA-256 / SHA3-512 | ✅ Yes (Grover's algorithm only halves the security level: 128-bit remains) |
| Quarantine & rollback vault encryption | AES-256-GCM | ✅ Yes (256-bit keys keep 128-bit security against quantum attacks) |
| Downloads of community feeds | TLS 1.2+ (whatever the operating system's TLS offers) | Depends on the server; feed *content* is never trusted to run code |

There is no public-key encryption of user data anywhere in the design, so "harvest now, decrypt later" attacks
have nothing to target. The only public-key operation, update signing, uses a NIST-standardised post-quantum
algorithm in a hybrid that stays secure as long as either algorithm holds.

## Sources

- [PCWorld — Norton 360 Deluxe review (2026)](https://www.pcworld.com/article/3569151/norton-360-deluxe-antivirus-review.html)
- [Tom's Guide — McAfee+ Premium review](https://www.tomsguide.com/computing/online-security/mcafee-premium-antivirus-review)
- [AV-TEST — Home Windows results](https://www.av-test.org/en/antivirus/home-windows/)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
