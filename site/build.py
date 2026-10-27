"""Build the Sentinel Vision website into site/public/.

    python site/build.py            # build
    python site/build.py --check    # build, then verify links, images, alt text, external resources and contrast
    python site/build.py --offline  # local preview: skip the release signature check (no fingerprints shown)

Without --offline the version, installer fingerprint and signing key shown come from the latest GitHub release,
after its signed SHA256SUMS.txt verifies against the pinned keys (site/release_check.py); otherwise the build fails.

The site is plain HTML and CSS: no JavaScript, no cookies, nothing loaded from other servers.
Screenshots and icons are converted from the repository's own files (docs/screenshots, packaging/assets).
"""

from __future__ import annotations

import datetime as dt
import html
import re
import shutil
import sys
from html.parser import HTMLParser
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
OUT = SITE / "public"
STATIC = SITE / "static"
SHOTS = ROOT / "docs" / "screenshots"
ICON = ROOT / "packaging" / "assets" / "icon.png"

OWNER = "dylanckoldan-boop"
REPO = f"https://github.com/{OWNER}/sentinel-vision"
SITE_URL = f"https://{OWNER}.github.io/sentinel-vision/"
BASE_PATH = "/sentinel-vision/"
RELEASES = f"{REPO}/releases/latest"
ISSUES = f"{REPO}/issues"
SECURITY = f"{REPO}/security/advisories/new"
MAINTAINER = "Dylan Koldan"
POLICY_DATE = dt.date(2026, 10, 11)  # change when the policies' meaning changes


def version_and_date(v: str = "") -> tuple[str, dt.date]:
    v = v or re.search(r'__version__ = "([^"]+)"', (ROOT / "src/sentinel_vision/__init__.py").read_text()).group(1)
    m = re.search(rf"^## \[{re.escape(v)}\] - (\d{{4}}-\d{{2}}-\d{{2}})", (ROOT / "CHANGELOG.md").read_text(), re.M)
    if not m:
        sys.exit(f"CHANGELOG.md has no '## [{v}] - YYYY-MM-DD' heading")
    return v, dt.date.fromisoformat(m.group(1))


OFFLINE = "--offline" in sys.argv
if OFFLINE:
    FACTS = None
    VERSION, RELEASED = version_and_date()
else:
    sys.path.insert(0, str(SITE))
    from release_check import ReleaseCheckError, latest

    try:
        FACTS = latest(OWNER)
    except ReleaseCheckError as exc:
        sys.exit(f"release check failed, the site was not built: {exc}")
    VERSION, RELEASED = version_and_date(FACTS.version)


def fingerprint_html() -> str:
    if FACTS is None:
        return (
            '<p class="release-note">Offline preview: the published site shows the installer\'s verified '
            "fingerprint here.</p>"
        )
    name, sha = FACTS.installer
    return f"""<p>Fingerprint of <code>{name}</code>, checked against the signed list when this page was built:</p>
        <p class="fingerprint"><code>{sha}</code></p>
        <p class="release-note">Signed by release key <code>{FACTS.key_id}</code>.</p>"""


def nice_date(d: dt.date) -> str:
    return f"{d.day} {d:%B %Y}"


# --------------------------------------------------------------------------- images
SCREENS = {
    "overview": (
        "The Sentinel Vision overview screen reporting that ransomware activity was stopped, with counts of "
        "threats, quarantined files, live network connections and installed detection rules."
    ),
    "ransomware": (
        "The Ransomware and rollback page: the shield is on, 14 documents are kept in the rollback vault, and one "
        "incident is listed in which 8 documents were encrypted within 20 seconds."
    ),
    "webshield": (
        "The Web Shield page warning that the link paypa1-account-verify.xyz is dangerous: it imitates the name "
        "PayPal, uses a domain ending popular with scam sites and asks for account details without encryption."
    ),
    "network": (
        "The Live traffic page listing connections by program. A connection from a program called invoice-viewer "
        "is highlighted because it goes to a known botnet server."
    ),
    "checkup": (
        "The Security checkup page showing a score of 73 out of 100, with findings marked at risk, to improve or "
        "OK, each with a suggested fix."
    ),
}


def build_images() -> dict[str, tuple[int, int]]:
    img_dir = OUT / "img"
    img_dir.mkdir(parents=True, exist_ok=True)
    sizes = {}
    for name in SCREENS:
        im = Image.open(SHOTS / f"{name}.png").convert("RGB")
        sizes[name] = im.size
        im.save(img_dir / f"{name}.webp", "WEBP", quality=86, method=6)
        half = im.resize((im.width // 2, im.height // 2), Image.LANCZOS)
        half.save(img_dir / f"{name}-680.webp", "WEBP", quality=86, method=6)
    og = Image.open(SHOTS / "overview.png").convert("RGB")
    og.thumbnail((1200, 1200))
    og.save(img_dir / "og.png", optimize=True)
    icon = Image.open(ICON).convert("RGBA")
    for size, fname in ((32, "favicon-32.png"), (180, "apple-touch-icon.png"), (72, "logo.png")):
        icon.resize((size, size), Image.LANCZOS).save(img_dir / fname, optimize=True)
    return sizes


def figure(name: str, sizes: dict, caption: str = "", eager: bool = False) -> str:
    w, h = sizes[name]
    loading = 'fetchpriority="high"' if eager else 'loading="lazy" decoding="async"'
    cap = f"<figcaption>{caption}</figcaption>" if caption else ""
    return (
        f'<figure class="shot"><img src="img/{name}.webp" '
        f'srcset="img/{name}-680.webp {w // 2}w, img/{name}.webp {w}w" '
        f'sizes="(min-width: 74rem) 70rem, 100vw" width="{w}" height="{h}" {loading} '
        f'alt="{html.escape(SCREENS[name])}">{cap}</figure>'
    )


# --------------------------------------------------------------------------- shared pieces
NAV = [
    ("index.html#features", "Features"),
    ("index.html#data", "Your data"),
    ("index.html#download", "Download"),
    (REPO, "Source code"),
]


def _local(href: str, prefix: str) -> str:
    return href if href.startswith("https://") else prefix + href


def header(current: str, prefix: str = "") -> str:
    items = []
    for href, label in NAV:
        cur = ' aria-current="page"' if href == current else ""
        items.append(f'<li><a href="{_local(href, prefix)}"{cur}>{label}</a></li>')
    return f"""<header class="site-header">
  <div class="wrap">
    <a class="brand" href="{prefix}index.html"><img src="{prefix}img/logo.png" width="36" height="36" alt="">Sentinel Vision</a>
    <nav class="site-nav" aria-label="Main">
      <ul>{"".join(items)}</ul>
    </nav>
  </div>
</header>"""


def footer(prefix: str = "") -> str:
    return f"""<footer class="site-footer">
  <div class="wrap">
    <div>
      <p>Sentinel Vision is a free, non-commercial open-source project by {MAINTAINER}, released under the MIT licence.</p>
      <p>Questions and bug reports: <a href="{ISSUES}">GitHub issues</a>. Security problems:
        <a href="{SECURITY}">report them privately</a>.</p>
    </div>
    <nav aria-label="Legal and project">
      <ul>
        <li><a href="{prefix}privacy.html">Privacy</a></li>
        <li><a href="{prefix}terms.html">Terms</a></li>
        <li><a href="{prefix}cookies.html">Cookies</a></li>
        <li><a href="{prefix}accessibility.html">Accessibility</a></li>
        <li><a href="{prefix}about.html">How it was built</a></li>
        <li><a href="{prefix}licences.html">Licences</a></li>
        <li><a href="{REPO}/blob/main/CHANGELOG.md">Changelog</a></li>
      </ul>
    </nav>
  </div>
</footer>"""


CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; "
    "base-uri 'none'; form-action 'none'; upgrade-insecure-requests"
)


def page(filename: str, title: str, description: str, body: str, current: str = "", prefix: str = "") -> str:
    """``prefix`` makes local URLs absolute (the 404 page is served at any missing path, however deep)."""
    full_title = title if title.startswith("Sentinel Vision") else f"{title} | Sentinel Vision"
    canonical = SITE_URL + ("" if filename == "index.html" else filename)
    return f"""<!doctype html>
<html lang="en-US">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="referrer" content="no-referrer">
<title>{html.escape(full_title)}</title>
<meta name="description" content="{html.escape(description)}">
<link rel="canonical" href="{canonical}">
<meta name="color-scheme" content="light dark">
<meta name="theme-color" content="#f4f7f8" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0d151b" media="(prefers-color-scheme: dark)">
<link rel="icon" href="{prefix}img/favicon-32.png" sizes="32x32" type="image/png">
<link rel="apple-touch-icon" href="{prefix}img/apple-touch-icon.png">
<link rel="stylesheet" href="{prefix}site.css?v={VERSION}">
<link rel="preload" href="{prefix}fonts/atkinson-hyperlegible-latin-400-normal.woff2" as="font" type="font/woff2" crossorigin>
<meta property="og:type" content="website">
<meta property="og:site_name" content="Sentinel Vision">
<meta property="og:title" content="{html.escape(full_title)}">
<meta property="og:description" content="{html.escape(description)}">
<meta property="og:url" content="{canonical}">
<meta property="og:image" content="{SITE_URL}img/og.png">
<meta property="og:image:alt" content="{html.escape(SCREENS["overview"])}">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
{header(current, prefix)}
<main id="main">
{body}
</main>
{footer(prefix)}
</body>
</html>
"""


# --------------------------------------------------------------------------- the data ledger
# Every network request the app makes. Keep this in step with the code (search for "https://" in src/).
LEDGER = [
    (
        "Threat-list downloads",
        ("on", "On by default", "Every 6 hours, and when you click Update now"),
        "The publisher of each list: GitHub (YARA Forge, Phishing.Database), abuse.ch, Spamhaus, "
        "Proofpoint Emerging Threats, Phishing Army, OpenPhish, and CINS Army (off unless you turn it on)",
        "A request to download the list. The abuse.ch URLhaus and ThreatFox lists need a free abuse.ch key; if "
        "you add one, it's included so abuse.ch can authorise the download.",
    ),
    (
        "Firewall and website-blocking lists (Windows)",
        ("on", "On by default", "Every 6 hours, by the protection service, while firewall or website blocking is on"),
        "GitHub (Phishing.Database), abuse.ch, Spamhaus, Proofpoint Emerging Threats, Phishing Army and OpenPhish",
        "A request to download the list. The service uses only lists that need no key.",
    ),
    (
        "ClamAV signature updates",
        ("on", "On by default", "Only if ClamAV is installed; run by ClamAV's own updater, freshclam"),
        "ClamAV's update servers",
        "A download request made by freshclam.",
    ),
    (
        "App update check",
        ("on", "On by default", "A minute after the app starts, then every 6 hours"),
        "GitHub",
        "A request for the latest release. Downloading an update is a further request to GitHub.",
    ),
    (
        "Cloud file reputation",
        ("off", "Off until you turn it on", "For new programs and scripts, and files a heuristic flagged"),
        "CIRCL hashlookup; MalwareBazaar (only if you add an abuse.ch key)",
        "The file's SHA-256 fingerprint. Never the file, its name or where it is.",
    ),
    (
        "Password breach check",
        ("use", "Only when you use it", ""),
        "Have I Been Pwned (Pwned Passwords)",
        "The first 5 characters of the password's SHA-1 hash, padded so the reply's size reveals nothing. "
        "Never the password.",
    ),
    (
        "IP address look-up",
        ("use", "Only when you click Look up IP", ""),
        "AbuseIPDB, opened in your web browser",
        "The IP address you chose to look up.",
    ),
]


def ledger_table() -> str:
    rows = []
    for what, (kind, pill, detail), dest, sent in LEDGER:
        det = f'<span class="when-detail">{detail}</span>' if detail else ""
        rows.append(
            f'<tr><th scope="row">{what}</th>'
            f'<td data-label="When"><span class="pill {kind}">{pill}</span>{det}</td>'
            f'<td data-label="Sent to"><span class="hosts">{dest}</span></td>'
            f'<td data-label="What is sent">{sent}</td></tr>'
        )
    rows.append(
        '<tr class="total"><th scope="row">Nothing else</th>'
        '<td colspan="3">Your files, documents, scan results, browsing, network activity and rollback vault stay '
        "on your computer. There's no telemetry, no crash reporting and no account.</td></tr>"
    )
    return f"""<table class="ledger">
  <caption>Every network request made by Sentinel Vision {VERSION}. Each can be switched off in Settings or simply not used.</caption>
  <thead><tr><th scope="col">What</th><th scope="col">When</th><th scope="col">Sent to</th><th scope="col">What is sent</th></tr></thead>
  <tbody>
  {"".join(rows)}
  </tbody>
</table>
<p class="ledger-note">Like any internet request, each of these shows the receiving server your IP address and the
app's name and version. No AI services are contacted. The code that makes every request is
<a href="{REPO}/tree/main/src/sentinel_vision">on GitHub</a> for anyone to check.</p>"""


# --------------------------------------------------------------------------- pages
def index(sizes) -> str:
    also = [
        (
            "Real-time file checks",
            "New and changed files are checked against hash lists, more than 5,000 YARA "
            "rules, ClamAV when it's installed, and heuristics.",
        ),
        (
            "Encrypted quarantine",
            "Detected files are encrypted so they can't run, and can be restored if you trust them.",
        ),
        ("Memory scan", "Looks for malware that runs only in memory, without a file on disk."),
        ("USB drive checks", "Removable drives are scanned when they're connected."),
        ("Scheduled scans", "A daily quick scan and a weekly full scan, caught up if your computer was off."),
        ("Camera and microphone alerts", "Know when an app starts using them (Windows and Linux)."),
        ("Password breach check", "Find out whether a password appears in known breaches, without sending it."),
        (
            "File shredder",
            "Overwrites files before deleting them. SSDs and cloud-synced folders can keep older copies, so use disk "
            "encryption for full protection.",
        ),
        (
            "Router and DNS checks",
            "Warns if a device on your network impersonates your router or your DNS "
            "settings point to a known bad server.",
        ),
        (
            "Tamper protection (Windows)",
            "A protected service keeps the quarantine, the rollback vault and your protection settings out of reach "
            "of programs running with your rights. Turning protection off or restoring a quarantined file needs "
            "administrator approval, and the app is restarted if something closes it. If the service is stopped, "
            "the app warns you and keeps your settings at full strength until it's back.",
        ),
        (
            "Firewall blocking (Windows)",
            "Known-malicious networks are blocked in Windows Firewall for the whole computer.",
        ),
        (
            "Signed updates",
            "Updates are signed with ML-DSA-65, a post-quantum algorithm standardised by NIST in "
            "FIPS 204, together with Ed25519. The app refuses an update that fails either check or is older than "
            "the version you have.",
        ),
    ]
    also_html = "".join(f"<div><dt>{t}</dt><dd>{d}</dd></div>" for t, d in also)
    limits = [
        (
            "Block a file before it opens on Windows or macOS",
            "That needs a kernel driver signed by Microsoft or an entitlement granted by Apple. Sentinel Vision checks "
            "files the moment they're written and programs right after they start.",
        ),
        (
            "Independent lab certification",
            "Labs such as AV-TEST and AV-Comparatives test products when their makers apply. Sentinel Vision hasn't "
            "been tested by them.",
        ),
        (
            "A large cloud detection network",
            "Commercial products learn from data collected across their customers' devices. Sentinel Vision uses "
            "public threat lists and collects nothing.",
        ),
        (
            "Registration with Windows Security",
            "Only members of Microsoft's Virus Initiative can register. Keep Microsoft Defender switched on alongside "
            "Sentinel Vision.",
        ),
        (
            "Stop malware that already has administrator rights",
            "A program running as administrator can stop any program, including the protection service, without a "
            "kernel driver. Sentinel Vision warns you if that happens. Approve administrator prompts only for "
            "programs you started yourself.",
        ),
        ("VPN, identity-theft insurance or credit monitoring", "These are paid services rather than software."),
    ]
    limits_html = "".join(f"<li><strong>{t}</strong>{d}</li>" for t, d in limits)
    credits = [
        (
            '<a href="https://virustotal.github.io/yara/">YARA</a> and <a href="https://github.com/YARAHQ/yara-forge">'
            "YARA Forge</a>, with the rule authors it collects"
        ),
        '<a href="https://www.clamav.net/">ClamAV</a>',
        '<a href="https://abuse.ch/">abuse.ch</a>: MalwareBazaar, Feodo Tracker, ThreatFox and URLhaus',
        '<a href="https://www.spamhaus.org/drop/">Spamhaus DROP</a>',
        '<a href="https://rules.emergingthreats.net/">Proofpoint Emerging Threats</a>',
        '<a href="https://cinsscore.com/">CINS Army</a> (off by default)',
        '<a href="https://github.com/Phishing-Database/Phishing.Database">Phishing.Database</a> (MIT licence)',
        (
            '<a href="https://phishing.army/">Phishing Army</a> (<a href="https://creativecommons.org/licenses/by-nc/4.0/">'
            "CC BY-NC 4.0</a>: personal, non-commercial use)"
        ),
        (
            '<a href="https://openphish.com/">OpenPhish</a> community feed (<a href="https://openphish.com/terms.html">'
            "personal, non-commercial use</a>)"
        ),
        '<a href="https://hashlookup.circl.lu/">CIRCL hashlookup</a>',
        '<a href="https://haveibeenpwned.com/Passwords">Have I Been Pwned: Pwned Passwords</a>',
        (
            '<a href="https://www.brailleinstitute.org/freefont/">Atkinson Hyperlegible</a> typeface by the Braille '
            'Institute (<a href="fonts/OFL.txt">SIL Open Font License 1.1</a>)'
        ),
    ]
    credits_html = "".join(f"<li>{c}</li>" for c in credits)
    return f"""
<section class="hero">
  <div class="wrap">
    <h1>An antivirus that shows its work.</h1>
    <p class="lede">Sentinel Vision is free, open-source security software for Windows, macOS and Linux. It checks
    files as they arrive, stops ransomware mid-attack and puts your documents back, keeps you away from malware and
    phishing sites, and shows every network connection on your computer. There's no account, no subscription and no
    data collection.</p>
    <div class="actions">
      <a class="button primary" href="{RELEASES}">Download Sentinel Vision</a>
      <a class="button secondary" href="{REPO}">Read the source code</a>
    </div>
    <p class="release-note">Version {VERSION}, released {nice_date(RELEASED)}, for Windows 10 and 11, macOS 14 or
    later on Apple silicon, and 64-bit Linux.</p>
    {figure("overview", sizes, "Screenshots show the app with demonstration data.", eager=True)}
  </div>
</section>

<section class="section" id="features" aria-labelledby="features-h">
  <div class="wrap">
    <h2 id="features-h">What it protects you from</h2>
    <p class="section-intro">Every protection runs on your computer, using threat information published by the
    security community.</p>

    <article class="feature">
      <div>
        <h3>Ransomware</h3>
        <p>Hidden decoy files and a watch on how quickly documents change catch encryption while it's happening.
        The program responsible is paused, so you decide whether to end it.</p>
        <p>Earlier versions of your documents are kept, encrypted, in a rollback vault. Pick a time, and every
        file changed since then goes back to how it was.</p>
      </div>
      {figure("ransomware", sizes)}
    </article>

    <article class="feature">
      <div>
        <h3>Dangerous websites</h3>
        <p>Lists of known malware and phishing sites are checked on your computer, and can be blocked for every
        browser and app at once.</p>
        <p>Paste a link from an email or text message to check it first. The checker also spots new scam sites
        that imitate a real brand's name, even before they appear on any list.</p>
      </div>
      {figure("webshield", sizes)}
    </article>

    <article class="feature">
      <div>
        <h3>Suspicious connections</h3>
        <p>See every connection your computer makes, which program made it, and whether the address is on a list
        of botnet or criminal servers. End the program or block the address in one click.</p>
      </div>
      {figure("network", sizes)}
    </article>

    <article class="feature">
      <div>
        <h3>Weak settings</h3>
        <p>The security checkup reviews your computer's own defences in plain language: firewall, disk
        encryption, system updates, remote access, Wi-Fi and router safety. Each finding says what to change, and
        nothing is changed without you.</p>
      </div>
      {figure("checkup", sizes)}
    </article>

    <h3>Also included</h3>
    <dl class="also">{also_html}</dl>
    <p class="section-intro">Sentinel Vision contains no machine-learning model and sends nothing to AI services. Detections come from hash lists, YARA rules, ClamAV signatures and fixed heuristics. <a href="about.html">How Sentinel Vision was built</a>.</p>
  </div>
</section>

<section class="section ledger-band" id="data" aria-labelledby="data-h">
  <div class="wrap">
    <h2 id="data-h">Everything that leaves your computer</h2>
    <p class="section-intro">This is the complete list. Sentinel Vision has no server of its own, so nothing is
    ever sent to us.</p>
    {ledger_table()}
  </div>
</section>

<section class="section" id="limits" aria-labelledby="limits-h">
  <div class="wrap">
    <h2 id="limits-h">What it doesn't do</h2>
    <p class="section-intro">Paid security suites still do some things Sentinel Vision can't. Here's what, and
    why.</p>
    <ul class="limits">{limits_html}</ul>
    <p class="recommend">For the strongest protection, run Sentinel Vision together with the protection built into
    your operating system: Microsoft Defender on Windows, XProtect on macOS.</p>
    <p><a href="{REPO}/blob/main/docs/COMPARISON.md">Read the sourced comparison with Norton 360 and McAfee+</a></p>
  </div>
</section>

<section class="section" id="download" aria-labelledby="download-h">
  <div class="wrap">
    <h2 id="download-h">Download and install</h2>
    <ol class="steps">
      <li>
        <h3>Download</h3>
        <p>Get the file for your system from the <a href="{RELEASES}">latest release on GitHub</a>: the
        <code>Setup.exe</code> for Windows, the <code>.zip</code> for macOS or the <code>.tar.gz</code> for Linux.</p>
      </li>
      <li>
        <h3>Check the download</h3>
        <p>Each release lists every file's SHA-256 fingerprint in <code>SHA256SUMS.txt</code>, signed with the
        project's post-quantum key. On Windows, compare it with the result of
        <code>Get-FileHash .\\SentinelVision-{VERSION}-Setup.exe</code> in PowerShell. If you already have
        Sentinel Vision, run <code>sentinel-vision-cli verify-release</code> in the download folder to check the
        signature and every fingerprint at once.</p>
        {fingerprint_html()}
      </li>
      <li>
        <h3>Install</h3>
        <p>The app isn't code-signed by Microsoft or Apple yet, so the first launch shows a warning. On Windows,
        choose <strong>More info</strong>, then <strong>Run anyway</strong>. On macOS, open <strong>System Settings,
        Privacy &amp; Security</strong> and choose <strong>Open Anyway</strong>.</p>
      </li>
      <li>
        <h3>Finish setting up</h3>
        <p>Click <strong>Update now</strong> in Settings to download the threat lists, then run the Security
        checkup. The <a href="{REPO}/blob/main/docs/INSTALL.md">installation guide</a> covers every step,
        including adding ClamAV.</p>
      </li>
    </ol>
  </div>
</section>

<section class="section" id="credits" aria-labelledby="credits-h">
  <div class="wrap">
    <h2 id="credits-h">Credits</h2>
    <p>Sentinel Vision is built on the work of the security community. Each copy of the app downloads threat lists
    directly from their publishers; we don't redistribute them, and they stay under their own licences.</p>
    <ul class="credits">{credits_html}</ul>
    <p>Using Sentinel Vision in a business? Untick Phishing Army and OpenPhish under <strong>Settings, Threat
    definitions, Sources</strong>, or ask their publishers for permission.</p>
    <p>Microsoft, Windows, Apple, macOS, Norton, McAfee, PayPal and other names are trademarks of their owners.
    Sentinel Vision isn't affiliated with or endorsed by any of them.</p>
  </div>
</section>
"""


def privacy() -> str:
    return f"""
<article class="prose">
  <div class="wrap">
    <h1>Privacy policy</h1>
    <p class="updated">Effective {nice_date(POLICY_DATE)}.</p>
    <div class="summary">
      <p><strong>In short:</strong> this website collects nothing about you and sets no cookies. The Sentinel
      Vision app has no account, no telemetry and no tracking. The few requests it makes are listed below, and your
      files never leave your computer.</p>
    </div>

    <h2>Who we are</h2>
    <p>Sentinel Vision is a free, open-source project maintained by {MAINTAINER}, an individual rather than a
    company. "We" in this policy means the project's maintainers. How to contact us is at the end.</p>

    <h2>This website</h2>
    <h3>Hosting</h3>
    <p>The site is hosted by GitHub Pages. GitHub logs every visitor's IP address for security purposes, whether
    or not they're signed in to GitHub (<a href="https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages#data-collection">GitHub
    Pages documentation</a>). GitHub handles that information under the
    <a href="https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement">GitHub
    General Privacy Statement</a>. We don't receive these logs or any statistics about visitors.</p>
    <h3>What the site doesn't do</h3>
    <ul>
      <li>It sets no cookies and stores nothing in your browser. See the <a href="cookies.html">cookie policy</a>.</li>
      <li>It has no analytics, advertising, tracking pixels or social-media widgets.</li>
      <li>It runs no JavaScript.</li>
      <li>It loads no fonts, images or other files from other servers. Everything comes from this site.</li>
      <li>It has no forms and asks you for no information.</li>
    </ul>
    <p>Links to GitHub and other sites take you to services with their own privacy policies.</p>

    <h2>The Sentinel Vision app</h2>
    <p>The app has no account and sends nothing to us. We have no server that could receive anything.
    Sentinel Vision contains no machine-learning model and sends nothing to AI services. Detections come from hash lists, YARA rules, ClamAV signatures and fixed heuristics.</p>
    <h3>What it sends over the internet</h3>
    {ledger_table()}

    <h3>What it keeps on your computer</h3>
    <ul>
      <li>Your settings, detection history and event log.</li>
      <li>The quarantine: detected files, encrypted with AES-256-GCM so they can't run.</li>
      <li>The rollback vault: encrypted copies of earlier versions of documents in the folders you protect, up to
      the size limit you set (5&nbsp;GB by default).</li>
      <li>Downloaded threat lists and the app's logs.</li>
      <li>Records kept for plugins you allowed (for example a companion program's audit log), only if you install
      one.</li>
    </ul>
    <p>These are stored in <code>%LOCALAPPDATA%\\SentinelVision</code> on Windows,
    <code>~/Library/Application Support/SentinelVision</code> on macOS and <code>~/.local/share/SentinelVision</code>
    on Linux. On Windows, the quarantine, the rollback vault and your protection settings are kept in
    <code>%ProgramData%\\SentinelVision\\Service</code>, which only the protection service and administrators can
    open, with each account's data kept separate. The app can also add a start-at-sign-in entry and hidden decoy
    files in protected folders. If you turn on website blocking it adds entries to your system's hosts file, and on
    Windows the protection service adds firewall rules that block known-malicious networks (you can turn this
    off).</p>
    <h3>Deleting it</h3>
    <p>On Windows, the uninstaller removes the protection service, the start-at-sign-in entry, the decoy files,
    website blocking and firewall blocking, then asks whether to delete the data too (for every account on the
    computer). On macOS and Linux, turn off the ransomware shield and website
    blocking in the app, then delete the app and the folder above.</p>

    <h2>Your rights</h2>
    <p>We don't collect, receive, sell or share personal information, so there's nothing we hold that you could
    ask us to access, correct or delete. This applies under the EU and UK General Data Protection Regulation and
    US state privacy laws such as the California Consumer Privacy Act. For information GitHub holds about your
    visit, use the rights described in GitHub's privacy statement. The app's optional look-ups go directly from
    your computer to the services listed above, each of which has its own privacy policy.</p>

    <h2>Children</h2>
    <p>Because neither the website nor the app collects personal information, none is collected from children.</p>

    <h2>Changes to this policy</h2>
    <p>If this policy changes, we'll update this page and the date at the top. Any change to what the app sends
    over the internet is also listed in the <a href="{REPO}/blob/main/CHANGELOG.md">changelog</a>.</p>

    <h2>Contact</h2>
    <p>Open an issue on <a href="{ISSUES}">GitHub</a>. Issues are public, so don't include personal information.
    To report a security problem, <a href="{SECURITY}">report it privately</a>.</p>
  </div>
</article>
"""


MIT_DISCLAIMER = (
    'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED '
    "TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL "
    "THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF "
    "CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER "
    "DEALINGS IN THE SOFTWARE."
)


def terms() -> str:
    return f"""
<article class="prose">
  <div class="wrap">
    <h1>Terms of use</h1>
    <p class="updated">Effective {nice_date(POLICY_DATE)}.</p>
    <div class="summary">
      <p><strong>In short:</strong> Sentinel Vision is free software under the MIT licence and comes with no
      warranty. No security product stops every threat, so keep backups and keep your operating system's own
      protection switched on.</p>
    </div>

    <h2>The software</h2>
    <p>Sentinel Vision is released under the <a href="{REPO}/blob/main/LICENSE">MIT licence</a>. You may use,
    copy, change and share it under that licence, which is what governs the software. Nothing on this website
    changes or adds to it.</p>

    <h2>No warranty</h2>
    <p>As the licence states:</p>
    <blockquote>{MIT_DISCLAIMER}</blockquote>

    <h2>Using it sensibly</h2>
    <ul>
      <li>No antivirus detects every threat. Sentinel Vision reduces risk; it can't remove it.</li>
      <li>The rollback vault is stored on the same computer as your documents, so it isn't a backup. Keep
      separate backups of anything important.</li>
      <li>Keep your operating system's built-in protection switched on as well.</li>
      <li>Like any antivirus, Sentinel Vision can occasionally flag a legitimate file. Quarantined files can be
      restored.</li>
      <li>System-wide changes, such as website blocking through the hosts file, are made only after you turn them
      on and approve the administrator prompt.</li>
    </ul>

    <h2>Threat information from other publishers</h2>
    <p>Each copy of the app downloads threat lists directly from their publishers. We don't redistribute them, and
    they're provided under their publishers' own licences and terms. Phishing Army
    (<a href="https://creativecommons.org/licenses/by-nc/4.0/">CC BY-NC 4.0</a>) and the
    <a href="https://openphish.com/terms.html">OpenPhish</a> community feed are for personal, non-commercial use.
    If you use Sentinel Vision in a business, untick them under <strong>Settings, Threat definitions,
    Sources</strong>, or get their publishers' permission.</p>

    <h2>This website</h2>
    <p>The website describes the software and may change at any time. Links to other websites are provided for
    convenience; we don't control them. Microsoft, Windows, Apple, macOS, Norton, McAfee, PayPal and other names
    are trademarks of their owners, and Sentinel Vision isn't affiliated with or endorsed by any of them.</p>

    <h2>Changes</h2>
    <p>If these terms change, we'll update this page and the date at the top.</p>

    <h2>Contact</h2>
    <p>Open an issue on <a href="{ISSUES}">GitHub</a>.</p>
  </div>
</article>
"""


def cookies() -> str:
    return f"""
<article class="prose">
  <div class="wrap">
    <h1>Cookie policy</h1>
    <p class="updated">Effective {nice_date(POLICY_DATE)}.</p>
    <div class="summary"><p><strong>This website doesn't use cookies.</strong></p></div>
    <h2>What that means</h2>
    <ul>
      <li>No cookies are set, by us or by anyone else.</li>
      <li>Nothing is saved in your browser's storage, such as local storage, session storage or IndexedDB.</li>
      <li>There are no tracking pixels, fingerprinting, analytics, advertising or embedded content from other
      sites.</li>
      <li>The site runs no JavaScript, and its security policy stops the browser from loading anything from other
      servers.</li>
    </ul>
    <p>Because nothing is stored on or read from your device, there's nothing to ask your consent for, so the site
    has no cookie banner.</p>
    <h2>The desktop app</h2>
    <p>The Sentinel Vision app doesn't use cookies. What it keeps on your computer is described in the
    <a href="privacy.html">privacy policy</a>.</p>
    <h2>Changes</h2>
    <p>If this ever changes, this page will be updated before the change is made.</p>
  </div>
</article>
"""


def accessibility() -> str:
    return f"""
<article class="prose">
  <div class="wrap">
    <h1>Accessibility</h1>
    <p class="updated">Last reviewed {nice_date(POLICY_DATE)}.</p>
    <p>We want everyone to be able to use this website. It aims to meet the
    <a href="https://www.w3.org/TR/WCAG22/">Web Content Accessibility Guidelines (WCAG) 2.2</a> at level AA.</p>
    <h2>How it's checked</h2>
    <p>Every time the site is built, it's checked automatically:</p>
    <ul>
      <li>with <a href="https://github.com/dequelabs/axe-core">axe-core</a> on every page, in light and dark
      mode;</li>
      <li>for colour contrast, by computing the contrast of every text and background colour pair;</li>
      <li>for text alternatives on every image, and for broken links;</li>
      <li>at a width of 320 pixels, so the layout works when zoomed to 400% without scrolling sideways.</li>
    </ul>
    <h2>Features</h2>
    <ul>
      <li>A "skip to content" link and a clearly visible keyboard focus outline.</li>
      <li>Follows your system's light or dark setting.</li>
      <li>No moving content.</li>
      <li>Set in Atkinson Hyperlegible, a typeface the Braille Institute designed to be easier to read for people
      with low vision.</li>
      <li>Works without images and without JavaScript.</li>
    </ul>
    <h2>Known limitations</h2>
    <ul>
      <li>The screenshots' text alternatives summarise what each screen shows rather than repeating every word on
      it.</li>
      <li>The desktop app is built with Qt, which supports the screen readers on Windows, macOS and Linux, but the
      app hasn't had a formal accessibility audit yet.</li>
    </ul>
    <h2>Tell us about a problem</h2>
    <p>If something on this site or in the app doesn't work for you, please
    <a href="{ISSUES}/new">open an issue on GitHub</a> and describe what happened and what you were using.</p>
  </div>
</article>
"""


def about() -> str:
    return f"""
<article class="prose">
  <div class="wrap">
    <h1>How Sentinel Vision was built</h1>
    <p>Sentinel Vision is designed and maintained by {MAINTAINER}. Most of its code and documentation was written
    with AI assistance (Anthropic's Claude), under his direction: he decides what it should do and what is
    released.</p>
    <h2>How changes are checked</h2>
    <ul>
      <li>Every change must pass the automated tests on Windows, macOS and Linux before it is released.</li>
      <li>Each Windows release is installed, upgraded from the previous release and uninstalled on a clean Windows
      machine, with checks that an ordinary account can't weaken its protection.</li>
      <li>Every week, a false-positive audit scans clean Windows, macOS and Linux computers, and a test checks that
      every threat list the app downloads still works.</li>
      <li>The source code, the tests and every result are public on <a href="{REPO}">GitHub</a>.</li>
    </ul>
    <h2>Who is responsible</h2>
    <p>{MAINTAINER} is responsible for the project and its releases. Using AI to write it doesn't change the
    licence: like all MIT-licensed software, Sentinel Vision comes with no warranty (see the
    <a href="terms.html">terms</a>).</p>
    <h2>The program itself uses no AI</h2>
    <p>Sentinel Vision contains no machine-learning model and sends nothing to AI services. Detections come from hash lists, YARA rules, ClamAV signatures and fixed heuristics.</p>
    <p class="release-note">Anthropic and Claude are trademarks of Anthropic. This project is not affiliated with or
    endorsed by Anthropic.</p>
  </div>
</article>"""


# Open-source software included in the app: (name in requirements/build.lock, shown name, licence, home page)
COMPONENTS = [
    ("pyside6", "Qt for Python (PySide6) and Qt", "LGPL-3.0", "https://www.qt.io/qt-for-python"),
    ("shiboken6", "Shiboken6", "LGPL-3.0", "https://www.qt.io/qt-for-python"),
    ("yara-python", "yara-python, with the YARA library", "Apache-2.0 and BSD-3-Clause", "https://virustotal.github.io/yara/"),
    ("cryptography", "cryptography, with OpenSSL", "Apache-2.0 or BSD-3-Clause; OpenSSL: Apache-2.0", "https://cryptography.io"),
    ("cffi", "cffi", "MIT-0", "https://cffi.readthedocs.io"),
    ("pycparser", "pycparser", "BSD-3-Clause", "https://github.com/eliben/pycparser"),
    ("psutil", "psutil", "BSD-3-Clause", "https://github.com/giampaolo/psutil"),
    ("watchdog", "watchdog", "Apache-2.0", "https://github.com/gorakhargosh/watchdog"),
    ("pefile", "pefile", "MIT", "https://github.com/erocarrera/pefile"),
    ("platformdirs", "platformdirs", "MIT", "https://github.com/platformdirs/platformdirs"),
    ("certifi", "certifi", "MPL-2.0", "https://github.com/certifi/python-certifi"),
    ("pywin32", "pywin32 (Windows only)", "PSF-2.0", "https://github.com/mhammond/pywin32"),
]  # fmt: skip


def locked_version(name: str) -> str:
    m = re.search(rf"^{re.escape(name)}==([^\s;]+)", (ROOT / "requirements" / "build.lock").read_text(), re.M)
    return m.group(1) if m else ""


def licences() -> str:
    rows = "".join(
        f'<tr><td><a href="{url}">{html.escape(shown)}</a></td><td>{locked_version(name)}</td>'
        f"<td>{html.escape(lic)}</td></tr>"
        for name, shown, lic, url in COMPONENTS
    )
    py = "3.12"
    qt = locked_version("pyside6")
    return f"""
<article class="prose">
  <div class="wrap">
    <h1>Licences</h1>
    <p>Sentinel Vision is free software under the <a href="{REPO}/blob/main/LICENSE">MIT licence</a>. Each download
    also includes the open-source software below, under its own licence. The full licence texts come with the app
    (Settings &rarr; <em>Third-party licences</em>) and with every release as
    <a href="{REPO}/releases/latest/download/THIRD_PARTY_NOTICES.txt">THIRD_PARTY_NOTICES.txt</a>.</p>
    <table>
      <caption>Software included in the current release</caption>
      <thead><tr><th scope="col">Software</th><th scope="col">Version</th><th scope="col">Licence</th></tr></thead>
      <tbody>{rows}<tr><td><a href="https://www.python.org">Python</a></td><td>{py}</td><td>PSF-2.0</td></tr></tbody>
    </table>
    <h2>Qt and PySide6 (LGPL-3.0)</h2>
    <p>Qt and Qt for Python are used under the GNU Lesser General Public License version 3. They are separate
    libraries inside the app, so you may replace them with your own modified versions. Their source code for the
    version in the current release ({qt}) is available from
    <a href="https://download.qt.io/official_releases/QtForPython/pyside6/PySide6-{qt}-src/">download.qt.io</a> and
    <a href="https://code.qt.io/cgit/pyside/pyside-setup.git/tag/?h=v{qt}">code.qt.io</a>. Qt also includes
    components under their own licences, listed in
    <a href="https://doc.qt.io/qt-6/licenses-used-in-qt.html">Qt's documentation</a>.</p>
    <h2>Threat data</h2>
    <p>The threat lists the app downloads come from their publishers under their own terms, listed on the
    <a href="index.html#credits">home page</a>. The Phishing Army and OpenPhish lists are for personal,
    non-commercial use.</p>
  </div>
</article>"""


def not_found() -> str:
    return """
<article class="prose">
  <div class="wrap">
    <h1>Page not found</h1>
    <p>That page doesn't exist. It may have moved.</p>
    <p><a href="/sentinel-vision/index.html">Go to the Sentinel Vision home page</a></p>
  </div>
</article>
"""


DESCRIPTION = (
    "Free, open-source antivirus for Windows, macOS and Linux: real-time file checks, ransomware rollback, "
    "malware and phishing site blocking, and a live network monitor. No account and no data collection."
)


def build() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    shutil.copy(STATIC / "site.css", OUT / "site.css")
    shutil.copytree(STATIC / "fonts", OUT / "fonts")
    sizes = build_images()
    pages = {
        "index.html": ("Sentinel Vision: free, open-source antivirus", DESCRIPTION, index(sizes), ""),
        "privacy.html": ("Privacy policy", "How Sentinel Vision and this website handle your data.", privacy(), ""),
        "terms.html": ("Terms of use", "The terms for using Sentinel Vision and this website.", terms(), ""),
        "cookies.html": ("Cookie policy", "This website doesn't use cookies.", cookies(), ""),
        "accessibility.html": (
            "Accessibility",
            "How this website is made accessible, and how to report a problem.",
            accessibility(),
            "",
        ),
        "about.html": (
            "How Sentinel Vision was built",
            "Who makes Sentinel Vision, how AI was used, and how every change is checked.",
            about(),
            "",
        ),
        "licences.html": (
            "Licences",
            "The open-source software included in Sentinel Vision and its licences.",
            licences(),
            "",
        ),
        "404.html": ("Page not found", "This page doesn't exist.", not_found(), ""),
    }
    for name, (title, desc, body, cur) in pages.items():
        prefix = BASE_PATH if name == "404.html" else ""
        (OUT / name).write_text(page(name, title, desc, body, cur, prefix), encoding="utf-8")
    (OUT / ".nojekyll").write_text("")
    (OUT / "robots.txt").write_text(f"User-agent: *\nAllow: /\nSitemap: {SITE_URL}sitemap.xml\n")
    urls = "".join(
        f"<url><loc>{SITE_URL}{'' if n == 'index.html' else n}</loc></url>" for n in pages if n != "404.html"
    )
    (OUT / "sitemap.xml").write_text(
        f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}'
        "</urlset>\n"
    )
    print(f"built {len(pages)} pages into {OUT.relative_to(ROOT)} (version {VERSION})")


# --------------------------------------------------------------------------- checks
class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.refs: list[tuple[str, str]] = []
        self.imgs: list[dict] = []
        self.ids: set[str] = set()
        self.problems: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        if tag == "img":
            self.imgs.append(a)
            if "alt" not in a:
                self.problems.append(f"<img src={a.get('src')}> has no alt attribute")
            self.refs.append(("src", a.get("src", "")))
        if tag == "a":
            self.refs.append(("href", a.get("href", "")))
        if tag == "link" and a.get("rel") != "canonical":
            self.refs.append(("link", a.get("href", "")))
        if tag in ("script", "iframe", "object", "embed", "form"):
            self.problems.append(f"<{tag}> is not allowed on this site")


def _lum(hex_: str) -> float:
    hex_ = hex_.lstrip("#")
    rgb = [int(hex_[i : i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# (foreground token, background token, minimum ratio) for every pairing the stylesheet uses
PAIRS = [
    ("ink", "paper", 4.5),
    ("ink", "surface", 4.5),
    ("ink", "band", 4.5),
    ("ink-2", "paper", 4.5),
    ("ink-2", "surface", 4.5),
    ("ink-2", "band", 4.5),
    ("accent", "paper", 4.5),
    ("accent", "band", 4.5),
    ("accent", "surface", 4.5),
    ("accent-hover", "paper", 4.5),
    ("on-accent", "accent", 4.5),
    ("on-accent", "accent-hover", 4.5),
    ("pill-on-ink", "pill-on", 4.5),
    ("pill-off-ink", "pill-off", 4.5),
    ("pill-use-ink", "pill-use", 4.5),
    ("caution", "paper", 3.0),
    ("focus", "paper", 3.0),
    ("focus", "band", 3.0),
    ("rule-strong", "band", 3.0),
    ("ink", "paper", 3.0),  # step markers' circle borders
]


def css_tokens() -> tuple[dict, dict]:
    css = (STATIC / "site.css").read_text()
    light_block = css[css.index(":root {") : css.index("}", css.index(":root {"))]
    dark_start = css.index("@media (prefers-color-scheme: dark)")
    dark_block = css[dark_start : css.index("}", css.index(":root {", dark_start))]
    pat = re.compile(r"--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})")
    light = dict(pat.findall(light_block))
    dark = {**light, **dict(pat.findall(dark_block))}
    return light, dark


def check() -> int:
    problems: list[str] = []
    files = {p.relative_to(OUT).as_posix() for p in OUT.rglob("*") if p.is_file()}
    ids_by_page = {}
    parsed = {}
    for name in sorted(f for f in files if f.endswith(".html")):
        c = _Collector()
        c.feed((OUT / name).read_text(encoding="utf-8"))
        parsed[name] = c
        ids_by_page[name] = c.ids
        problems += [f"{name}: {p}" for p in c.problems]
    for name, c in parsed.items():
        for kind, ref in c.refs:
            if not ref:
                problems.append(f"{name}: empty {kind}")
                continue
            if ref.startswith(("https://", "mailto:")):
                if kind != "href":
                    problems.append(f"{name}: external resource {ref} (only links may point elsewhere)")
                continue
            if ref.startswith("http://"):
                problems.append(f"{name}: insecure link {ref}")
                continue
            path, _, frag = ref.partition("#")
            path = path.split("?")[0] or name
            if path.startswith(BASE_PATH):
                path = path[len(BASE_PATH) :]
            if path not in files:
                problems.append(f"{name}: broken link {ref}")
            elif frag and path.endswith(".html") and frag not in ids_by_page.get(path, set()):
                problems.append(f"{name}: missing anchor {ref}")
    css = (OUT / "site.css").read_text()
    for url in re.findall(r"url\(\"?([^\")]+)\"?\)", css):
        if url not in files:
            problems.append(f"site.css: missing {url}")
    light, dark = css_tokens()
    for mode, tokens in (("light", light), ("dark", dark)):
        for fg, bg, minimum in PAIRS:
            r = contrast(tokens[fg], tokens[bg])
            if r < minimum:
                problems.append(f"contrast {mode}: {fg} on {bg} is {r:.2f}:1, needs {minimum}:1")
    for p in problems:
        print("PROBLEM:", p)
    print(f"checked {len(parsed)} pages, {len(files)} files: {'OK' if not problems else f'{len(problems)} problem(s)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    build()
    if "--check" in sys.argv:
        sys.exit(check())
