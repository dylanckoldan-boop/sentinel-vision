# Name clearance: "Sentinel Vision"

Recorded 31 October 2026. **This is due diligence, not legal advice.** Before a trademark filing or any commercial
use, run a formal search (USPTO, EUIPO, WIPO Global Brand Database) or ask a trademark attorney.

## Checks performed (31 October 2026)

| Source | Result |
|---|---|
| PyPI `sentinel-vision` | Not registered (404). See the next section: PyPI is likely to refuse it anyway. |
| PyPI `sentinelvision` | **Taken** by an unrelated project ("Real-time autonomous visual tracking and reasoning system", version 0.1.0). |
| PyPI `sentinel-vision-cli` | Not registered (404). |
| npm `sentinel-vision`, `sentinelvision` | Not registered (404). |
| USPTO "SENTINEL VISION" (serial 78110698, registration 2824057) | **Dead**: class 9, video-monitoring hardware and software for properties; cancelled in 2010 for a missing declaration of use. |
| Justia trademark index | Lists an owner named "Sentinel Vision, Inc."; its marks couldn't be retrieved here. Check them in the formal search. |
| Same name, other market | Sentinel (Sentinel Concept Group) presents "Sentinel Vision" software for industrial machine vision in factories. |
| Same word, same market | "Sentinel" is crowded in security software: SentinelOne (endpoint protection), Sentinel Anti-malware (Danami, for Plesk servers), NetIQ Sentinel, Sentinel Labs. |

## PyPI: the name can't simply be claimed

PyPI refuses a new project whose name is "too similar to an existing project": it compares names with case and
separators removed, so `sentinel-vision` is compared as `sentinelvision`, which is taken. In practice nobody, this
project included, can register `sentinel-vision` without PyPI's administrators. That also means nobody can squat it,
but `pip install sentinelvision` installs the unrelated project.

This project's documents never install Sentinel Vision from PyPI: the installers come from GitHub releases and source
installs use `pip install .`. Keep it that way, and never write `pip install sentinelvision` or
`pip install sentinel-vision` in a document, issue or answer. If a PyPI release is wanted later, the options are:

1. A distinct distribution name (for example `sentinel-vision-av`), keeping the import package `sentinel_vision`.
2. A request to PyPI under PEP 541, if the `sentinelvision` project is abandoned. It isn't a basis for taking an
   active project.

## Assessment

No live US registration for the exact words "Sentinel Vision" turned up, but the word "Sentinel" is used by several
established security products, one of them an anti-malware product. For a free, open-source project the risk is low;
it rises with commercial use, paid distribution or a logo that resembles one of those products.

## Still to do (owner)

- [ ] Run a formal search for "SENTINEL VISION" and "SENTINEL" in classes 9 (software) and 42 (software as a
      service) at USPTO Trademark Search, EUIPO eSearch and the WIPO Global Brand Database, and look up the marks of
      Sentinel Vision, Inc.
- [ ] Decide to keep the name, or rename before a wider release, and record the decision here with the date.
- [ ] If a PyPI release is wanted, choose option 1 or 2 above.
- [ ] Optionally secure a domain; none was checked here.
