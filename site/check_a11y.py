"""Browser checks for the built website (run after `python site/build.py --check`).

    python site/check_a11y.py path/to/axe.min.js

Serves site/public under /sentinel-vision/ (like GitHub Pages) and, in light and dark mode at 1280 px and 320 px:
runs axe-core (WCAG 2.0-2.2 A/AA + best practices), checks there's no sideways scrolling, that no request leaves
the site, that the self-hosted font loads and that there are no console errors. The 404 page is also tested at a
nested missing path, the way GitHub Pages serves it.
"""

from __future__ import annotations

import functools
import http.server
import sys
import tempfile
import threading
from pathlib import Path

from playwright.sync_api import sync_playwright

PUBLIC = Path(__file__).resolve().parent / "public"
PAGES = ["index.html", "privacy.html", "terms.html", "cookies.html", "accessibility.html", "404.html", "no/such/page"]
AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]


def serve() -> tuple[http.server.ThreadingHTTPServer, str]:
    root = Path(tempfile.mkdtemp())
    (root / "sentinel-vision").symlink_to(PUBLIC, target_is_directory=True)

    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *args) -> None:
            pass

    handler = functools.partial(Quiet, directory=str(root))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}/"


def main() -> int:
    axe = Path(sys.argv[1]).read_text()
    not_found = (PUBLIC / "404.html").read_text()
    srv, origin = serve()
    base = origin + "sentinel-vision/"
    problems: list[str] = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for scheme in ("light", "dark"):
            for width in (1280, 320):
                ctx = browser.new_context(
                    viewport={"width": width, "height": 800}, color_scheme=scheme, bypass_csp=True
                )
                pg = ctx.new_page()
                pg.route("**/no/such/page", lambda r: r.fulfill(status=404, body=not_found, content_type="text/html"))
                requests: list[str] = []
                errors: list[str] = []
                pg.on("request", lambda r, out=requests: out.append(r.url))
                pg.on("console", lambda m, out=errors: out.append(m.text) if m.type == "error" else None)
                for name in PAGES:
                    requests.clear()
                    errors.clear()
                    pg.goto(base + name, wait_until="networkidle")
                    where = f"{scheme} {width}px {name}"
                    outside = [u for u in requests if not u.startswith(origin)]
                    if outside:
                        problems.append(f"{where}: requests outside the site: {outside}")
                    errs = [e for e in errors if not (name == "no/such/page" and "404" in e)]
                    if errs:
                        problems.append(f"{where}: console errors: {errs}")
                    overflow = pg.evaluate("document.documentElement.scrollWidth - window.innerWidth")
                    if overflow > 0:
                        problems.append(f"{where}: scrolls sideways by {overflow}px")
                    pg.evaluate("document.fonts.ready")
                    if not pg.evaluate("document.fonts.check('16px \"Atkinson Hyperlegible\"')"):
                        problems.append(f"{where}: the site font did not load")
                    pg.add_script_tag(content=axe)
                    result = pg.evaluate("tags => axe.run(document, {runOnly: {type: 'tag', values: tags}})", AXE_TAGS)
                    for v in result["violations"]:
                        targets = [n["target"] for n in v["nodes"][:3]]
                        problems.append(f"{where}: axe {v['id']} ({v['impact']}): {v['help']} {targets}")
                    print(f"{where}: {len(result['violations'])} axe violations", flush=True)
                ctx.close()
        # keyboard: the first Tab reaches the skip link, and it moves focus to the main content
        pg = browser.new_page()
        pg.goto(base + "index.html")
        pg.keyboard.press("Tab")
        if pg.evaluate("document.activeElement.textContent.trim()") != "Skip to content":
            problems.append("first Tab does not focus the skip link")
        pg.keyboard.press("Enter")
        if not pg.evaluate("location.hash === '#main'"):
            problems.append("skip link does not move to #main")
        browser.close()
    srv.shutdown()
    for prob in problems:
        print("PROBLEM:", prob)
    print("accessibility checks:", "OK" if not problems else f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
