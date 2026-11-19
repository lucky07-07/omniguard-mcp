"""High-resolution screenshots of the LIVE dashboard (Vercel UI + Render API) for the report and slides.

    python benchmarks/capture_screenshots.py [--site URL] [--api URL] [--theme light|dark]

Writes benchmarks/screenshots/{01_overview,02_sqli_block,03_schema_drift_block,04_r3_rewrite_alerts,
05_redact_tainted_trace,06_benchmarks_panel}.png at 2x device-pixel density (3200x1800 viewport shots).
Every shot follows a real interaction with the deployed API.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from playwright.sync_api import sync_playwright

W, H, DSF = 1600, 900, 2
OUT = Path(__file__).resolve().parent / "screenshots"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", default="https://omniguard-mcp.vercel.app")
    ap.add_argument("--api", default="https://omniguard-mcp-api.onrender.com")
    ap.add_argument("--theme", default="light")
    a = ap.parse_args()
    OUT.mkdir(exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        page = browser.new_context(viewport={"width": W, "height": H}, device_scale_factor=DSF).new_page()

        def top(sel: str, off: int = 80) -> None:
            page.evaluate(f"""(() => {{ const e = document.querySelector({json.dumps(sel)});
                window.scrollTo(0, e.getBoundingClientRect().top + window.scrollY - {off}); }})()""")
            page.wait_for_timeout(500)

        def shot(name: str, full: bool = False) -> None:
            page.screenshot(path=str(OUT / f"{name}.png"), full_page=full)
            print("shot", name)

        def scenario(text: str, done_js: str) -> None:
            top("#v-gateway .section-h", 70)
            page.locator(".scn", has_text=text).first.click()
            page.wait_for_function(done_js, timeout=90_000)
            page.wait_for_function("getComputedStyle(document.querySelector('#toast')).display !== 'block'", timeout=30_000)
            page.wait_for_timeout(500)
            top("#trace", 80)

        page.goto(f"{a.site}/?theme={a.theme}&api={a.api}", wait_until="networkidle")
        page.evaluate("document.fonts.ready")
        page.wait_for_function("document.querySelector('#status-txt').textContent === 'Live'", timeout=180_000)
        page.request.post(f"{a.api}/api/ledger/reset")
        page.wait_for_timeout(600)
        shot("01_overview")

        scenario("SQL injection", "document.querySelector('#t-where').textContent.includes('ingress')")
        shot("02_sqli_block")
        scenario("Tool rug-pull", "document.querySelector('.why') && document.querySelector('.why').textContent.includes('SCHEMA_DRIFT')"
                                  " || document.querySelector('#trace').textContent.includes('SCHEMA_DRIFT_RUG_PULL')")
        shot("03_schema_drift_block")
        scenario("Reading secrets", "document.querySelector('#t-dec').textContent.includes('redacted')")
        page.locator(".scn", has_text="Cross-tool exfiltration").first.click()
        page.wait_for_function("document.querySelector('#t-where').textContent.includes('abac')", timeout=90_000)
        page.wait_for_function("getComputedStyle(document.querySelector('#toast')).display !== 'block'", timeout=30_000)
        page.wait_for_timeout(500)
        top("#trace", 80)
        shot("05_redact_tainted_trace")

        page.click(".top .seg [data-view='lab']")
        for _ in range(6):
            page.request.post(f"{a.api}/api/gateway/call", data=json.dumps(
                {"role": "operator", "tool": "read_file", "arguments": {"path": "/workspace/../etc/passwd"}}),
                headers={"Content-Type": "application/json"})
        page.click("#sweep")
        page.wait_for_function("document.querySelectorAll('.shield.sh-clean').length === 3", timeout=90_000)
        page.click("[data-attack='rewrite_chain']")
        page.wait_for_function("document.querySelector('#atk-log').textContent.includes('recomputed')", timeout=90_000)
        page.click("#sweep")
        page.wait_for_function("document.querySelector('.shield.sh-alert') !== null", timeout=90_000)
        page.wait_for_timeout(800)
        top("#regimes", 110)
        shot("04_r3_rewrite_alerts")

        page.click(".top .seg [data-view='bench']")
        page.wait_for_function("!document.querySelector('#abl-wrap').hidden", timeout=90_000)
        page.wait_for_timeout(800)
        top("#abl-wrap", 120)
        shot("06_benchmarks_panel")
        page.request.post(f"{a.api}/api/ledger/reset")
        browser.close()


if __name__ == "__main__":
    main()
