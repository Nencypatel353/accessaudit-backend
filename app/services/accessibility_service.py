"""
Runs a real headless browser against the target URL, injects axe-core,
and returns structured accessibility violations.
"""
from playwright.async_api import async_playwright

AXE_CDN_URL = "https://cdnjs.cloudflare.com/ajax/libs/axe-core/4.10.0/axe.min.js"


async def run_accessibility_scan(url: str) -> dict:
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
        except Exception:
            # some sites never fully go idle (analytics pings etc) -- fall back
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)

        # dismiss common cookie banners so they don't skew results -- best effort only
        for text in ["Accept", "Accept all", "I agree", "Got it"]:
            try:
                await page.click(f"button:has-text('{text}')", timeout=1500)
                break
            except Exception:
                continue

        await page.add_script_tag(url=AXE_CDN_URL)
        axe_results = await page.evaluate("async () => { return await axe.run(); }")

        # also grab data needed for the mixed-content security check while the
        # page is already loaded, so we don't have to load it twice
        mixed_content = await page.evaluate(
            """
            () => {
                const insecure = [];
                document.querySelectorAll('img,script,link,iframe').forEach(el => {
                    const src = el.src || el.href;
                    if (src && src.startsWith('http://')) insecure.push(src);
                });
                return insecure;
            }
            """
        )

        await browser.close()

    return {
        "violations": axe_results.get("violations", []),
        "mixed_content": mixed_content,
    }


def calculate_accessibility_score(violations: list) -> int:
    """Weighted scoring: critical issues cost the most, minor issues the least."""
    weights = {"critical": 10, "serious": 5, "moderate": 2, "minor": 1}
    penalty = 0
    for v in violations:
        impact = v.get("impact", "minor")
        node_count = len(v.get("nodes", []))
        penalty += weights.get(impact, 1) * min(node_count, 5)  # cap so one rule can't zero the score alone
    score = max(0, 100 - penalty)
    return score
