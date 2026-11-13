"""مُصيّر Playwright الحقيقي لزحف SPA — يعمل داخل الـ worker (Chromium مثبّت).

يُحقَن في spa_crawl.crawl_spa كـ render. يلتقط روابط DOM بعد التصيير وطلبات XHR/fetch.
لا يُختبَر وحدويًا (يحتاج متصفّحًا)؛ منطق الزحف نفسه مختبَر ببديل.
"""

from __future__ import annotations

from workers.spa_crawl import RenderedPage

NAV_TIMEOUT = 15000
SETTLE_MS = 1500
CHROMIUM_PATH = "/opt/pw-browsers/chromium"


def make_spa_renderer():
    """يرجّع render(url, cookies) -> RenderedPage باستخدام Chromium headless."""

    def render(url: str, cookies: dict) -> RenderedPage:
        from playwright.sync_api import sync_playwright

        xhr: list[str] = []
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            except Exception:
                browser = p.chromium.launch(
                    headless=True, args=["--no-sandbox"], executable_path=CHROMIUM_PATH)
            ctx = browser.new_context(ignore_https_errors=True)
            if cookies:
                from urllib.parse import urlsplit
                host = urlsplit(url).hostname or ""
                ctx.add_cookies([{"name": k, "value": v, "domain": host, "path": "/"}
                                 for k, v in cookies.items()])
            page = ctx.new_page()
            # نلتقط طلبات XHR/fetch الفعلية.
            page.on("request", lambda r: xhr.append(r.url) if r.resource_type in
                    ("xhr", "fetch") else None)
            try:
                resp = page.goto(url, timeout=NAV_TIMEOUT, wait_until="networkidle")
                status = resp.status if resp else 0
            except Exception:
                browser.close()
                return RenderedPage(status=0)
            page.wait_for_timeout(SETTLE_MS)
            links = page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)") or []
            final = page.url
            browser.close()
        return RenderedPage(status=status, links=list(links), xhr=xhr, final_url=final)

    return render
