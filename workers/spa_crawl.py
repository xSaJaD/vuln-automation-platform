"""زحف تطبيقات SPA برأس متصفّح (headless) — نقي وقابل للاختبار.

الزحف الثابت (HTML/regex) يفوت المسارات التي يبنيها JavaScript وقت التشغيل (Angular/
React/Vue routers، نداءات XHR الديناميكية). رأس المتصفّح يُصيّر الصفحة ويلتقط:
  • روابط DOM بعد التصيير.  • طلبات الشبكة الفعلية (XHR/fetch).
مُصيّر الصفحة (render) محقون — في الإنتاج Playwright داخل الـ worker؛ في الاختبار بديل.
كل زحف ضمن مضيف البذرة والنطاق فقط.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from api.services.scope_matching import ScopeRule, evaluate, host_of

MAX_PAGES = 20


@dataclass
class RenderedPage:
    status: int
    links: list[str] = field(default_factory=list)       # روابط DOM بعد التصيير
    xhr: list[str] = field(default_factory=list)          # طلبات XHR/fetch الملتقطة
    final_url: str = ""


# render(url, cookies) -> RenderedPage
RenderFn = Callable[[str, dict], RenderedPage]


@dataclass
class SpaCrawlResult:
    pages: list[str] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)    # روابط + XHR (ضمن النطاق)


def crawl_spa(
    seed: str, render: RenderFn, rules: list[ScopeRule],
    *, cookies: dict | None = None, max_pages: int = MAX_PAGES,
) -> SpaCrawlResult:
    """يصيّر الصفحات برأس متصفّح ويجمع الروابط وطلبات XHR (ضمن النطاق)."""
    base = seed if "://" in seed else f"https://{seed}"
    seed_host = host_of(base)
    cookies = cookies or {}

    def scoped(u: str) -> bool:
        return bool(u) and host_of(u) == seed_host and evaluate(u, rules).allowed

    queue = [base]
    seen: set[str] = set()
    endpoints: dict[str, None] = {}
    out = SpaCrawlResult()

    while queue and len(seen) < max_pages:
        url = queue.pop(0)
        if url in seen or not scoped(url):
            continue
        seen.add(url)
        try:
            page = render(url, cookies)
        except Exception:
            continue
        if page.status == 0:
            continue
        out.pages.append(url)

        # طلبات XHR/fetch التي أطلقها JS = endpoints حقيقية.
        for x in page.xhr:
            if scoped(x):
                endpoints.setdefault(x, None)
        # روابط DOM بعد التصيير — تُزحف وتُسجَّل.
        for link in page.links:
            link = link.split("#", 1)[0]
            if not scoped(link):
                continue
            endpoints.setdefault(link, None)
            if link not in seen and len(seen) + len(queue) < max_pages:
                queue.append(link)

    out.endpoints = list(endpoints)
    return out
