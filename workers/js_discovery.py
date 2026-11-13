"""اكتشاف كل الـ endpoints من ملفات JS الخاصة بالموقع — نقي وقابل للاختبار.

لكل صفحة ضمن النطاق: يجمع <script src> + الأكواد المضمّنة، يجلب كل ملف JS، ويستخرج
الـ endpoints منه. يجمع النتائج ويُبقي ما يقع ضمن النطاق فقط. الجالب (fetch) محقون.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from api.services.html_forms import parse_page
from api.services.scope_matching import ScopeRule, evaluate, host_of
from workers.js_endpoints import extract_endpoints

MAX_PAGES = 15
MAX_SCRIPTS = 60


@dataclass
class Fetched:
    status_code: int
    body: str = ""
    final_url: str = ""


# fetch(url) -> Fetched
FetchFn = Callable[[str], Fetched]


@dataclass
class JsDiscovery:
    endpoints: list[str] = field(default_factory=list)
    scripts_read: list[str] = field(default_factory=list)
    pages_crawled: list[str] = field(default_factory=list)


def discover_js_endpoints(
    seed_urls: list[str],
    fetch: FetchFn,
    rules: list[ScopeRule],
    *,
    max_pages: int = MAX_PAGES,
    max_scripts: int = MAX_SCRIPTS,
) -> JsDiscovery:
    """يزحف الصفحات، يقرأ كل JS مرتبط، ويستخرج الـ endpoints (كلها ضمن النطاق)."""
    seeds = [
        (u if "://" in u else f"https://{u}")
        for u in seed_urls if u and evaluate(u, rules).allowed
    ]
    if not seeds:
        return JsDiscovery()
    seed_host = host_of(seeds[0])

    page_q = list(dict.fromkeys(seeds))
    seen_pages: set[str] = set()
    seen_scripts: set[str] = set()
    endpoints: dict[str, None] = {}
    out = JsDiscovery()

    def _scoped(url: str) -> bool:
        return host_of(url) == seed_host and evaluate(url, rules).allowed

    while page_q and len(seen_pages) < max_pages:
        page = page_q.pop(0)
        if page in seen_pages or not _scoped(page):
            continue
        seen_pages.add(page)
        try:
            res = fetch(page)
        except Exception:
            continue
        if res.status_code != 200 or not res.body:
            continue
        out.pages_crawled.append(page)
        parsed = parse_page(res.body, res.final_url or page)

        # أكواد JS المضمّنة في الصفحة.
        for inline in parsed.inline_scripts:
            for ep in extract_endpoints(inline, page):
                endpoints.setdefault(ep, None)

        # ملفات JS الخارجية.
        for src in parsed.scripts:
            if src in seen_scripts or len(seen_scripts) >= max_scripts or not _scoped(src):
                continue
            seen_scripts.add(src)
            try:
                js = fetch(src)
            except Exception:
                continue
            if js.status_code != 200 or not js.body:
                continue
            out.scripts_read.append(src)
            for ep in extract_endpoints(js.body, src):
                if _scoped(ep):
                    endpoints.setdefault(ep, None)

        # توسّع محدود على روابط الصفحة نفسها (ضمن المضيف).
        for link in parsed.links:
            if _scoped(link) and link not in seen_pages and len(page_q) + len(seen_pages) < max_pages:
                page_q.append(link)

    out.endpoints = list(endpoints)
    return out
