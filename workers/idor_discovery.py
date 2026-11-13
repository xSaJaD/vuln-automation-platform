"""اكتشاف مراجع الكائنات المملوكة تلقائيًا (لـ IDOR) — نقي وقابل للاختبار.

يسجّل الدخول كحساب A (جلسته مُمرَّرة)، يزحف صفحاته المصادَقة، ويستخرج الروابط التي
تحوي معرّف كائن (رقم أو UUID) في المسار أو الاستعلام — هذه مرشّحات IDOR. العلامة
(marker) التي تثبت ملكية A هي معرّفه (بريده/اسمه): لو ظهر في رد الحساب B => IDOR.

الطلبات محقونة (requester) حتى تُختبَر بلا شبكة. الزحف محدود ولا يخرج عن النطاق.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from api.services.html_forms import parse
from api.services.scope_matching import ScopeRule, evaluate, host_of
from workers.idor_logic import OwnedResource, Session

MAX_PAGES = 25
MAX_RESOURCES = 50

# رابط يحوي مرجع كائن: رقم (/orders/123، ?id=5) أو UUID.
_NUMERIC_REF = re.compile(r"/\d+(?:/|$|\?)|[?&][\w-]*id[\w-]*=\d+", re.I)
_UUID_REF = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)

# امتدادات ملفات ثابتة نتجاهلها أثناء الزحف.
_SKIP_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")


@dataclass
class PageResponse:
    status_code: int
    body: str = ""


# requester(session, url) -> PageResponse
Requester = Callable[[Session, str], PageResponse]


def _has_object_ref(url: str) -> bool:
    return bool(_NUMERIC_REF.search(url) or _UUID_REF.search(url))


def discover_owned_resources(
    session_a: Session,
    owner_marker: str,
    seed_urls: list[str],
    requester: Requester,
    rules: list[ScopeRule],
    *,
    max_pages: int = MAX_PAGES,
    max_resources: int = MAX_RESOURCES,
) -> list[OwnedResource]:
    """يزحف كحساب A ويرجّع روابط تحوي مراجع كائنات (مرشّحة لـ IDOR)."""
    seeds = [u for u in seed_urls if u and evaluate(u, rules).allowed]
    if not seeds:
        return []
    seed_host = host_of(seeds[0])

    queue = list(dict.fromkeys(seeds))
    seen: set[str] = set()
    resources: dict[str, OwnedResource] = {}

    while queue and len(seen) < max_pages and len(resources) < max_resources:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        # كل طلب ضمن النطاق فقط، ولا يخرج عن مضيف البذرة.
        if host_of(url) != seed_host or not evaluate(url, rules).allowed:
            continue
        if url.lower().rsplit("?", 1)[0].endswith(_SKIP_EXT):
            continue
        try:
            res = requester(session_a, url)
        except Exception:
            continue
        if res.status_code != 200 or not res.body:
            continue

        _, links = parse(res.body, url)
        for link in links:
            link = link.split("#", 1)[0]
            if not link or host_of(link) != seed_host:
                continue
            if _has_object_ref(link) and link not in resources:
                resources[link] = OwnedResource(
                    url=link, owner_label=session_a.label or "idor-a", marker=owner_marker
                )
            if link not in seen and len(seen) + len(queue) < max_pages:
                queue.append(link)

    return list(resources.values())[:max_resources]
