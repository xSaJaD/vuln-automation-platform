"""اكتشاف آلي لمراجع كائنات IDOR — منطق نقي.

يزحف الموقع **بجلسة الحساب A**، يجمع الروابط التي تبدو مراجع كائنات (فيها معرّف
رقمي/UUID مثل /orders/1042، /api/users/5، ?id=88)، ويبني OwnedResource لكل رابط
يُرجّح أنه يخصّ A — مع marker يميّز بيانات A داخل الرد (بريده/معرّفه).

الطلبات محقونة (requester) حتى تُختبَر بلا شبكة. كل رابط يُفحَص مقابل النطاق في
مرحلة find_idor لاحقًا؛ هنا نقيّده بنفس المضيف فقط.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from api.services.scope_matching import host_of
from workers.idor_logic import HttpResponse, Session

MAX_PAGES = 60
MAX_RESOURCES = 40

# مسار فيه معرّف كائن: رقم، UUID، أو معرّف طويل.
_NUMERIC_SEG = re.compile(r"/\d{1,12}(?:/|$)")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
_ID_QUERY = re.compile(r"(?:^|&)(?:id|uid|user|account|order|doc|file|record|pid|no)=[\w-]+", re.I)

# مسارات ثابتة لا معنى لتعدادها (أصول/صفحات عامة).
_SKIP_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
             ".woff2", ".ttf", ".map", ".pdf")


@dataclass(frozen=True)
class DiscoveredRef:
    url: str
    reason: str          # لماذا اعتُبر مرجع كائن


class _LinkParser(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links: set[str] = set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        href = a.get("href") or a.get("action") or a.get("data-href")
        if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
            self.links.add(urljoin(self.base, href))


def looks_like_object_ref(url: str) -> str | None:
    """يرجّع سبب اعتبار الرابط مرجع كائن، أو None."""
    path = urlsplit(url).path.lower()
    if path.endswith(_SKIP_EXT):
        return None
    if _UUID.search(url):
        return "uuid"
    if _NUMERIC_SEG.search(urlsplit(url).path):
        return "numeric-path-id"
    if _ID_QUERY.search(urlsplit(url).query):
        return "id-query-param"
    return None


# requester(session, url) -> HttpResponse
Requester = Callable[[Session, str], HttpResponse]


def discover_owned_refs(
    seed_url: str,
    owner: Session,
    markers: list[str],
    requester: Requester,
    *,
    max_pages: int = MAX_PAGES,
    max_resources: int = MAX_RESOURCES,
) -> list[DiscoveredRef]:
    """يزحف بجلسة المالك ويجمع روابط مراجع الكائنات التي يظهر فيها marker المالك.

    markers: نصوص تميّز بيانات المالك (بريده، اسم المستخدم، معرّفه) — المرجع
    يُقبَل فقط إن ظهر أحدها في رده (دليل أنه فعلًا يخصّ المالك).
    """
    root_host = host_of(seed_url)
    norm_markers = [m.lower() for m in markers if m]
    seen: set[str] = set()
    refs: list[DiscoveredRef] = []
    queue: list[str] = [seed_url]
    pages = 0

    while queue and pages < max_pages and len(refs) < max_resources:
        url = queue.pop(0).split("#", 1)[0]
        if url in seen or host_of(url) != root_host:
            continue
        seen.add(url)

        try:
            resp = requester(owner, url)
        except Exception:
            continue
        pages += 1
        if resp.status_code >= 400 or not resp.body:
            continue

        body_low = resp.body.lower()
        reason = looks_like_object_ref(url)
        if reason and (not norm_markers or any(m in body_low for m in norm_markers)):
            refs.append(DiscoveredRef(url=url, reason=reason))

        parser = _LinkParser(url)
        try:
            parser.feed(resp.body)
        except Exception:
            continue
        for link in parser.links:
            link = link.split("#", 1)[0]
            if link not in seen and host_of(link) == root_host:
                queue.append(link)

    return refs
