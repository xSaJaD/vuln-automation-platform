"""استخراج الـ endpoints من ملفات/أكواد JavaScript — نقي وقابل للاختبار.

المواقع الحديثة (SPA) تخبّئ أغلب مساراتها داخل JS (fetch/axios/XHR، ثوابت المسارات).
هذا المحلّل يستخرجها بتعبيرات نمطية (أسلوب LinkFinder) ثم ينظّفها ويحوّلها لروابط
مطلقة ضمن مضيف الأساس. لا يطلب شبكة — يعمل على نصّ JS مُمرَّر.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from api.services.scope_matching import host_of

# سلاسل مقتبسة تبدو كمسار/رابط API.
_PATTERN = re.compile(
    r"""(?:"|'|`)
    (
        (?:[a-zA-Z][a-zA-Z0-9+.-]{1,9}://|//)[\w.-]+\.[a-zA-Z]{2,}[^"'`\s]*  # رابط كامل
        |
        /[\w./-]+(?:/[\w.-]+)*(?:\?[^"'`\s]*)?                               # مسار يبدأ بـ /
        |
        [\w-]+/[\w./-]{2,}(?:\?[^"'`\s]*)?                                   # مسار نسبي api/x
    )
    (?:"|'|`)""",
    re.VERBOSE,
)

# استدعاءات fetch/axios/XHR الصريحة (تلتقط المسار حتى لو جمعه كود).
_CALL = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?|\.open|url)\s*\(\s*
        (?:"|'|`)([^"'`]+)(?:"|'|`)""",
    re.VERBOSE | re.IGNORECASE,
)

# نتجاهل السلاسل التي هي امتداد ملف ثابت/نوع MIME/نص لا معنى له كمسار.
_NOISE_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
              ".woff2", ".ttf", ".map", ".scss", ".less")
_NOISE_SUBSTR = ("text/", "image/", "application/", "charset", "@babel", "node_modules")
_PATH_RE = re.compile(r"^[\w./~!$&'()*+,;=:@%-]*$")


def _looks_like_path(s: str) -> bool:
    low = s.lower()
    if any(n in low for n in _NOISE_SUBSTR):
        return False
    base = low.split("?", 1)[0]
    if base.endswith(_NOISE_EXT):
        return False
    # يجب أن يحوي '/' (مسار) أو يبدأ بـ http.
    if "://" in s or s.startswith("//"):
        return True
    if "/" not in s:
        return False
    # يرفض السلاسل التي تحوي مسافات أو محارف لا تظهر في مسار.
    return bool(_PATH_RE.match(s.split("?", 1)[0]))


def extract_endpoints(js: str, base_url: str = "") -> list[str]:
    """يرجّع قائمة روابط/مسارات فريدة مكتشفة في نصّ JS.

    مع base_url: يحوّل النسبي إلى مطلق ويُبقي فقط ما يقع على مضيف الأساس.
    """
    found: set[str] = set()
    for m in _PATTERN.finditer(js or ""):
        found.add(m.group(1))
    for m in _CALL.finditer(js or ""):
        found.add(m.group(1))

    out: dict[str, None] = {}
    base_host = host_of(base_url) if base_url else ""
    for raw in found:
        s = raw.strip()
        if not s or not _looks_like_path(s):
            continue
        if base_url:
            absu = urljoin(base_url, s if not s.startswith("//") else "https:" + s)
            # خارج مضيف الأساس يُهمَل (لا نزحف أطرافًا ثالثة).
            if base_host and host_of(absu) != base_host:
                continue
            out.setdefault(absu, None)
        else:
            out.setdefault(s, None)
    return list(out)
