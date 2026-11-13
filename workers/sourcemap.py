"""استعادة الكود الأصلي من source maps (.map) — نقي وقابل للاختبار.

إذا نشر الموقع ملفات .map، نستعيد المصادر غير المضغوطة فنستخرج منها endpoints
وأسرارًا يفوتها الـ regex على الـ bundle المضغوط.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class SourceMap:
    sources: list[str] = field(default_factory=list)       # أسماء الملفات الأصلية
    contents: list[str] = field(default_factory=list)      # نصوصها (sourcesContent)


def parse_sourcemap(raw: str) -> SourceMap | None:
    """يحلّل ملف .map ويرجّع المصادر ومحتواها (إن وُجد sourcesContent)."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    sources = [str(s) for s in (data.get("sources") or []) if s]
    contents = [c for c in (data.get("sourcesContent") or []) if isinstance(c, str)]
    return SourceMap(sources=sources, contents=contents)


def sourcemap_url_for(js_url: str, body: str = "") -> str | None:
    """يستنتج رابط الـ .map: من تعليق sourceMappingURL أو بإضافة .map افتراضيًا."""
    for line in (body or "").splitlines()[-5:]:
        line = line.strip()
        if "sourceMappingURL=" in line:
            ref = line.split("sourceMappingURL=", 1)[1].strip().rstrip("*/ ")
            if ref and not ref.startswith("data:"):
                from urllib.parse import urljoin
                return urljoin(js_url, ref)
    if js_url.endswith(".js"):
        return js_url + ".map"
    return None
