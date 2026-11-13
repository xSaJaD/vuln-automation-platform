"""الفحص التفاضلي (Delta) — افحص الجديد فقط. نقي وقابل للاختبار.

يقارن بصمة سطح الهجوم الحالية (مضيفات/روابط/تقنيات/منافذ) بآخر لقطة مخزّنة، ويرجّع
الجديد فقط. أسرع بكثير، وبالـ bug bounty أغلب الثغرات في ما استُحدث.
"""

from __future__ import annotations

from collections.abc import Iterable


def fingerprint_hosts(hosts: Iterable) -> set[str]:
    """بصمة سطح الهجوم: مضيف، كل رابط، تقنية، ومنافذ — سطر لكل عنصر."""
    fp: set[str] = set()
    for h in hosts:
        name = (getattr(h, "hostname", "") or "").lower()
        if not name:
            continue
        fp.add(f"host:{name}")
        for url in (getattr(h, "urls", "") or "").splitlines():
            if url.strip():
                fp.add(f"url:{url.strip()}")
        if getattr(h, "tech", None):
            for t in str(h.tech).split(","):
                if t.strip():
                    fp.add(f"tech:{name}:{t.strip().lower()}")
        if getattr(h, "open_ports", None):
            fp.add(f"ports:{name}:{h.open_ports}")
    return fp


def diff(previous: set[str], current: set[str]) -> dict:
    """يرجّع الجديد والمُزال بين لقطتين."""
    added = current - previous
    removed = previous - current
    return {
        "added": sorted(added),
        "removed": sorted(removed),
        "new_urls": sorted(x[4:] for x in added if x.startswith("url:")),
        "new_hosts": sorted(x[5:] for x in added if x.startswith("host:")),
        "changed": bool(added or removed),
    }
