"""تشابه الردود — لقياس IDOR بدقّة بدل الاعتماد على marker واحد.

المقارنة الثلاثية: رد المالك (A)، رد الآخر (B)، رد الخطأ/المجهول. إذا رد B يشبه رد A
بدرجة عالية ويختلف جوهريًا عن رد الخطأ => B يرى بيانات A (IDOR). نقي بالكامل.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

_WS = re.compile(r"\s+")
# قيم متغيّرة بين الطلبات (تواريخ، توكنات CSRF، nonces) نحذفها قبل المقارنة.
_VOLATILE = re.compile(r"(?i)(csrf|nonce|token|timestamp|_t=)[\w=-]+")


def _normalize(body: str) -> str:
    body = _VOLATILE.sub("", body or "")
    return _WS.sub(" ", body).strip()


def ratio(a: str, b: str) -> float:
    """نسبة تشابه 0..1 بين نصّين (بعد التطبيع)."""
    na, nb = _normalize(a), _normalize(b)
    if not na and not nb:
        return 1.0
    return SequenceMatcher(None, na, nb, autojunk=False).ratio()


def is_same_resource(
    owner_body: str, other_body: str, error_body: str,
    *, same_threshold: float = 0.9, diff_threshold: float = 0.6,
) -> bool:
    """True إذا رد الآخر يشبه رد المالك (≥same) ويختلف عن رد الخطأ (≤diff)."""
    to_owner = ratio(owner_body, other_body)
    to_error = ratio(error_body, other_body)
    return to_owner >= same_threshold and to_error <= diff_threshold
