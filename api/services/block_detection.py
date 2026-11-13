"""كشف الحظر (WAF/rate-limit/captcha) — نقي وقابل للاختبار.

يميّز "استجابة محظورة" عن "لا ثغرات فعلية": المضيف المحظور تكون نتيجته
inconclusive وليست clean.

ملاحظة: 401 ليس حظرًا (صفحة مصادقة طبيعية)، لذلك لا يُعدّ إشارة WAF.
"""

from __future__ import annotations

WAF_STATUSES = {403, 406, 429, 503}
BLOCK_MARKERS = (
    "captcha",
    "cloudflare",
    "access denied",
    "are you human",
    "attention required",
    "request blocked",
    "rate limited",
)

# نسبة الاستجابات المحظورة أثناء الفحص التي نعتبر بعدها المضيف محظورًا.
BLOCK_RATIO_THRESHOLD = 0.5
MIN_SAMPLES = 5


def looks_blocked(status_code: int | None = None, title: str = "", body: str = "") -> bool:
    if status_code in WAF_STATUSES:
        return True
    hay = f"{title} {body}".lower()
    return any(marker in hay for marker in BLOCK_MARKERS)


def blocked_by_ratio(status_codes: list[int]) -> bool:
    """حظر أثناء الفحص: أغلب استجابات المضيف 403/429/…​ (بعد عيّنة كافية)."""
    if len(status_codes) < MIN_SAMPLES:
        return False
    blocked = sum(1 for s in status_codes if s in WAF_STATUSES)
    return blocked / len(status_codes) >= BLOCK_RATIO_THRESHOLD


def scan_outcome(findings_count: int, blocked: bool) -> str:
    """findings / inconclusive / clean — المحظور لا يُعتبر clean."""
    if findings_count > 0:
        return "findings"
    return "inconclusive" if blocked else "clean"
