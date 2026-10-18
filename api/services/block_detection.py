"""كشف الحظر (WAF/rate-limit/captcha) — نقي وقابل للاختبار.

يميّز "استجابة محظورة" عن "لا ثغرات فعلية": المضيف المحظور تكون نتيجته
inconclusive وليست clean.
"""

from __future__ import annotations

WAF_STATUSES = {401, 403, 406, 429, 503}
BLOCK_MARKERS = (
    "captcha",
    "cloudflare",
    "access denied",
    "are you human",
    "attention required",
    "request blocked",
    "rate limited",
)


def looks_blocked(status_code: int | None = None, title: str = "", body: str = "") -> bool:
    if status_code in WAF_STATUSES:
        return True
    hay = f"{title} {body}".lower()
    return any(marker in hay for marker in BLOCK_MARKERS)


def scan_outcome(findings_count: int, blocked: bool) -> str:
    """findings / inconclusive / clean — المحظور لا يُعتبر clean."""
    if findings_count > 0:
        return "findings"
    return "inconclusive" if blocked else "clean"
