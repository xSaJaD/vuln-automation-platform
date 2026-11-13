"""تطبيع نوع الثغرة إلى صنف موحّد (vuln_class) + CWE — نقي وقابل للاختبار.

الأدوات تسمّي الثغرة نفسها بأسماء مختلفة (nuclei: template-id، Strix: عنوان حرّ).
بدون تطبيع لا يتطابق مصدران أبدًا فيفشل الدمج. الأولوية: CWE ثم الكلمات المفتاحية،
وإن لم يُعرف الصنف يبقى الاسم الأصلي (حتى لا تُدمج ثغرات مختلفة بالخطأ).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

_CWE_CLASS = {
    79: "xss",
    89: "sqli",
    564: "sqli",
    918: "ssrf",
    22: "path-traversal",
    23: "path-traversal",
    98: "path-traversal",
    77: "rce",
    78: "rce",
    94: "rce",
    95: "rce",
    502: "deserialization",
    1336: "ssti",
    639: "idor",
    284: "access-control",
    285: "access-control",
    862: "access-control",
    863: "access-control",
    287: "auth-bypass",
    306: "auth-bypass",
    601: "open-redirect",
    352: "csrf",
    611: "xxe",
    200: "info-disclosure",
    538: "info-disclosure",
    798: "default-credentials",
    1392: "default-credentials",
}

# الترتيب مهم: الأكثر تحديدًا أولًا.
_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("ssti", ("ssti", "template injection")),
    ("sqli", ("sqli", "sql injection", "sql-injection")),
    ("xss", ("xss", "cross-site scripting", "cross site scripting")),
    ("ssrf", ("ssrf", "server-side request forgery", "server side request forgery")),
    ("xxe", ("xxe", "xml external entity")),
    ("path-traversal", ("lfi", "path traversal", "path-traversal", "directory traversal",
                        "local file inclusion", "file-inclusion")),
    ("deserialization", ("deserialization", "deserialisation")),
    ("rce", ("rce", "remote code execution", "command injection", "code injection")),
    ("idor", ("idor", "insecure direct object")),
    ("open-redirect", ("open redirect", "open-redirect", "unvalidated redirect")),
    ("csrf", ("csrf", "cross-site request forgery")),
    ("default-credentials", ("default login", "default-login", "default credentials",
                             "default-credentials")),
    ("auth-bypass", ("auth bypass", "auth-bypass", "authentication bypass")),
]

_CLASS_CWE = {
    "xss": "CWE-79",
    "sqli": "CWE-89",
    "ssrf": "CWE-918",
    "path-traversal": "CWE-22",
    "rce": "CWE-94",
    "ssti": "CWE-1336",
    "idor": "CWE-639",
    "open-redirect": "CWE-601",
    "csrf": "CWE-352",
    "xxe": "CWE-611",
    "deserialization": "CWE-502",
}


def _cwe_numbers(cwe_ids) -> list[int]:
    if not cwe_ids:
        return []
    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]
    nums: list[int] = []
    for raw in cwe_ids:
        m = re.search(r"(\d+)", str(raw))
        if m:
            nums.append(int(m.group(1)))
    return nums


def _has_word(haystack: str, needle: str) -> bool:
    # مطابقة على حدود الكلمة: "lfi" لا يطابق "selfie"، و"rce" لا يطابق "source".
    return re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", haystack) is not None


def classify(vuln_type: str | None, cwe_ids=None) -> tuple[str, str | None]:
    """يرجّع (vuln_class, cwe). الصنف غير المعروف يبقى باسمه الأصلي مطبَّعًا."""
    nums = _cwe_numbers(cwe_ids)
    for n in nums:
        if n in _CWE_CLASS:
            return _CWE_CLASS[n], f"CWE-{n}"

    name = (vuln_type or "").strip().lower()
    for cls, words in _KEYWORDS:
        if any(_has_word(name, w) for w in words):
            return cls, (f"CWE-{nums[0]}" if nums else _CLASS_CWE.get(cls))

    return (name or "unknown"), (f"CWE-{nums[0]}" if nums else None)


def normalize_endpoint(endpoint: str | None) -> str:
    """host[:port]/path بدون scheme ولا قيم query (تبقى أسماء المعاملات مرتّبة).

    هكذا يُدمج الرصدان `/x?id=1` و `/x?id=2` بينما يبقى `/x?name=a` مستقلًا.
    """
    raw = (endpoint or "").strip()
    if not raw:
        return ""
    parts = urlsplit(raw if "://" in raw else f"//{raw}")
    host = (parts.hostname or "").lower().rstrip(".")
    try:
        port = parts.port
    except ValueError:
        port = None
    if port and port not in (80, 443):
        host = f"{host}:{port}"
    path = parts.path.rstrip("/").lower()
    names = sorted({p.split("=", 1)[0].lower() for p in parts.query.split("&") if p})
    query = ("?" + "&".join(names)) if names else ""
    return f"{host}{path}{query}"
