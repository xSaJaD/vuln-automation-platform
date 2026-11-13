"""كشف الأسرار المسرّبة في JS/الردود — نقي وقابل للاختبار.

مفاتيح/توكنات مكشوفة في ملفات JS للواجهة من أكثر الثغرات المقبولة ببرامج bug bounty.
الأنماط محافِظة (تتطلب بنية مميّزة) لتقليل الإيجابيات الكاذبة. كل كشف يُطبَّع إلى
نوع + قيمة مقنّعة (لا نُخزّن السر كاملًا في النتائج).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# (النوع, الشدّة, النمط). الترتيب: الأكثر تحديدًا أولًا.
_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("aws_access_key", "high", re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16})\b")),
    ("aws_secret_key", "high", re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]")),
    ("google_api_key", "high", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("gcp_oauth", "high", re.compile(r"\b([0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com)\b")),
    ("stripe_secret", "critical", re.compile(r"\b(sk_live_[0-9a-zA-Z]{24,})\b")),
    ("stripe_restricted", "high", re.compile(r"\b(rk_live_[0-9a-zA-Z]{24,})\b")),
    ("github_token", "high", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36,})\b")),
    ("slack_token", "high", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")),
    ("slack_webhook", "medium", re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)")),
    ("twilio_sid", "medium", re.compile(r"\b(AC[0-9a-fA-F]{32})\b")),
    ("sendgrid_key", "high", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b")),
    ("private_key", "critical", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)")),
    ("jwt", "low", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")),
    ("generic_api_key", "medium", re.compile(
        r"(?i)(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,64})['\"]")),
]

# قيم شائعة زائفة تُستبعَد (أمثلة/حشو).
_FALSE = re.compile(r"(?i)^(?:x{8,}|0{8,}|your[_-]?(?:api|key|token)|example|placeholder|test|dummy|changeme|none|null|undefined)")


@dataclass(frozen=True)
class SecretHit:
    kind: str
    severity: str
    masked: str          # قيمة مقنّعة (أول 4 + آخر 4)
    context: str = ""


def _mask(value: str) -> str:
    v = value.strip()
    if len(v) <= 10:
        return v[:2] + "…"
    return f"{v[:4]}…{v[-4:]} (len={len(v)})"


def scan_secrets(text: str, *, context: str = "") -> list[SecretHit]:
    """يرجّع الأسرار المكتشفة (مقنّعة). يتجاهل التكرار والقيم الزائفة الواضحة."""
    hits: dict[str, SecretHit] = {}
    for kind, severity, pattern in _PATTERNS:
        for m in pattern.finditer(text or ""):
            value = m.group(1)
            if _FALSE.match(value.strip()):
                continue
            key = f"{kind}:{value}"
            if key not in hits:
                hits[key] = SecretHit(kind=kind, severity=severity, masked=_mask(value),
                                      context=context[:200])
    return list(hits.values())
