"""قياس دقّة الفحص (precision / recall / F1) مقابل أهداف معروفة الثغرات — نقي.

الدليل الوحيد الذي يسمح بقول "الفحص صحيح": نقارن ما اكتشفته المنصة بقائمة الحقيقة
الأرضية (ground truth) لهدف اختباري (Juice Shop/DVWA/WebGoat/crAPI). كل ثغرة تُطبَّع
إلى مفتاح موحّد (صنف + مضيف + مسار) حتى تُقارَن بإنصاف.
"""

from __future__ import annotations

from dataclasses import dataclass

from api.services.vuln_class import classify, normalize_endpoint


def finding_key(vuln_class: str | None, host: str | None, endpoint: str | None) -> str:
    cls = (vuln_class or "").strip().lower() or classify(vuln_class)[0]
    ep = normalize_endpoint(endpoint) or (host or "").strip().lower()
    return f"{cls}|{ep}"


@dataclass
class BenchmarkScore:
    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    false_negatives: int
    matched: list[str]
    missed: list[str]
    extra: list[str]


def score(found: set[str], expected: set[str]) -> BenchmarkScore:
    """يحسب المقاييس من مجموعتَي مفاتيح (اكتُشف / المتوقّع)."""
    tp = found & expected
    fp = found - expected
    fn = expected - found
    precision = len(tp) / len(found) if found else (1.0 if not expected else 0.0)
    recall = len(tp) / len(expected) if expected else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return BenchmarkScore(
        precision=round(precision, 3), recall=round(recall, 3), f1=round(f1, 3),
        true_positives=len(tp), false_positives=len(fp), false_negatives=len(fn),
        matched=sorted(tp), missed=sorted(fn), extra=sorted(fp),
    )
