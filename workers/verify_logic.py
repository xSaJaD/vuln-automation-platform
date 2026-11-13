"""مرحلة التحقق (Verification) — قابلة للاختبار، مع فرض النطاق.

الفكرة: نتيجة تظهر مرّة واحدة قد تكون عارضة (false positive). نعيد تشغيل **نفس
قالب nuclei على نفس الهدف** بشكل مستقل؛ إن تكرّرت النتيجة تُعلَّم verified وترتفع
ثقتها إلى high. إن لم تتكرّر تبقى للمراجعة البشرية بثقة منخفضة — لا تُحذف.

ما لا يفعله هذا الملف (عمدًا):
  • لا يتحقق من نتائج Strix آليًا — تبقى غير verified حتى يراجعها إنسان.
  • لا يغيّر حالة الـ triage: التأكيد النهائي (confirmed) قرار بشري دائمًا.
"""

from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.correlation import CorrelatedFinding
from api.models.program import Program
from api.models.scan import Finding, FindingStatus, ScanRun
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import evaluate
from workers.correlation_logic import confidence_for, correlation_key

# rerun(target, template_id) -> نتائج nuclei الخام لذلك القالب على ذلك الهدف
Rerun = Callable[[str, str], list[dict]]


def verify_findings(db: Session, program: Program, rerun: Rerun, actor: str = "verify") -> dict:
    rules = rules_for(program)
    rows = (
        db.query(CorrelatedFinding)
        .filter_by(program_id=program.id, verified=False, status=FindingStatus.needs_review)
        .all()
    )
    raw = (
        db.query(Finding)
        .join(ScanRun, Finding.scan_run_id == ScanRun.id)
        .filter(ScanRun.program_id == program.id, Finding.source_tool == "nuclei")
        .all()
    )
    by_key: dict[str, Finding] = {}
    for f in raw:
        by_key.setdefault(correlation_key(f.host, f.endpoint, f.vuln_type, f.vuln_class), f)

    stats = {"checked": 0, "verified": 0, "not_reproduced": 0, "skipped": 0, "errors": 0}
    for cf in rows:
        source = by_key.get(cf.correlation_key)
        target = (source.endpoint or source.host) if source else None
        if source is None or not target:
            stats["skipped"] += 1  # لا مصدر nuclei (Strix فقط) => مراجعة بشرية
            continue

        # النطاق قد يكون تغيّر منذ الفحص — يُعاد التحقق قبل أي طلب جديد.
        decision = evaluate(target, rules)
        if not decision.allowed:
            db.add(
                AuditLog(
                    action="verify_scope_block",
                    target_value=target[:500],
                    program_id=program.id,
                    decision="deny",
                    reason=decision.reason,
                    actor=actor,
                )
            )
            stats["skipped"] += 1
            continue

        stats["checked"] += 1
        try:
            results = rerun(target, source.vuln_type)
        except Exception:
            stats["errors"] += 1  # فشل الأداة ليس "لم تتكرّر"
            continue

        reproduced = any((r.get("template-id") or "") == source.vuln_type for r in results)
        db.add(
            AuditLog(
                action="verify_finding",
                target_value=target[:500],
                program_id=program.id,
                decision="allow",
                reason="أُعيد إنتاجها" if reproduced else "لم تتكرّر",
                actor=actor,
            )
        )
        if reproduced:
            cf.verified = True
            stats["verified"] += 1
        else:
            stats["not_reproduced"] += 1
        cf.confidence = confidence_for((cf.sources or "").split(","), bool(cf.verified))

    db.commit()
    return stats
