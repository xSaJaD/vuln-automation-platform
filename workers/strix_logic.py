"""منطق دمج Strix — قابل للاختبار، مع فرض النطاق.

المُشغِّل (runner) يُحقَن حتى يمكن استبداله ببديل وهمي في الاختبارات.

الضمانات:
  • الهدف يمر عبر Scope Gatekeeper قبل تشغيل Strix (يُسجَّل في audit_log).
  • نتائج Strix تُعلَّم confirmed_by_strix=True (Strix يتحقق بالاستغلال الفعلي)،
    لكن حالتها تبقى needs_review — لا تأكيد نهائي ولا إرسال بدون مراجعة بشرية.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.program import Program
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.services.scope_gatekeeper import check_target, rules_for
from api.services.scope_matching import evaluate, host_of
from api.services.vuln_class import classify


@dataclass
class StrixResult:
    exit_code: int
    vulnerabilities: list[dict] = field(default_factory=list)
    run_dir: str | None = None


# runner(target, instruction) -> StrixResult
StrixRunner = Callable[[str, "str | None"], StrixResult]


def _finding_from_strix(scan_run_id: int, vuln: dict) -> Finding:
    location = vuln.get("url") or vuln.get("location") or vuln.get("endpoint") or ""
    vuln_type = str(vuln.get("type") or vuln.get("title") or vuln.get("name") or "unknown")
    vuln_class, cwe = classify(vuln_type, vuln.get("cwe") or vuln.get("cwe_id"))
    return Finding(
        scan_run_id=scan_run_id,
        host=host_of(location) or vuln.get("host") or location,
        endpoint=location or None,
        vuln_type=vuln_type[:100],
        vuln_class=vuln_class[:100],
        cwe=cwe,
        severity=(vuln.get("severity") or "info").lower(),
        evidence=vuln.get("poc") or vuln.get("evidence") or vuln.get("description"),
        source_tool="strix",
        confirmed_by_strix=True,          # Strix يتحقق بالاستغلال الفعلي
        status=FindingStatus.needs_review,  # تبقى للمراجعة البشرية قبل أي تقرير
    )


def run_strix_scan(
    db: Session,
    program: Program,
    target: str,
    runner: StrixRunner,
    *,
    instruction: str | None = None,
    actor: str = "strix",
) -> tuple[ScanRun, list[Finding]]:
    # فرض النطاق أولًا — يُسجَّل في audit_log داخل check_target.
    decision = check_target(db, program, target, actor=actor)

    scan_run = ScanRun(
        program_id=program.id,
        run_name=f"strix-{program.handle}",
        tool="strix",
        status=ScanStatus.running,
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    if not decision.allowed:
        # هدف خارج النطاق — لا يُشغَّل Strix إطلاقًا.
        scan_run.status = ScanStatus.failed
        db.commit()
        return scan_run, []

    try:
        result = runner(target, instruction)
    except Exception as exc:
        # انقطاع Docker/LLM أو خطأ => يُسجَّل كـ failed، لا يُعتبر "لا ثغرات".
        scan_run.status = ScanStatus.failed
        scan_run.error = str(exc)[:2000]
        db.commit()
        raise

    # Strix وكيل ذاتي قد يبتعد عن الهدف: كل نتيجة يُعاد فحص مضيفها مقابل النطاق.
    rules = rules_for(program)
    findings: list[Finding] = []
    for vuln in result.vulnerabilities:
        finding = _finding_from_strix(scan_run.id, vuln)
        if not finding.host:
            finding.host = host_of(target) or target
        elif not evaluate(finding.host, rules).allowed:
            db.add(
                AuditLog(
                    action="strix_result_dropped",
                    target_value=finding.host[:500],
                    program_id=program.id,
                    decision="deny",
                    reason="نتيجة Strix على مضيف خارج النطاق",
                    actor=actor,
                )
            )
            continue
        db.add(finding)
        findings.append(finding)

    # أي exit code غير 0 (انهيار، 124 = timeout) => فشل، وليس "لا ثغرات".
    # النتائج الجزئية تُحفظ، لكن التشغيل لا يُعدّ مكتملًا.
    if result.exit_code != 0:
        scan_run.status = ScanStatus.failed
        scan_run.error = f"strix exit code {result.exit_code}"
    else:
        scan_run.status = ScanStatus.done
        scan_run.outcome = "findings" if findings else "clean"
    db.commit()
    return scan_run, findings
