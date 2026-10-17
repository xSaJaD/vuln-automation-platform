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

from api.models.program import Program
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.services.scope_gatekeeper import check_target
from api.services.scope_matching import host_of


@dataclass
class StrixResult:
    exit_code: int
    vulnerabilities: list[dict] = field(default_factory=list)
    run_dir: str | None = None


# runner(target, instruction) -> StrixResult
StrixRunner = Callable[[str, "str | None"], StrixResult]


def _finding_from_strix(scan_run_id: int, vuln: dict) -> Finding:
    location = vuln.get("url") or vuln.get("location") or vuln.get("endpoint") or ""
    return Finding(
        scan_run_id=scan_run_id,
        host=host_of(location) or vuln.get("host") or location,
        endpoint=location or None,
        vuln_type=vuln.get("type") or vuln.get("title") or vuln.get("name") or "unknown",
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

    result = runner(target, instruction)

    findings: list[Finding] = []
    for vuln in result.vulnerabilities:
        finding = _finding_from_strix(scan_run.id, vuln)
        db.add(finding)
        findings.append(finding)

    # exit_code 124 = انتهت المهلة (timeout) => فشل. غير ذلك => اكتمل.
    scan_run.status = ScanStatus.failed if result.exit_code == 124 else ScanStatus.done
    db.commit()
    return scan_run, findings
