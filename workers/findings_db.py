"""حفظ نتائج الفاحصات الجديدة (أسرار، معاملات، تحكّم وصول) كـ findings موحّدة.

كل صف يمرّ عبر حارس النطاق قبل حفظه، ويدخل بحالة needs_review (تأكيد بشري لاحقًا).
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.program import Program
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import evaluate, host_of
from api.services.vuln_class import classify

_CWE = {
    "xss": "CWE-79", "sqli": "CWE-89", "ssrf": "CWE-918", "path-traversal": "CWE-22",
    "rce": "CWE-94", "ssti": "CWE-1336", "idor": "CWE-639", "open-redirect": "CWE-601",
    "privilege-escalation": "CWE-269", "broken-access-control": "CWE-284",
    "secret-exposure": "CWE-200", "xxe": "CWE-611",
}


def persist(db: Session, program: Program, tool: str, rows: list[dict],
            actor: str = "scanner") -> tuple[ScanRun, list[Finding]]:
    """rows: [{host, endpoint, vuln_class, severity, evidence, cwe?}]. يحفظ ضمن النطاق فقط."""
    scan_run = ScanRun(program_id=program.id, run_name=f"{tool}-{program.handle}",
                       tool=tool, status=ScanStatus.running)
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    rules = rules_for(program)
    findings: list[Finding] = []
    for row in rows:
        host = row.get("host") or host_of(row.get("endpoint") or "")
        target = row.get("endpoint") or host
        if target and not evaluate(target, rules).allowed:
            db.add(AuditLog(action=f"{tool}_scope_drop", target_value=str(target)[:500],
                            program_id=program.id, decision="deny",
                            reason="نتيجة خارج النطاق أُهمِلت", actor=actor))
            continue
        vclass = row.get("vuln_class") or classify(row.get("vuln_type"))[0]
        f = Finding(
            scan_run_id=scan_run.id, host=host, endpoint=row.get("endpoint"),
            vuln_type=row.get("vuln_type") or vclass, severity=row.get("severity") or "info",
            evidence=row.get("evidence"), source_tool=tool, vuln_class=vclass,
            cwe=row.get("cwe") or _CWE.get(vclass), status=FindingStatus.needs_review,
        )
        db.add(f)
        findings.append(f)

    scan_run.outcome = "findings" if findings else "clean"
    scan_run.status = ScanStatus.done
    db.commit()
    return scan_run, findings
