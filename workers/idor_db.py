"""ربط فحص IDOR بقاعدة البيانات: يحمّل الحسابات، يفكّ جلساتها، يشغّل الفحص التفاضلي،
ويحفظ النتائج كـ findings (source_tool='idor', vuln_class='idor'/'broken-access-control').
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session as DbSession

from api.models.account import ProvisionedAccount
from api.models.audit import AuditLog
from api.models.program import Program
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.services.crypto import get_cipher
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import host_of
from workers.idor_logic import OwnedResource, Requester, Session, find_idor

# CVSS افتراضي يُحسب لاحقًا في مرحلة الدمج حسب vuln_class.


def _load_sessions(db: DbSession, program: Program) -> list[Session]:
    cipher = get_cipher()
    if cipher is None:
        raise RuntimeError("التشفير غير مُهيّأ — تعذّر فكّ جلسات الحسابات")
    out = [Session(label=None)]  # جلسة مجهولة دائمًا
    rows = (
        db.query(ProvisionedAccount)
        .filter_by(program_id=program.id, status="created")
        .all()
    )
    for row in rows:
        if not row.session_encrypted:
            continue
        data = json.loads(cipher.decrypt(row.session_encrypted))
        out.append(Session(label=row.label, cookies=data.get("cookies") or {},
                           token=data.get("token")))
    return out


def run_idor(
    db: DbSession,
    program: Program,
    resources: list[OwnedResource],
    requester: Requester,
    actor: str = "idor",
) -> tuple[ScanRun, list[Finding]]:
    scan_run = ScanRun(program_id=program.id, run_name=f"idor-{program.handle}",
                       tool="idor", status=ScanStatus.running)
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    sessions = _load_sessions(db, program)
    if len([s for s in sessions if s.label]) < 2:
        scan_run.status = ScanStatus.failed
        scan_run.error = "يلزم حسابان مُنشآن (created) لاختبار IDOR"
        db.commit()
        return scan_run, []

    def on_block(url, decision):
        db.add(AuditLog(action="idor_scope_block", target_value=url[:500],
                        program_id=program.id, decision="deny", reason=decision.reason, actor=actor))

    try:
        hits = find_idor(resources, sessions, requester, rules_for(program), on_scope_block=on_block)
    except Exception as exc:
        scan_run.status = ScanStatus.failed
        scan_run.error = str(exc)[:2000]
        db.commit()
        raise

    findings: list[Finding] = []
    for h in hits:
        f = Finding(
            scan_run_id=scan_run.id, host=host_of(h.url), endpoint=h.url,
            vuln_type=h.vuln_class, severity=h.severity, evidence=h.evidence,
            source_tool="idor", vuln_class=h.vuln_class,
            cwe="CWE-639" if h.vuln_class == "idor" else "CWE-284",
            status=FindingStatus.needs_review,
        )
        db.add(f)
        findings.append(f)

    scan_run.outcome = "findings" if findings else "clean"
    scan_run.status = ScanStatus.done
    db.commit()
    return scan_run, findings
