"""منطق الفحص (nuclei) — قابل للاختبار، مع فرض النطاق (دفاع متعدّد الطبقات).

nuclei يُطبَّق على المضيفات الحيّة ضمن النطاق فقط، ويُعاد التحقق من النطاق وقت
الفحص (لو تغيّر نطاق البرنامج بعد الـ recon). كل النتائج تدخل بحالة needs_review
— لا تأكيد تلقائي ولا إرسال.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass

from sqlalchemy.orm import Session

from api.models.audit import AuditLog
from api.models.program import Program
from api.models.recon import Host
from api.models.scan import Finding, FindingStatus, ScanRun, ScanStatus
from api.services.scope_gatekeeper import rules_for
from api.services.scope_matching import evaluate, host_of


@dataclass
class ScanTools:
    nuclei: Callable[[list[str]], list[dict]]


def _finding_from_nuclei(scan_run_id: int, item: dict) -> Finding:
    info = item.get("info") or {}
    host = item.get("host") or ""
    matched = item.get("matched-at") or item.get("matched_at") or host

    evidence_parts: list[str] = []
    if item.get("matcher-name"):
        evidence_parts.append(f"matcher={item['matcher-name']}")
    extracted = item.get("extracted-results")
    if extracted:
        evidence_parts.append(f"extracted={extracted}")

    return Finding(
        scan_run_id=scan_run_id,
        host=host_of(host or matched) or (host or matched),
        endpoint=matched or None,
        vuln_type=item.get("template-id") or info.get("name") or "unknown",
        severity=(info.get("severity") or "info").lower(),
        evidence="; ".join(evidence_parts) or None,
        source_tool="nuclei",
        status=FindingStatus.needs_review,
    )


def _save_raw(output_dir: str, scan_run_id: int, raw: list[dict]) -> None:
    run_dir = os.path.join(output_dir, f"nuclei-{scan_run_id}")
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "results.jsonl"), "w", encoding="utf-8") as fh:
        for item in raw:
            fh.write(json.dumps(item, ensure_ascii=False) + "\n")


def scan_hosts(
    db: Session,
    program: Program,
    tools: ScanTools,
    actor: str = "scan",
    output_dir: str | None = None,
) -> tuple[ScanRun, list[Finding]]:
    scan_run = ScanRun(
        program_id=program.id,
        run_name=f"nuclei-{program.handle}",
        tool="nuclei",
        status=ScanStatus.running,
    )
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)

    hosts = db.query(Host).filter_by(program_id=program.id, in_scope=True, is_live=True).all()

    # إعادة التحقق من النطاق وقت الفحص (قد يكون النطاق تغيّر بعد الـ recon).
    rules = rules_for(program)
    safe: list[Host] = []
    for host in hosts:
        decision = evaluate(host.hostname, rules)
        if decision.allowed:
            safe.append(host)
        else:
            db.add(
                AuditLog(
                    action="scan_scope_block",
                    target_value=host.hostname,
                    program_id=program.id,
                    decision="deny",
                    reason=decision.reason,
                    actor=actor,
                )
            )
    db.commit()

    raw = tools.nuclei([h.hostname for h in safe]) if safe else []
    if output_dir:
        _save_raw(output_dir, scan_run.id, raw)

    findings: list[Finding] = []
    for item in raw:
        finding = _finding_from_nuclei(scan_run.id, item)
        db.add(finding)
        findings.append(finding)

    scan_run.status = ScanStatus.done
    db.commit()
    return scan_run, findings
