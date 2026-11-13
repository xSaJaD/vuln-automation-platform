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
from api.services.vuln_class import classify

MAX_RAW = 20000  # حد تخزين الطلب/الاستجابة الخام لكل finding


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

    vuln_type = item.get("template-id") or info.get("name") or "unknown"
    classification = info.get("classification") or {}
    # الصنف من CWE أولًا، ثم من الـ template-id، ثم من اسم القالب.
    vuln_class, cwe = classify(vuln_type, classification.get("cwe-id"))
    if vuln_class == vuln_type.strip().lower() and info.get("name"):
        by_name, cwe_by_name = classify(info["name"])
        if by_name != info["name"].strip().lower():
            vuln_class, cwe = by_name, cwe or cwe_by_name

    return Finding(
        scan_run_id=scan_run_id,
        host=host_of(host or matched) or (host or matched),
        endpoint=matched or None,
        vuln_type=vuln_type[:100],
        severity=(info.get("severity") or "info").lower(),
        evidence="; ".join(evidence_parts) or None,
        source_tool="nuclei",
        status=FindingStatus.needs_review,
        vuln_class=vuln_class[:100],
        cwe=cwe,
        request=_clip(item.get("request")),
        response=_clip(item.get("response")),
        curl_command=_clip(item.get("curl-command")),
    )


def _clip(value) -> str | None:
    if not value:
        return None
    text = str(value)
    return text if len(text) <= MAX_RAW else text[:MAX_RAW] + "\n…[truncated]"


def scan_targets(hosts: list[Host]) -> list[str]:
    """أهداف nuclei: كل الروابط الحيّة للمضيف (تشمل المنافذ غير القياسية).

    مضيف بلا روابط محفوظة (recon قديم) يُفحص باسمه كما كان.
    """
    targets: list[str] = []
    for host in hosts:
        urls = [u for u in (host.urls or "").splitlines() if u.strip()]
        # دفاع إضافي: الرابط يجب أن يخصّ المضيف نفسه (الذي مرّ الحارس).
        urls = [u for u in urls if host_of(u) == host.hostname.lower()]
        targets.extend(urls or [host.hostname])
    return list(dict.fromkeys(targets))


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

    try:
        raw = tools.nuclei(scan_targets(safe)) if safe else []
    except Exception as exc:
        # انقطاع/خطأ أثناء الفحص => يُسجَّل كـ failed، لا يُعتبر "لا ثغرات".
        scan_run.status = ScanStatus.failed
        scan_run.error = str(exc)[:2000]
        db.commit()
        raise
    if output_dir:
        _save_raw(output_dir, scan_run.id, raw)

    # دفاع إضافي: نتيجة على مضيف لم نطلب فحصه (redirect لطرف ثالث مثلًا) تُهمَل وتُسجَّل.
    allowed_hosts = {h.hostname.lower() for h in safe}
    findings: list[Finding] = []
    for item in raw:
        finding = _finding_from_nuclei(scan_run.id, item)
        if finding.host.lower() not in allowed_hosts:
            db.add(
                AuditLog(
                    action="scan_result_dropped",
                    target_value=finding.host[:500],
                    program_id=program.id,
                    decision="deny",
                    reason="نتيجة على مضيف خارج قائمة الفحص",
                    actor=actor,
                )
            )
            continue
        db.add(finding)
        findings.append(finding)

    # كشف الحظر لكل مضيف: محظور بلا نتائج => نتيجته غير حاسمة (وليست clean).
    from api.services.block_detection import scan_outcome

    with_findings = {f.host.lower() for f in findings}
    blocked_hosts = sorted(
        h.hostname
        for h in safe
        if h.block_status == "blocked" and h.hostname.lower() not in with_findings
    )
    scan_run.blocked_hosts = ",".join(blocked_hosts) or None
    scan_run.outcome = scan_outcome(len(findings), bool(blocked_hosts))
    scan_run.status = ScanStatus.done
    db.commit()
    return scan_run, findings
